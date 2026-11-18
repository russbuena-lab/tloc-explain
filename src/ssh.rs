use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use regex::Regex;

use crate::models::{runtime_scratch_dir, utc_now_rfc3339, RouterSnapshot};
use crate::parsers::{build_snapshot_from_text, parse_omp_routes, parse_omp_tlocs};

/// Validates that every CLI command sent over SSH is strictly read-only.
pub fn validate_readonly_cli_command(cmd: &str) -> Result<&str, String> {
    let trimmed = cmd.trim();
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(format!("Refusing multi-line command: {:?}", cmd));
    }
    let redirect_re = Regex::new(r"(?i)\|\s*(redirect|append|tee|save|copy)\b").expect("valid regex");
    if redirect_re.is_match(trimmed) {
        return Err(format!("Refusing file redirection in command: {:?}", cmd));
    }
    let allow_re =
        Regex::new(r"(?i)^(terminal\s+length\s+0|paginate\s+false|show\s+.+|exit)$")
            .expect("valid regex");
    if !allow_re.is_match(trimmed) {
        return Err(format!("Command outside read-only allowlist: {:?}", cmd));
    }
    Ok(trimmed)
}

struct AskpassGuard {
    path: PathBuf,
}

impl AskpassGuard {
    fn create() -> Result<Self, String> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = runtime_scratch_dir()
            .join(format!("tloc-askpass-{}-{}.sh", std::process::id(), nanos));
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("Failed creating askpass helper: {e}"))?;
        f.write_all(b"#!/bin/sh\nprintf '%s\\n' \"$TLOC_SSH_PASS\"\n")
            .map_err(|e| format!("Failed writing askpass helper: {e}"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Failed chmod askpass helper: {e}"))?;
        Ok(Self { path })
    }
}

impl Drop for AskpassGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct TtyEchoGuard {
    tty_fd: fs::File,
}

impl TtyEchoGuard {
    fn disable_echo() -> Result<Self, String> {
        let tty = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|_| {
                "Cannot prompt for password without an interactive terminal (/dev/tty). Pass -i <keyfile> or set TLOC_SSH_PASS.".to_string()
            })?;
        let status = Command::new("stty")
            .arg("-echo")
            .stdin(Stdio::from(
                tty.try_clone()
                    .map_err(|e| format!("Failed cloning /dev/tty descriptor: {e}"))?,
            ))
            .status()
            .map_err(|e| format!("Failed disabling terminal echo via stty: {e}"))?;
        if !status.success() {
            return Err("stty -echo failed on /dev/tty".to_string());
        }
        Ok(Self { tty_fd: tty })
    }
}

impl Drop for TtyEchoGuard {
    fn drop(&mut self) {
        if let Ok(fd) = self.tty_fd.try_clone() {
            let _ = Command::new("stty")
                .arg("echo")
                .stdin(Stdio::from(fd))
                .status();
        }
    }
}

/// Prompts for an SSH password directly on `/dev/tty` with echo disabled, then restores echo cleanly.
pub fn prompt_password_hidden(prompt: &str) -> Result<String, String> {
    let guard = TtyEchoGuard::disable_echo()?;
    let mut writer = guard
        .tty_fd
        .try_clone()
        .map_err(|e| format!("Failed cloning /dev/tty for prompt: {e}"))?;
    writer
        .write_all(prompt.as_bytes())
        .and_then(|_| writer.flush())
        .map_err(|e| format!("Failed writing password prompt to /dev/tty: {e}"))?;

    let reader_file = guard
        .tty_fd
        .try_clone()
        .map_err(|e| format!("Failed cloning /dev/tty for input: {e}"))?;
    let mut reader = BufReader::new(reader_file);
    let mut line = String::new();
    let read_res = reader.read_line(&mut line);

    drop(guard);
    let _ = writer.write_all(b"\n");
    let _ = writer.flush();

    read_res.map_err(|e| format!("Failed reading password from /dev/tty: {e}"))?;
    Ok(line.trim_end_matches(&['\r', '\n'][..]).to_string())
}

fn looks_like_prompt_tail(buf: &str) -> bool {
    let after_nl = match buf.rfind('\n') {
        Some(idx) => &buf[idx + 1..],
        None => buf,
    };
    let line = after_nl.trim_end_matches(&['\r', ' '][..]);
    if line.len() < 2 || line.len() > 64 {
        return false;
    }
    if !(line.ends_with('#') || line.ends_with('>')) {
        return false;
    }
    if line.contains("##") || line.contains(">>") || line.contains(' ') {
        return false;
    }
    let host_part = &line[..line.len() - 1];
    !host_part.is_empty()
        && host_part.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/' | b'(' | b')')
        })
}

fn tail_has_more_prompt(buf: &str) -> bool {
    let after_nl = match buf.rfind('\n') {
        Some(idx) => &buf[idx + 1..],
        None => buf,
    };
    after_nl.to_ascii_lowercase().contains("--more--")
}

fn write_debug_log(path: &Path, lines: &[String]) {
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
    {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        for line in lines {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// Connection and query options for collecting read-only SD-WAN telemetry over SSH.
pub struct SshTarget<'a> {
    pub host: &'a str,
    pub user: &'a str,
    pub port: u16,
    pub identity_file: Option<&'a str>,
    pub password: Option<&'a str>,
    pub is_vsmart: bool,
    pub vpn_id: &'a str,
    pub flow_spec: Option<&'a str>,
    pub timeout_secs: u64,
    pub debug: bool,
}

/// Runs a batch of read-only CLI commands over native OpenSSH with continuous pipe draining,
/// prompt-synchronized stepping, `--More--` handling, and diagnostic logging.
pub fn run_ssh_commands(target: &SshTarget<'_>, commands: &[String]) -> Result<String, String> {
    for c in commands {
        validate_readonly_cli_command(c)?;
    }

    let log_path = runtime_scratch_dir().join("tloc-explain-debug.log");
    let mut log_lines = vec![
        format!("=== tloc-explain SSH diagnostic log ({}) ===", utc_now_rfc3339()),
        format!(
            "target={}@{}:{} timeout={}s vsmart={}",
            target.user, target.host, target.port, target.timeout_secs, target.is_vsmart
        ),
    ];

    let _guard: Option<AskpassGuard>;
    let mut cmd = Command::new("/usr/bin/ssh");
    cmd.arg("-T")
        .arg("-p")
        .arg(target.port.to_string())
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-o")
        .arg("ConnectTimeout=8");

    if let Some(key) = target.identity_file.filter(|s| !s.is_empty()) {
        cmd.arg("-i")
            .arg(key)
            .arg("-o")
            .arg("IdentitiesOnly=yes");
        log_lines.push(format!("auth=pubkey identity_file={key}"));
    }

    if let Some(pw) = target.password.filter(|s| !s.is_empty()) {
        let guard = AskpassGuard::create()?;
        if target.identity_file.is_none() {
            cmd.arg("-o").arg("PubkeyAuthentication=no");
        }
        cmd.arg("-o")
            .arg("NumberOfPasswordPrompts=1")
            .env("SSH_ASKPASS", &guard.path)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", "tloc-explain:0")
            .env("TLOC_SSH_PASS", pw);
        log_lines.push("auth=password_askpass".to_string());
        _guard = Some(guard);
    } else {
        cmd.arg("-o").arg("BatchMode=yes");
        log_lines.push("auth=batch_mode".to_string());
        _guard = None;
    }

    cmd.arg(format!("{}@{}", target.user, target.host))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed launching /usr/bin/ssh to {}: {e}", target.host))?;

    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| "Failed capturing SSH stdin pipe".to_string())?;
    let mut child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Failed capturing SSH stdout pipe".to_string())?;
    let mut child_stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Failed capturing SSH stderr pipe".to_string())?;

    let stdout_buf = Arc::new(Mutex::new(String::new()));
    let stdout_done = Arc::new(AtomicBool::new(false));
    let out_ref = Arc::clone(&stdout_buf);
    let out_done_ref = Arc::clone(&stdout_done);
    let out_handle = std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(n) = child_stdout.read(&mut chunk) {
            if n == 0 {
                break;
            }
            let s = String::from_utf8_lossy(&chunk[..n]);
            if let Ok(mut guard) = out_ref.lock() {
                guard.push_str(&s);
            }
        }
        out_done_ref.store(true, Ordering::Release);
    });

    let stderr_buf = Arc::new(Mutex::new(String::new()));
    let stderr_done = Arc::new(AtomicBool::new(false));
    let err_ref = Arc::clone(&stderr_buf);
    let err_done_ref = Arc::clone(&stderr_done);
    let err_handle = std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(n) = child_stderr.read(&mut chunk) {
            if n == 0 {
                break;
            }
            let s = String::from_utf8_lossy(&chunk[..n]);
            if let Ok(mut guard) = err_ref.lock() {
                guard.push_str(&s);
            }
        }
        err_done_ref.store(true, Ordering::Release);
    });

    let session_start = Instant::now();
    let total_deadline = session_start + Duration::from_secs(target.timeout_secs);
    let mut prompt_mode = false;
    let mut first_byte_at: Option<Instant> = None;
    let mut last_more_len = 0usize;

    // Wait for initial prompt (IOS-XE) or initial login banner settlement (Viptela vSmart -T)
    loop {
        if Instant::now() >= total_deadline {
            break;
        }
        let (len, has_prompt, has_more) = if let Ok(guard) = stdout_buf.lock() {
            (
                guard.len(),
                looks_like_prompt_tail(&guard),
                tail_has_more_prompt(&guard),
            )
        } else {
            (0, false, false)
        };

        if len > 0 && first_byte_at.is_none() {
            first_byte_at = Some(Instant::now());
        }
        if has_more && len > last_more_len {
            let _ = child_stdin.write_all(b" ");
            let _ = child_stdin.flush();
            last_more_len = len;
        }
        if has_prompt {
            prompt_mode = true;
            break;
        }
        if let Some(fb) = first_byte_at {
            if fb.elapsed() >= Duration::from_millis(900) {
                // Received initial output (e.g. "Last login: ...") without interactive prompt
                break;
            }
        }
        if stdout_done.load(Ordering::Acquire) || matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    log_lines.push(format!(
        "[+{:.2}s] init_settled prompt_mode={prompt_mode}",
        session_start.elapsed().as_secs_f64()
    ));

    let mut timed_out = false;
    let mut timed_out_cmd = String::new();
    let mut completed_cmds = 0usize;
    let mut exit_status = None;

    if Instant::now() >= total_deadline && first_byte_at.is_none() {
        timed_out = true;
        timed_out_cmd = "SSH handshake / initial prompt".to_string();
    } else if prompt_mode {
        for (idx, cmd_str) in commands.iter().enumerate() {
            if Instant::now() >= total_deadline {
                timed_out = true;
                timed_out_cmd = cmd_str.clone();
                break;
            }

            eprintln!("[{}/{}] {} ...", idx + 1, commands.len(), cmd_str);
            let cmd_t0 = Instant::now();
            let start_len = stdout_buf.lock().map(|g| g.len()).unwrap_or(0);
            last_more_len = start_len;

            if let Err(e) = child_stdin
                .write_all(format!("{cmd_str}\n").as_bytes())
                .and_then(|_| child_stdin.flush())
            {
                log_lines.push(format!("[+{:.2}s] stdin write failed on '{}': {e}", session_start.elapsed().as_secs_f64(), cmd_str));
                break;
            }

            loop {
                if Instant::now() >= total_deadline {
                    timed_out = true;
                    timed_out_cmd = cmd_str.clone();
                    break;
                }

                let (cur_len, prompt_ready, has_more) = if let Ok(guard) = stdout_buf.lock() {
                    let cur_len = guard.len();
                    let slice = if cur_len > start_len {
                        &guard[start_len..]
                    } else {
                        ""
                    };
                    let has_nl = slice.contains('\n');
                    let tail_prompt = looks_like_prompt_tail(slice);
                    let ready = !slice.is_empty()
                        && tail_prompt
                        && (has_nl || cmd_t0.elapsed() >= Duration::from_millis(400));
                    (cur_len, ready, tail_has_more_prompt(slice))
                } else {
                    (0, false, false)
                };

                if has_more && cur_len > last_more_len {
                    let _ = child_stdin.write_all(b" ");
                    let _ = child_stdin.flush();
                    last_more_len = cur_len;
                    log_lines.push(format!("[+{:.2}s] answered --More-- prompt", session_start.elapsed().as_secs_f64()));
                }

                if prompt_ready {
                    completed_cmds += 1;
                    let end_len = stdout_buf.lock().map(|g| g.len()).unwrap_or(start_len);
                    let delta = end_len.saturating_sub(start_len);
                    let elapsed = cmd_t0.elapsed().as_secs_f64();
                    let msg = format!(
                        "[+{:.2}s] step [{}/{}] '{}' done ({elapsed:.2}s, {delta}B)",
                        session_start.elapsed().as_secs_f64(),
                        idx + 1,
                        commands.len(),
                        cmd_str
                    );
                    log_lines.push(msg.clone());
                    if target.debug {
                        eprintln!("  {msg}");
                    }
                    break;
                }

                if stdout_done.load(Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }

            if timed_out || stdout_done.load(Ordering::Acquire) {
                break;
            }
        }

        if !timed_out && !stdout_done.load(Ordering::Acquire) {
            let _ = child_stdin.write_all(b"exit\n");
            let _ = child_stdin.flush();
        }
        drop(child_stdin);

        let exit_wait_end = (Instant::now() + Duration::from_secs(3)).min(total_deadline);
        while Instant::now() < exit_wait_end {
            match child.try_wait() {
                Ok(Some(st)) => {
                    exit_status = Some(st);
                    break;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(25)),
                Err(_) => break,
            }
        }
    } else {
        // Non-interactive shell mode (e.g. Viptela vSmart with ssh -T): pipeline commands while
        // continuously draining pipes in reader threads.
        for (idx, cmd_str) in commands.iter().enumerate() {
            if target.debug {
                eprintln!("[{}/{}] {} (batch) ...", idx + 1, commands.len(), cmd_str);
            }
            let _ = child_stdin.write_all(format!("{cmd_str}\n").as_bytes());
        }
        let _ = child_stdin.write_all(b"exit\n");
        let _ = child_stdin.flush();
        drop(child_stdin);

        loop {
            match child.try_wait() {
                Ok(Some(st)) => {
                    exit_status = Some(st);
                    completed_cmds = commands.len();
                    break;
                }
                Ok(None) => {
                    if Instant::now() >= total_deadline {
                        timed_out = true;
                        timed_out_cmd = "batch session".to_string();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => return Err(format!("SSH wait error: {e}")),
            }
        }
    }

    if timed_out || exit_status.is_none() {
        let _ = child.kill();
        if let Ok(st) = child.wait() {
            exit_status = Some(st);
        }
    }

    let _ = out_handle.join();
    let _ = err_handle.join();

    let stdout = stdout_buf.lock().map(|g| g.clone()).unwrap_or_default();
    let stderr = stderr_buf.lock().map(|g| g.clone()).unwrap_or_default();

    log_lines.push(format!(
        "[+{:.2}s] session_end timed_out={timed_out} exit={:?} stdout_bytes={} stderr_bytes={}",
        session_start.elapsed().as_secs_f64(),
        exit_status.and_then(|s| s.code()),
        stdout.len(),
        stderr.len()
    ));
    if !stderr.trim().is_empty() {
        log_lines.push(format!("--- ssh stderr ---\n{}", stderr.trim()));
    }
    write_debug_log(&log_path, &log_lines);

    if target.debug {
        eprintln!("[debug] SSH diagnostic log: {}", log_path.display());
    }

    let has_usable_telemetry = !stdout.trim().is_empty()
        && (completed_cmds > 1
            || stdout.contains("tloc entries for ")
            || stdout.contains("tunnel stats ")
            || stdout.contains("app-route statistics ")
            || stdout.contains("SYSTEM IP"));

    if timed_out {
        if has_usable_telemetry {
            eprintln!(
                "[warn] SSH timed out after {}s during '{}' — continuing with partial telemetry ({} bytes). Debug log: {}",
                target.timeout_secs,
                timed_out_cmd,
                stdout.len(),
                log_path.display()
            );
            return Ok(stdout);
        }
        return Err(format!(
            "SSH session to {} timed out after {}s during '{}' (debug log: {}){}",
            target.host,
            target.timeout_secs,
            timed_out_cmd,
            log_path.display(),
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", stderr.trim())
            }
        ));
    }

    if exit_status.is_some_and(|s| !s.success()) && stdout.trim().is_empty() {
        return Err(format!(
            "SSH to {}@{} failed (exit {:?}, debug log: {}): {}",
            target.user,
            target.host,
            exit_status.and_then(|s| s.code()),
            log_path.display(),
            stderr.trim()
        ));
    }

    Ok(stdout)
}

/// Collects a full `RouterSnapshot` from either an IOS-XE `cEdge` router or a `vSmart` controller over SSH.
pub fn collect_via_ssh(target: &SshTarget<'_>) -> Result<RouterSnapshot, String> {
    let vpn_id = target.vpn_id;
    let mut cmds: Vec<String> = if target.is_vsmart {
        vec![
            "paginate false".to_string(),
            "show omp tlocs".to_string(),
            format!("show omp routes vpn {vpn_id}"),
            "show running-config apply-policy".to_string(),
        ]
    } else {
        vec![
            "terminal length 0".to_string(),
            "show sdwan control local-properties".to_string(),
            "show sdwan running-config sdwan".to_string(),
            "show sdwan omp tlocs".to_string(),
            format!("show sdwan omp routes vpn {vpn_id}"),
            "show sdwan bfd sessions".to_string(),
            "show sdwan tunnel statistics".to_string(),
            "show sdwan app-route stats".to_string(),
        ]
    };

    if let Some(flow) = target.flow_spec {
        cmds.push(flow.to_string());
    }

    let raw = run_ssh_commands(target, &cmds)?;

    if target.is_vsmart {
        let tlocs = parse_omp_tlocs(&raw);
        let routes = parse_omp_routes(&raw);
        let mut snap = build_snapshot_from_text("vsmart", target.host, "100", "ssh-vsmart", &raw);
        snap.remote_tlocs = tlocs;
        snap.omp_routes = routes;
        if let Some(idx) = raw.find("apply-policy") {
            snap.policy_summary = Some(raw[idx..].trim().to_string());
        }
        return Ok(snap);
    }

    let (sys_ip, site_id, host_name) = extract_system_identity(&raw, target.host);
    Ok(build_snapshot_from_text(&host_name, &sys_ip, &site_id, "ssh", &raw))
}

pub(crate) fn extract_system_identity(raw: &str, fallback_host: &str) -> (String, String, String) {
    let mut sys_ip = String::new();
    let mut site_id = String::new();
    let mut host_name = String::new();

    for line in raw.lines() {
        let t = line.trim();
        // Stop scanning whitespace key/values once we enter remote OMP/tunnel tables so peer IDs
        // cannot overwrite local identity.
        if t.starts_with("tloc entries for ")
            || t.starts_with("tunnel stats ")
            || t.starts_with("app-route statistics ")
        {
            break;
        }
        if let Some(v) = t.strip_prefix("System IP:") {
            if sys_ip.is_empty() {
                sys_ip = v.trim().to_string();
            }
        } else if let Some(v) = t.strip_prefix("Site ID:") {
            if site_id.is_empty() {
                site_id = v.trim().to_string();
            }
        } else if let Some(v) = t.strip_prefix("Host Name:") {
            if host_name.is_empty() {
                host_name = v.trim().to_string();
            }
        } else {
            let mut parts = t.split_whitespace();
            if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                match k {
                    "system-ip" if sys_ip.is_empty() && v.parse::<std::net::Ipv4Addr>().is_ok() => {
                        sys_ip = v.to_string();
                    }
                    "site-id" if site_id.is_empty() && !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()) => {
                        site_id = v.to_string();
                    }
                    "host-name" if host_name.is_empty() && !v.is_empty() => {
                        host_name = v.to_string();
                    }
                    _ => {}
                }
            }
        }
    }
    if host_name.is_empty() {
        let prompt_re = Regex::new(r"(?m)^([A-Za-z0-9._-]+)#").expect("valid regex");
        if let Some(c) = prompt_re.captures(raw) {
            host_name = c[1].to_string();
        } else {
            host_name = fallback_host.to_string();
        }
    }
    (sys_ip, site_id, host_name)
}

#[cfg(test)]
mod tests {
    use super::{looks_like_prompt_tail, tail_has_more_prompt};

    #[test]
    fn detects_iosxe_and_ignores_banners() {
        assert!(looks_like_prompt_tail("\n\nsite101-kit1#"));
        assert!(looks_like_prompt_tail("output line\r\nvsmart# "));
        assert!(looks_like_prompt_tail("sdwan-border1>"));
        assert!(!looks_like_prompt_tail("###### WARNING ######"));
        assert!(!looks_like_prompt_tail("Generating output, please wait ..."));
        assert!(!looks_like_prompt_tail("site101-kit1#show sdwan omp tlocs\n"));
        assert!(tail_has_more_prompt("line 1\r\n --More-- "));
        assert!(!tail_has_more_prompt("line 1\r\nsite101-kit1#"));
    }
}
