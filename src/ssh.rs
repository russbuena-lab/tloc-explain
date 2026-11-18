use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use regex::Regex;

use crate::models::RouterSnapshot;
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
        let path = std::env::temp_dir().join(format!("tloc-askpass-{}-{}.sh", std::process::id(), nanos));
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

/// Runs a batch of read-only CLI commands over native OpenSSH in a single session and returns raw stdout.
pub fn run_ssh_commands(
    host: &str,
    user: &str,
    port: u16,
    password: Option<&str>,
    commands: &[String],
    timeout_secs: u64,
) -> Result<String, String> {
    for c in commands {
        validate_readonly_cli_command(c)?;
    }

    let _guard: Option<AskpassGuard>;
    let mut cmd = Command::new("/usr/bin/ssh");
    cmd.arg("-T")
        .arg("-p")
        .arg(port.to_string())
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-o")
        .arg("ConnectTimeout=8");

    if let Some(pw) = password.filter(|s| !s.is_empty()) {
        let guard = AskpassGuard::create()?;
        cmd.arg("-o")
            .arg("PubkeyAuthentication=no")
            .arg("-o")
            .arg("NumberOfPasswordPrompts=1")
            .env("SSH_ASKPASS", &guard.path)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", "tloc-explain:0")
            .env("TLOC_SSH_PASS", pw);
        _guard = Some(guard);
    } else {
        cmd.arg("-o").arg("BatchMode=yes");
        _guard = None;
    }

    cmd.arg(format!("{}@{}", user, host))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed launching /usr/bin/ssh to {}: {e}", host))?;

    if let Some(mut stdin) = child.stdin.take() {
        for c in commands {
            stdin
                .write_all(format!("{c}\n").as_bytes())
                .map_err(|e| format!("Failed writing CLI command to SSH stdin: {e}"))?;
        }
        let _ = stdin.write_all(b"exit\n");
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("SSH session to {} timed out after {}s", host, timeout_secs));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("SSH wait error: {e}")),
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed collecting SSH output: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() && stdout.trim().is_empty() {
        return Err(format!(
            "SSH to {}@{} failed (exit {:?}): {}",
            user,
            host,
            output.status.code(),
            stderr.trim()
        ));
    }

    Ok(stdout)
}

/// Collects a full `RouterSnapshot` from either an IOS-XE `cEdge` router or a `vSmart` controller over SSH.
pub fn collect_via_ssh(
    host: &str,
    user: &str,
    port: u16,
    password: Option<&str>,
    is_vsmart: bool,
    vpn_id: &str,
    flow_spec: Option<&str>,
) -> Result<RouterSnapshot, String> {
    let mut cmds: Vec<String> = if is_vsmart {
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

    if let Some(flow) = flow_spec {
        cmds.push(flow.to_string());
    }

    let raw = run_ssh_commands(host, user, port, password, &cmds, 30)?;

    if is_vsmart {
        let tlocs = parse_omp_tlocs(&raw);
        let routes = parse_omp_routes(&raw);
        let mut snap = build_snapshot_from_text("vsmart", host, "100", "ssh-vsmart", &raw);
        snap.remote_tlocs = tlocs;
        snap.omp_routes = routes;
        if let Some(idx) = raw.find("apply-policy") {
            snap.policy_summary = Some(raw[idx..].trim().to_string());
        }
        return Ok(snap);
    }

    let (sys_ip, site_id, host_name) = extract_system_identity(&raw, host);
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
