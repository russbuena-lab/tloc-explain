mod explainer;
mod models;
mod parsers;
mod render;
mod ssh;
mod vmanage;

use std::fs;
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::process;

use crate::explainer::explain_snapshot;
use crate::models::AnalysisReport;
use crate::parsers::build_snapshot_from_text;
use crate::render::{render_markdown, render_terminal};
use crate::ssh::{collect_via_ssh, prompt_password_hidden, SshTarget};
use crate::vmanage::{resolve_vmanage_credentials, VManageClient};

#[derive(Debug)]
enum CommandMode {
    Ssh {
        host: String,
        user: String,
        port: u16,
        identity_file: Option<String>,
        ask_pass: bool,
        password: Option<String>,
        password_env: Option<String>,
        vsmart: bool,
        vpn: String,
        discover: bool,
        flow: Option<String>,
        timeout_secs: u64,
        debug: bool,
    },
    Vmanage {
        host: Option<String>,
        user: Option<String>,
        device: String,
        vpn: String,
        insecure: bool,
    },
    File {
        path: String,
        hostname: String,
        system_ip: String,
        site_id: String,
    },
}

#[derive(Debug)]
struct CliArgs {
    mode: CommandMode,
    peer: Option<String>,
    all_tunnels: bool,
    json: bool,
    markdown_out: Option<String>,
    no_color: bool,
}

#[derive(Debug)]
struct CommonOpts {
    peer: Option<String>,
    all_tunnels: bool,
    json: bool,
    markdown_out: Option<String>,
    no_color: bool,
}

impl CommonOpts {
    fn new() -> Self {
        Self {
            peer: None,
            all_tunnels: false,
            json: false,
            markdown_out: None,
            no_color: !io::stdout().is_terminal(),
        }
    }

    fn try_consume(&mut self, args: &[String], idx: &mut usize) -> Result<bool, String> {
        match args[*idx].as_str() {
            "--peer" => {
                self.peer = Some(take_val(args, idx, "--peer")?);
                Ok(true)
            }
            "--all-tunnels" => {
                self.all_tunnels = true;
                Ok(true)
            }
            "--json" => {
                self.json = true;
                Ok(true)
            }
            "--markdown" => {
                self.markdown_out = Some(take_val(args, idx, "--markdown")?);
                Ok(true)
            }
            "--no-color" => {
                self.no_color = true;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

fn print_help() {
    eprintln!(
        r#"tloc-explain — Cisco Catalyst SD-WAN TLOC, OMP Route & Transport Preferencing Explainer

USAGE:
  tloc-explain [ssh] <host> [-u <user>] [-p <port>] [-i <keyfile>] [-P|--ask-pass] [--password-env <VAR>] [--peer <sys-ip|wan-ip>] [--vpn <id|all>] [--discover] [--all-tunnels] [--timeout <secs>] [-v|--debug] [--vsmart] [--flow <spec>] [--json] [--markdown <file>] [--no-color]
  tloc-explain vmanage [--host <host:port>] [--user <user>] [--device <name|sysip|all>] [--peer <ip>] [--vpn <id|all>] [--all-tunnels] [--insecure] [--json] [--markdown <file>] [--no-color]
  tloc-explain file <capture.txt> [--hostname <name>] [--system-ip <ip>] [--site-id <id>] [--peer <ip>] [--all-tunnels] [--json] [--markdown <file>] [--no-color]

EXAMPLES:
  # Fast ~3s discovery of active Service VPNs and remote peers on a hub/branch:
  tloc-explain 10.10.1.21 -u admin --discover

  # Focus full analysis (and router-side app-route stats) on one peer & Service VPN:
  tloc-explain 10.10.1.21 -u admin --peer 10.255.1.1
  tloc-explain 10.10.1.21 -u admin --peer 10.255.1.1 --vpn 10

  # Default auto-discovers all Service VPNs and summarizes large standby tunnel sets:
  tloc-explain 10.10.1.21 -u admin --timeout 180 -v
  tloc-explain 10.10.1.21 -u admin -i ~/.ssh/id_ed25519 --all-tunnels
  tloc-explain ssh 172.16.1.12 -u admin --vsmart

AUTHENTICATION & DIAGNOSTICS:
  Direct SSH uses `-i <keyfile>` if given, or checks TLOC_SSH_PASS / ROUTER_SSH_PASS
  (env, ~/.tloc_env, /home/russb/code/sdwan-lab/.vmanage_env). When no env password is
  found or `-P` / `--ask-pass` is passed, `tloc-explain` prompts securely with hidden
  input on `/dev/tty` (never echoed or exposed in CLI arguments).
  Diagnostic SSH logs are always written to ~/.cache/tloc-explain/tloc-explain-debug.log.
"#
    );
}

fn take_val(args: &[String], idx: &mut usize, flag: &str) -> Result<String, String> {
    *idx += 1;
    args.get(*idx)
        .cloned()
        .ok_or_else(|| format!("Missing value for {flag}"))
}

fn parse_ssh_args(args: &[String]) -> Result<CliArgs, String> {
    let mut common = CommonOpts::new();

    let mut host = String::new();
    let mut user = "admin".to_string();
    let mut port = 22u16;
    let mut identity_file = None;
    let mut ask_pass = false;
    let mut password = None;
    let mut password_env = None;
    let mut vsmart = false;
    let mut vpn = "all".to_string();
    let mut discover = false;
    let mut flow = None;
    let mut timeout_secs = 120u64;
    let mut debug = false;

    let mut i = 0usize;
    while i < args.len() {
        if common.try_consume(args, &mut i)? {
            i += 1;
            continue;
        }
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            "-u" | "--user" => user = take_val(args, &mut i, "--user")?,
            "-p" | "--port" => {
                let s = take_val(args, &mut i, "--port")?;
                port = s.parse::<u16>().map_err(|_| format!("Invalid port: {s}"))?;
            }
            "-i" | "--identity" => identity_file = Some(take_val(args, &mut i, "--identity")?),
            "-P" | "--ask-pass" => ask_pass = true,
            "--password" => password = Some(take_val(args, &mut i, "--password")?),
            "--password-env" => password_env = Some(take_val(args, &mut i, "--password-env")?),
            "--timeout" => {
                let s = take_val(args, &mut i, "--timeout")?;
                timeout_secs = s.parse::<u64>().map_err(|_| format!("Invalid timeout: {s}"))?;
                if timeout_secs == 0 {
                    return Err("--timeout must be at least 1 second".to_string());
                }
            }
            "-v" | "--debug" => debug = true,
            "--vsmart" => vsmart = true,
            "--vpn" => vpn = take_val(args, &mut i, "--vpn")?,
            "--discover" => discover = true,
            "--flow" => flow = Some(take_val(args, &mut i, "--flow")?),
            arg if !arg.starts_with('-') && host.is_empty() => host = arg.to_string(),
            other => return Err(format!("Unknown argument: {other}")),
        }
        i += 1;
    }

    if host.is_empty() {
        return Err("Missing <host> argument for direct router SSH".to_string());
    }

    Ok(CliArgs {
        mode: CommandMode::Ssh {
            host,
            user,
            port,
            identity_file,
            ask_pass,
            password,
            password_env,
            vsmart,
            vpn,
            discover,
            flow,
            timeout_secs,
            debug,
        },
        peer: common.peer,
        all_tunnels: common.all_tunnels,
        json: common.json,
        markdown_out: common.markdown_out,
        no_color: common.no_color,
    })
}

fn parse_args() -> Result<CliArgs, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_help();
        process::exit(0);
    }

    let sub = args[0].as_str();
    let mut common = CommonOpts::new();
    let mut i = 1usize;

    match sub {
        "ssh" => parse_ssh_args(&args[1..]),
        "vmanage" => {
            let mut host = None;
            let mut user = None;
            let mut device = "all".to_string();
            let mut vpn = "all".to_string();
            let mut insecure = true;

            while i < args.len() {
                if common.try_consume(&args, &mut i)? {
                    i += 1;
                    continue;
                }
                match args[i].as_str() {
                    "-h" | "--help" => {
                        print_help();
                        process::exit(0);
                    }
                    "--host" => host = Some(take_val(&args, &mut i, "--host")?),
                    "-u" | "--user" => user = Some(take_val(&args, &mut i, "--user")?),
                    "-d" | "--device" => device = take_val(&args, &mut i, "--device")?,
                    "--vpn" => vpn = take_val(&args, &mut i, "--vpn")?,
                    "--insecure" => insecure = true,
                    "--verify-tls" => insecure = false,
                    other => return Err(format!("Unknown argument for 'vmanage': {other}")),
                }
                i += 1;
            }
            Ok(CliArgs {
                mode: CommandMode::Vmanage {
                    host,
                    user,
                    device,
                    vpn,
                    insecure,
                },
                peer: common.peer,
                all_tunnels: common.all_tunnels,
                json: common.json,
                markdown_out: common.markdown_out,
                no_color: common.no_color,
            })
        }
        "file" => {
            let mut path = String::new();
            let mut hostname = String::new();
            let mut system_ip = String::new();
            let mut site_id = String::new();

            while i < args.len() {
                if common.try_consume(&args, &mut i)? {
                    i += 1;
                    continue;
                }
                match args[i].as_str() {
                    "-h" | "--help" => {
                        print_help();
                        process::exit(0);
                    }
                    "--hostname" => hostname = take_val(&args, &mut i, "--hostname")?,
                    "--system-ip" => system_ip = take_val(&args, &mut i, "--system-ip")?,
                    "--site-id" => site_id = take_val(&args, &mut i, "--site-id")?,
                    arg if !arg.starts_with('-') && path.is_empty() => path = arg.to_string(),
                    other => return Err(format!("Unknown argument for 'file': {other}")),
                }
                i += 1;
            }
            if path.is_empty() {
                return Err("Missing <capture.txt> argument for 'file'".to_string());
            }
            Ok(CliArgs {
                mode: CommandMode::File {
                    path,
                    hostname,
                    system_ip,
                    site_id,
                },
                peer: common.peer,
                all_tunnels: common.all_tunnels,
                json: common.json,
                markdown_out: common.markdown_out,
                no_color: common.no_color,
            })
        }
        _ => parse_ssh_args(&args),
    }
}

fn read_env_key_from_sources(key: &str) -> Option<String> {
    if let Ok(v) = std::env::var(key) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            paths.push(PathBuf::from(home).join(".tloc_env"));
        }
    }
    paths.push(PathBuf::from("/home/russb/code/sdwan-lab/.vmanage_env"));
    paths.push(PathBuf::from("/home/russb/code/ironclad-forge/.forge_env"));

    for path in paths {
        if let Ok(text) = fs::read_to_string(path) {
            for line in text.lines() {
                let t = line.trim();
                if t.is_empty() || t.starts_with('#') {
                    continue;
                }
                let t = t.strip_prefix("export ").unwrap_or(t).trim();
                if let Some((k, v)) = t.split_once('=') {
                    if k.trim() == key {
                        let raw = v.trim();
                        let clean = if (raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2)
                            || (raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2)
                        {
                            raw[1..raw.len() - 1].to_string()
                        } else {
                            raw.to_string()
                        };
                        if !clean.is_empty() {
                            return Some(clean);
                        }
                    }
                }
            }
        }
    }
    None
}

fn load_ssh_password(explicit_env: Option<&str>, is_vsmart: bool) -> Option<String> {
    if let Some(env_name) = explicit_env {
        return read_env_key_from_sources(env_name);
    }
    let order: &[&str] = if is_vsmart {
        &["VMANAGE_PASSWORD", "TLOC_SSH_PASS", "ROUTER_SSH_PASS"]
    } else {
        &["TLOC_SSH_PASS", "ROUTER_SSH_PASS", "VMANAGE_PASSWORD"]
    };
    for key in order {
        if let Some(val) = read_env_key_from_sources(key) {
            return Some(val);
        }
    }
    None
}

fn main() {
    let cli = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(2);
        }
    };

    let reports: Vec<AnalysisReport> = match &cli.mode {
        CommandMode::File {
            path,
            hostname,
            system_ip,
            site_id,
        } => {
            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error reading '{path}': {e}");
                    process::exit(1);
                }
            };
            let mut snap = build_snapshot_from_text(hostname, system_ip, site_id, "file", &content);
            snap.peer_filter = cli.peer.clone();
            vec![explain_snapshot(snap)]
        }
        CommandMode::Ssh {
            host,
            user,
            port,
            identity_file,
            ask_pass,
            password,
            password_env,
            vsmart,
            vpn,
            discover,
            flow,
            timeout_secs,
            debug,
        } => {
            let resolved_pw = if *ask_pass && identity_file.is_none() {
                match prompt_password_hidden(&format!("Password for {user}@{host}: ")) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        eprintln!("SSH prompt error: {e}");
                        process::exit(1);
                    }
                }
            } else if let Some(p) = password.clone().filter(|s| !s.is_empty()) {
                Some(p)
            } else if identity_file.is_some() {
                None
            } else {
                match load_ssh_password(password_env.as_deref(), *vsmart) {
                    Some(p) => Some(p),
                    None => match prompt_password_hidden(&format!("Password for {user}@{host}: ")) {
                        Ok(p) => Some(p),
                        Err(e) => {
                            eprintln!("SSH auth error: {e}");
                            process::exit(1);
                        }
                    },
                }
            };
            match collect_via_ssh(&SshTarget {
                host,
                user,
                port: *port,
                identity_file: identity_file.as_deref(),
                password: resolved_pw.as_deref(),
                is_vsmart: *vsmart,
                vpn_id: vpn,
                peer: cli.peer.as_deref(),
                discover: *discover,
                flow_spec: flow.as_deref(),
                timeout_secs: *timeout_secs,
                debug: *debug,
            }) {
                Ok(snap) => vec![explain_snapshot(snap)],
                Err(e) => {
                    eprintln!("SSH collection error: {e}");
                    process::exit(1);
                }
            }
        }
        CommandMode::Vmanage {
            host,
            user,
            device,
            vpn,
            insecure,
        } => {
            let (vm_host, vm_user, vm_pw) =
                match resolve_vmanage_credentials(host.as_deref(), user.as_deref()) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Credential error: {e}");
                        process::exit(1);
                    }
                };
            let client = match VManageClient::connect(&vm_host, &vm_user, &vm_pw, *insecure) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("vManage auth error: {e}");
                    process::exit(1);
                }
            };
            let devices = match client.list_wan_edges() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("vManage inventory error: {e}");
                    process::exit(1);
                }
            };
            let targets: Vec<_> = if device.eq_ignore_ascii_case("all") {
                devices
                    .into_iter()
                    .filter(|d| d.reachability.eq_ignore_ascii_case("reachable"))
                    .collect()
            } else {
                devices
                    .into_iter()
                    .filter(|d| {
                        d.host_name.eq_ignore_ascii_case(device)
                            || d.system_ip == *device
                            || d.uuid.eq_ignore_ascii_case(device)
                    })
                    .collect()
            };
            if targets.is_empty() {
                eprintln!("No reachable WAN Edge matched --device '{device}'.");
                process::exit(1);
            }
            let mut out = Vec::new();
            for dev in targets {
                match client.collect_device_snapshot(&dev, vpn) {
                    Ok(mut snap) => {
                        snap.peer_filter = cli.peer.clone();
                        out.push(explain_snapshot(snap));
                    }
                    Err(e) => eprintln!("Warning: failed collecting {}: {e}", dev.host_name),
                }
            }
            out
        }
    };

    if cli.json {
        let json_out = serde_json::to_string_pretty(&reports).unwrap_or_else(|_| "[]".to_string());
        println!("{json_out}");
    } else {
        for r in &reports {
            print!("{}", render_terminal(r, !cli.no_color, cli.all_tunnels));
        }
    }

    if let Some(md_path) = &cli.markdown_out {
        let mut combined = String::new();
        for r in &reports {
            combined.push_str(&render_markdown(r, cli.all_tunnels));
            combined.push_str("\n---\n\n");
        }
        if let Err(e) = fs::write(md_path, combined) {
            eprintln!("Error writing markdown '{md_path}': {e}");
            process::exit(1);
        }
        eprintln!("Wrote markdown report to {md_path}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_identity_and_ask_pass_flags() {
        let args: Vec<String> = vec![
            "10.10.1.21",
            "-u",
            "netops",
            "-i",
            "/home/russb/.ssh/id_ed25519",
            "-P",
            "--peer",
            "10.255.1.1",
            "--discover",
            "--all-tunnels",
            "--timeout",
            "180",
            "-v",
            "--vpn",
            "10",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let cli = parse_ssh_args(&args).expect("valid ssh args");
        assert_eq!(cli.peer.as_deref(), Some("10.255.1.1"));
        assert!(cli.all_tunnels);
        match cli.mode {
            CommandMode::Ssh {
                host,
                user,
                identity_file,
                ask_pass,
                vpn,
                discover,
                timeout_secs,
                debug,
                ..
            } => {
                assert_eq!(host, "10.10.1.21");
                assert_eq!(user, "netops");
                assert_eq!(identity_file.as_deref(), Some("/home/russb/.ssh/id_ed25519"));
                assert!(ask_pass);
                assert_eq!(vpn, "10");
                assert!(discover);
                assert_eq!(timeout_secs, 180);
                assert!(debug);
            }
            _ => panic!("expected Ssh mode"),
        }
    }
}
