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
use crate::ssh::collect_via_ssh;
use crate::vmanage::{resolve_vmanage_credentials, VManageClient};

#[derive(Debug)]
enum CommandMode {
    Ssh {
        host: String,
        user: String,
        port: u16,
        password: Option<String>,
        password_env: Option<String>,
        vsmart: bool,
        vpn: String,
        flow: Option<String>,
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
    json: bool,
    markdown_out: Option<String>,
    no_color: bool,
}

fn print_help() {
    eprintln!(
        r#"tloc-explain — Cisco Catalyst SD-WAN TLOC, OMP Route & Transport Preferencing Explainer

USAGE:
  tloc-explain [ssh] <host> [-u <user>] [-p <port>] [--password <pw>] [--password-env <VAR>] [--vsmart] [--vpn <id>] [--flow <spec>] [--json] [--markdown <file>] [--no-color]
  tloc-explain vmanage [--host <host:port>] [--user <user>] [--device <name|sysip|all>] [--vpn <id>] [--insecure] [--json] [--markdown <file>] [--no-color]
  tloc-explain file <capture.txt> [--hostname <name>] [--system-ip <ip>] [--site-id <id>] [--json] [--markdown <file>] [--no-color]

EXAMPLES:
  tloc-explain 10.10.1.21
  tloc-explain 10.10.1.21 -u admin --vpn 1000
  tloc-explain 172.16.1.21 --markdown /tmp/border1-report.md
  tloc-explain ssh 172.16.1.12 -u admin --vsmart
  tloc-explain file router_capture.txt --hostname site101-kit1 --system-ip 10.255.1.11 --site-id 1011
  tloc-explain vmanage --device all

ENVIRONMENT:
  Direct router SSH automatically checks TLOC_SSH_PASS and ROUTER_SSH_PASS in the
  process environment, ~/.tloc_env, and /home/russb/code/sdwan-lab/.vmanage_env
  (falling back to VMANAGE_PASSWORD for vSmart or shared credentials).
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
    let mut json = false;
    let mut markdown_out = None;
    let mut no_color = !io::stdout().is_terminal();

    let mut host = String::new();
    let mut user = "admin".to_string();
    let mut port = 22u16;
    let mut password = None;
    let mut password_env = None;
    let mut vsmart = false;
    let mut vpn = "1000".to_string();
    let mut flow = None;

    let mut i = 0usize;
    while i < args.len() {
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
            "--password" => password = Some(take_val(args, &mut i, "--password")?),
            "--password-env" => password_env = Some(take_val(args, &mut i, "--password-env")?),
            "--vsmart" => vsmart = true,
            "--vpn" => vpn = take_val(args, &mut i, "--vpn")?,
            "--flow" => flow = Some(take_val(args, &mut i, "--flow")?),
            "--json" => json = true,
            "--markdown" => markdown_out = Some(take_val(args, &mut i, "--markdown")?),
            "--no-color" => no_color = true,
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
            password,
            password_env,
            vsmart,
            vpn,
            flow,
        },
        json,
        markdown_out,
        no_color,
    })
}

fn parse_args() -> Result<CliArgs, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_help();
        process::exit(0);
    }

    let sub = args[0].as_str();
    let mut json = false;
    let mut markdown_out = None;
    let mut no_color = !io::stdout().is_terminal();

    let mut i = 1usize;

    match sub {
        "ssh" => parse_ssh_args(&args[1..]),
        "vmanage" => {
            let mut host = None;
            let mut user = None;
            let mut device = "all".to_string();
            let mut vpn = "1000".to_string();
            let mut insecure = true;

            while i < args.len() {
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
                    "--json" => json = true,
                    "--markdown" => markdown_out = Some(take_val(&args, &mut i, "--markdown")?),
                    "--no-color" => no_color = true,
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
                json,
                markdown_out,
                no_color,
            })
        }
        "file" => {
            let mut path = String::new();
            let mut hostname = String::new();
            let mut system_ip = String::new();
            let mut site_id = String::new();

            while i < args.len() {
                match args[i].as_str() {
                    "-h" | "--help" => {
                        print_help();
                        process::exit(0);
                    }
                    "--hostname" => hostname = take_val(&args, &mut i, "--hostname")?,
                    "--system-ip" => system_ip = take_val(&args, &mut i, "--system-ip")?,
                    "--site-id" => site_id = take_val(&args, &mut i, "--site-id")?,
                    "--json" => json = true,
                    "--markdown" => markdown_out = Some(take_val(&args, &mut i, "--markdown")?),
                    "--no-color" => no_color = true,
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
                json,
                markdown_out,
                no_color,
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

#[tokio::main]
async fn main() {
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
            let snap = build_snapshot_from_text(hostname, system_ip, site_id, "file", &content);
            vec![explain_snapshot(snap)]
        }
        CommandMode::Ssh {
            host,
            user,
            port,
            password,
            password_env,
            vsmart,
            vpn,
            flow,
        } => {
            let pw = password
                .clone()
                .or_else(|| load_ssh_password(password_env.as_deref(), *vsmart));
            match collect_via_ssh(host, user, *port, pw.as_deref(), *vsmart, vpn, flow.as_deref()) {
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
            let client = match VManageClient::connect(&vm_host, &vm_user, &vm_pw, *insecure).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("vManage auth error: {e}");
                    process::exit(1);
                }
            };
            let devices = match client.list_wan_edges().await {
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
                match client.collect_device_snapshot(&dev, vpn).await {
                    Ok(snap) => out.push(explain_snapshot(snap)),
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
            print!("{}", render_terminal(r, !cli.no_color));
        }
    }

    if let Some(md_path) = &cli.markdown_out {
        let mut combined = String::new();
        for r in &reports {
            combined.push_str(&render_markdown(r));
            combined.push_str("\n---\n\n");
        }
        if let Err(e) = fs::write(md_path, combined) {
            eprintln!("Error writing markdown '{md_path}': {e}");
            process::exit(1);
        }
        eprintln!("Wrote markdown report to {md_path}");
    }
}
