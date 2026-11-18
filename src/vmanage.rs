use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::models::{
    runtime_scratch_dir, utc_now_rfc3339, OmpRouteEntry, RouterSnapshot, TlocEntry, TunnelDiag,
};
use crate::parsers::{
    compute_tunnel_averages, is_route_chosen_installed, merge_tunnel_diags,
    parse_running_config_sdwan, sort_unique_vpns,
};

struct CookieJarGuard {
    path: PathBuf,
}

impl CookieJarGuard {
    fn create() -> Result<Self, String> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = runtime_scratch_dir()
            .join(format!("tloc-cookie-{}-{}.txt", std::process::id(), nanos));
        let _ = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("Failed creating cookie jar '{}': {e}", path.display()))?;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        Ok(Self { path })
    }
}

impl Drop for CookieJarGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn curl_request(
    base_url: &str,
    path: &str,
    jar_path: &Path,
    write_cookies: bool,
    insecure: bool,
    xsrf_token: Option<&str>,
    post_body: Option<&str>,
) -> Result<(u16, String), String> {
    let url = format!("{base_url}{path}");
    let mut cmd = Command::new("curl");
    cmd.arg("-sS")
        .arg("--max-time")
        .arg("20")
        .arg("-b")
        .arg(jar_path);
    if write_cookies {
        cmd.arg("-c").arg(jar_path);
    }
    if insecure {
        cmd.arg("-k");
    }
    if let Some(tok) = xsrf_token.filter(|t| !t.is_empty()) {
        cmd.arg("-H").arg(format!("X-XSRF-TOKEN: {tok}"));
    }
    cmd.arg("-w").arg("\n%{http_code}");

    if post_body.is_some() {
        cmd.arg("-X")
            .arg("POST")
            .arg("-H")
            .arg("Content-Type: application/x-www-form-urlencoded")
            .arg("--data-binary")
            .arg("@-")
            .stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    cmd.arg(url).stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed launching curl for {path}: {e}"))?;

    if let Some(body) = post_body {
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(body.as_bytes())
                .map_err(|e| format!("Failed writing POST body to curl: {e}"))?;
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("curl execution failed for {path}: {e}"))?;
    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success() {
        return Err(format!("curl {path} failed: {stderr}"));
    }

    let (body, code_str) = raw
        .rsplit_once('\n')
        .unwrap_or((raw.as_str(), "0"));
    let status = code_str.trim().parse::<u16>().unwrap_or(0);
    Ok((status, body.to_string()))
}

/// Authenticated Cisco Catalyst SD-WAN vManage REST client (backed by native `curl`).
pub struct VManageClient {
    base_url: String,
    xsrf_token: String,
    insecure: bool,
    cookie_jar: CookieJarGuard,
}

#[derive(Debug, Clone)]
pub struct VManageDeviceSummary {
    pub host_name: String,
    pub system_ip: String,
    pub site_id: String,
    pub uuid: String,
    pub reachability: String,
}

impl VManageClient {
    pub fn connect(
        host: &str,
        user: &str,
        password: &str,
        insecure: bool,
    ) -> Result<Self, String> {
        let normalized = host
            .trim()
            .trim_end_matches('/')
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let base_url = if normalized.contains(':') {
            format!("https://{normalized}")
        } else {
            format!("https://{normalized}:8443")
        };

        let cookie_jar = CookieJarGuard::create()?;
        let form_body = format!(
            "j_username={}&j_password={}",
            percent_encode(user),
            percent_encode(password)
        );
        let (login_status, login_body) = curl_request(
            &base_url,
            "/j_security_check",
            &cookie_jar.path,
            true,
            insecure,
            None,
            Some(&form_body),
        )
        .map_err(|e| format!("vManage login request failed: {e}"))?;

        if !(200..400).contains(&login_status)
            || login_body.contains("j_security_check")
            || login_body.to_lowercase().contains("<html")
        {
            return Err(format!("vManage rejected credentials for user '{}'", user));
        }

        let (tok_status, xsrf_raw) = curl_request(
            &base_url,
            "/dataservice/client/token",
            &cookie_jar.path,
            true,
            insecure,
            None,
            None,
        )
        .map_err(|e| format!("Failed fetching XSRF token: {e}"))?;

        let xsrf_token = xsrf_raw.trim().to_string();
        if !(200..300).contains(&tok_status)
            || xsrf_token.is_empty()
            || xsrf_token.to_lowercase().contains("<html")
        {
            return Err("vManage did not return a valid X-XSRF-TOKEN".to_string());
        }

        Ok(Self {
            base_url,
            xsrf_token,
            insecure,
            cookie_jar,
        })
    }

    pub fn get_json(&self, path: &str) -> Result<Value, String> {
        let (status, text) = curl_request(
            &self.base_url,
            path,
            &self.cookie_jar.path,
            false,
            self.insecure,
            Some(&self.xsrf_token),
            None,
        )?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "GET {path} -> HTTP {status}: {}",
                text.chars().take(200).collect::<String>()
            ));
        }
        serde_json::from_str(&text).map_err(|e| format!("Invalid JSON from {path}: {e}"))
    }

    pub fn list_wan_edges(&self) -> Result<Vec<VManageDeviceSummary>, String> {
        let val = self.get_json("/dataservice/system/device/vedges")?;
        let rows = val.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default();
        let mut out = Vec::new();
        for r in rows {
            let sys_ip = json_str(&r, "system-ip");
            if sys_ip.is_empty() {
                continue;
            }
            out.push(VManageDeviceSummary {
                host_name: json_str(&r, "host-name"),
                system_ip: sys_ip,
                site_id: json_str(&r, "site-id"),
                uuid: json_str(&r, "uuid"),
                reachability: json_str(&r, "reachability"),
            });
        }
        Ok(out)
    }

    pub fn collect_device_snapshot(
        &self,
        dev: &VManageDeviceSummary,
        vpn_id: &str,
    ) -> Result<RouterSnapshot, String> {
        let sys_ip = &dev.system_ip;
        let uuid = &dev.uuid;

        let p_cfg = format!("/dataservice/template/config/running/{uuid}");
        let p_tloc_adv = format!("/dataservice/device/omp/tlocs/advertised?deviceId={sys_ip}");
        let p_tloc_recv = format!("/dataservice/device/omp/tlocs/received?deviceId={sys_ip}");
        let p_routes = if vpn_id.eq_ignore_ascii_case("all") || vpn_id.is_empty() {
            format!("/dataservice/device/omp/routes/received?deviceId={sys_ip}")
        } else {
            format!("/dataservice/device/omp/routes/received?deviceId={sys_ip}&vpn-id={vpn_id}")
        };
        let p_bfd = format!("/dataservice/device/bfd/sessions?deviceId={sys_ip}");
        let p_tun = format!("/dataservice/device/tunnel/statistics?deviceId={sys_ip}");
        let p_app = format!("/dataservice/device/app-route/statistics?deviceId={sys_ip}");

        let (cfg_res, tloc_adv_res, tloc_recv_res, routes_res, bfd_res, tun_res, app_res) =
            std::thread::scope(|s| {
                let h_cfg = s.spawn(|| self.get_json(&p_cfg));
                let h_adv = s.spawn(|| self.get_json(&p_tloc_adv));
                let h_recv = s.spawn(|| self.get_json(&p_tloc_recv));
                let h_routes = s.spawn(|| self.get_json(&p_routes));
                let h_bfd = s.spawn(|| self.get_json(&p_bfd));
                let h_tun = s.spawn(|| self.get_json(&p_tun));
                let h_app = s.spawn(|| self.get_json(&p_app));
                (
                    h_cfg.join().unwrap_or_else(|_| Err("cfg request panicked".into())),
                    h_adv.join().unwrap_or_else(|_| Err("tloc adv request panicked".into())),
                    h_recv.join().unwrap_or_else(|_| Err("tloc recv request panicked".into())),
                    h_routes.join().unwrap_or_else(|_| Err("routes request panicked".into())),
                    h_bfd.join().unwrap_or_else(|_| Err("bfd request panicked".into())),
                    h_tun.join().unwrap_or_else(|_| Err("tunnel request panicked".into())),
                    h_app.join().unwrap_or_else(|_| Err("app-route request panicked".into())),
                )
            });

        let running_text = cfg_res
            .ok()
            .and_then(|v| v.get("config").and_then(|c| c.as_str()).map(|s| s.to_string()))
            .unwrap_or_default();
        let cfg = parse_running_config_sdwan(&running_text);

        let mut local_tlocs = parse_vmanage_tlocs(&tloc_adv_res.unwrap_or(Value::Null), sys_ip, &dev.site_id);
        // Enrich local TLOCs with physical interface names, restrict, last-resort, and bfd color multiplier from running config
        for lt in &mut local_tlocs {
            if let Some(if_cfg) = cfg.interfaces.iter().find(|i| i.color == lt.color) {
                lt.interface = Some(if_cfg.interface.clone());
                lt.restrict = if_cfg.restrict;
                lt.last_resort_circuit = if_cfg.last_resort_circuit;
            }
            lt.bfd_color_multiplier = cfg.bfd_colors.get(&lt.color).and_then(|(_, m)| *m);
        }

        let all_recv_tlocs = parse_vmanage_tlocs(&tloc_recv_res.unwrap_or(Value::Null), "", "");
        let remote_tlocs: Vec<TlocEntry> = all_recv_tlocs
            .into_iter()
            .filter(|t| t.system_ip != *sys_ip)
            .collect();

        let omp_routes = parse_vmanage_routes(&routes_res.unwrap_or(Value::Null));
        let bfd_list = parse_vmanage_bfd(&bfd_res.unwrap_or(Value::Null));
        let tun_list = parse_vmanage_tunnels(&tun_res.unwrap_or(Value::Null));
        let app_list = parse_vmanage_approute(&app_res.unwrap_or(Value::Null));

        let mut tunnels = merge_tunnel_diags(bfd_list, tun_list, app_list);
        for td in &mut tunnels {
            compute_tunnel_averages(td);
        }

        let discovered_vpns = sort_unique_vpns(omp_routes.iter().map(|r| r.vpn_id.as_str()));
        let target_vpn = if vpn_id.eq_ignore_ascii_case("all") || vpn_id.is_empty() {
            discovered_vpns.first().cloned()
        } else {
            Some(vpn_id.to_string())
        };

        Ok(RouterSnapshot {
            host_name: dev.host_name.clone(),
            system_ip: dev.system_ip.clone(),
            site_id: dev.site_id.clone(),
            source_mode: "vmanage".to_string(),
            captured_at_utc: utc_now_rfc3339(),
            target_vpn,
            discovered_vpns,
            peer_filter: None,
            local_tlocs,
            remote_tlocs,
            omp_routes,
            service_paths: Vec::new(),
            tunnels,
            policy_summary: None,
        })
    }
}

/// Loads default lab env files if standard `VMANAGE_*` environment variables are absent.
pub fn resolve_vmanage_credentials(
    host_arg: Option<&str>,
    user_arg: Option<&str>,
) -> Result<(String, String, String), String> {
    let mut file_env = BTreeMap::new();
    for path in [
        "/home/russb/code/sdwan-lab/.vmanage_env",
        "/home/russb/code/ironclad-forge/.forge_env",
    ] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let mut t = line.trim();
                if t.is_empty() || t.starts_with('#') {
                    continue;
                }
                if let Some(rest) = t.strip_prefix("export ") {
                    t = rest.trim();
                }
                if let Some((k, v)) = t.split_once('=') {
                    let clean = v.trim().trim_matches('"').trim_matches('\'').to_string();
                    file_env.entry(k.trim().to_string()).or_insert(clean);
                }
            }
        }
    }

    let host = host_arg
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("VMANAGE_HOST").ok().filter(|s| !s.is_empty()))
        .or_else(|| file_env.get("VMANAGE_HOST").cloned())
        .ok_or_else(|| "VMANAGE_HOST is not set (pass --host or export VMANAGE_HOST)".to_string())?;

    let password = std::env::var("VMANAGE_PASS")
        .or_else(|_| std::env::var("VMANAGE_PASSWORD"))
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| file_env.get("VMANAGE_PASSWORD").cloned())
        .or_else(|| file_env.get("FORGE_ADMIN_PASSWORD").cloned())
        .ok_or_else(|| "VMANAGE_PASS / VMANAGE_PASSWORD is not set".to_string())?;

    let user = user_arg
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("VMANAGE_USER").ok().filter(|s| !s.is_empty()))
        .or_else(|| {
            if file_env.contains_key("VMANAGE_PASSWORD") {
                file_env.get("VMANAGE_USER").cloned()
            } else {
                Some("admin_test".to_string())
            }
        })
        .unwrap_or_else(|| "admin".to_string());

    Ok((host, user, password))
}

fn parse_vmanage_tlocs(val: &Value, default_sys: &str, default_site: &str) -> Vec<TlocEntry> {
    let rows = val.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default();
    let mut out = Vec::new();
    for r in rows {
        let sys_ip = non_empty(json_str(&r, "ip"), default_sys);
        let site_id = non_empty(json_str(&r, "site-id"), default_site);
        out.push(TlocEntry {
            interface: None,
            system_ip: sys_ip,
            site_id,
            color: json_str(&r, "color"),
            encap: non_empty(json_str(&r, "encap"), "ipsec"),
            public_ip: json_str(&r, "tloc-public-ip"),
            private_ip: json_str(&r, "tloc-private-ip"),
            preference: json_u64(&r, "preference") as u32,
            weight: json_u64(&r, "weight").max(1) as u32,
            restrict: json_str(&r, "restrict") == "1" || json_str(&r, "restrict").eq_ignore_ascii_case("true"),
            bfd_status: json_str(&r, "bfd-status"),
            bfd_color_multiplier: None,
            last_resort_circuit: false,
        });
    }
    out
}

fn parse_vmanage_routes(val: &Value) -> Vec<OmpRouteEntry> {
    let rows = val.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default();
    let mut out = Vec::new();
    for r in rows {
        let status = json_str(&r, "status");
        out.push(OmpRouteEntry {
            vpn_id: json_str(&r, "vpn-id"),
            prefix: json_str(&r, "prefix"),
            from_peer: json_str(&r, "from-peer"),
            originator: json_str(&r, "originator"),
            next_hop_tloc_ip: json_str(&r, "ip"),
            site_id: json_str(&r, "site-id"),
            color: json_str(&r, "color"),
            encap: json_str(&r, "encap"),
            is_chosen_installed: is_route_chosen_installed(&status),
            is_redistributed: status.contains("Red"),
            status,
            protocol: json_str(&r, "protocol"),
        });
    }
    out
}

fn parse_vmanage_bfd(val: &Value) -> Vec<TunnelDiag> {
    let rows = val.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default();
    let mut out = Vec::new();
    for r in rows {
        out.push(TunnelDiag {
            local_ip: json_str(&r, "src-ip"),
            remote_ip: json_str(&r, "dst-ip"),
            remote_system_ip: json_str(&r, "system-ip"),
            remote_site_id: json_str(&r, "site-id"),
            local_color: json_str(&r, "local-color"),
            remote_color: json_str(&r, "color"),
            bfd_state: json_str(&r, "state").to_lowercase(),
            detect_multiplier: json_u64(&r, "detect-multiplier") as u32,
            tx_interval_ms: json_u64(&r, "tx-interval").max(1000) as u32,
            transitions: json_u64(&r, "transitions"),
            uptime: json_str(&r, "uptime"),
            ..Default::default()
        });
    }
    out
}

fn parse_vmanage_tunnels(val: &Value) -> Vec<TunnelDiag> {
    let rows = val.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default();
    let mut out = Vec::new();
    for r in rows {
        out.push(TunnelDiag {
            local_ip: json_str(&r, "source-ip"),
            remote_ip: json_str(&r, "dest-ip"),
            remote_system_ip: json_str(&r, "system-ip"),
            local_color: json_str(&r, "local-color"),
            remote_color: json_str(&r, "remote-color"),
            tunnel_mtu: json_u64(&r, "tunnel-mtu") as u32,
            tcp_mss_adjust: json_u64(&r, "tcp-mss-adjust") as u32,
            cum_tx_pkts: json_u64(&r, "tx_pkts"),
            cum_rx_pkts: json_u64(&r, "rx_pkts"),
            cum_tx_octets: json_u64(&r, "tx_octets"),
            cum_rx_octets: json_u64(&r, "rx_octets"),
            has_tunnel_stats: true,
            ..Default::default()
        });
    }
    out
}

fn parse_vmanage_approute(val: &Value) -> Vec<TunnelDiag> {
    let rows = val.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default();
    let mut agg: BTreeMap<(String, String), TunnelDiag> = BTreeMap::new();
    for r in rows {
        let src = json_str(&r, "src-ip");
        let dst = json_str(&r, "dst-ip");
        if src.is_empty() || dst.is_empty() {
            continue;
        }
        let entry = agg.entry((src.clone(), dst.clone())).or_insert_with(|| TunnelDiag {
            local_ip: src,
            remote_ip: dst,
            remote_system_ip: json_str(&r, "remote-system-ip"),
            local_color: json_str(&r, "local-color"),
            remote_color: json_str(&r, "remote-color"),
            sla_class_index: json_str(&r, "sla-class-index"),
            mean_latency_ms: json_u64(&r, "mean-latency"),
            mean_jitter_ms: json_u64(&r, "mean-jitter"),
            mean_loss_pct: json_f64(&r, "mean-loss"),
            has_app_route: true,
            ..Default::default()
        });
        entry.recent_tx_data_pkts += json_u64(&r, "tx-data-pkts");
        entry.recent_rx_data_pkts += json_u64(&r, "rx-data-pkts");
        entry.recent_bfd_probes += json_u64(&r, "total-packets");
    }
    agg.into_values().collect()
}

fn non_empty(val: String, fallback: &str) -> String {
    if val.is_empty() {
        fallback.to_string()
    } else {
        val
    }
}

fn json_str(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn json_u64(v: &Value, key: &str) -> u64 {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}

fn json_f64(v: &Value, key: &str) -> f64 {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.trim().parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    }
}
