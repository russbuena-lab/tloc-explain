use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use chrono::Utc;
use reqwest::Client;
use serde_json::Value;

use crate::models::{OmpRouteEntry, RouterSnapshot, TlocEntry, TunnelDiag};
use crate::parsers::{compute_tunnel_averages, is_route_chosen_installed, merge_tunnel_diags, parse_running_config_sdwan};

/// Authenticated Cisco Catalyst SD-WAN vManage REST client.
pub struct VManageClient {
    base_url: String,
    client: Client,
    xsrf_token: String,
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
    pub async fn connect(
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

        let client = Client::builder()
            .cookie_store(true)
            .danger_accept_invalid_certs(insecure)
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| format!("Failed building HTTP client: {e}"))?;

        let login_res = client
            .post(format!("{base_url}/j_security_check"))
            .form(&[("j_username", user), ("j_password", password)])
            .send()
            .await
            .map_err(|e| format!("vManage login request failed: {e}"))?;

        let login_body = login_res.text().await.unwrap_or_default();
        if login_body.contains("j_security_check") || login_body.to_lowercase().contains("<html") {
            return Err(format!("vManage rejected credentials for user '{}'", user));
        }

        let token_res = client
            .get(format!("{base_url}/dataservice/client/token"))
            .send()
            .await
            .map_err(|e| format!("Failed fetching XSRF token: {e}"))?;
        let xsrf_token = token_res.text().await.unwrap_or_default().trim().to_string();
        if xsrf_token.is_empty() || xsrf_token.to_lowercase().contains("<html") {
            return Err("vManage did not return a valid X-XSRF-TOKEN".to_string());
        }

        Ok(Self {
            base_url,
            client,
            xsrf_token,
        })
    }

    pub async fn get_json(&self, path: &str) -> Result<Value, String> {
        let resp = self
            .client
            .get(format!("{}{path}", self.base_url))
            .header("X-XSRF-TOKEN", &self.xsrf_token)
            .send()
            .await
            .map_err(|e| format!("GET {path} failed: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("GET {path} -> HTTP {status}: {}", text.chars().take(200).collect::<String>()));
        }
        serde_json::from_str(&text).map_err(|e| format!("Invalid JSON from {path}: {e}"))
    }

    pub async fn list_wan_edges(&self) -> Result<Vec<VManageDeviceSummary>, String> {
        let val = self.get_json("/dataservice/system/device/vedges").await?;
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

    pub async fn collect_device_snapshot(
        &self,
        dev: &VManageDeviceSummary,
        vpn_id: &str,
    ) -> Result<RouterSnapshot, String> {
        let sys_ip = &dev.system_ip;
        let uuid = &dev.uuid;

        let p_cfg = format!("/dataservice/template/config/running/{uuid}");
        let p_tloc_adv = format!("/dataservice/device/omp/tlocs/advertised?deviceId={sys_ip}");
        let p_tloc_recv = format!("/dataservice/device/omp/tlocs/received?deviceId={sys_ip}");
        let p_routes = format!("/dataservice/device/omp/routes/received?deviceId={sys_ip}&vpn-id={vpn_id}");
        let p_bfd = format!("/dataservice/device/bfd/sessions?deviceId={sys_ip}");
        let p_tun = format!("/dataservice/device/tunnel/statistics?deviceId={sys_ip}");
        let p_app = format!("/dataservice/device/app-route/statistics?deviceId={sys_ip}");

        let (cfg_res, tloc_adv_res, tloc_recv_res, routes_res, bfd_res, tun_res, app_res) = tokio::join!(
            self.get_json(&p_cfg),
            self.get_json(&p_tloc_adv),
            self.get_json(&p_tloc_recv),
            self.get_json(&p_routes),
            self.get_json(&p_bfd),
            self.get_json(&p_tun),
            self.get_json(&p_app),
        );

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

        Ok(RouterSnapshot {
            host_name: dev.host_name.clone(),
            system_ip: dev.system_ip.clone(),
            site_id: dev.site_id.clone(),
            source_mode: "vmanage".to_string(),
            captured_at_utc: Utc::now().to_rfc3339(),
            local_tlocs,
            remote_tlocs,
            omp_routes,
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
