use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Returns the current UTC timestamp formatted as RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn utc_now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    // Howard Hinnant's civil_from_days algorithm (days since 1970-01-01)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Returns a `0700` user-private runtime scratch directory (`~/.cache/tloc-explain`),
/// avoiding `/tmp` which may be mounted `noexec` on hardened STIG hosts.
pub fn runtime_scratch_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            let dir = PathBuf::from(home).join(".cache").join("tloc-explain");
            if fs::create_dir_all(&dir).is_ok() {
                let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
                return dir;
            }
        }
    }
    std::env::temp_dir()
}

/// Normalized snapshot of a Cisco Catalyst SD-WAN router's TLOCs, OMP routes, BFD sessions,
/// cumulative tunnel statistics, and rolling app-route SLA statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouterSnapshot {
    pub host_name: String,
    pub system_ip: String,
    pub site_id: String,
    pub source_mode: String,
    pub captured_at_utc: String,
    pub discovered_vpns: Vec<String>,
    pub peer_filter: Option<String>,
    pub local_tlocs: Vec<TlocEntry>,
    pub remote_tlocs: Vec<TlocEntry>,
    pub omp_routes: Vec<OmpRouteEntry>,
    pub tunnels: Vec<TunnelDiag>,
    pub policy_summary: Option<String>,
}

/// A local or remote Transport Locator (TLOC) entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlocEntry {
    pub interface: Option<String>,
    pub system_ip: String,
    pub site_id: String,
    pub color: String,
    pub encap: String,
    pub public_ip: String,
    pub private_ip: String,
    pub preference: u32,
    pub weight: u32,
    pub restrict: bool,
    pub bfd_status: String,
    pub bfd_color_multiplier: Option<u32>,
    pub last_resort_circuit: bool,
}

/// An OMP route entry received or originated in a service VPN.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OmpRouteEntry {
    pub vpn_id: String,
    pub prefix: String,
    pub from_peer: String,
    pub originator: String,
    pub next_hop_tloc_ip: String,
    pub site_id: String,
    pub color: String,
    pub encap: String,
    pub status: String,
    pub protocol: String,
    pub is_chosen_installed: bool,
    pub is_redistributed: bool,
}

/// Combined per-tunnel diagnostic record merging BFD, cumulative tunnel stats, and rolling app-route SLA stats.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelDiag {
    pub local_ip: String,
    pub remote_ip: String,
    pub remote_system_ip: String,
    pub remote_site_id: String,
    pub local_color: String,
    pub remote_color: String,
    pub bfd_state: String,
    pub detect_multiplier: u32,
    pub tx_interval_ms: u32,
    pub transitions: u64,
    pub uptime: String,
    pub tunnel_mtu: u32,
    pub tcp_mss_adjust: u32,
    pub cum_tx_pkts: u64,
    pub cum_rx_pkts: u64,
    pub cum_tx_octets: u64,
    pub cum_rx_octets: u64,
    pub avg_tx_pkt_bytes: f64,
    pub avg_rx_pkt_bytes: f64,
    pub est_cum_data_pkts: u64,
    pub sla_class_index: String,
    pub mean_latency_ms: u64,
    pub mean_jitter_ms: u64,
    pub mean_loss_pct: f64,
    pub recent_tx_data_pkts: u64,
    pub recent_rx_data_pkts: u64,
    pub recent_bfd_probes: u64,
    pub has_app_route: bool,
    pub has_tunnel_stats: bool,
}

/// Plain-English verdict for a single local-to-remote IPsec tunnel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerdictKind {
    ActivePrimary,
    StandbyBfdOnly,
    HistoricalFailoverIdle,
    BackupDataBleed,
    DownOrDegraded,
}

impl VerdictKind {
    pub fn label(&self) -> &'static str {
        match self {
            VerdictKind::ActivePrimary => "ACTIVE PRIMARY (CARRYING DATA)",
            VerdictKind::StandbyBfdOnly => "STANDBY (BFD HEARTBEAT ONLY)",
            VerdictKind::HistoricalFailoverIdle => "HISTORICAL FAILOVER TRAFFIC (CURRENTLY IDLE)",
            VerdictKind::BackupDataBleed => "ALERT: BACKUP/METERED CIRCUIT BLEEDING DATA",
            VerdictKind::DownOrDegraded => "DOWN / DEGRADED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelVerdict {
    pub local_ip: String,
    pub remote_ip: String,
    pub remote_system_ip: String,
    pub local_color: String,
    pub remote_color: String,
    pub verdict: VerdictKind,
    pub recent_tx_data_pkts: u64,
    pub recent_rx_data_pkts: u64,
    pub avg_tx_pkt_bytes: f64,
    pub avg_rx_pkt_bytes: f64,
    pub est_cum_data_pkts: u64,
    pub bfd_state: String,
    pub detect_multiplier: u32,
    pub mean_latency_ms: u64,
    pub mean_jitter_ms: u64,
    pub mean_loss_pct: f64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteExplanation {
    pub vpn_id: String,
    pub prefix: String,
    pub winning_color: String,
    pub winning_originator: String,
    pub backup_paths: Vec<String>,
    pub local_egress_color: String,
    pub local_egress_ip: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warn,
    Alert,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Alert => "ALERT",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftFinding {
    pub severity: Severity,
    pub code: String,
    pub title: String,
    pub explanation: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerSummary {
    pub system_ip: String,
    pub site_id: String,
    pub tunnels_up: usize,
    pub tunnels_total: usize,
    pub recent_tx_pkts: u64,
    pub recent_rx_pkts: u64,
    pub est_cum_data_pkts: u64,
    pub cir_routes: usize,
    pub backup_routes: usize,
    pub is_default_route_winner: bool,
    pub colors: Vec<String>,
    pub remote_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub snapshot: RouterSnapshot,
    pub active_primary_tunnels: Vec<String>,
    pub peer_summaries: Vec<PeerSummary>,
    pub tunnel_verdicts: Vec<TunnelVerdict>,
    pub route_explanations: Vec<RouteExplanation>,
    pub findings: Vec<DriftFinding>,
}
