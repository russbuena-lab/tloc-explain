use serde::{Deserialize, Serialize};

/// Normalized snapshot of a Cisco Catalyst SD-WAN router's TLOCs, OMP routes, BFD sessions,
/// cumulative tunnel statistics, and rolling app-route SLA statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouterSnapshot {
    pub host_name: String,
    pub system_ip: String,
    pub site_id: String,
    pub source_mode: String,
    pub captured_at_utc: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub snapshot: RouterSnapshot,
    pub active_primary_tunnels: Vec<String>,
    pub tunnel_verdicts: Vec<TunnelVerdict>,
    pub route_explanations: Vec<RouteExplanation>,
    pub findings: Vec<DriftFinding>,
}
