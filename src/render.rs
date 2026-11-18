use crate::models::{AnalysisReport, Severity, VerdictKind};

/// Renders an `AnalysisReport` as human-readable terminal text (ANSI color optional).
pub fn render_terminal(report: &AnalysisReport, use_color: bool, show_all_tunnels: bool) -> String {
    let c_bold = if use_color { "\x1b[1m" } else { "" };
    let c_cyan = if use_color { "\x1b[1;36m" } else { "" };
    let c_green = if use_color { "\x1b[1;32m" } else { "" };
    let c_yellow = if use_color { "\x1b[1;33m" } else { "" };
    let c_red = if use_color { "\x1b[1;31m" } else { "" };
    let c_dim = if use_color { "\x1b[2m" } else { "" };
    let c_reset = if use_color { "\x1b[0m" } else { "" };

    let snap = &report.snapshot;
    let is_discover = snap.source_mode == "ssh-discover";
    let mut out = String::new();

    out.push_str(&format!(
        "\n{c_cyan}=============================================================================={c_reset}\n"
    ));
    out.push_str(&format!(
        "{c_bold}TLOC & ROUTE EXPLAINER: {}{c_reset}  (System IP: {}, Site ID: {}, Source: {})\n",
        snap.host_name,
        non_empty(&snap.system_ip, "-"),
        non_empty(&snap.site_id, "-"),
        snap.source_mode
    ));
    out.push_str(&format!(
        "{c_cyan}=============================================================================={c_reset}\n"
    ));

    let vpns_display = if snap.discovered_vpns.is_empty() {
        "none".to_string()
    } else {
        snap.discovered_vpns.join(", ")
    };
    out.push_str(&format!("{c_bold}Discovered Service VPNs:{c_reset} {vpns_display}\n"));
    if let Some(peer) = &snap.peer_filter {
        out.push_str(&format!("{c_bold}Focused Peer:{c_reset} {peer}\n"));
    }

    if is_discover {
        out.push_str(&format!(
            "{c_cyan}Discovery Mode:{c_reset} Pick a peer IP below and re-run with {c_bold}--peer <ip>{c_reset} for full data-plane & OMP route analysis.\n"
        ));
    } else if report.active_primary_tunnels.is_empty() {
        out.push_str(&format!(
            "{c_yellow}Summary:{c_reset} No active primary user-data tunnel detected in current telemetry.\n"
        ));
    } else {
        out.push_str(&format!(
            "{c_green}Active Forwarding Tunnel(s):{c_reset} {}\n",
            report.active_primary_tunnels.join(" | ")
        ));
    }

    // 1. Local TLOCs
    out.push_str(&format!("\n{c_bold}1. Local Advertised TLOC Preferences{c_reset}\n"));
    if snap.local_tlocs.is_empty() {
        out.push_str(&format!("  {c_dim}(none parsed){c_reset}\n"));
    } else {
        for lt in &snap.local_tlocs {
            let iface = lt.interface.as_deref().unwrap_or("-");
            out.push_str(&format!(
                "  - {:<18} color={:<16} ip={:<13} pref={:<4} wt={:<2} restrict={} last_resort={}\n",
                iface,
                non_empty(&lt.color, "-"),
                non_empty(&lt.public_ip, "-"),
                lt.preference,
                lt.weight,
                lt.restrict,
                lt.last_resort_circuit
            ));
        }
    }

    // 2. Remote Peers Summary
    out.push_str(&format!(
        "\n{c_bold}2. Remote Peers Summary ({}){c_reset}\n",
        report.peer_summaries.len()
    ));
    if report.peer_summaries.is_empty() {
        out.push_str(&format!("  {c_dim}(no remote peers found){c_reset}\n"));
    } else {
        out.push_str(&format!(
            "  {c_dim}{:<16} {:<8} {:<12} {:<18} {}{c_reset}\n",
            "Peer System IP", "Site ID", "BFD Up/Tot", "3m Data (TX/RX)", "Remote Colors & WAN IPs"
        ));
        for ps in &report.peer_summaries {
            let bfd_ratio = format!("{}/{}", ps.tunnels_up, ps.tunnels_total);
            let data_ratio = format!("{}/{}", ps.recent_tx_pkts, ps.recent_rx_pkts);
            let detail = format!(
                "{} ({})",
                if ps.colors.is_empty() { "-".to_string() } else { ps.colors.join(", ") },
                if ps.remote_ips.is_empty() { "-".to_string() } else { ps.remote_ips.join(", ") }
            );
            out.push_str(&format!(
                "  {:<16} {:<8} {:<12} {:<18} {}\n",
                ps.system_ip,
                non_empty(&ps.site_id, "-"),
                bfd_ratio,
                data_ratio,
                detail
            ));
        }
    }

    // 3. Tunnel Verdicts
    let collapse_standby =
        snap.peer_filter.is_none() && !show_all_tunnels && report.tunnel_verdicts.len() > 8;
    let mut hidden_standby = 0usize;

    out.push_str(&format!(
        "\n{c_bold}3. Tunnel Data-Plane Usage & Plain-English Verdicts ({}){c_reset}\n",
        report.tunnel_verdicts.len()
    ));
    for tv in &report.tunnel_verdicts {
        if collapse_standby && tv.verdict == VerdictKind::StandbyBfdOnly {
            hidden_standby += 1;
            continue;
        }
        let badge_color = match tv.verdict {
            VerdictKind::ActivePrimary => c_green,
            VerdictKind::StandbyBfdOnly => c_dim,
            VerdictKind::HistoricalFailoverIdle => c_yellow,
            VerdictKind::BackupDataBleed | VerdictKind::DownOrDegraded => c_red,
        };
        out.push_str(&format!(
            "\n  {badge_color}[{}]{c_reset}\n  Tunnel : {} ({}) -> {} ({})  [peer={} BFD={} mult={}]\n  Recent : {} TX / {} RX user data pkts (3m) | Avg Size: {:.1}B TX / {:.1}B RX | Est Hist Data: ~{} pkts | SLA: {}ms/{}ms/{:.1}%\n  Why    : {}\n",
            tv.verdict.label(),
            tv.local_color,
            tv.local_ip,
            tv.remote_color,
            tv.remote_ip,
            non_empty(&tv.remote_system_ip, "-"),
            tv.bfd_state,
            tv.detect_multiplier,
            tv.recent_tx_data_pkts,
            tv.recent_rx_data_pkts,
            tv.avg_tx_pkt_bytes,
            tv.avg_rx_pkt_bytes,
            tv.est_cum_data_pkts,
            tv.mean_latency_ms,
            tv.mean_jitter_ms,
            tv.mean_loss_pct,
            tv.reason
        ));
    }
    if hidden_standby > 0 {
        out.push_str(&format!(
            "\n  {c_dim}... plus {hidden_standby} idle STANDBY (BFD HEARTBEAT ONLY) tunnels hidden (use --peer <ip> or --all-tunnels to show all).{c_reset}\n"
        ));
    }

    // 4. OMP Route Explanations
    out.push_str(&format!(
        "\n{c_bold}4. OMP Route Selection (Why Each Prefix Picked Its Path){c_reset}\n"
    ));
    if is_discover {
        out.push_str(&format!(
            "  {c_dim}(skipped in --discover mode; re-run with --peer <ip> to inspect OMP routes){c_reset}\n"
        ));
    } else if report.route_explanations.is_empty() {
        out.push_str(&format!("  {c_dim}(no received OMP routes in snapshot){c_reset}\n"));
    } else {
        for re in &report.route_explanations {
            out.push_str(&format!(
                "  - VPN {:<4} {:<18} -> Winner: {} ({}) via local {}\n    Why    : {}\n",
                re.vpn_id,
                re.prefix,
                re.winning_color,
                non_empty(&re.winning_originator, "-"),
                re.local_egress_color,
                re.explanation
            ));
            if !re.backup_paths.is_empty() {
                out.push_str(&format!("    Backup : {}\n", re.backup_paths.join(" ; ")));
            }
        }
    }

    // 5. Automated Drift & Risk Findings
    out.push_str(&format!(
        "\n{c_bold}5. Automated Drift & Risk Findings ({}){c_reset}\n",
        report.findings.len()
    ));
    if report.findings.is_empty() {
        out.push_str(&format!("  {c_green}[OK]{c_reset} No configuration or policy drifts detected.\n"));
    } else {
        for f in &report.findings {
            let sev_col = match f.severity {
                Severity::Info => c_cyan,
                Severity::Warn => c_yellow,
                Severity::Alert => c_red,
            };
            out.push_str(&format!(
                "  {sev_col}[{}]{c_reset} {} — {}\n    Detail: {}\n    Fix   : {}\n",
                f.severity.label(),
                f.code,
                f.title,
                f.explanation,
                f.remediation
            ));
        }
    }

    if let Some(pol) = &snap.policy_summary {
        out.push_str(&format!("\n{c_bold}6. vSmart Apply-Policy Summary{c_reset}\n{}\n", pol));
    }

    out.push('\n');
    out
}

/// Renders an `AnalysisReport` as a clean Markdown report.
pub fn render_markdown(report: &AnalysisReport, show_all_tunnels: bool) -> String {
    let snap = &report.snapshot;
    let mut md = String::new();
    let vpns_display = if snap.discovered_vpns.is_empty() {
        "none".to_string()
    } else {
        snap.discovered_vpns.join(", ")
    };
    md.push_str(&format!(
        "# TLOC & Route Explanation — `{}`\n\n- **System IP:** `{}`\n- **Site ID:** `{}`\n- **Discovered Service VPNs:** `{}`\n- **Source:** `{}`\n- **Captured (UTC):** `{}`\n",
        snap.host_name,
        non_empty(&snap.system_ip, "-"),
        non_empty(&snap.site_id, "-"),
        vpns_display,
        snap.source_mode,
        snap.captured_at_utc
    ));
    if let Some(peer) = &snap.peer_filter {
        md.push_str(&format!("- **Focused Peer:** `{peer}`\n"));
    }
    md.push('\n');

    md.push_str("## Remote Peers Summary\n\n");
    md.push_str("| Peer System IP | Site ID | BFD (`Up/Total`) | 3m Data (`TX/RX`) | Colors | Remote WAN IPs |\n");
    md.push_str("| :--- | :---: | :---: | :---: | :--- | :--- |\n");
    for ps in &report.peer_summaries {
        md.push_str(&format!(
            "| `{}` | `{}` | `{}/{}` | `{}/{}` | `{}` | `{}` |\n",
            ps.system_ip,
            non_empty(&ps.site_id, "-"),
            ps.tunnels_up,
            ps.tunnels_total,
            ps.recent_tx_pkts,
            ps.recent_rx_pkts,
            if ps.colors.is_empty() { "-".to_string() } else { ps.colors.join(", ") },
            if ps.remote_ips.is_empty() { "-".to_string() } else { ps.remote_ips.join(", ") }
        ));
    }
    md.push('\n');

    let collapse_standby =
        snap.peer_filter.is_none() && !show_all_tunnels && report.tunnel_verdicts.len() > 8;
    let mut hidden_standby = 0usize;

    md.push_str("## Tunnel Data-Plane Verdicts\n\n");
    md.push_str("| Tunnel (`Local -> Remote`) | Colors | Verdict | Recent Data (`TX / RX`) | Avg Pkt (`TX / RX`) | BFD (`State / Mult`) | Explanation |\n");
    md.push_str("| :--- | :--- | :--- | :---: | :---: | :---: | :--- |\n");
    for tv in &report.tunnel_verdicts {
        if collapse_standby && tv.verdict == VerdictKind::StandbyBfdOnly {
            hidden_standby += 1;
            continue;
        }
        md.push_str(&format!(
            "| `{} -> {}` | `{} -> {}` | **{}** | `{} / {}` | `{:.1}B / {:.1}B` | `{} / {}` | {} |\n",
            tv.local_ip,
            tv.remote_ip,
            tv.local_color,
            tv.remote_color,
            tv.verdict.label(),
            tv.recent_tx_data_pkts,
            tv.recent_rx_data_pkts,
            tv.avg_tx_pkt_bytes,
            tv.avg_rx_pkt_bytes,
            tv.bfd_state,
            tv.detect_multiplier,
            tv.reason
        ));
    }
    if hidden_standby > 0 {
        md.push_str(&format!(
            "\n*Plus `{hidden_standby}` idle `STANDBY (BFD HEARTBEAT ONLY)` tunnels hidden (pass `--peer <ip>` or `--all-tunnels` to inspect all).*\n"
        ));
    }

    md.push_str("\n## OMP Route Selection\n\n");
    for re in &report.route_explanations {
        md.push_str(&format!(
            "- **VPN `{}` `{}`:** Winner `{}` (`{}`) via local `{}` — {}\n",
            re.vpn_id, re.prefix, re.winning_color, re.winning_originator, re.local_egress_color, re.explanation
        ));
    }

    md.push_str("\n## Drift & Risk Findings\n\n");
    if report.findings.is_empty() {
        md.push_str("- No configuration or policy drifts detected.\n");
    } else {
        for f in &report.findings {
            md.push_str(&format!(
                "- **[{}] `{}`:** {} — {} *(Fix: {})*\n",
                f.severity.label(),
                f.code,
                f.title,
                f.explanation,
                f.remediation
            ));
        }
    }

    md
}

fn non_empty<'a>(s: &'a str, fallback: &'a str) -> &'a str {
    if s.is_empty() { fallback } else { s }
}
