use crate::models::{AnalysisReport, Severity, VerdictKind};

/// Renders an `AnalysisReport` as human-readable terminal text (ANSI color optional).
pub fn render_terminal(report: &AnalysisReport, use_color: bool) -> String {
    let c_bold = if use_color { "\x1b[1m" } else { "" };
    let c_cyan = if use_color { "\x1b[1;36m" } else { "" };
    let c_green = if use_color { "\x1b[1;32m" } else { "" };
    let c_yellow = if use_color { "\x1b[1;33m" } else { "" };
    let c_red = if use_color { "\x1b[1;31m" } else { "" };
    let c_dim = if use_color { "\x1b[2m" } else { "" };
    let c_reset = if use_color { "\x1b[0m" } else { "" };

    let snap = &report.snapshot;
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

    if report.active_primary_tunnels.is_empty() {
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

    // 2. Tunnel Verdicts
    out.push_str(&format!(
        "\n{c_bold}2. Tunnel Data-Plane Usage & Plain-English Verdicts ({}){c_reset}\n",
        report.tunnel_verdicts.len()
    ));
    for tv in &report.tunnel_verdicts {
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

    // 3. OMP Route Explanations
    out.push_str(&format!(
        "\n{c_bold}3. OMP Route Selection (Why Each Prefix Picked Its Path){c_reset}\n"
    ));
    if report.route_explanations.is_empty() {
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

    // 4. Automated Drift & Risk Findings
    out.push_str(&format!(
        "\n{c_bold}4. Automated Drift & Risk Findings ({}){c_reset}\n",
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
        out.push_str(&format!("\n{c_bold}5. vSmart Apply-Policy Summary{c_reset}\n{}\n", pol));
    }

    out.push('\n');
    out
}

/// Renders an `AnalysisReport` as a clean Markdown report.
pub fn render_markdown(report: &AnalysisReport) -> String {
    let snap = &report.snapshot;
    let mut md = String::new();
    md.push_str(&format!(
        "# TLOC & Route Explanation — `{}`\n\n- **System IP:** `{}`\n- **Site ID:** `{}`\n- **Source:** `{}`\n- **Captured (UTC):** `{}`\n\n",
        snap.host_name,
        non_empty(&snap.system_ip, "-"),
        non_empty(&snap.site_id, "-"),
        snap.source_mode,
        snap.captured_at_utc
    ));

    md.push_str("## Tunnel Data-Plane Verdicts\n\n");
    md.push_str("| Tunnel (`Local -> Remote`) | Colors | Verdict | Recent Data (`TX / RX`) | Avg Pkt (`TX / RX`) | BFD (`State / Mult`) | Explanation |\n");
    md.push_str("| :--- | :--- | :--- | :---: | :---: | :---: | :--- |\n");
    for tv in &report.tunnel_verdicts {
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
