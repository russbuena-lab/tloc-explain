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
    if let Some(vpn) = &snap.target_vpn {
        if !vpn.is_empty() {
            out.push_str(&format!("{c_bold}Target Service VPN:{c_reset} {vpn}\n"));
        }
    }
    if let Some(peer) = &snap.peer_filter {
        out.push_str(&format!("{c_bold}Focused Peer:{c_reset} {peer}\n"));
    }

    if let Some(q0) = &report.quad_zero {
        let site_part = if q0.winner_site_id.is_empty() {
            String::new()
        } else {
            format!(" (site {})", q0.winner_site_id)
        };
        let local_iface_part = if !q0.local_interface.is_empty() && !q0.local_ip.is_empty() {
            format!("{}, {}", q0.local_interface, q0.local_ip)
        } else if !q0.local_interface.is_empty() {
            q0.local_interface.clone()
        } else if !q0.local_ip.is_empty() {
            q0.local_ip.clone()
        } else {
            "-".to_string()
        };
        let lp_part = q0
            .local_pref
            .map(|p| format!(", Pref {p}"))
            .unwrap_or_default();
        let remote_ip_part = if q0.remote_ip.is_empty() {
            "-".to_string()
        } else {
            q0.remote_ip.clone()
        };
        let rp_part = q0
            .remote_pref
            .map(|p| format!(", Pref {p}"))
            .unwrap_or_default();
        let source_tag = if q0.via_service_path {
            "QFP service-path + RIB"
        } else {
            "OMP/RIB + tunnel stats"
        };

        out.push_str(&format!(
            "\n{c_bold}{c_cyan}== Quad-Zero (0.0.0.0/0) & Primary Color Verdict =={c_reset}\n"
        ));
        out.push_str(&format!(
            "  {c_bold}Target Service VPN :{c_reset} {}\n",
            if q0.target_vpn.is_empty() { "-" } else { &q0.target_vpn }
        ));
        out.push_str(&format!(
            "  {c_bold}0.0.0.0/0 Winner   :{c_reset} {c_green}{}{c_reset}{site_part}\n",
            q0.winner_system_ip
        ));
        out.push_str(&format!(
            "  {c_bold}Primary Color      :{c_reset} {c_green}{}{c_reset} ({local_iface_part}{lp_part}) -> {} ({remote_ip_part}{rp_part}) [{source_tag}]\n",
            q0.local_color, q0.remote_color
        ));
        out.push_str(&format!(
            "  {c_bold}Why It Is Primary  :{c_reset} {}\n\n",
            q0.why
        ));
    } else if let Some(vpn) = &snap.target_vpn {
        if !vpn.is_empty() {
            out.push_str(&format!(
                "{c_yellow}0.0.0.0/0 Verdict:{c_reset} No active 0.0.0.0/0 default route detected in Service VPN {vpn}.\n"
            ));
        }
    }

    if report.active_primary_tunnels.is_empty() {
        out.push_str(&format!(
            "{c_yellow}Summary:{c_reset} No active primary forwarding tunnel detected in current telemetry.\n"
        ));
    } else {
        out.push_str(&format!(
            "{c_green}Active Forwarding Tunnel(s):{c_reset} {}\n",
            report.active_primary_tunnels.join(" | ")
        ));
    }
    if is_discover {
        out.push_str(&format!(
            "{c_cyan}Discovery Tip:{c_reset} Run with {c_bold}--peer <system-ip>{c_reset} on an active or target peer for 3m app-route SLA stats & TLOC preferences.\n"
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
            "  {c_dim}{:<16} {:<7} {:<6} {:<18} {:<16} {}{c_reset}\n",
            "Peer System IP", "Site", "BFD", "OMP (C,I,R / R)", "Data (3m/Cum)", "Remote Colors & WAN IPs"
        ));
        for ps in &report.peer_summaries {
            let bfd_ratio = format!("{}/{}", ps.tunnels_up, ps.tunnels_total);
            let omp_ratio = if ps.is_default_route_winner {
                format!("{}/{} [0.0.0.0/0]", ps.cir_routes, ps.backup_routes)
            } else {
                format!("{}/{}", ps.cir_routes, ps.backup_routes)
            };
            let data_ratio = format!(
                "{}/{} (~{})",
                ps.recent_tx_pkts, ps.recent_rx_pkts, ps.est_cum_data_pkts
            );
            let detail = format!(
                "{} ({})",
                if ps.colors.is_empty() { "-".to_string() } else { ps.colors.join(", ") },
                if ps.remote_ips.is_empty() { "-".to_string() } else { ps.remote_ips.join(", ") }
            );
            out.push_str(&format!(
                "  {:<16} {:<7} {:<6} {:<18} {:<16} {}\n",
                ps.system_ip,
                non_empty(&ps.site_id, "-"),
                bfd_ratio,
                omp_ratio,
                data_ratio,
                detail
            ));
        }
    }

    // 3. Tunnel Verdicts
    let discover_compact = is_discover && snap.peer_filter.is_none() && !show_all_tunnels;
    let collapse_standby =
        snap.peer_filter.is_none() && !show_all_tunnels && (is_discover || report.tunnel_verdicts.len() > 8);
    let mut hidden_standby = 0usize;

    out.push_str(&format!(
        "\n{c_bold}3. Tunnel Data-Plane Usage & Plain-English Verdicts ({}){c_reset}\n",
        report.tunnel_verdicts.len()
    ));
    for tv in &report.tunnel_verdicts {
        let should_hide = if discover_compact {
            !matches!(
                tv.verdict,
                VerdictKind::ActivePrimary | VerdictKind::BackupDataBleed | VerdictKind::DownOrDegraded
            )
        } else {
            collapse_standby && tv.verdict == VerdictKind::StandbyBfdOnly
        };
        if should_hide {
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
            "\n  {c_dim}... plus {hidden_standby} standby/idle tunnel(s) hidden (use --peer <ip> or --all-tunnels to show all).{c_reset}\n"
        ));
    }

    // 4. OMP Route Explanations
    out.push_str(&format!(
        "\n{c_bold}4. OMP Route Selection (Why Each Prefix Picked Its Path){c_reset}\n"
    ));
    if report.route_explanations.is_empty() {
        out.push_str(&format!("  {c_dim}(no received OMP routes in snapshot){c_reset}\n"));
    } else {
        let mut hidden_routes = 0usize;
        let mut shown_default = 0usize;
        for re in &report.route_explanations {
            if discover_compact && re.prefix != "0.0.0.0/0" {
                hidden_routes += 1;
                continue;
            }
            if re.prefix == "0.0.0.0/0" {
                shown_default += 1;
            }
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
        if hidden_routes > 0 {
            if shown_default == 0 {
                out.push_str(&format!(
                    "  {c_dim}(no 0.0.0.0/0 default route; {hidden_routes} other service prefix(es) hidden in --discover — pass --peer <ip> or --all-tunnels to list){c_reset}\n"
                ));
            } else {
                out.push_str(&format!(
                    "  {c_dim}... plus {hidden_routes} other service prefix(es) hidden in --discover (pass --peer <ip> or --all-tunnels to list).{c_reset}\n"
                ));
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
    if let Some(vpn) = &snap.target_vpn {
        if !vpn.is_empty() {
            md.push_str(&format!("- **Target Service VPN:** `{vpn}`\n"));
        }
    }
    if let Some(peer) = &snap.peer_filter {
        md.push_str(&format!("- **Focused Peer:** `{peer}`\n"));
    }
    md.push('\n');

    if let Some(q0) = &report.quad_zero {
        let site_part = if q0.winner_site_id.is_empty() {
            String::new()
        } else {
            format!(" (site `{}`)", q0.winner_site_id)
        };
        let local_iface_part = if !q0.local_interface.is_empty() && !q0.local_ip.is_empty() {
            format!("{}, {}", q0.local_interface, q0.local_ip)
        } else if !q0.local_interface.is_empty() {
            q0.local_interface.clone()
        } else {
            non_empty(&q0.local_ip, "-").to_string()
        };
        let lp_part = q0
            .local_pref
            .map(|p| format!(", Pref {p}"))
            .unwrap_or_default();
        let rp_part = q0
            .remote_pref
            .map(|p| format!(", Pref {p}"))
            .unwrap_or_default();
        let source_tag = if q0.via_service_path {
            "QFP service-path + RIB"
        } else {
            "OMP/RIB + tunnel stats"
        };

        md.push_str("## Quad-Zero (`0.0.0.0/0`) & Primary Color Verdict\n\n");
        md.push_str(&format!(
            "- **Target Service VPN:** `{}`\n",
            non_empty(&q0.target_vpn, "-")
        ));
        md.push_str(&format!(
            "- **0.0.0.0/0 Winner:** `{}`{}\n",
            q0.winner_system_ip, site_part
        ));
        md.push_str(&format!(
            "- **Primary Color:** `{}` (`{}`{}) -> `{}` (`{}`{}) [{}]\n",
            q0.local_color,
            local_iface_part,
            lp_part,
            q0.remote_color,
            non_empty(&q0.remote_ip, "-"),
            rp_part,
            source_tag
        ));
        md.push_str(&format!("- **Why It Is Primary:** {}\n\n", q0.why));
    }

    md.push_str("## Remote Peers Summary\n\n");
    md.push_str("| Peer System IP | Site ID | BFD (`Up/Tot`) | OMP (`C,I,R / R`) | Data (`3m / Cumul`) | Colors | Remote WAN IPs |\n");
    md.push_str("| :--- | :---: | :---: | :---: | :---: | :--- | :--- |\n");
    for ps in &report.peer_summaries {
        let omp_col = if ps.is_default_route_winner {
            format!("{}/{} [0.0.0.0/0]", ps.cir_routes, ps.backup_routes)
        } else {
            format!("{}/{}", ps.cir_routes, ps.backup_routes)
        };
        md.push_str(&format!(
            "| `{}` | `{}` | `{}/{}` | `{}` | `{}/{} (~{})` | `{}` | `{}` |\n",
            ps.system_ip,
            non_empty(&ps.site_id, "-"),
            ps.tunnels_up,
            ps.tunnels_total,
            omp_col,
            ps.recent_tx_pkts,
            ps.recent_rx_pkts,
            ps.est_cum_data_pkts,
            if ps.colors.is_empty() { "-".to_string() } else { ps.colors.join(", ") },
            if ps.remote_ips.is_empty() { "-".to_string() } else { ps.remote_ips.join(", ") }
        ));
    }
    md.push('\n');

    let is_discover = snap.source_mode == "ssh-discover";
    let discover_compact = is_discover && snap.peer_filter.is_none() && !show_all_tunnels;
    let collapse_standby =
        snap.peer_filter.is_none() && !show_all_tunnels && (is_discover || report.tunnel_verdicts.len() > 8);
    let mut hidden_standby = 0usize;

    md.push_str("## Tunnel Data-Plane Verdicts\n\n");
    md.push_str("| Tunnel (`Local -> Remote`) | Colors | Verdict | Recent Data (`TX / RX`) | Avg Pkt (`TX / RX`) | BFD (`State / Mult`) | Explanation |\n");
    md.push_str("| :--- | :--- | :--- | :---: | :---: | :---: | :--- |\n");
    for tv in &report.tunnel_verdicts {
        let should_hide = if discover_compact {
            !matches!(
                tv.verdict,
                VerdictKind::ActivePrimary | VerdictKind::BackupDataBleed | VerdictKind::DownOrDegraded
            )
        } else {
            collapse_standby && tv.verdict == VerdictKind::StandbyBfdOnly
        };
        if should_hide {
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
    let mut md_hidden_routes = 0usize;
    for re in &report.route_explanations {
        if discover_compact && re.prefix != "0.0.0.0/0" {
            md_hidden_routes += 1;
            continue;
        }
        md.push_str(&format!(
            "- **VPN `{}` `{}`:** Winner `{}` (`{}`) via local `{}` — {}\n",
            re.vpn_id, re.prefix, re.winning_color, re.winning_originator, re.local_egress_color, re.explanation
        ));
    }
    if md_hidden_routes > 0 {
        md.push_str(&format!(
            "\n*Plus `{md_hidden_routes}` non-default service prefix(es) hidden in `--discover` (pass `--peer <ip>` or `--all-tunnels` to list).*\n"
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
