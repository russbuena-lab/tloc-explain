use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use crate::models::{
    AnalysisReport, DriftFinding, PeerSummary, RouteExplanation, RouterSnapshot, Severity,
    TlocEntry, TunnelDiag, TunnelVerdict, VerdictKind,
};
use crate::parsers::is_route_chosen_resolved;

fn verdict_rank(v: &VerdictKind) -> u8 {
    match v {
        VerdictKind::BackupDataBleed => 0,
        VerdictKind::ActivePrimary => 1,
        VerdictKind::DownOrDegraded => 2,
        VerdictKind::HistoricalFailoverIdle => 3,
        VerdictKind::StandbyBfdOnly => 4,
    }
}

fn route_peer_key(r: &crate::models::OmpRouteEntry) -> &str {
    if !r.originator.is_empty() {
        &r.originator
    } else if !r.next_hop_tloc_ip.is_empty() {
        &r.next_hop_tloc_ip
    } else {
        &r.from_peer
    }
}

fn build_peer_summaries(snapshot: &RouterSnapshot) -> Vec<PeerSummary> {
    struct Accum {
        site_id: String,
        tunnels_up: usize,
        tunnels_total: usize,
        recent_tx_pkts: u64,
        recent_rx_pkts: u64,
        est_cum_data_pkts: u64,
        cir_routes: usize,
        backup_routes: usize,
        is_default_route_winner: bool,
        colors: BTreeSet<String>,
        remote_ips: BTreeSet<String>,
    }

    let default_acc = |site_id: String| Accum {
        site_id,
        tunnels_up: 0,
        tunnels_total: 0,
        recent_tx_pkts: 0,
        recent_rx_pkts: 0,
        est_cum_data_pkts: 0,
        cir_routes: 0,
        backup_routes: 0,
        is_default_route_winner: false,
        colors: BTreeSet::new(),
        remote_ips: BTreeSet::new(),
    };

    let mut by_peer: BTreeMap<String, Accum> = BTreeMap::new();
    for td in &snapshot.tunnels {
        let key = if td.remote_system_ip.is_empty() {
            td.remote_ip.clone()
        } else {
            td.remote_system_ip.clone()
        };
        if key.is_empty() {
            continue;
        }
        let acc = by_peer.entry(key).or_insert_with(|| default_acc(String::new()));
        if acc.site_id.is_empty() && !td.remote_site_id.is_empty() {
            acc.site_id = td.remote_site_id.clone();
        }
        acc.tunnels_total += 1;
        if td.bfd_state == "up" {
            acc.tunnels_up += 1;
        }
        acc.recent_tx_pkts += td.recent_tx_data_pkts;
        acc.recent_rx_pkts += td.recent_rx_data_pkts;
        acc.est_cum_data_pkts += td.est_cum_data_pkts;
        if !td.remote_color.is_empty() {
            acc.colors.insert(td.remote_color.clone());
        }
        if !td.remote_ip.is_empty() {
            acc.remote_ips.insert(td.remote_ip.clone());
        }
    }

    if by_peer.is_empty() {
        for rt in &snapshot.remote_tlocs {
            if rt.system_ip.is_empty() {
                continue;
            }
            let acc = by_peer
                .entry(rt.system_ip.clone())
                .or_insert_with(|| default_acc(rt.site_id.clone()));
            if acc.site_id.is_empty() && !rt.site_id.is_empty() {
                acc.site_id = rt.site_id.clone();
            }
            if !rt.color.is_empty() {
                acc.colors.insert(rt.color.clone());
            }
            if !rt.public_ip.is_empty() {
                acc.remote_ips.insert(rt.public_ip.clone());
            }
        }
    }

    let is_vsmart_mode = snapshot.source_mode == "ssh-vsmart";
    let peer_filtered = snapshot.peer_filter.is_some();
    for r in &snapshot.omp_routes {
        if r.from_peer == "0.0.0.0" || r.is_redistributed {
            continue;
        }
        let peer_key = route_peer_key(r);
        if peer_key.is_empty() {
            continue;
        }
        let acc = if peer_filtered {
            match by_peer.get_mut(peer_key) {
                Some(a) => a,
                None => continue,
            }
        } else {
            by_peer
                .entry(peer_key.to_string())
                .or_insert_with(|| default_acc(r.site_id.clone()))
        };
        let is_winner =
            r.is_chosen_installed || (is_vsmart_mode && is_route_chosen_resolved(&r.status));
        if is_winner {
            acc.cir_routes += 1;
            if r.prefix == "0.0.0.0/0" {
                acc.is_default_route_winner = true;
            }
        } else {
            acc.backup_routes += 1;
        }
    }

    let mut out: Vec<PeerSummary> = by_peer
        .into_iter()
        .map(|(system_ip, mut acc)| {
            if acc.site_id.is_empty() {
                if let Some(rt) = snapshot
                    .remote_tlocs
                    .iter()
                    .find(|t| t.system_ip == system_ip && !t.site_id.is_empty())
                {
                    acc.site_id = rt.site_id.clone();
                }
            }
            PeerSummary {
                system_ip,
                site_id: acc.site_id,
                tunnels_up: acc.tunnels_up,
                tunnels_total: acc.tunnels_total,
                recent_tx_pkts: acc.recent_tx_pkts,
                recent_rx_pkts: acc.recent_rx_pkts,
                est_cum_data_pkts: acc.est_cum_data_pkts,
                cir_routes: acc.cir_routes,
                backup_routes: acc.backup_routes,
                is_default_route_winner: acc.is_default_route_winner,
                colors: acc.colors.into_iter().collect(),
                remote_ips: acc.remote_ips.into_iter().collect(),
            }
        })
        .collect();

    out.sort_by(|a, b| {
        Reverse(a.is_default_route_winner)
            .cmp(&Reverse(b.is_default_route_winner))
            .then_with(|| Reverse(a.cir_routes).cmp(&Reverse(b.cir_routes)))
            .then_with(|| {
                Reverse(a.recent_tx_pkts + a.recent_rx_pkts)
                    .cmp(&Reverse(b.recent_tx_pkts + b.recent_rx_pkts))
            })
            .then_with(|| Reverse(a.est_cum_data_pkts).cmp(&Reverse(b.est_cum_data_pkts)))
            .then_with(|| Reverse(a.tunnels_up).cmp(&Reverse(b.tunnels_up)))
            .then_with(|| a.system_ip.cmp(&b.system_ip))
    });
    out
}

fn resolve_local_egress<'a>(
    tunnels: &[TunnelDiag],
    local_tlocs: &'a [TlocEntry],
    best_global: Option<&'a TlocEntry>,
    remote_sys: &str,
    remote_color: &str,
) -> (String, String, Option<u32>) {
    let matched_local = tunnels
        .iter()
        .filter(|t| {
            (t.bfd_state.is_empty() || t.bfd_state == "up")
                && t.remote_system_ip == remote_sys
                && (remote_color.is_empty() || t.remote_color == remote_color)
        })
        .filter_map(|t| {
            local_tlocs
                .iter()
                .find(|l| (!l.color.is_empty() && l.color == t.local_color) || l.public_ip == t.local_ip)
        })
        .max_by_key(|l| l.preference)
        .or(best_global);

    match matched_local {
        Some(lt) => (lt.color.clone(), lt.public_ip.clone(), Some(lt.preference)),
        None => ("unknown".to_string(), String::new(), None),
    }
}

/// Evaluates a `RouterSnapshot` and generates plain-English tunnel verdicts, route explanations,
/// and automated drift/risk findings.
pub fn explain_snapshot(mut snapshot: RouterSnapshot) -> AnalysisReport {
    let all_remote_tlocs = snapshot.remote_tlocs.clone();
    let all_tunnels = snapshot.tunnels.clone();
    let all_omp_routes = snapshot.omp_routes.clone();

    if let Some(filter) = snapshot.peer_filter.clone() {
        let target_sys = snapshot
            .tunnels
            .iter()
            .find(|t| t.remote_system_ip == filter || t.remote_ip == filter)
            .and_then(|t| {
                if t.remote_system_ip.is_empty() {
                    None
                } else {
                    Some(t.remote_system_ip.clone())
                }
            })
            .or_else(|| {
                snapshot
                    .remote_tlocs
                    .iter()
                    .find(|rt| {
                        rt.system_ip == filter || rt.public_ip == filter || rt.private_ip == filter
                    })
                    .map(|rt| rt.system_ip.clone())
            })
            .unwrap_or_else(|| filter.clone());

        snapshot
            .tunnels
            .retain(|t| t.remote_system_ip == target_sys || t.remote_ip == filter);
        snapshot.remote_tlocs.retain(|rt| {
            rt.system_ip == target_sys || rt.public_ip == filter || rt.private_ip == filter
        });

        // Keep competing C,I,R winners for any (vpn_id, prefix) where the focused peer appears
        // so Section 4 shows why the peer is standby if another hub/peer owns the active route.
        let matching_prefixes: BTreeSet<(String, String)> = snapshot
            .omp_routes
            .iter()
            .filter(|r| {
                r.originator == target_sys
                    || r.next_hop_tloc_ip == target_sys
                    || r.from_peer == target_sys
            })
            .map(|r| (r.vpn_id.clone(), r.prefix.clone()))
            .collect();
        snapshot
            .omp_routes
            .retain(|r| matching_prefixes.contains(&(r.vpn_id.clone(), r.prefix.clone())));
    }

    let is_vsmart_mode = snapshot.source_mode == "ssh-vsmart";
    let peer_summaries = build_peer_summaries(&snapshot);

    // Map each (remote_system_ip, remote_color) to (cir_route_count, wins_default_route).
    let mut cir_by_target: BTreeMap<(String, String), (usize, bool)> = BTreeMap::new();
    let mut cir_peers: BTreeSet<String> = BTreeSet::new();
    for r in &snapshot.omp_routes {
        if r.from_peer == "0.0.0.0" || r.is_redistributed {
            continue;
        }
        let is_winner =
            r.is_chosen_installed || (is_vsmart_mode && is_route_chosen_resolved(&r.status));
        if is_winner {
            let p_sys = route_peer_key(r).to_string();
            cir_peers.insert(p_sys.clone());
            let entry = cir_by_target
                .entry((p_sys, r.color.clone()))
                .or_insert((0, false));
            entry.0 += 1;
            if r.prefix == "0.0.0.0/0" {
                entry.1 = true;
            }
        }
    }

    let up_local_colors: BTreeSet<String> = snapshot
        .tunnels
        .iter()
        .filter(|t| t.bfd_state.is_empty() || t.bfd_state == "up")
        .map(|t| t.local_color.clone())
        .collect();

    let best_local_tloc = snapshot
        .local_tlocs
        .iter()
        .filter(|l| up_local_colors.is_empty() || up_local_colors.contains(&l.color))
        .max_by_key(|l| l.preference)
        .cloned();

    let mut tunnel_verdicts = Vec::new();
    let mut active_primary_tunnels = Vec::new();

    for td in &snapshot.tunnels {
        let local_pref = lookup_tloc_pref(&snapshot.local_tlocs, None, &td.local_color, &td.local_ip);
        let remote_pref = lookup_tloc_pref(
            &snapshot.remote_tlocs,
            Some(&td.remote_system_ip),
            &td.remote_color,
            &td.remote_ip,
        );
        let max_remote_pref = snapshot
            .remote_tlocs
            .iter()
            .filter(|r| td.remote_system_ip.is_empty() || r.system_ip == td.remote_system_ip)
            .map(|r| r.preference)
            .max()
            .unwrap_or(remote_pref.unwrap_or(0));

        let lp = local_pref.unwrap_or(0);
        let rp = remote_pref.unwrap_or(0);
        let max_local_pref_for_target = snapshot
            .tunnels
            .iter()
            .filter(|other| {
                (other.bfd_state.is_empty() || other.bfd_state == "up")
                    && other.remote_system_ip == td.remote_system_ip
                    && other.remote_color == td.remote_color
            })
            .filter_map(|other| {
                lookup_tloc_pref(&snapshot.local_tlocs, None, &other.local_color, &other.local_ip)
            })
            .max()
            .unwrap_or(lp);

        let (cir_cnt, wins_default) = cir_by_target
            .get(&(td.remote_system_ip.clone(), td.remote_color.clone()))
            .copied()
            .unwrap_or((0, false));
        let peer_has_any_cir = cir_peers.contains(&td.remote_system_ip);
        let remote_is_winner = if peer_has_any_cir {
            cir_cnt > 0
        } else {
            rp >= max_remote_pref
        };
        let is_preferred_pair =
            (snapshot.local_tlocs.len() <= 1 || lp >= max_local_pref_for_target) && remote_is_winner;

        let recent_total = td.recent_tx_data_pkts + td.recent_rx_data_pkts;
        let is_down = !td.bfd_state.is_empty() && td.bfd_state != "up";
        let route_note = if cir_cnt > 0 {
            if wins_default {
                format!("; OMP C,I,R winner for {cir_cnt} route(s) including 0.0.0.0/0")
            } else {
                format!("; OMP C,I,R winner for {cir_cnt} route(s)")
            }
        } else {
            String::new()
        };

        let (verdict, reason) = if is_down {
            (
                VerdictKind::DownOrDegraded,
                format!(
                    "BFD state is '{}' (transitions={}); tunnel cannot forward traffic.",
                    td.bfd_state, td.transitions
                ),
            )
        } else if td.has_app_route && recent_total > 0 {
            if is_preferred_pair {
                active_primary_tunnels.push(format!(
                    "{} ({}) -> {} ({})",
                    td.local_color, td.local_ip, td.remote_color, td.remote_ip
                ));
                (
                    VerdictKind::ActivePrimary,
                    format!(
                        "Actively forwarding user traffic ({} TX / {} RX data pkts in last 3m; avg {:.1}B TX / {:.1}B RX). Selected because local {} Pref={} (max={}){route_note} (remote {} Pref={}).",
                        td.recent_tx_data_pkts,
                        td.recent_rx_data_pkts,
                        td.avg_tx_pkt_bytes,
                        td.avg_rx_pkt_bytes,
                        td.local_color,
                        lp,
                        max_local_pref_for_target,
                        td.remote_color,
                        rp
                    ),
                )
            } else {
                (
                    VerdictKind::BackupDataBleed,
                    format!(
                        "Non-primary tunnel is actively carrying {} TX / {} RX recent user packets despite higher-preference TLOCs being UP (local {} Pref={} vs max={}, remote {} Pref={} vs max={}). Check AAR policy or ECMP weights.",
                        td.recent_tx_data_pkts,
                        td.recent_rx_data_pkts,
                        td.local_color,
                        lp,
                        max_local_pref_for_target,
                        td.remote_color,
                        rp,
                        max_remote_pref
                    ),
                )
            }
        } else if !td.has_app_route && td.est_cum_data_pkts > 20 {
            if is_preferred_pair {
                active_primary_tunnels.push(format!(
                    "{} ({}) -> {} ({})",
                    td.local_color, td.local_ip, td.remote_color, td.remote_ip
                ));
                (
                    VerdictKind::ActivePrimary,
                    format!(
                        "Highest-preference TLOC pair (local {} Pref={}, remote {} Pref={}{route_note}) with ~{} cumulative data packets above BFD baseline (avg {:.1}B TX / {:.1}B RX).",
                        td.local_color, lp, td.remote_color, rp, td.est_cum_data_pkts, td.avg_tx_pkt_bytes, td.avg_rx_pkt_bytes
                    ),
                )
            } else {
                (
                    VerdictKind::HistoricalFailoverIdle,
                    format!(
                        "Lower-preference TLOC pair showing ~{} cumulative data packets above BFD baseline (avg {:.1}B TX / {:.1}B RX), likely from past failover/testing; run app-route stats to verify current 3m window is 0.",
                        td.est_cum_data_pkts, td.avg_tx_pkt_bytes, td.avg_rx_pkt_bytes
                    ),
                )
            }
        } else if is_preferred_pair && cir_cnt > 0 {
            active_primary_tunnels.push(format!(
                "{} ({}) -> {} ({})",
                td.local_color, td.local_ip, td.remote_color, td.remote_ip
            ));
            let omp_desc = if wins_default {
                format!("OMP C,I,R winner for {cir_cnt} route(s) including 0.0.0.0/0")
            } else {
                format!("OMP C,I,R winner for {cir_cnt} route(s)")
            };
            (
                VerdictKind::ActivePrimary,
                format!(
                    "Primary OMP forwarding tunnel ({omp_desc}; local {} Pref={} [max={}], remote {} Pref={}). Current payload counters show {} TX / {} RX (3m) and ~{} cumulative data pkts.",
                    td.local_color,
                    lp,
                    max_local_pref_for_target,
                    td.remote_color,
                    rp,
                    td.recent_tx_data_pkts,
                    td.recent_rx_data_pkts,
                    td.est_cum_data_pkts
                ),
            )
        } else if td.has_app_route && recent_total == 0 && td.est_cum_data_pkts > 20 {
            (
                VerdictKind::HistoricalFailoverIdle,
                format!(
                    "Currently 0 recent user packets in app-route stats (BFD-only right now), but cumulative tunnel stats show ~{} historical data packets (avg {:.1}B TX / {:.1}B RX) from earlier failover or preference changes.",
                    td.est_cum_data_pkts, td.avg_tx_pkt_bytes, td.avg_rx_pkt_bytes
                ),
            )
        } else {
            (
                VerdictKind::StandbyBfdOnly,
                format!(
                    "Standby path carrying 0 user data packets; cumulative counters ({:.1}B TX / {:.1}B RX avg) reflect ~118B BFD health/SLA probes only.",
                    td.avg_tx_pkt_bytes, td.avg_rx_pkt_bytes
                ),
            )
        };

        tunnel_verdicts.push(TunnelVerdict {
            local_ip: td.local_ip.clone(),
            remote_ip: td.remote_ip.clone(),
            remote_system_ip: td.remote_system_ip.clone(),
            local_color: td.local_color.clone(),
            remote_color: td.remote_color.clone(),
            verdict,
            recent_tx_data_pkts: td.recent_tx_data_pkts,
            recent_rx_data_pkts: td.recent_rx_data_pkts,
            avg_tx_pkt_bytes: td.avg_tx_pkt_bytes,
            avg_rx_pkt_bytes: td.avg_rx_pkt_bytes,
            est_cum_data_pkts: td.est_cum_data_pkts,
            bfd_state: if td.bfd_state.is_empty() {
                "unknown".to_string()
            } else {
                td.bfd_state.clone()
            },
            detect_multiplier: td.detect_multiplier,
            mean_latency_ms: td.mean_latency_ms,
            mean_jitter_ms: td.mean_jitter_ms,
            mean_loss_pct: td.mean_loss_pct,
            reason,
        });
    }

    // Group received OMP routes by (vpn_id, prefix)
    let mut route_groups: BTreeMap<(String, String), Vec<_>> = BTreeMap::new();
    for r in &snapshot.omp_routes {
        if r.from_peer == "0.0.0.0" || r.is_redistributed {
            continue;
        }
        route_groups
            .entry((r.vpn_id.clone(), r.prefix.clone()))
            .or_default()
            .push(r.clone());
    }

    let mut route_explanations = Vec::new();
    for ((vpn_id, prefix), entries) in route_groups {
        let winners: Vec<_> = entries
            .iter()
            .filter(|e| {
                e.is_chosen_installed
                    || (is_vsmart_mode && is_route_chosen_resolved(&e.status))
            })
            .collect();
        let backups: Vec<_> = entries
            .iter()
            .filter(|e| {
                !(e.is_chosen_installed
                    || (is_vsmart_mode && is_route_chosen_resolved(&e.status)))
            })
            .collect();

        let winning_color = winners
            .iter()
            .map(|w| w.color.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let winning_originator = winners
            .first()
            .map(|w| w.originator.clone())
            .unwrap_or_else(|| entries.first().map(|e| e.originator.clone()).unwrap_or_default());

        let backup_paths: Vec<String> = backups
            .iter()
            .map(|b| {
                let b_pref = lookup_tloc_pref(&all_remote_tlocs, Some(&b.originator), &b.color, "");
                match b_pref {
                    Some(p) => format!("{} via {} (Pref {}, status={})", b.color, b.originator, p, b.status),
                    None => format!("{} via {} (status={})", b.color, b.originator, b.status),
                }
            })
            .collect();

        let (local_egress_color, local_egress_ip, local_pref_val) = match winners.first() {
            Some(w) => resolve_local_egress(
                &all_tunnels,
                &snapshot.local_tlocs,
                best_local_tloc.as_ref(),
                &w.originator,
                &w.color,
            ),
            None => match &best_local_tloc {
                Some(lt) => (lt.color.clone(), lt.public_ip.clone(), Some(lt.preference)),
                None => ("unknown".to_string(), String::new(), None),
            },
        };

        let win_remote_pref = winners
            .first()
            .and_then(|w| lookup_tloc_pref(&all_remote_tlocs, Some(&w.originator), &w.color, ""));

        let explanation = match (winners.first(), win_remote_pref, local_pref_val) {
            (Some(w), Some(rp), Some(lp)) => format!(
                "Installed via remote TLOC '{}' (peer {}, Pref={}) paired with local egress '{}' (Pref={}); {} backup path(s) held in OMP as R.",
                w.color,
                w.originator,
                rp,
                local_egress_color,
                lp,
                backups.len()
            ),
            (Some(w), _, _) => format!(
                "Installed via remote TLOC '{}' (peer {}) via local egress '{}'; {} standby path(s) held as R.",
                w.color,
                w.originator,
                local_egress_color,
                backups.len()
            ),
            (None, _, _) => "No C,I,R installed path found for this prefix.".to_string(),
        };

        route_explanations.push(RouteExplanation {
            vpn_id,
            prefix,
            winning_color: if winning_color.is_empty() {
                "none".to_string()
            } else {
                winning_color
            },
            winning_originator,
            backup_paths,
            local_egress_color,
            local_egress_ip,
            explanation,
        });
    }

    tunnel_verdicts.sort_by(|a, b| {
        verdict_rank(&a.verdict)
            .cmp(&verdict_rank(&b.verdict))
            .then_with(|| {
                Reverse(a.recent_tx_data_pkts + a.recent_rx_data_pkts)
                    .cmp(&Reverse(b.recent_tx_data_pkts + b.recent_rx_data_pkts))
            })
            .then_with(|| Reverse(a.est_cum_data_pkts).cmp(&Reverse(b.est_cum_data_pkts)))
            .then_with(|| a.remote_system_ip.cmp(&b.remote_system_ip))
            .then_with(|| a.local_color.cmp(&b.local_color))
            .then_with(|| a.remote_color.cmp(&b.remote_color))
    });

    let findings = collect_drift_findings(&snapshot, &tunnel_verdicts);
    let quad_zero = build_quad_zero_verdict(
        &snapshot,
        &all_omp_routes,
        &all_remote_tlocs,
        &all_tunnels,
        best_local_tloc.as_ref(),
        &tunnel_verdicts,
        is_vsmart_mode,
    );

    AnalysisReport {
        snapshot,
        quad_zero,
        active_primary_tunnels,
        peer_summaries,
        tunnel_verdicts,
        route_explanations,
        findings,
    }
}

fn collect_drift_findings(
    snapshot: &RouterSnapshot,
    verdicts: &[TunnelVerdict],
) -> Vec<DriftFinding> {
    let mut findings = Vec::new();

    // 1. Backup / metered transport data bleed
    for tv in verdicts {
        if tv.verdict == VerdictKind::BackupDataBleed {
            findings.push(DriftFinding {
                severity: Severity::Alert,
                code: "BACKUP_TRANSPORT_DATA_BLEED".to_string(),
                title: format!(
                    "Backup tunnel {} ({}) -> {} ({}) is carrying live user traffic",
                    tv.local_color, tv.local_ip, tv.remote_color, tv.remote_ip
                ),
                explanation: format!(
                    "Detected {} TX / {} RX recent data packets on a lower-preference transport while a higher-preference link is healthy.",
                    tv.recent_tx_data_pkts, tv.recent_rx_data_pkts
                ),
                remediation: "Check centralized AAR policy preferred-color/SLA thresholds, local TLOC preference values, and restrict flags.".to_string(),
            });
        }
    }

    // 2. Equal TLOC preference causing unintended ECMP
    if snapshot.local_tlocs.len() > 1 {
        let mut by_pref: BTreeMap<u32, Vec<&TlocEntry>> = BTreeMap::new();
        for lt in &snapshot.local_tlocs {
            by_pref.entry(lt.preference).or_default().push(lt);
        }
        for (pref, group) in by_pref {
            if group.len() > 1 {
                let colors: Vec<&str> = group.iter().map(|g| g.color.as_str()).collect();
                findings.push(DriftFinding {
                    severity: Severity::Warn,
                    code: "EQUAL_TLOC_PREFERENCE_ECMP".to_string(),
                    title: format!(
                        "Multiple local TLOCs share identical preference={} ({})",
                        pref,
                        colors.join(", ")
                    ),
                    explanation: "Identical TLOC preferences enable per-flow ECMP across all tied WAN circuits. If one circuit is metered (e.g. Starlink/LTE), roughly half of user flows will traverse it.".to_string(),
                    remediation: "Assign distinct TLOC preferences (e.g. 200 on primary Campus/DIA, 100 on backup Starlink/LTE).".to_string(),
                });
            }
        }
    }

    // 3. SLA class index = 0 only (missing vSmart AAR SLA policy)
    let app_route_tunnels: Vec<_> = snapshot
        .tunnels
        .iter()
        .filter(|t| t.has_app_route && !t.sla_class_index.is_empty())
        .collect();
    if !app_route_tunnels.is_empty()
        && app_route_tunnels.iter().all(|t| t.sla_class_index.trim() == "0")
    {
        findings.push(DriftFinding {
            severity: Severity::Warn,
            code: "SLA_CLASS_INDEX_ZERO_ONLY".to_string(),
            title: "Only built-in SLA class 0 (__all_tunnels__) is active; no custom vSmart AAR SLA policy matched".to_string(),
            explanation: format!(
                "All {} app-route tunnel entries report sla-class-index=0. Verify that vSmart centralized policy site-lists include site-id '{}'.",
                app_route_tunnels.len(),
                if snapshot.site_id.is_empty() { "<unknown>" } else { &snapshot.site_id }
            ),
            remediation: "Expand vSmart site-list ranges (e.g. ALL_SITES / BRANCH_SITES) to cover this router's site-id and re-activate the centralized policy.".to_string(),
        });
    }

    // 4. Asymmetric BFD detect-multipliers across UP tunnels
    let mults: BTreeSet<u32> = snapshot
        .tunnels
        .iter()
        .filter(|t| t.bfd_state == "up" && t.detect_multiplier > 0)
        .map(|t| t.detect_multiplier)
        .collect();
    if mults.len() > 1 {
        let min_m = *mults.iter().min().unwrap_or(&0);
        let max_m = *mults.iter().max().unwrap_or(&0);
        findings.push(DriftFinding {
            severity: Severity::Warn,
            code: "ASYMMETRIC_BFD_MULTIPLIERS".to_string(),
            title: format!(
                "Asymmetric BFD detect-multipliers across active tunnels ({} vs {})",
                min_m, max_m
            ),
            explanation: format!(
                "Tunnels with multiplier={} detect loss in ~{}s while cross-color/backup tunnels with multiplier={} remain UP for ~{}s, delaying symmetric return-path OMP convergence during a primary WAN blackout.",
                min_m, min_m, max_m, max_m
            ),
            remediation: "Align `sdwan bfd color <color> multiplier <N>` across all active transport colors in your Configuration Group.".to_string(),
        });
    }

    // 5. Remote or local secondary TLOC relying on implicit default preference 0
    let mut remote_by_sys: BTreeMap<&str, Vec<&TlocEntry>> = BTreeMap::new();
    for rt in &snapshot.remote_tlocs {
        remote_by_sys.entry(rt.system_ip.as_str()).or_default().push(rt);
    }
    for (sys, list) in remote_by_sys {
        if list.len() > 1 && list.iter().any(|t| t.preference == 0) {
            let zero_colors: BTreeSet<&str> = list
                .iter()
                .filter(|t| t.preference == 0)
                .map(|t| t.color.as_str())
                .collect();
            let zero_vec: Vec<&str> = zero_colors.into_iter().collect();
            findings.push(DriftFinding {
                severity: Severity::Info,
                code: "REMOTE_TLOC_PREF_UNSET_ZERO".to_string(),
                title: format!(
                    "Peer {} has TLOC(s) at implicit default preference=0 ({})",
                    sys,
                    zero_vec.join(", ")
                ),
                explanation: "Unconfigured TLOC preference defaults to 0. Explicit preference values (e.g., 200 primary / 100 secondary) make multi-hub tie-breaking predictable.".to_string(),
                remediation: "Bind an explicit preference variable on secondary transport interfaces in the peer Configuration Group.".to_string(),
            });
        }
    }

    // 6. Down or flapped BFD sessions
    for t in &snapshot.tunnels {
        if !t.bfd_state.is_empty() && t.bfd_state != "up" {
            findings.push(DriftFinding {
                severity: Severity::Alert,
                code: "BFD_SESSION_DOWN".to_string(),
                title: format!(
                    "BFD session DOWN: {} ({}) -> {} ({})",
                    t.local_color, t.local_ip, t.remote_color, t.remote_ip
                ),
                explanation: format!(
                    "Session state is '{}' with {} recorded transition(s).",
                    t.bfd_state, t.transitions
                ),
                remediation: "Check underlay IP reachability, firewall UDP 12346-13146, and interface link status.".to_string(),
            });
        } else if t.transitions > 0 {
            findings.push(DriftFinding {
                severity: Severity::Info,
                code: "BFD_SESSION_FLAPPED".to_string(),
                title: format!(
                    "Historical BFD flap on {} ({}) -> {} ({})",
                    t.local_color, t.local_ip, t.remote_color, t.remote_ip
                ),
                explanation: format!(
                    "Session is currently UP (uptime {}) with {} past state transition(s).",
                    if t.uptime.is_empty() { "-" } else { &t.uptime },
                    t.transitions
                ),
                remediation: "Verify whether the transition corresponds to an expected maintenance/failover test.".to_string(),
            });
        }
    }

    findings
}

fn lookup_tloc_pref(
    tlocs: &[TlocEntry],
    sys_ip: Option<&str>,
    color: &str,
    transport_ip: &str,
) -> Option<u32> {
    tlocs
        .iter()
        .find(|t| {
            let sys_ok = match sys_ip {
                Some(s) if !s.is_empty() => t.system_ip == s,
                _ => true,
            };
            let color_ok = !color.is_empty() && t.color == color;
            let ip_ok = !transport_ip.is_empty()
                && (t.public_ip == transport_ip || t.private_ip == transport_ip);
            sys_ok && (color_ok || ip_ok)
        })
        .map(|t| t.preference)
}

fn build_quad_zero_verdict(
    snapshot: &RouterSnapshot,
    all_omp_routes: &[crate::models::OmpRouteEntry],
    all_remote_tlocs: &[TlocEntry],
    all_tunnels: &[crate::models::TunnelDiag],
    best_local_tloc: Option<&TlocEntry>,
    tunnel_verdicts: &[TunnelVerdict],
    is_vsmart_mode: bool,
) -> Option<crate::models::QuadZeroVerdict> {
    let mut target_vpn = snapshot
        .target_vpn
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default()
        .to_string();

    let all_q0: Vec<&crate::models::OmpRouteEntry> = all_omp_routes
        .iter()
        .filter(|r| {
            (r.prefix == "0.0.0.0/0" || r.prefix == "0.0.0.0")
                && !r.is_redistributed
                && r.from_peer != "0.0.0.0"
        })
        .collect();

    if target_vpn.is_empty() {
        target_vpn = all_q0
            .iter()
            .find(|r| r.is_chosen_installed || (is_vsmart_mode && is_route_chosen_resolved(&r.status)))
            .or_else(|| all_q0.first())
            .map(|r| r.vpn_id.clone())
            .or_else(|| snapshot.discovered_vpns.first().cloned())
            .unwrap_or_default();
    }

    let scoped_q0: Vec<&crate::models::OmpRouteEntry> = all_q0
        .iter()
        .copied()
        .filter(|r| target_vpn.is_empty() || r.vpn_id == target_vpn)
        .collect();

    let winning_route = scoped_q0
        .iter()
        .copied()
        .find(|r| r.is_chosen_installed || (is_vsmart_mode && is_route_chosen_resolved(&r.status)))
        .or_else(|| scoped_q0.first().copied());

    let mut winner_system_ip = winning_route
        .map(|r| r.originator.trim().to_string())
        .filter(|ip| !ip.is_empty() && ip != "0.0.0.0")
        .unwrap_or_default();

    let matching_hop = if !winner_system_ip.is_empty() {
        snapshot
            .service_paths
            .iter()
            .find(|h| h.remote_system_ip == winner_system_ip)
            .or_else(|| snapshot.service_paths.first())
    } else {
        snapshot.service_paths.first()
    };

    if winner_system_ip.is_empty() {
        if let Some(hop) = matching_hop {
            winner_system_ip = hop.remote_system_ip.clone();
        }
    }

    if winner_system_ip.is_empty() {
        return None;
    }

    let (local_color, local_ip, remote_color, remote_ip, via_service_path) =
        if let Some(hop) = matching_hop {
            (
                hop.local_color.clone(),
                hop.local_ip.clone(),
                hop.remote_color.clone(),
                hop.remote_ip.clone(),
                true,
            )
        } else {
            let best_tv = tunnel_verdicts
                .iter()
                .filter(|tv| tv.remote_system_ip == winner_system_ip)
                .max_by_key(|tv| {
                    (
                        u8::from(tv.verdict == VerdictKind::ActivePrimary),
                        u8::from(tv.bfd_state == "up"),
                        tv.recent_tx_data_pkts + tv.recent_rx_data_pkts,
                        tv.est_cum_data_pkts,
                    )
                });
            if let Some(tv) = best_tv {
                (
                    tv.local_color.clone(),
                    tv.local_ip.clone(),
                    tv.remote_color.clone(),
                    tv.remote_ip.clone(),
                    false,
                )
            } else {
                let best_td = all_tunnels
                    .iter()
                    .filter(|td| td.remote_system_ip == winner_system_ip)
                    .max_by_key(|td| {
                        (
                            u8::from(td.bfd_state == "up"),
                            td.recent_tx_data_pkts + td.recent_rx_data_pkts,
                            lookup_tloc_pref(&snapshot.local_tlocs, None, &td.local_color, &td.local_ip)
                                .unwrap_or(0),
                            td.est_cum_data_pkts,
                        )
                    });
                if let Some(td) = best_td {
                    (
                        td.local_color.clone(),
                        td.local_ip.clone(),
                        td.remote_color.clone(),
                        td.remote_ip.clone(),
                        false,
                    )
                } else {
                    let route_color = winning_route.map(|r| r.color.as_str()).unwrap_or("");
                    let (lc, lip, _) = resolve_local_egress(
                        all_tunnels,
                        &snapshot.local_tlocs,
                        best_local_tloc,
                        &winner_system_ip,
                        route_color,
                    );
                    (
                        lc,
                        lip,
                        if route_color.is_empty() || route_color == "rib" {
                            "unknown".to_string()
                        } else {
                            route_color.to_string()
                        },
                        String::new(),
                        false,
                    )
                }
            }
        };

    let winner_site_id = all_tunnels
        .iter()
        .find(|t| t.remote_system_ip == winner_system_ip && !t.remote_site_id.is_empty())
        .map(|t| t.remote_site_id.clone())
        .or_else(|| {
            all_remote_tlocs
                .iter()
                .find(|rt| rt.system_ip == winner_system_ip && !rt.site_id.is_empty())
                .map(|rt| rt.site_id.clone())
        })
        .unwrap_or_default();

    let local_tloc_match = snapshot.local_tlocs.iter().find(|lt| {
        (!local_color.is_empty() && lt.color == local_color)
            || (!local_ip.is_empty()
                && (lt.public_ip == local_ip || lt.private_ip == local_ip))
    });
    let local_pref = local_tloc_match.map(|lt| lt.preference);
    let local_interface = local_tloc_match
        .and_then(|lt| lt.interface.clone())
        .unwrap_or_default();
    let remote_pref =
        lookup_tloc_pref(all_remote_tlocs, Some(&winner_system_ip), &remote_color, &remote_ip);

    let mut reasons = Vec::new();
    let vpn_label = if target_vpn.is_empty() {
        "default".to_string()
    } else {
        format!("VPN {target_vpn}")
    };

    if via_service_path && snapshot.service_paths.len() > 1 {
        let hop_colors: Vec<String> = snapshot
            .service_paths
            .iter()
            .map(|h| format!("{}->{}", h.local_color, h.remote_color))
            .collect();
        reasons.push(format!(
            "{vpn_label} RIB installs 0.0.0.0/0 via {winner_system_ip}; QFP service-path shows {} ECMP IPsec hops ({})",
            snapshot.service_paths.len(),
            hop_colors.join(", ")
        ));
    } else if via_service_path {
        reasons.push(format!(
            "{vpn_label} RIB installs 0.0.0.0/0 via {winner_system_ip}, and QFP hardware service-path selects IPsec {local_color} -> {remote_color}"
        ));
    } else {
        reasons.push(format!(
            "{vpn_label} selects peer {winner_system_ip} for 0.0.0.0/0 via {local_color} -> {remote_color}"
        ));
    }

    if let Some(lp) = local_pref {
        let iface_prefix = if local_interface.is_empty() {
            String::new()
        } else {
            format!("{local_interface} ")
        };
        let others: Vec<&TlocEntry> = snapshot
            .local_tlocs
            .iter()
            .filter(|lt| lt.color != local_color)
            .collect();
        let higher: Vec<String> = others
            .iter()
            .filter(|lt| lt.preference > lp)
            .map(|lt| format!("{} Pref={}", lt.color, lt.preference))
            .collect();
        let tied: Vec<String> = others
            .iter()
            .filter(|lt| lt.preference == lp)
            .map(|lt| lt.color.clone())
            .collect();
        let lower: Vec<String> = others
            .iter()
            .filter(|lt| lt.preference < lp)
            .map(|lt| format!("{} Pref={}", lt.color, lt.preference))
            .collect();

        if !higher.is_empty() {
            reasons.push(format!(
                "local {iface_prefix}({local_color}) Pref={lp} is active because higher-preference transport ({}) is down, restricted, or deprioritized by policy",
                higher.join(", ")
            ));
        } else if !lower.is_empty() && tied.is_empty() {
            reasons.push(format!(
                "local {iface_prefix}({local_color}) has highest TLOC Pref={lp} (beating {})",
                lower.join(", ")
            ));
        } else if !tied.is_empty() {
            reasons.push(format!(
                "local {iface_prefix}({local_color}) shares TLOC Pref={lp} with {} (ECMP-eligible)",
                tied.join(", ")
            ));
        } else {
            reasons.push(format!("local {iface_prefix}({local_color}) TLOC Pref={lp}"));
        }
    }

    if let Some(rp) = remote_pref {
        reasons.push(format!("remote {remote_color} TLOC Pref={rp}"));
    }

    if let Some(tv) = tunnel_verdicts.iter().find(|tv| {
        tv.remote_system_ip == winner_system_ip
            && (local_color.is_empty() || tv.local_color == local_color)
            && (remote_color.is_empty() || remote_color == "unknown" || tv.remote_color == remote_color)
    }) {
        let mut health = format!("BFD {}", tv.bfd_state);
        if tv.detect_multiplier > 0 {
            health.push_str(&format!(" mult={}", tv.detect_multiplier));
        }
        if tv.mean_latency_ms > 0 {
            health.push_str(&format!(", {}ms latency", tv.mean_latency_ms));
        }
        let recent = tv.recent_tx_data_pkts + tv.recent_rx_data_pkts;
        if recent > 0 {
            health.push_str(&format!(
                ", carrying {}/{} recent TX/RX data pkts",
                tv.recent_tx_data_pkts, tv.recent_rx_data_pkts
            ));
        } else if tv.est_cum_data_pkts > 0 {
            health.push_str(&format!(
                ", ~{} est. cumulative data pkts",
                tv.est_cum_data_pkts
            ));
        }
        reasons.push(health);
    }

    let standby_peers: BTreeSet<String> = scoped_q0
        .iter()
        .map(|r| r.originator.trim())
        .filter(|ip| !ip.is_empty() && *ip != winner_system_ip && *ip != "0.0.0.0")
        .map(ToString::to_string)
        .collect();
    if !standby_peers.is_empty() {
        let peers_list: Vec<String> = standby_peers.into_iter().collect();
        reasons.push(format!("standby 0.0.0.0/0 peer(s): {}", peers_list.join(", ")));
    }

    Some(crate::models::QuadZeroVerdict {
        target_vpn,
        winner_system_ip,
        winner_site_id,
        local_color,
        local_ip,
        local_interface,
        local_pref,
        remote_color,
        remote_ip,
        remote_pref,
        via_service_path,
        why: reasons.join("; "),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::{
        build_snapshot_from_text, expand_iosxe_interface_name, parse_ip_route_quad_zero,
        parse_service_path_output, resolve_vrf_lan_interface_and_ip,
    };

    #[test]
    fn parses_rib_quad_zero_and_qfp_service_path_without_omp_routes() {
        let raw = r#"
site101-kit1# show sdwan system status
System IP:              10.101.1.1
Site ID:                101
host-name               site101-kit1
site101-kit1# show vrf
  Name                             Default RD            Protocols   Interfaces
  1000                             <not set>             ipv4        Gi3
  Mgmt-intf                        <not set>             ipv4,ipv6   Gi4
site101-kit1# show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet1       10.10.1.21      YES other  up                    up
GigabitEthernet2       172.16.10.21    YES other  up                    up
GigabitEthernet3       10.101.1.1      YES other  up                    up
site101-kit1# show sdwan running-config sdwan
sdwan
 interface GigabitEthernet1
  tunnel-interface
   encapsulation ipsec preference 200 weight 1
   color biz-internet
  exit
 exit
 interface GigabitEthernet2
  tunnel-interface
   encapsulation ipsec preference 100 weight 1
   color public-internet
  exit
 exit
!
site101-kit1# show ip route vrf 1000 0.0.0.0 0.0.0.0
Routing Table: 1000
Routing entry for 0.0.0.0/0, supernet
  Known via "omp", distance 251, metric 0, type intra area
  Last update from 10.255.1.1 on Sdwan-system-intf, 1w2d ago
  Routing Descriptor Blocks:
  * 10.255.1.1 (default), from 10.255.1.1, 1w2d ago, via Sdwan-system-intf
site101-kit1# show sdwan policy service-path vpn 1000 interface GigabitEthernet3 source-ip 10.101.1.1 dest-ip 8.8.8.8 protocol 6 all
Number of possible next hops: 1
Next Hop: IPsec
  Source: 10.10.1.21 12366 Destination: 172.16.1.21 12346 Local Color: biz-internet Remote Color: biz-internet Remote System IP: 10.255.1.1
site101-kit1# show sdwan bfd sessions
                                      SOURCE TLOC      REMOTE TLOC                                                      DETECT
SYSTEM IP        SITE ID  STATE       COLOR            COLOR            SOURCE IP        DST PUBLIC IP    DST PORT ENCAP MULTIPLIER TX INT UPTIME          TRANSITIONS
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
10.255.1.1       1        up          biz-internet     biz-internet     10.10.1.21       172.16.1.21      12346    ipsec 7          1000   1w2d:00:00:00   0
10.255.1.1       1        up          public-internet  public-internet  172.16.10.21     172.16.1.22      12346    ipsec 7          1000   1w2d:00:00:00   0
site101-kit1# show sdwan app-route stats remote-system-ip 10.255.1.1
app-route stats 10.10.1.21 172.16.1.21
 remote-system-ip 10.255.1.1
 local-color biz-internet
 remote-color biz-internet
 mean-loss 0
 mean-latency 12
 mean-jitter 1
 tx-pkts 420
 rx-pkts 410
 site-id 1
 sla-class-index 1
"#;
        assert_eq!(expand_iosxe_interface_name("Gi3"), "GigabitEthernet3");
        assert_eq!(
            resolve_vrf_lan_interface_and_ip(raw, "1000"),
            Some(("GigabitEthernet3".to_string(), "10.101.1.1".to_string()))
        );
        let rib_q0 = parse_ip_route_quad_zero(raw, "1000");
        assert_eq!(rib_q0.len(), 1);
        assert_eq!(rib_q0[0].originator, "10.255.1.1");
        assert!(rib_q0[0].is_chosen_installed);

        let hops = parse_service_path_output(raw);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].local_color, "biz-internet");
        assert_eq!(hops[0].remote_color, "biz-internet");
        assert_eq!(hops[0].remote_system_ip, "10.255.1.1");

        let mut snap = build_snapshot_from_text("site101-kit1", "10.101.1.1", "101", "test", raw);
        snap.target_vpn = Some("1000".to_string());
        let report = explain_snapshot(snap);
        let q0 = report.quad_zero.expect("quad_zero verdict must be present");
        assert_eq!(q0.target_vpn, "1000");
        assert_eq!(q0.winner_system_ip, "10.255.1.1");
        assert_eq!(q0.winner_site_id, "1");
        assert_eq!(q0.local_color, "biz-internet");
        assert_eq!(q0.remote_color, "biz-internet");
        assert_eq!(q0.local_pref, Some(200));
        assert!(q0.via_service_path);
        assert!(q0.why.contains("Pref=200"));
        assert!(q0.why.contains("10.255.1.1"));
    }

    const SAMPLE_CAPTURE: &str = r#"
site101-kit1# show sdwan running-config sdwan
sdwan
 interface GigabitEthernet1
  tunnel-interface
   encapsulation ipsec preference 200 weight 1
   color biz-internet
  exit
 exit
 interface GigabitEthernet2
  tunnel-interface
   encapsulation ipsec preference 100 weight 1
   color public-internet
  exit
 exit
!
bfd color biz-internet
bfd color lte

site101-kit1# show sdwan bfd sessions
10.10.1.21 172.16.1.21 ipsec 12346 12346 10.255.1.1 10 up 3 1000 0:00:16:34 1 biz-internet biz-internet
10.10.1.21 172.16.2.21 ipsec 12346 12346 10.255.1.1 10 up 7 1000 0:00:16:35 1 biz-internet public-internet
10.10.2.21 172.16.1.21 ipsec 12346 12346 10.255.1.1 10 up 7 1000 0:00:17:06 0 public-internet biz-internet
10.10.2.21 172.16.2.21 ipsec 12346 12346 10.255.1.1 10 up 7 1000 0:00:17:05 0 public-internet public-internet

site101-kit1# show sdwan tunnel statistics
tunnel stats ipsec 10.10.1.21 172.16.1.21 12346 12346
 system-ip 10.255.1.1
 local-color biz-internet
 remote-color biz-internet
 tunnel-mtu 1218
 tx_pkts 10355
 tx_octets 1421803
 rx_pkts 9747
 rx_octets 1595057
 tcp-mss-adjust 1138
tunnel stats ipsec 10.10.1.21 172.16.2.21 12346 12346
 system-ip 10.255.1.1
 local-color biz-internet
 remote-color public-internet
 tunnel-mtu 1218
 tx_pkts 8029
 tx_octets 955789
 rx_pkts 7867
 rx_octets 926301
 tcp-mss-adjust 1138
tunnel stats ipsec 10.10.2.21 172.16.1.21 12346 12346
 system-ip 10.255.1.1
 local-color public-internet
 remote-color biz-internet
 tunnel-mtu 1218
 tx_pkts 9184
 tx_octets 1207731
 rx_pkts 8840
 rx_octets 1304647
 tcp-mss-adjust 1138
tunnel stats ipsec 10.10.2.21 172.16.2.21 12346 12346
 system-ip 10.255.1.1
 local-color public-internet
 remote-color public-internet
 tunnel-mtu 1218
 tx_pkts 8073
 tx_octets 960145
 rx_pkts 7964
 rx_octets 937570
 tcp-mss-adjust 1138

site101-kit1# show sdwan app-route stats
app-route statistics 10.10.1.21 172.16.1.21 ipsec 12346 12346
 remote-system-ip 10.255.1.1
 local-color biz-internet
 remote-color biz-internet
 sla-class-index 0
 mean-loss 0.000
 mean-latency 35
 mean-jitter 3
 interval 0
  total-packets 65
  tx-data-pkts 6
  rx-data-pkts 6
 interval 1
  total-packets 66
  tx-data-pkts 42
  rx-data-pkts 31
 interval 2
  total-packets 67
  tx-data-pkts 6
  rx-data-pkts 6
app-route statistics 10.10.1.21 172.16.2.21 ipsec 12346 12346
 remote-system-ip 10.255.1.1
 local-color biz-internet
 remote-color public-internet
 sla-class-index 0
 mean-loss 0.000
 mean-latency 35
 mean-jitter 3
 interval 0
  total-packets 67
  tx-data-pkts 0
  rx-data-pkts 0
app-route statistics 10.10.2.21 172.16.1.21 ipsec 12346 12346
 remote-system-ip 10.255.1.1
 local-color public-internet
 remote-color biz-internet
 sla-class-index 0
 mean-loss 0.000
 mean-latency 35
 mean-jitter 3
 interval 0
  total-packets 66
  tx-data-pkts 0
  rx-data-pkts 0
app-route statistics 10.10.2.21 172.16.2.21 ipsec 12346 12346
 remote-system-ip 10.255.1.1
 local-color public-internet
 remote-color public-internet
 sla-class-index 0
 mean-loss 0.000
 mean-latency 35
 mean-jitter 3
 interval 0
  total-packets 66
  tx-data-pkts 0
  rx-data-pkts 0

site101-kit1# show sdwan omp tlocs
---------------------------------------------------
tloc entries for 10.255.1.1
                 biz-internet
                 ipsec
---------------------------------------------------
            RECEIVED FROM:
peer            10.255.0.3
status          C,I,R
    Attributes:
     public-ip         172.16.1.21
     private-ip        172.16.1.21
     site-id           10
     preference        200
     weight            1
---------------------------------------------------
tloc entries for 10.255.1.1
                 public-internet
                 ipsec
---------------------------------------------------
            RECEIVED FROM:
peer            10.255.0.3
status          C,I,R
    Attributes:
     public-ip         172.16.2.21
     private-ip        172.16.2.21
     site-id           10
     preference        0
     weight            1

site101-kit1# show sdwan omp routes vpn 1000 detail
---------------------------------------------------
omp route entries for vpn 1000 route 10.10.10.0/24
---------------------------------------------------
            RECEIVED FROM:
peer            10.255.0.3
status          C I R
    Attributes:
     originator       10.255.1.1
     tloc             10.255.1.1, biz-internet, ipsec
            RECEIVED FROM:
peer            10.255.0.3
status          R
    Attributes:
     originator       10.255.1.1
     tloc             10.255.1.1, public-internet, ipsec
"#;

    #[test]
    fn explains_live_site101_capture_verdicts_and_drifts() {
        let snap = build_snapshot_from_text("site101-kit1", "10.255.1.11", "1011", "file", SAMPLE_CAPTURE);
        let report = explain_snapshot(snap);

        assert_eq!(report.tunnel_verdicts.len(), 4);

        let t_primary = report
            .tunnel_verdicts
            .iter()
            .find(|v| v.local_ip == "10.10.1.21" && v.remote_ip == "172.16.1.21")
            .expect("primary tunnel present");
        assert_eq!(t_primary.verdict, VerdictKind::ActivePrimary);
        assert_eq!(t_primary.recent_tx_data_pkts, 54);
        assert_eq!(t_primary.recent_rx_data_pkts, 43);
        assert!(t_primary.est_cum_data_pkts > 2000);

        let t_hist = report
            .tunnel_verdicts
            .iter()
            .find(|v| v.local_ip == "10.10.2.21" && v.remote_ip == "172.16.1.21")
            .expect("historical failover tunnel present");
        assert_eq!(t_hist.verdict, VerdictKind::HistoricalFailoverIdle);
        assert_eq!(t_hist.recent_tx_data_pkts, 0);
        assert!(t_hist.est_cum_data_pkts > 1000);

        let t_standby1 = report
            .tunnel_verdicts
            .iter()
            .find(|v| v.local_ip == "10.10.1.21" && v.remote_ip == "172.16.2.21")
            .expect("standby 1 present");
        assert_eq!(t_standby1.verdict, VerdictKind::StandbyBfdOnly);

        let t_standby2 = report
            .tunnel_verdicts
            .iter()
            .find(|v| v.local_ip == "10.10.2.21" && v.remote_ip == "172.16.2.21")
            .expect("standby 2 present");
        assert_eq!(t_standby2.verdict, VerdictKind::StandbyBfdOnly);

        let codes: Vec<&str> = report.findings.iter().map(|f| f.code.as_str()).collect();
        assert!(codes.contains(&"SLA_CLASS_INDEX_ZERO_ONLY"));
        assert!(codes.contains(&"ASYMMETRIC_BFD_MULTIPLIERS"));
        assert!(codes.contains(&"REMOTE_TLOC_PREF_UNSET_ZERO"));
        assert!(!codes.contains(&"BACKUP_TRANSPORT_DATA_BLEED"));

        assert_eq!(report.route_explanations.len(), 1);
        assert_eq!(report.route_explanations[0].winning_color, "biz-internet");
        assert_eq!(report.route_explanations[0].local_egress_color, "biz-internet");
    }

    #[test]
    fn flags_backup_data_bleed_and_equal_ecmp_preferences() {
        let bleed_capture = r#"
site101-kit1# show sdwan running-config sdwan
sdwan
 interface GigabitEthernet1
  tunnel-interface
   encapsulation ipsec preference 200 weight 1
   color biz-internet
  exit
 exit
 interface GigabitEthernet2
  tunnel-interface
   encapsulation ipsec preference 200 weight 1
   color lte
  exit
 exit

site101-kit1# show sdwan bfd sessions
10.10.1.21 172.16.1.21 ipsec 12346 12346 10.255.1.1 10 up 3 1000 0:00:10:00 0 biz-internet biz-internet
10.10.2.21 172.16.1.21 ipsec 12346 12346 10.255.1.1 10 up 3 1000 0:00:10:00 0 lte biz-internet

site101-kit1# show sdwan app-route stats
app-route statistics 10.10.1.21 172.16.1.21 ipsec 12346 12346
 remote-system-ip 10.255.1.1
 local-color biz-internet
 remote-color biz-internet
 sla-class-index 0, 1
 interval 0
  total-packets 65
  tx-data-pkts 25
  rx-data-pkts 25
app-route statistics 10.10.2.21 172.16.1.21 ipsec 12346 12346
 remote-system-ip 10.255.1.1
 local-color lte
 remote-color biz-internet
 sla-class-index 0, 1
 interval 0
  total-packets 65
  tx-data-pkts 18
  rx-data-pkts 19
"#;
        let snap = build_snapshot_from_text("site101-kit1", "10.255.1.11", "1011", "file", bleed_capture);
        let report = explain_snapshot(snap);
        let codes: Vec<&str> = report.findings.iter().map(|f| f.code.as_str()).collect();
        assert!(codes.contains(&"EQUAL_TLOC_PREFERENCE_ECMP"));
        assert!(!codes.contains(&"SLA_CLASS_INDEX_ZERO_ONLY"));
    }

    #[test]
    fn parses_iosxe_17_ssh_formats_without_vmanage() {
        let iosxe_ssh_capture = r#"
site101-kit1#terminal length 0
site101-kit1#show sdwan control local-properties
personality                       vedge
site-id                           1011
system-ip                         10.255.1.11
site101-kit1#show sdwan running-config sdwan
sdwan
 interface GigabitEthernet1
  tunnel-interface
   encapsulation ipsec preference 200 weight 1
   color biz-internet
  exit
 exit
 interface GigabitEthernet2
  tunnel-interface
   encapsulation ipsec preference 100 weight 1
   color public-internet
  exit
 exit
!
site101-kit1#show sdwan omp tlocs
---------------------------------------------------
tloc entries for 10.255.1.1
                 biz-internet
                 ipsec
---------------------------------------------------
            RECEIVED FROM:
peer            10.255.0.3
status          C,I,R
    Attributes:
     public-ip         172.16.1.21
     private-ip        172.16.1.21
     site-id           10
     preference        200
     weight            1
---------------------------------------------------
tloc entries for 10.255.1.1
                 public-internet
                 ipsec
---------------------------------------------------
            RECEIVED FROM:
peer            10.255.0.3
status          C,I,R
    Attributes:
     public-ip         172.16.2.21
     private-ip        172.16.2.21
     site-id           10
     preference        0
     weight            1
---------------------------------------------------
tloc entries for 10.255.1.11
                 biz-internet
                 ipsec
---------------------------------------------------
            RECEIVED FROM:
peer            0.0.0.0
status          C,Red,R
    Attributes:
     public-ip         10.10.1.21
     private-ip        10.10.1.21
     site-id           1011
     preference        200
     weight            1
            ADVERTISED TO:
peer            10.255.0.3
    Attributes:
     public-ip         10.10.1.21
     preference        200
site101-kit1#show sdwan omp routes vpn 1000
TENANT    VPN    PREFIX              FROM PEER        ID     LABEL    STATUS    TYPE       TLOC IP          COLOR            ENCAP  PREFERENCE  NUMBER      REGION ID   REGION PATH
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
0         1000   0.0.0.0/0           10.255.0.3       1      1003     C,I,R     installed  10.255.1.1       biz-internet     ipsec  -           None        None        -
                                     10.255.0.3       2      1003     R         installed  10.255.1.1       public-internet  ipsec  -           None        None        -
0         1000   10.101.1.0/26       0.0.0.0          68     1003     C,Red,R   installed  10.255.1.11      biz-internet     ipsec  -           None        None        -
site101-kit1#show sdwan bfd sessions
SYSTEM IP        SITE ID     STATE       SOURCE TLOC      REMOTE TLOC                                      DST PUBLIC                      DST PUBLIC         DETECT      TX
10.255.1.1       10          up          biz-internet     biz-internet     10.10.1.21                                      172.16.1.21                                     12346       ipsec  3           1000           0:00:47:43      3
10.255.1.1       10          up          public-internet  public-internet  10.10.2.21                                      172.16.2.21                                     12346       ipsec  7           1000           0:05:25:12      1
site101-kit1#show sdwan app-route stats
app-route statistics 10.10.1.21 172.16.1.21 ipsec 12346 12346
 remote-system-ip 10.255.1.1
 local-color biz-internet
 remote-color biz-internet
 sla-class-index 0
 interval 0
  tx-data-pkts 18
  rx-data-pkts 18
app-route statistics 10.10.2.21 172.16.2.21 ipsec 12346 12346
 remote-system-ip 10.255.1.1
 local-color public-internet
 remote-color public-internet
 sla-class-index 0
 interval 0
  tx-data-pkts 0
  rx-data-pkts 0
"#;
        let (sys_ip, site_id, host_name) =
            crate::ssh::extract_system_identity(iosxe_ssh_capture, "10.10.1.21");
        assert_eq!(sys_ip, "10.255.1.11");
        assert_eq!(site_id, "1011");
        assert_eq!(host_name, "site101-kit1");

        let snap = build_snapshot_from_text(&host_name, &sys_ip, &site_id, "ssh", iosxe_ssh_capture);
        let local_biz = snap
            .local_tlocs
            .iter()
            .find(|t| t.color == "biz-internet")
            .expect("local biz-internet present");
        assert_eq!(local_biz.public_ip, "10.10.1.21");
        assert_eq!(local_biz.bfd_status, "C,Red,R");
        assert_eq!(snap.remote_tlocs.len(), 2);

        let report = explain_snapshot(snap);
        assert_eq!(report.route_explanations.len(), 1);
        assert_eq!(report.route_explanations[0].prefix, "0.0.0.0/0");
        assert_eq!(report.route_explanations[0].winning_color, "biz-internet");
        assert_eq!(report.route_explanations[0].backup_paths.len(), 1);

        let primary = report
            .tunnel_verdicts
            .iter()
            .find(|v| v.local_ip == "10.10.1.21" && v.remote_ip == "172.16.1.21")
            .expect("primary BFD+app-route tunnel merged");
        assert_eq!(primary.bfd_state, "up");
        assert_eq!(primary.detect_multiplier, 3);
        assert_eq!(primary.verdict, VerdictKind::ActivePrimary);
    }

    #[test]
    fn discovers_service_vrfs_and_filters_by_peer_cleanly() {
        let multi_peer_capture = r#"
hub1#show vrf
  Name                             Default RD            Protocols   Interfaces
  10                               <not set>             ipv4,ipv6   Gi3.10
  100                              <not set>             ipv4        Gi3.100
  65528                            <not set>             ipv4        Lo65528
  65529                            <not set>             ipv4        Lo65529
  Mgmt-intf                        <not set>             ipv4        Gi0
hub1#show sdwan running-config sdwan
sdwan
 interface GigabitEthernet1
  tunnel-interface
   encapsulation ipsec preference 200 weight 1
   color biz-internet
  exit
 exit
!
hub1#show sdwan bfd sessions
SYSTEM IP        SITE ID     STATE       SOURCE TLOC      REMOTE TLOC                                      DST PUBLIC                      DST PUBLIC         DETECT      TX
10.255.2.10      200         up          biz-internet     biz-internet     10.10.1.1                                       172.16.20.2                                     12346       ipsec  3           1000           0:01:00:00      0
10.255.3.10      300         up          biz-internet     public-internet  10.10.1.1                                       172.16.30.2                                     12346       ipsec  3           1000           0:01:00:00      0
hub1#show sdwan omp tlocs
---------------------------------------------------
tloc entries for 10.255.2.10
                 biz-internet
                 ipsec
---------------------------------------------------
            RECEIVED FROM:
peer            10.255.0.3
status          C,I,R
    Attributes:
     public-ip         172.16.20.2
     private-ip        172.16.20.2
     site-id           200
     preference        200
---------------------------------------------------
tloc entries for 10.255.3.10
                 public-internet
                 ipsec
---------------------------------------------------
            RECEIVED FROM:
peer            10.255.0.3
status          C,I,R
    Attributes:
     public-ip         172.16.30.2
     private-ip        172.16.30.2
     site-id           300
     preference        100
hub1#show sdwan omp routes
TENANT    VPN    PREFIX              FROM PEER        ID     LABEL    STATUS    TYPE       TLOC IP          COLOR            ENCAP  PREFERENCE  NUMBER      REGION ID   REGION PATH
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
0         10     10.20.0.0/16        10.255.0.3       1      1001     C,I,R     installed  10.255.2.10      biz-internet     ipsec  -           None        None        -
0         200    10.30.0.0/16        10.255.0.3       1      1002     C,I,R     installed  10.255.3.10      public-internet  ipsec  -           None        None        -
hub1#show sdwan app-route stats
app-route statistics 10.10.1.1 172.16.20.2 ipsec 12346 12346
 remote-system-ip 10.255.2.10
 local-color biz-internet
 remote-color biz-internet
 sla-class-index 0
 interval 0
  tx-data-pkts 40
  rx-data-pkts 30
app-route statistics 10.10.1.1 172.16.30.2 ipsec 12346 12346
 remote-system-ip 10.255.3.10
 local-color biz-internet
 remote-color public-internet
 sla-class-index 0
 interval 0
  tx-data-pkts 0
  rx-data-pkts 0
"#;
        let mut snap = build_snapshot_from_text("hub1", "10.255.1.1", "10", "ssh", multi_peer_capture);
        assert_eq!(snap.discovered_vpns, vec!["10", "100", "200"]);

        // Test peer filter by remote WAN IP resolves to System IP 10.255.3.10
        snap.peer_filter = Some("172.16.30.2".to_string());
        let filtered = explain_snapshot(snap);
        assert_eq!(filtered.tunnel_verdicts.len(), 1);
        assert_eq!(filtered.tunnel_verdicts[0].remote_system_ip, "10.255.3.10");
        assert_eq!(filtered.peer_summaries.len(), 1);
        assert_eq!(filtered.peer_summaries[0].site_id, "300");
        assert_eq!(filtered.route_explanations.len(), 1);
        assert_eq!(filtered.route_explanations[0].vpn_id, "200");
    }

    #[test]
    fn marks_cir_default_route_winner_active_in_discover_and_retains_winner_for_backup_peer() {
        let capture = r#"
spoke1#show vrf
  Name                             Default RD            Protocols   Interfaces
  10                               <not set>             ipv4        Gi3
spoke1#show sdwan running-config sdwan
sdwan
 interface GigabitEthernet1
  tunnel-interface
   encapsulation ipsec preference 200 weight 1
   color biz-internet
  exit
 exit
 interface GigabitEthernet2
  tunnel-interface
   encapsulation ipsec preference 100 weight 1
   color mpls
  exit
 exit
!
spoke1#show sdwan bfd sessions
SYSTEM IP        SITE ID     STATE       SOURCE TLOC      REMOTE TLOC                                      DST PUBLIC                      DST PUBLIC         DETECT      TX
10.255.1.1       10          up          biz-internet     biz-internet     10.10.1.11                                      172.16.1.1                                      12346       ipsec  3           1000           0:01:00:00      0
10.255.1.2       20          up          mpls             mpls             10.10.2.11                                      172.16.2.1                                      12346       ipsec  3           1000           0:01:00:00      0
spoke1#show sdwan omp routes
TENANT    VPN    PREFIX              FROM PEER        ID     LABEL    STATUS    TYPE       TLOC IP          COLOR            ENCAP  PREFERENCE  NUMBER      REGION ID   REGION PATH
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
0         10     0.0.0.0/0           10.255.0.3       1      1001     C,I,R     installed  10.255.1.1       biz-internet     ipsec  -           None        None        -
                                     10.255.0.3       2      1002     R         installed  10.255.1.2       mpls             ipsec  -           None        None        -
"#;
        // 1. Discover mode without app-route stats identifies 10.255.1.1 as 0.0.0.0/0 winner & ActivePrimary
        let snap_disc = build_snapshot_from_text("spoke1", "10.255.10.1", "101", "ssh-discover", capture);
        assert_eq!(snap_disc.local_tlocs[0].public_ip, "10.10.1.11");
        let rep_disc = explain_snapshot(snap_disc);
        assert_eq!(rep_disc.active_primary_tunnels.len(), 1);
        assert!(rep_disc.active_primary_tunnels[0].contains("172.16.1.1"));
        assert_eq!(rep_disc.peer_summaries[0].system_ip, "10.255.1.1");
        assert!(rep_disc.peer_summaries[0].is_default_route_winner);
        assert_eq!(rep_disc.peer_summaries[0].cir_routes, 1);
        assert_eq!(rep_disc.peer_summaries[1].system_ip, "10.255.1.2");
        assert!(!rep_disc.peer_summaries[1].is_default_route_winner);
        assert_eq!(rep_disc.peer_summaries[1].backup_routes, 1);

        // 2. Focusing --peer 10.255.1.2 (backup hub) keeps competing C,I,R winner 10.255.1.1 in Section 4
        let mut snap_backup = build_snapshot_from_text("spoke1", "10.255.10.1", "101", "ssh", capture);
        snap_backup.peer_filter = Some("10.255.1.2".to_string());
        let rep_backup = explain_snapshot(snap_backup);
        assert_eq!(rep_backup.tunnel_verdicts.len(), 1);
        assert_eq!(rep_backup.tunnel_verdicts[0].verdict, VerdictKind::StandbyBfdOnly);
        assert_eq!(rep_backup.route_explanations.len(), 1);
        assert_eq!(rep_backup.route_explanations[0].winning_originator, "10.255.1.1");
        assert_eq!(rep_backup.route_explanations[0].backup_paths.len(), 1);
        assert!(rep_backup.route_explanations[0].backup_paths[0].contains("10.255.1.2"));
    }
}
