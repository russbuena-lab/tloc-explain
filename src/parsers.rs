use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use crate::models::{
    utc_now_rfc3339, OmpRouteEntry, RouterSnapshot, ServicePathHop, TlocEntry, TunnelDiag,
};

fn is_internal_vrf(name: &str) -> bool {
    matches!(name, "65528" | "65529")
        || name.eq_ignore_ascii_case("mgmt-intf")
        || name.eq_ignore_ascii_case("mgmt-vrf")
}

/// Parses `show vrf` output into `(vrf_name, interfaces)` pairs, excluding internal IOS-XE VRFs
/// (`65528`, `65529`, `Mgmt-intf`, `Mgmt-vrf`).
pub fn parse_vrf_table(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut table: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut in_vrf_table = false;
    let mut last_vrf = String::new();

    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.contains('#') {
            in_vrf_table = false;
            last_vrf.clear();
            continue;
        }
        if trimmed.contains("Name") && trimmed.contains("Default RD") {
            in_vrf_table = true;
            last_vrf.clear();
            continue;
        }
        if !in_vrf_table {
            continue;
        }
        if trimmed.starts_with('-') {
            continue;
        }

        let leading_ws = raw.len().saturating_sub(raw.trim_start().len());
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        if tokens.len() >= 2 && (trimmed.contains("<not set>") || tokens[1].contains(':')) {
            let name = tokens[0];
            if is_internal_vrf(name) {
                last_vrf.clear();
                continue;
            }
            // Columns: Name, Default RD (<not set> is 2 tokens!), Protocols, Interfaces...
            let proto_idx = if tokens.len() >= 3 && tokens[1] == "<not" && tokens[2] == "set>" {
                3
            } else {
                2
            };
            let ifaces: Vec<String> = tokens
                .get(proto_idx + 1..)
                .unwrap_or(&[])
                .iter()
                .map(|s| s.trim_end_matches(',').to_string())
                .filter(|s| !s.is_empty())
                .collect();
            table.entry(name.to_string()).or_default().extend(ifaces);
            last_vrf = name.to_string();
        } else if !last_vrf.is_empty() && leading_ws >= 20 {
            let ifaces: Vec<String> = tokens
                .iter()
                .map(|s| s.trim_end_matches(',').to_string())
                .filter(|s| !s.is_empty())
                .collect();
            table.entry(last_vrf.clone()).or_default().extend(ifaces);
        } else {
            in_vrf_table = false;
            last_vrf.clear();
        }
    }

    table
}

/// Parses `show vrf` output into sorted Service VPN / VRF identifiers, excluding IOS-XE internal
/// management/loopback VRFs (`65528`, `65529`, `Mgmt-intf`, `Mgmt-vrf`).
pub fn parse_vrfs(text: &str) -> Vec<String> {
    let table = parse_vrf_table(text);
    sort_unique_vpns(table.keys().map(String::as_str))
}

/// Expands IOS-XE abbreviated interface names (e.g. `Gi3` -> `GigabitEthernet3`,
/// `Vl10` -> `Vlan10`, `Gi0/0/1.10` -> `GigabitEthernet0/0/1.10`).
pub fn expand_iosxe_interface_name(short: &str) -> String {
    const ABBREVS: &[(&str, &str)] = &[
        ("GigabitEthernet", "GigabitEthernet"),
        ("TenGigabitEthernet", "TenGigabitEthernet"),
        ("TwoGigabitEthernet", "TwoGigabitEthernet"),
        ("FortyGigabitEthernet", "FortyGigabitEthernet"),
        ("HundredGigE", "HundredGigE"),
        ("FastEthernet", "FastEthernet"),
        ("Port-channel", "Port-channel"),
        ("Loopback", "Loopback"),
        ("Tunnel", "Tunnel"),
        ("Vlan", "Vlan"),
        ("Dialer", "Dialer"),
        ("Cellular", "Cellular"),
        ("BDI", "BDI"),
        ("Gi", "GigabitEthernet"),
        ("Te", "TenGigabitEthernet"),
        ("Tw", "TwoGigabitEthernet"),
        ("Fo", "FortyGigabitEthernet"),
        ("Hu", "HundredGigE"),
        ("Fa", "FastEthernet"),
        ("Po", "Port-channel"),
        ("Lo", "Loopback"),
        ("Tu", "Tunnel"),
        ("Vl", "Vlan"),
        ("Di", "Dialer"),
        ("Ce", "Cellular"),
    ];
    let trimmed = short.trim().trim_end_matches(',');
    for (prefix, full) in ABBREVS {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return format!("{full}{rest}");
            }
        }
    }
    trimmed.to_string()
}

/// Parses `show ip interface brief` into `InterfaceName -> IPv4` for UP interfaces with valid IPs.
pub fn parse_ip_int_brief(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for raw in text.lines() {
        let tokens: Vec<&str> = raw.split_whitespace().collect();
        if tokens.len() < 6 || !is_ipv4(tokens[1]) {
            continue;
        }
        let protocol = tokens.last().copied().unwrap_or("");
        if !protocol.eq_ignore_ascii_case("up") {
            continue;
        }
        map.insert(tokens[0].to_string(), tokens[1].to_string());
    }
    map
}

/// Resolves an active LAN/service interface name (full IOS-XE name) and IPv4 address for `vpn_id`
/// by correlating `show vrf` with `show ip interface brief`.
pub fn resolve_vrf_lan_interface_and_ip(text: &str, vpn_id: &str) -> Option<(String, String)> {
    let vrf_table = parse_vrf_table(text);
    let ip_brief = parse_ip_int_brief(text);
    let ifaces = vrf_table.get(vpn_id)?;

    let mut fallback: Option<(String, String)> = None;
    for raw_if in ifaces {
        let expanded = expand_iosxe_interface_name(raw_if);
        let found = ip_brief
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&expanded) || k.eq_ignore_ascii_case(raw_if));
        if let Some((iface, ip)) = found {
            if !iface.to_ascii_lowercase().starts_with("loopback") {
                return Some((iface.clone(), ip.clone()));
            }
            if fallback.is_none() {
                fallback = Some((iface.clone(), ip.clone()));
            }
        }
    }
    fallback
}

/// Parses `show ip route vrf <vpn> 0.0.0.0 0.0.0.0` RIB entries into OMP `C,I,R` `0.0.0.0/0` routes.
pub fn parse_ip_route_quad_zero(text: &str, default_vpn: &str) -> Vec<OmpRouteEntry> {
    let mut cur_vpn = default_vpn.trim().to_string();
    let mut in_quad = false;
    let mut proto = String::new();
    let mut out = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();

    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.contains('#') {
            if trimmed.contains('#') {
                in_quad = false;
                proto.clear();
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Routing Table:") {
            cur_vpn = rest.trim().to_string();
            in_quad = false;
            proto.clear();
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Routing entry for ") {
            in_quad = rest.trim_start().starts_with("0.0.0.0/0");
            proto.clear();
            continue;
        }
        if !in_quad {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Known via \"") {
            if let Some((p, _)) = rest.split_once('"') {
                proto = p.to_ascii_lowercase();
            }
            continue;
        }
        if proto == "omp" && trimmed.contains("Sdwan-system-intf") {
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(nh_ip) = tokens
                .iter()
                .map(|t| t.trim_end_matches(','))
                .find(|t| is_ipv4(t))
            {
                let vpn_val = if cur_vpn.is_empty() {
                    default_vpn.to_string()
                } else {
                    cur_vpn.clone()
                };
                if seen.insert((vpn_val.clone(), nh_ip.to_string())) {
                    out.push(OmpRouteEntry {
                        vpn_id: vpn_val,
                        prefix: "0.0.0.0/0".to_string(),
                        from_peer: nh_ip.to_string(),
                        originator: nh_ip.to_string(),
                        next_hop_tloc_ip: nh_ip.to_string(),
                        site_id: String::new(),
                        color: String::new(),
                        encap: "ipsec".to_string(),
                        status: "C,I,R".to_string(),
                        protocol: "omp".to_string(),
                        is_chosen_installed: true,
                        is_redistributed: false,
                    });
                }
            }
        }
    }

    out
}

/// Parses `show sdwan policy service-path ...` next-hop tunnel details.
pub fn parse_service_path_output(text: &str) -> Vec<ServicePathHop> {
    let mut hops = Vec::new();
    for raw in text.lines() {
        let trimmed = raw.trim();
        if !(trimmed.contains("Source:") && trimmed.contains("Destination:")) {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let mut hop = ServicePathHop::default();
        let mut i = 0usize;
        while i < tokens.len() {
            if tokens[i] == "Source:" && i + 1 < tokens.len() {
                hop.local_ip = tokens[i + 1].to_string();
                i += 2;
            } else if tokens[i] == "Destination:" && i + 1 < tokens.len() {
                hop.remote_ip = tokens[i + 1].to_string();
                i += 2;
            } else if tokens[i] == "Local" && i + 2 < tokens.len() && tokens[i + 1] == "Color:" {
                hop.local_color = tokens[i + 2].to_string();
                i += 3;
            } else if tokens[i] == "Remote" && i + 2 < tokens.len() && tokens[i + 1] == "Color:" {
                hop.remote_color = tokens[i + 2].to_string();
                i += 3;
            } else if tokens[i] == "Remote"
                && i + 3 < tokens.len()
                && tokens[i + 1] == "System"
                && tokens[i + 2] == "IP:"
            {
                hop.remote_system_ip = tokens[i + 3].to_string();
                i += 4;
            } else {
                i += 1;
            }
        }
        if !hop.remote_system_ip.is_empty() || !hop.remote_ip.is_empty() {
            hops.push(hop);
        }
    }
    hops
}

/// Deduplicates and sorts Service VPN IDs numerically first, then lexicographically.
pub fn sort_unique_vpns<'a, I: IntoIterator<Item = &'a str>>(items: I) -> Vec<String> {
    let set: BTreeSet<String> = items
        .into_iter()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "0" && *s != "65528" && *s != "65529")
        .map(String::from)
        .collect();
    let mut out: Vec<String> = set.into_iter().collect();
    out.sort_by(|a, b| match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(na), Ok(nb)) => na.cmp(&nb),
        (Ok(_), Err(_)) => std::cmp::Ordering::Less,
        (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
        (Err(_), Err(_)) => a.cmp(b),
    });
    out
}

/// Parsed local SD-WAN interface attributes extracted from `show sdwan running-config sdwan`.
#[derive(Debug, Clone, Default)]
pub struct SdwanInterfaceCfg {
    pub interface: String,
    pub color: String,
    pub preference: u32,
    pub weight: u32,
    pub restrict: bool,
    pub last_resort_circuit: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SdwanConfigSummary {
    pub interfaces: Vec<SdwanInterfaceCfg>,
    pub bfd_colors: BTreeMap<String, (Option<u32>, Option<u32>)>,
}

/// Parses `show sdwan running-config sdwan` (or full IOS-XE running-config containing an `sdwan` block).
pub fn parse_running_config_sdwan(text: &str) -> SdwanConfigSummary {
    let mut summary = SdwanConfigSummary::default();
    let mut cur_iface: Option<SdwanInterfaceCfg> = None;
    let mut in_tunnel_if = false;
    let mut cur_bfd_color: Option<String> = None;
    let mut bfd_hello: Option<u32> = None;
    let mut bfd_mult: Option<u32> = None;

    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("interface ") {
            if let Some(prev) = cur_iface.take() {
                if !prev.color.is_empty() {
                    summary.interfaces.push(prev);
                }
            }
            cur_iface = Some(SdwanInterfaceCfg {
                interface: rest.trim().to_string(),
                weight: 1,
                ..Default::default()
            });
            in_tunnel_if = false;
            continue;
        }

        if trimmed == "tunnel-interface" {
            in_tunnel_if = true;
            continue;
        }

        if in_tunnel_if {
            if let Some(cfg) = cur_iface.as_mut() {
                if let Some(rest) = trimmed.strip_prefix("encapsulation ") {
                    let tokens: Vec<&str> = rest.split_whitespace().collect();
                    for pair in tokens.windows(2) {
                        if pair[0] == "preference" {
                            if let Ok(p) = pair[1].parse::<u32>() {
                                cfg.preference = p;
                            }
                        } else if pair[0] == "weight" {
                            if let Ok(w) = pair[1].parse::<u32>() {
                                cfg.weight = w;
                            }
                        }
                    }
                } else if let Some(rest) = trimmed.strip_prefix("color ") {
                    cfg.color = rest.trim().to_string();
                } else if trimmed == "restrict" {
                    cfg.restrict = true;
                } else if trimmed == "last-resort-circuit" {
                    cfg.last_resort_circuit = true;
                } else if trimmed == "exit" {
                    in_tunnel_if = false;
                }
            }
            continue;
        }

        if trimmed == "exit" || trimmed == "!" {
            if let Some(prev) = cur_iface.take() {
                if !prev.color.is_empty() {
                    summary.interfaces.push(prev);
                }
            }
            if let Some(c) = cur_bfd_color.take() {
                summary.bfd_colors.insert(c, (bfd_hello, bfd_mult));
                bfd_hello = None;
                bfd_mult = None;
            }
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("bfd color ") {
            if let Some(c) = cur_bfd_color.take() {
                summary.bfd_colors.insert(c, (bfd_hello, bfd_mult));
            }
            cur_bfd_color = Some(rest.trim().to_string());
            bfd_hello = None;
            bfd_mult = None;
            continue;
        }

        if cur_bfd_color.is_some() {
            if let Some(rest) = trimmed.strip_prefix("hello-interval ") {
                bfd_hello = rest.trim().parse::<u32>().ok();
            } else if let Some(rest) = trimmed.strip_prefix("multiplier ") {
                bfd_mult = rest.trim().parse::<u32>().ok();
            }
        }
    }

    if let Some(prev) = cur_iface.take() {
        if !prev.color.is_empty() {
            summary.interfaces.push(prev);
        }
    }
    if let Some(c) = cur_bfd_color.take() {
        summary.bfd_colors.insert(c, (bfd_hello, bfd_mult));
    }

    summary
}

/// Parses `show sdwan tunnel statistics` output into partial `TunnelDiag` records.
pub fn parse_tunnel_statistics(text: &str) -> Vec<TunnelDiag> {
    let header_re = Regex::new(
        r"^tunnel\s+stats\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+$",
    )
    .expect("valid regex");

    let mut out = Vec::new();
    let mut cur: Option<TunnelDiag> = None;

    for raw in text.lines() {
        let trimmed = raw.trim();
        if let Some(caps) = header_re.captures(trimmed) {
            if let Some(prev) = cur.take() {
                out.push(prev);
            }
            cur = Some(TunnelDiag {
                local_ip: caps[1].to_string(),
                remote_ip: caps[2].to_string(),
                has_tunnel_stats: true,
                ..Default::default()
            });
            continue;
        }

        let Some(t) = cur.as_mut() else {
            continue;
        };

        let mut parts = trimmed.split_whitespace();
        let Some(key) = parts.next() else { continue };
        let Some(val) = parts.next() else { continue };

        match key {
            "system-ip" => t.remote_system_ip = val.to_string(),
            "local-color" => t.local_color = val.to_string(),
            "remote-color" => t.remote_color = val.to_string(),
            "tunnel-mtu" => t.tunnel_mtu = val.parse().unwrap_or(0),
            "tcp-mss-adjust" => t.tcp_mss_adjust = val.parse().unwrap_or(0),
            "tx_pkts" => t.cum_tx_pkts = val.parse().unwrap_or(0),
            "tx_octets" => t.cum_tx_octets = val.parse().unwrap_or(0),
            "rx_pkts" => t.cum_rx_pkts = val.parse().unwrap_or(0),
            "rx_octets" => t.cum_rx_octets = val.parse().unwrap_or(0),
            _ => {}
        }
    }

    if let Some(prev) = cur.take() {
        out.push(prev);
    }
    out
}

/// Parses `show sdwan app-route stats` output, summing `tx-data-pkts` and `rx-data-pkts` across intervals.
pub fn parse_app_route_stats(text: &str) -> Vec<TunnelDiag> {
    let header_re = Regex::new(
        r"^app-route\s+statistics\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\d+\s+\d+$",
    )
    .expect("valid regex");

    let mut out = Vec::new();
    let mut cur: Option<TunnelDiag> = None;

    for raw in text.lines() {
        let trimmed = raw.trim();
        if let Some(caps) = header_re.captures(trimmed) {
            if let Some(prev) = cur.take() {
                out.push(prev);
            }
            cur = Some(TunnelDiag {
                local_ip: caps[1].to_string(),
                remote_ip: caps[2].to_string(),
                has_app_route: true,
                ..Default::default()
            });
            continue;
        }

        let Some(t) = cur.as_mut() else {
            continue;
        };

        let mut parts = trimmed.split_whitespace();
        let Some(key) = parts.next() else { continue };
        let Some(val) = parts.next() else { continue };

        match key {
            "remote-system-ip" => t.remote_system_ip = val.to_string(),
            "local-color" => t.local_color = val.to_string(),
            "remote-color" => t.remote_color = val.to_string(),
            "sla-class-index" => t.sla_class_index = trimmed.strip_prefix("sla-class-index").unwrap_or(val).trim().to_string(),
            "mean-loss" => t.mean_loss_pct = val.parse().unwrap_or(0.0),
            "mean-latency" => t.mean_latency_ms = val.parse().unwrap_or(0),
            "mean-jitter" => t.mean_jitter_ms = val.parse().unwrap_or(0),
            "total-packets" => t.recent_bfd_probes += val.parse::<u64>().unwrap_or(0),
            "tx-data-pkts" => t.recent_tx_data_pkts += val.parse::<u64>().unwrap_or(0),
            "rx-data-pkts" => t.recent_rx_data_pkts += val.parse::<u64>().unwrap_or(0),
            _ => {}
        }
    }

    if let Some(prev) = cur.take() {
        out.push(prev);
    }
    out
}

/// Parses multi-block `show sdwan omp tlocs` or `show omp tlocs` output.
pub fn parse_omp_tlocs(text: &str) -> Vec<TlocEntry> {
    let hdr_re = Regex::new(r"^tloc\s+entries\s+for\s+(\d+\.\d+\.\d+\.\d+)$").expect("valid regex");
    let mut out = Vec::new();

    let mut cur_sys_ip = String::new();
    let mut cur_color = String::new();
    let mut cur_encap = String::new();
    let mut active: Option<TlocEntry> = None;
    let mut active_is_advertised = false;

    let push_tloc_entry = |out: &mut Vec<TlocEntry>, entry: TlocEntry, is_advertised: bool| {
        if is_advertised {
            if let Some(existing) = out.iter_mut().rev().find(|e| {
                e.system_ip == entry.system_ip && e.color == entry.color && e.encap == entry.encap
            }) {
                // ADVERTISED TO blocks lack `status` / `bfd-status`; never overwrite RECEIVED FROM fields.
                if existing.public_ip.is_empty() && !entry.public_ip.is_empty() {
                    existing.public_ip = entry.public_ip;
                }
                if existing.private_ip.is_empty() && !entry.private_ip.is_empty() {
                    existing.private_ip = entry.private_ip;
                }
                if existing.site_id.is_empty() && !entry.site_id.is_empty() {
                    existing.site_id = entry.site_id;
                }
                if existing.bfd_status.is_empty() && !entry.bfd_status.is_empty() {
                    existing.bfd_status = entry.bfd_status;
                }
                return;
            }
        }
        out.push(entry);
    };

    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if let Some(caps) = hdr_re.captures(trimmed) {
            if let Some(prev) = active.take() {
                push_tloc_entry(&mut out, prev, active_is_advertised);
            }
            cur_sys_ip = caps[1].to_string();
            cur_color.clear();
            cur_encap.clear();
            if i + 1 < lines.len() && !lines[i + 1].trim().starts_with('-') {
                cur_color = lines[i + 1].trim().to_string();
                i += 1;
            }
            if i + 1 < lines.len() && !lines[i + 1].trim().starts_with('-') {
                cur_encap = lines[i + 1].trim().to_string();
                i += 1;
            }
            i += 1;
            continue;
        }

        if trimmed.starts_with("omp route entries")
            || trimmed.starts_with("apply-policy")
            || trimmed.starts_with("tunnel stats ")
            || trimmed.starts_with("app-route statistics ")
            || trimmed.contains("# show ")
            || trimmed.contains("#show ")
        {
            if let Some(prev) = active.take() {
                push_tloc_entry(&mut out, prev, active_is_advertised);
            }
            cur_sys_ip.clear();
            cur_color.clear();
            cur_encap.clear();
            i += 1;
            continue;
        }

        if trimmed.starts_with("RECEIVED FROM:") || trimmed.starts_with("ADVERTISED TO:") {
            if let Some(prev) = active.take() {
                push_tloc_entry(&mut out, prev, active_is_advertised);
            }
            active_is_advertised = trimmed.starts_with("ADVERTISED TO:");
            if !cur_sys_ip.is_empty() {
                active = Some(TlocEntry {
                    system_ip: cur_sys_ip.clone(),
                    color: cur_color.clone(),
                    encap: cur_encap.clone(),
                    weight: 1,
                    ..Default::default()
                });
            }
            i += 1;
            continue;
        }

        if let Some(t) = active.as_mut() {
            let mut parts = trimmed.split_whitespace();
            if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                match k {
                    "public-ip" if v != "::" => t.public_ip = v.to_string(),
                    "private-ip" if v != "::" => t.private_ip = v.to_string(),
                    "site-id" => t.site_id = v.to_string(),
                    "preference" => t.preference = v.parse().unwrap_or(0),
                    "weight" => t.weight = v.parse().unwrap_or(1),
                    "restrict" => t.restrict = v == "1" || v.eq_ignore_ascii_case("true"),
                    "status" => t.bfd_status = v.to_string(),
                    _ => {}
                }
            }
        }
        i += 1;
    }

    if let Some(prev) = active.take() {
        push_tloc_entry(&mut out, prev, active_is_advertised);
    }

    // Fallback for tabular `show omp tlocs | tab` or IOS-XE summary table
    if out.is_empty() {
        let row_re = Regex::new(
            r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+([A-Za-z,]+)\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+(\d+)",
        )
        .expect("valid regex");
        for line in text.lines() {
            if let Some(caps) = row_re.captures(line) {
                out.push(TlocEntry {
                    system_ip: caps[1].to_string(),
                    color: caps[2].to_string(),
                    encap: caps[3].to_string(),
                    bfd_status: caps[5].to_string(),
                    public_ip: caps[6].to_string(),
                    private_ip: caps[7].to_string(),
                    site_id: caps[8].to_string(),
                    preference: caps[9].parse().unwrap_or(0),
                    weight: 1,
                    ..Default::default()
                });
            }
        }
    }

    out
}

/// Parses `show sdwan omp routes [vpn N]` (both detail blocks and tabular summary).
pub fn parse_omp_routes(text: &str) -> Vec<OmpRouteEntry> {
    let mut out = Vec::new();
    let detail_re =
        Regex::new(r"^omp\s+route\s+entries\s+for\s+vpn\s+(\d+)\s+route\s+(\S+)$")
            .expect("valid regex");

    let mut cur_vpn = String::new();
    let mut cur_prefix = String::new();
    let mut active: Option<OmpRouteEntry> = None;

    for raw in text.lines() {
        let trimmed = raw.trim();
        if let Some(caps) = detail_re.captures(trimmed) {
            if let Some(prev) = active.take() {
                out.push(prev);
            }
            cur_vpn = caps[1].to_string();
            cur_prefix = caps[2].to_string();
            continue;
        }
        if trimmed.starts_with("RECEIVED FROM:") && !cur_prefix.is_empty() {
            if let Some(prev) = active.take() {
                out.push(prev);
            }
            active = Some(OmpRouteEntry {
                vpn_id: cur_vpn.clone(),
                prefix: cur_prefix.clone(),
                ..Default::default()
            });
            continue;
        }
        if let Some(r) = active.as_mut() {
            if let Some(rest) = trimmed.strip_prefix("tloc ") {
                let items: Vec<&str> = rest
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !items.is_empty() {
                    r.next_hop_tloc_ip = items[0].to_string();
                }
                if items.len() >= 2 {
                    r.color = items[1].to_string();
                }
                if items.len() >= 3 {
                    r.encap = items[2].to_string();
                }
                continue;
            }
            let mut parts = trimmed.split_whitespace();
            if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                match k {
                    "peer" => r.from_peer = v.to_string(),
                    "originator" => r.originator = v.to_string(),
                    "site-id" => r.site_id = v.to_string(),
                    "origin-proto" => r.protocol = v.to_string(),
                    "status" => {
                        let st = trimmed.strip_prefix("status").unwrap_or(v).trim().to_string();
                        r.is_chosen_installed = is_route_chosen_installed(&st);
                        r.is_redistributed = st.contains("Red");
                        r.status = st;
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some(prev) = active.take() {
        out.push(prev);
    }

    // Tabular IOS-XE / Viptela `show sdwan omp routes` fallback
    if out.is_empty() {
        let mut last_vpn = String::new();
        let mut last_prefix = String::new();
        for raw in text.lines() {
            let trimmed = raw.trim();
            if trimmed.is_empty()
                || trimmed.contains('#')
                || trimmed.starts_with("tloc entries")
                || trimmed.starts_with("tunnel stats")
                || trimmed.starts_with("app-route statistics")
                || trimmed.starts_with("SYSTEM IP")
            {
                last_vpn.clear();
                last_prefix.clear();
                continue;
            }
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            if tokens.len() < 7 {
                continue;
            }
            // Match IOS-XE 17.x multi-tenant format (<tenant> <vpn> <prefix> <from_peer> ...),
            // legacy format (<vpn> <prefix> <from_peer> ...), or continuation starting with <from_peer>.
            if tokens.len() >= 11
                && tokens[0].chars().all(|c| c.is_ascii_digit())
                && tokens[1].chars().all(|c| c.is_ascii_digit())
                && is_cidr_prefix(tokens[2])
            {
                last_vpn = tokens[1].to_string();
                last_prefix = tokens[2].to_string();
                if let Some(entry) = parse_tabular_route_tokens(&last_vpn, &last_prefix, &tokens[3..]) {
                    out.push(entry);
                }
            } else if tokens[0].chars().all(|c| c.is_ascii_digit()) && is_cidr_prefix(tokens[1]) {
                last_vpn = tokens[0].to_string();
                last_prefix = tokens[1].to_string();
                // Columns typically: VPN PREFIX FROM_PEER PATH_ID LABEL STATUS ATTR_TYPE TLOC_IP COLOR ENCAP
                if let Some(entry) = parse_tabular_route_tokens(&last_vpn, &last_prefix, &tokens[2..]) {
                    out.push(entry);
                }
            } else if !last_prefix.is_empty() && is_ipv4(tokens[0]) {
                if let Some(entry) = parse_tabular_route_tokens(&last_vpn, &last_prefix, &tokens) {
                    out.push(entry);
                }
            }
        }
    }

    out
}

fn is_cidr_prefix(s: &str) -> bool {
    s.split_once('/').is_some_and(|(ip, mask)| {
        !mask.is_empty() && mask.chars().all(|c| c.is_ascii_digit()) && (is_ipv4(ip) || ip.contains(':'))
    })
}

fn parse_tabular_route_tokens(vpn: &str, prefix: &str, rest: &[&str]) -> Option<OmpRouteEntry> {
    // Look for status token (e.g., C,I,R / R / C,Red,R) and TLOC ip/color at tail
    let ip_indices: Vec<usize> = rest
        .iter()
        .enumerate()
        .filter(|(_, t)| is_ipv4(t))
        .map(|(i, _)| i)
        .collect();
    if ip_indices.is_empty() {
        return None;
    }
    let from_peer = rest[0].to_string();
    let tloc_idx = *ip_indices.last()?;
    let next_hop_tloc_ip = rest[tloc_idx].to_string();
    let color = rest.get(tloc_idx + 1).copied().unwrap_or("").to_string();
    let encap = rest.get(tloc_idx + 2).copied().unwrap_or("ipsec").to_string();
    let status = rest
        .iter()
        .find(|t| {
            let up = t.to_ascii_uppercase();
            up == "R"
                || up == "C"
                || up == "U"
                || up.contains("C,")
                || up.contains("I,")
                || up.contains(",R")
                || up.contains("RED")
                || up == "INV"
                || up == "REJ"
        })
        .copied()
        .unwrap_or("")
        .to_string();
    if status.is_empty() {
        return None;
    }
    Some(OmpRouteEntry {
        vpn_id: vpn.to_string(),
        prefix: prefix.to_string(),
        from_peer,
        originator: next_hop_tloc_ip.clone(),
        next_hop_tloc_ip,
        site_id: String::new(),
        color,
        encap,
        is_chosen_installed: is_route_chosen_installed(&status),
        is_redistributed: status.contains("Red"),
        status,
        protocol: String::new(),
    })
}

/// Parses `show sdwan bfd sessions` output.
pub fn parse_bfd_sessions(text: &str) -> Vec<TunnelDiag> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let tokens: Vec<&str> = raw.split_whitespace().collect();
        if tokens.len() < 10 || !is_ipv4(tokens[0]) {
            continue;
        }
        let (
            src_ip,
            dst_ip,
            sys_ip,
            site_id,
            state,
            mult,
            tx_int,
            uptime,
            transitions,
            local_color,
            remote_color,
        ) = if tokens.len() >= 13 && !is_ipv4(tokens[1]) && is_ipv4(tokens[5]) && is_ipv4(tokens[6])
        {
            // IOS-XE 17.x format:
            // SYSTEM_IP SITE_ID STATE SOURCE_COLOR REMOTE_COLOR SOURCE_IP DST_PUBLIC_IP DST_PORT ENCAP DETECT_MULTIPLIER TX_INTERVAL UPTIME TRANSITIONS
            (
                tokens[5].to_string(),
                tokens[6].to_string(),
                tokens[0].to_string(),
                tokens[1].to_string(),
                tokens[2].to_lowercase(),
                tokens[9].parse::<u32>().unwrap_or(0),
                tokens[10].parse::<u32>().unwrap_or(1000),
                tokens[11].to_string(),
                tokens[12].parse::<u64>().unwrap_or(0),
                tokens[3].to_string(),
                tokens[4].to_string(),
            )
        } else if is_ipv4(tokens[1]) {
            // Legacy Viptela format:
            // SRC_IP DST_IP PROTO SRC_PORT DST_PORT SYSTEM_IP SITE_ID STATE DETECT_MULT TX_INT UPTIME TRANSITIONS LOCAL_COLOR COLOR
            (
                tokens[0].to_string(),
                tokens[1].to_string(),
                tokens.get(5).copied().unwrap_or("").to_string(),
                tokens.get(6).copied().unwrap_or("").to_string(),
                tokens.get(7).copied().unwrap_or("").to_lowercase(),
                tokens.get(8).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0),
                tokens.get(9).and_then(|s| s.parse::<u32>().ok()).unwrap_or(1000),
                tokens.get(10).copied().unwrap_or("").to_string(),
                tokens.get(11).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
                tokens.get(12).copied().unwrap_or("").to_string(),
                tokens.get(13).copied().unwrap_or("").to_string(),
            )
        } else {
            continue;
        };

        out.push(TunnelDiag {
            local_ip: src_ip,
            remote_ip: dst_ip,
            remote_system_ip: sys_ip,
            remote_site_id: site_id,
            local_color,
            remote_color,
            bfd_state: state,
            detect_multiplier: mult,
            tx_interval_ms: tx_int,
            uptime,
            transitions,
            ..Default::default()
        });
    }
    out
}

/// Builds a `RouterSnapshot` from an offline text capture containing one or more CLI `show` outputs.
pub fn build_snapshot_from_text(
    host_name: &str,
    system_ip: &str,
    site_id: &str,
    source_mode: &str,
    text: &str,
) -> RouterSnapshot {
    let cfg = parse_running_config_sdwan(text);
    let tun_stats = parse_tunnel_statistics(text);
    let app_stats = parse_app_route_stats(text);
    let bfd_list = parse_bfd_sessions(text);
    let all_tlocs = parse_omp_tlocs(text);
    let mut omp_routes = parse_omp_routes(text);
    let service_paths = parse_service_path_output(text);

    let vrfs = parse_vrfs(text);
    let rib_vpn = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("Routing Table:").map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty());
    let default_vpn = rib_vpn
        .clone()
        .or_else(|| vrfs.first().cloned())
        .or_else(|| omp_routes.first().map(|r| r.vpn_id.clone()))
        .unwrap_or_default();

    if omp_routes.is_empty() {
        let mut rib_routes = parse_ip_route_quad_zero(text, &default_vpn);
        if rib_routes.is_empty() && !service_paths.is_empty() {
            for hop in &service_paths {
                rib_routes.push(OmpRouteEntry {
                    vpn_id: if default_vpn.is_empty() { "-".to_string() } else { default_vpn.clone() },
                    prefix: "0.0.0.0/0".to_string(),
                    from_peer: hop.remote_system_ip.clone(),
                    originator: hop.remote_system_ip.clone(),
                    next_hop_tloc_ip: hop.remote_system_ip.clone(),
                    site_id: String::new(),
                    color: hop.remote_color.clone(),
                    encap: "ipsec".to_string(),
                    status: "C,I,R".to_string(),
                    protocol: "omp".to_string(),
                    is_chosen_installed: true,
                    is_redistributed: false,
                });
            }
        } else if !service_paths.is_empty() {
            let mut expanded = Vec::new();
            for r in rib_routes {
                let matching_hops: Vec<&ServicePathHop> = service_paths
                    .iter()
                    .filter(|h| h.remote_system_ip == r.originator)
                    .collect();
                if matching_hops.is_empty() {
                    expanded.push(r);
                } else {
                    for h in matching_hops {
                        let mut clone = r.clone();
                        clone.color = h.remote_color.clone();
                        expanded.push(clone);
                    }
                }
            }
            rib_routes = expanded;
        }
        omp_routes = rib_routes;
    }

    let mut inferred_host = host_name.to_string();
    if inferred_host.is_empty() {
        let prompt_re = Regex::new(r"(?m)^([A-Za-z0-9._-]+)#").expect("valid regex");
        if let Some(c) = prompt_re.captures(text) {
            inferred_host = c[1].to_string();
        } else {
            inferred_host = "router".to_string();
        }
    }

    let mut local_tlocs: Vec<TlocEntry> = Vec::new();
    let mut remote_tlocs: Vec<TlocEntry> = Vec::new();

    for if_cfg in &cfg.interfaces {
        let mult = cfg
            .bfd_colors
            .get(&if_cfg.color)
            .and_then(|(_, m)| *m);
        local_tlocs.push(TlocEntry {
            interface: Some(if_cfg.interface.clone()),
            system_ip: system_ip.to_string(),
            site_id: site_id.to_string(),
            color: if_cfg.color.clone(),
            encap: "ipsec".to_string(),
            preference: if_cfg.preference,
            weight: if_cfg.weight,
            restrict: if_cfg.restrict,
            last_resort_circuit: if_cfg.last_resort_circuit,
            bfd_color_multiplier: mult,
            ..Default::default()
        });
    }

    for t in all_tlocs {
        if !system_ip.is_empty() && t.system_ip == system_ip {
            if let Some(existing) = local_tlocs.iter_mut().find(|l| l.color == t.color) {
                existing.public_ip = t.public_ip;
                existing.private_ip = t.private_ip;
                existing.preference = t.preference;
                existing.weight = t.weight;
                existing.bfd_status = t.bfd_status;
                if existing.site_id.is_empty() {
                    existing.site_id = t.site_id;
                }
            } else {
                local_tlocs.push(t);
            }
        } else {
            remote_tlocs.push(t);
        }
    }

    let tunnels = merge_tunnel_diags(bfd_list, tun_stats, app_stats);

    // Backfill local_tlocs public_ip from BFD/tunnel source IPs when `show sdwan omp tlocs` was skipped (e.g. --discover)
    for lt in &mut local_tlocs {
        if lt.public_ip.is_empty() {
            if let Some(td) = tunnels.iter().find(|td| td.local_color == lt.color && !td.local_ip.is_empty()) {
                lt.public_ip = td.local_ip.clone();
                if lt.private_ip.is_empty() {
                    lt.private_ip = td.local_ip.clone();
                }
            }
        }
    }

    // Infer local_tlocs from tunnel local_ips if neither running-config nor omp tlocs populated them
    if local_tlocs.is_empty() {
        let mut seen = BTreeMap::new();
        for td in &tunnels {
            if !td.local_color.is_empty() {
                seen.entry((td.local_color.clone(), td.local_ip.clone()))
                    .or_insert_with(|| TlocEntry {
                        system_ip: system_ip.to_string(),
                        site_id: site_id.to_string(),
                        color: td.local_color.clone(),
                        encap: "ipsec".to_string(),
                        public_ip: td.local_ip.clone(),
                        private_ip: td.local_ip.clone(),
                        weight: 1,
                        bfd_status: td.bfd_state.clone(),
                        ..Default::default()
                    });
            }
        }
        local_tlocs.extend(seen.into_values());
    }

    let mut vpn_refs: Vec<String> = vrfs;
    for r in &omp_routes {
        vpn_refs.push(r.vpn_id.clone());
    }
    let discovered_vpns = sort_unique_vpns(vpn_refs.iter().map(String::as_str));
    let target_vpn = rib_vpn
        .or_else(|| discovered_vpns.first().cloned());

    RouterSnapshot {
        host_name: inferred_host,
        system_ip: system_ip.to_string(),
        site_id: site_id.to_string(),
        source_mode: source_mode.to_string(),
        captured_at_utc: utc_now_rfc3339(),
        target_vpn,
        discovered_vpns,
        peer_filter: None,
        local_tlocs,
        remote_tlocs,
        omp_routes,
        service_paths,
        tunnels,
        policy_summary: None,
    }
}

/// Merges BFD sessions, `tunnel statistics`, and `app-route stats` keyed by `(local_ip, remote_ip)`.
pub fn merge_tunnel_diags(
    bfd_list: Vec<TunnelDiag>,
    tun_stats: Vec<TunnelDiag>,
    app_stats: Vec<TunnelDiag>,
) -> Vec<TunnelDiag> {
    let mut map: BTreeMap<(String, String), TunnelDiag> = BTreeMap::new();

    for b in bfd_list {
        let key = (b.local_ip.clone(), b.remote_ip.clone());
        map.insert(key, b);
    }

    for ts in tun_stats {
        let key = (ts.local_ip.clone(), ts.remote_ip.clone());
        let entry = map.entry(key).or_insert_with(|| TunnelDiag {
            local_ip: ts.local_ip.clone(),
            remote_ip: ts.remote_ip.clone(),
            ..Default::default()
        });
        if entry.remote_system_ip.is_empty() {
            entry.remote_system_ip = ts.remote_system_ip;
        }
        if entry.local_color.is_empty() {
            entry.local_color = ts.local_color;
        }
        if entry.remote_color.is_empty() {
            entry.remote_color = ts.remote_color;
        }
        entry.tunnel_mtu = ts.tunnel_mtu;
        entry.tcp_mss_adjust = ts.tcp_mss_adjust;
        entry.cum_tx_pkts = ts.cum_tx_pkts;
        entry.cum_rx_pkts = ts.cum_rx_pkts;
        entry.cum_tx_octets = ts.cum_tx_octets;
        entry.cum_rx_octets = ts.cum_rx_octets;
        entry.has_tunnel_stats = true;
    }

    for ar in app_stats {
        let key = (ar.local_ip.clone(), ar.remote_ip.clone());
        let entry = map.entry(key).or_insert_with(|| TunnelDiag {
            local_ip: ar.local_ip.clone(),
            remote_ip: ar.remote_ip.clone(),
            ..Default::default()
        });
        if entry.remote_system_ip.is_empty() {
            entry.remote_system_ip = ar.remote_system_ip;
        }
        if entry.local_color.is_empty() {
            entry.local_color = ar.local_color;
        }
        if entry.remote_color.is_empty() {
            entry.remote_color = ar.remote_color;
        }
        entry.sla_class_index = ar.sla_class_index;
        entry.mean_latency_ms = ar.mean_latency_ms;
        entry.mean_jitter_ms = ar.mean_jitter_ms;
        entry.mean_loss_pct = ar.mean_loss_pct;
        entry.recent_tx_data_pkts += ar.recent_tx_data_pkts;
        entry.recent_rx_data_pkts += ar.recent_rx_data_pkts;
        entry.recent_bfd_probes += ar.recent_bfd_probes;
        entry.has_app_route = true;
    }

    for td in map.values_mut() {
        compute_tunnel_averages(td);
    }

    map.into_values().collect()
}

pub fn compute_tunnel_averages(td: &mut TunnelDiag) {
    td.avg_tx_pkt_bytes = if td.cum_tx_pkts > 0 {
        td.cum_tx_octets as f64 / td.cum_tx_pkts as f64
    } else {
        0.0
    };
    td.avg_rx_pkt_bytes = if td.cum_rx_pkts > 0 {
        td.cum_rx_octets as f64 / td.cum_rx_pkts as f64
    } else {
        0.0
    };
    // BFD keepalives inside IPsec average ~118 bytes/packet; octets above 122B*pkts reflect payload bursts.
    let est_tx = estimate_data_pkts_above_bfd(td.cum_tx_pkts, td.cum_tx_octets);
    let est_rx = estimate_data_pkts_above_bfd(td.cum_rx_pkts, td.cum_rx_octets);
    td.est_cum_data_pkts = est_tx.saturating_add(est_rx);
}

fn estimate_data_pkts_above_bfd(pkts: u64, octets: u64) -> u64 {
    if pkts == 0 {
        return 0;
    }
    let avg = octets as f64 / pkts as f64;
    if avg <= 122.0 {
        return 0;
    }
    // Excess bytes over ~118B BFD baseline / ~195B average excess payload per data frame
    let baseline = pkts as f64 * 118.0;
    let excess = (octets as f64 - baseline).max(0.0);
    (excess / 150.0).round() as u64
}

pub fn is_route_chosen_installed(status: &str) -> bool {
    let tokens: Vec<String> = status
        .replace(',', " ")
        .split_whitespace()
        .map(|s| s.to_ascii_uppercase())
        .collect();
    tokens.iter().any(|t| t == "C")
        && tokens.iter().any(|t| t == "I")
        && tokens.iter().any(|t| t == "R")
}

pub fn is_route_chosen_resolved(status: &str) -> bool {
    let tokens: Vec<String> = status
        .replace(',', " ")
        .split_whitespace()
        .map(|s| s.to_ascii_uppercase())
        .collect();
    tokens.iter().any(|t| t == "C") && tokens.iter().any(|t| t == "R")
}

fn is_ipv4(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}
