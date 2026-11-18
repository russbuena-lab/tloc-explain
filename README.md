# `tloc-explain`

Standalone, zero-warning Rust CLI (`x86_64-unknown-linux-musl` static binary) that connects to Cisco Catalyst SD-WAN routers (`cEdge` IOS-XE `17.15+`), `vSmart` controllers, or `vManage` (`20.15+`), inspects TLOC preferences, OMP routes, BFD sessions, cumulative tunnel statistics, and rolling `app-route stats`, and generates a plain-English diagnosis of transport preferencing and configuration drift.

## Capabilities

- **Plain-English Tunnel Classification:** Separates ~118-byte BFD keepalives from user payload (`tx-data-pkts` / `rx-data-pkts` and `octets / pkts` averages) to distinguish:
  - `ACTIVE PRIMARY (CARRYING DATA)`
  - `STANDBY (BFD HEARTBEAT ONLY)`
  - `HISTORICAL FAILOVER TRAFFIC (CURRENTLY IDLE)`
  - `ALERT: BACKUP/METERED CIRCUIT BLEEDING DATA`
  - `DOWN / DEGRADED`
- **OMP Route Selection Explainer:** Explains why each service VPN prefix installed (`C,I,R`) its winning remote TLOC and local egress transport vs. standby (`R`) paths.
- **Automated Drift & Risk Checks:**
  - `SLA_CLASS_INDEX_ZERO_ONLY`: Detects when `vSmart` AAR/SLA policy is not matching the router's `site-id`.
  - `ASYMMETRIC_BFD_MULTIPLIERS`: Flags mismatched `detect-multiplier` timers across active colors (e.g., `3` vs. `7`) that delay return-path convergence.
  - `BACKUP_TRANSPORT_DATA_BLEED`: Alerts when a non-primary transport carries live user traffic while primary WAN is up.
  - `EQUAL_TLOC_PREFERENCE_ECMP`: Flags identical TLOC preferences causing unintended ECMP onto metered circuits.
  - `REMOTE_TLOC_PREF_UNSET_ZERO` & `BFD_SESSION_DOWN` / `BFD_SESSION_FLAPPED`.
- **Three Input Modes:**
  - `vmanage`: Queries `vManage` real-time APIs concurrently (`tokio::join!`) across one device or `--device all`.
  - `ssh`: Connects directly to a `cEdge` or `--vsmart` router using read-only `show` commands via ephemeral `0700` `SSH_ASKPASS` (zero password exposure on `argv`).
  - `file`: Parses offline CLI captures cleanly.

## Build & Install

```bash
cargo check
cargo clippy -- -D warnings
cargo test
CC_x86_64_unknown_linux_musl=gcc cargo build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/tloc-explain ~/.local/bin/tloc-explain
```

## Usage Examples

```bash
# Explain all reachable WAN Edges via vManage
tloc-explain vmanage --device all

# Export Markdown report for a single site
tloc-explain vmanage --device site101-kit1 --markdown /tmp/site101-kit1.md

# Connect directly to a cEdge router or vSmart over SSH
tloc-explain ssh 10.10.1.21 -u admin --vpn 1000
tloc-explain ssh 172.16.1.12 -u admin --vsmart

# Analyze an offline CLI capture file
tloc-explain file capture.txt --hostname site101-kit1 --system-ip 10.255.1.11 --site-id 1011
```
