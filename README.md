# `tloc-explain`

Standalone, zero-warning Rust CLI (`x86_64-unknown-linux-musl` static binary) that connects to Cisco Catalyst SD-WAN routers (`cEdge` IOS-XE `17.15+`), `vSmart` controllers, or `vManage` (`20.15+`), inspects TLOC preferences, OMP routes, BFD sessions, cumulative tunnel statistics, and rolling `app-route stats`, and generates a plain-English diagnosis of transport preferencing and configuration drift.

## Capabilities

- **Plain-English Tunnel Classification:** Separates ~118-byte BFD keepalives from user payload (`tx-data-pkts` / `rx-data-pkts` and `octets / pkts` averages) to distinguish:
  - `ACTIVE PRIMARY (CARRYING DATA)`
  - `STANDBY (BFD HEARTBEAT ONLY)`
  - `HISTORICAL FAILOVER TRAFFIC (CURRENTLY IDLE)`
  - `ALERT: BACKUP/METERED CIRCUIT BLEEDING DATA`
  - `DOWN / DEGRADED`
- **Quad-Zero (`0.0.0.0/0`) & Primary Color Verdict:** Top-of-report summary answering which peer won `0.0.0.0/0` in a target Service VPN, which local/remote TLOC colors are primary, and **why** (combining VRF RIB next-hop, QFP `service-path` hardware forwarding, TLOC preferences, BFD state/multipliers, and app-route packet counters).
- **OMP Route Selection Explainer:** Explains why Service VPN prefixes installed (`C,I,R`) their winning remote TLOC and local egress transport vs. standby (`R`) paths (via `--full-omp` or offline captures).
- **Automated Drift & Risk Checks:**
  - `SLA_CLASS_INDEX_ZERO_ONLY`: Detects when `vSmart` AAR/SLA policy is not matching the router's `site-id`.
  - `ASYMMETRIC_BFD_MULTIPLIERS`: Flags mismatched `detect-multiplier` timers across active colors (e.g., `3` vs. `7`) that delay return-path convergence.
  - `BACKUP_TRANSPORT_DATA_BLEED`: Alerts when a non-primary transport carries live user traffic while primary WAN is up.
  - `EQUAL_TLOC_PREFERENCE_ECMP`: Flags identical TLOC preferences causing unintended ECMP onto metered circuits.
  - `REMOTE_TLOC_PREF_UNSET_ZERO` & `BFD_SESSION_DOWN` / `BFD_SESSION_FLAPPED`.
- **Zero External Build or Runtime Crates Needed:**
  - Pure-Rust dependency tree (`serde`, `serde_json`, `regex` — zero `ring`, zero `cc`, zero OpenSSL/tokio C-toolchain requirements). All 20 crates are **vendored right in [`vendor/`](vendor/)** with [`.cargo/config.toml`](.cargo/config.toml), alongside a pre-built static [`tloc-explain`](tloc-explain) binary, [`install.sh`](install.sh), and a self-contained Debian package [`dist/tloc-explain_0.1.0_amd64.deb`](dist/tloc-explain_0.1.0_amd64.deb).
- **Direct Router First (No vManage Required):**
  - **Direct Router SSH (default):** `tloc-explain <router-ip> -u <user>` connects straight to a `cEdge` (or `--vsmart`) via native OpenSSH. By default, it skips slow `show sdwan omp routes` / `show sdwan omp tlocs` dumps (avoiding SSH timeouts on large routing tables), targets the specified `--vpn <id>` (or auto-selects the first active Service VRF from `show vrf`), resolves `0.0.0.0/0` directly from `show ip route vrf <vpn> 0.0.0.0 0.0.0.0` + QFP `show sdwan policy service-path ...` using the VRF LAN interface, and automatically scopes `show sdwan app-route stats remote-system-ip` onto the `0.0.0.0/0` winning peer (unless `--discover`, `--all-tunnels`, or an explicit `--peer <sys-ip|wan-ip>` is passed). Pass `--full-omp` only when full OMP tables are needed. Continuously drains stdout/stderr pipes, steps command-by-command after each router prompt (`120s` default timeout, configurable via `--timeout <secs>`), auto-advances `--More--`, and writes a per-step diagnostic log to `~/.cache/tloc-explain/tloc-explain-debug.log` (use `-v` / `--debug` for live step timing). Supports SSH keys (`-i <keyfile>`), hidden interactive `/dev/tty` password prompting (`stty -echo`, `-P`/`--ask-pass`), or `TLOC_SSH_PASS` / `ROUTER_SSH_PASS` / `--password-env <VAR>` via ephemeral `0700` `SSH_ASKPASS` in `~/.cache/tloc-explain/` (safe on DISA STIG `/tmp noexec` hosts).
  - **`file`:** Parses offline CLI captures cleanly.
  - **`vmanage` (optional):** Queries `vManage` real-time APIs concurrently (`std::thread::scope` + native `curl`, no `reqwest`/`rustls` crates required) across one device or `--device all`.

## Install (Offline / Zero-Dependency Options)

Choose any method — all dependencies are carried inside the repo:

```bash
# Option 1: Install pre-built static binary directly (no Rust toolchain needed)
./install.sh

# Option 2: Install self-contained Debian/Ubuntu .deb package
sudo dpkg -i dist/tloc-explain_0.1.0_amd64.deb

# Option 3: Rebuild completely offline from vendored crates in ./vendor
./install.sh --build
# or: cargo build --release --offline
```

## Usage Examples

```bash
# 1. Fast default 0.0.0.0/0 & primary color verdict for one Service VPN (RIB + QFP service-path, skips slow OMP dumps)
tloc-explain 10.10.1.21 -u admin --vpn 1000
tloc-explain 10.10.1.21 -u admin

# 2. Compact discovery on a busy hub/branch (identifies active peer, 0.0.0.0/0 winner & VPNs)
tloc-explain 10.10.1.21 -u admin --discover

# 3. Focus full analysis & router-side app-route stats on ONE specific peer & Service VPN
tloc-explain 10.10.1.21 -u admin --vpn 1000 --peer 10.255.1.1

# 4. Include full OMP route/TLOC tables (when needed; may take longer on large routers)
tloc-explain 10.10.1.21 -u admin --vpn 1000 --full-omp --timeout 180 -v

# Authenticate with an SSH private key or force hidden password prompt
tloc-explain 10.10.1.21 -u admin -i ~/.ssh/id_ed25519
tloc-explain 10.10.1.21 -u admin -P --all-tunnels -v

# Export Markdown or inspect a vSmart controller
tloc-explain 172.16.1.21 -u admin --peer 10.255.1.11 --markdown /tmp/border1.md
tloc-explain 172.16.1.12 -u admin --vsmart

# Analyze an offline CLI capture file
tloc-explain file capture.txt --hostname site101-kit1 --system-ip 10.255.1.11 --site-id 1011

# Optional: explain all reachable WAN Edges via vManage API
tloc-explain vmanage --device all
```
