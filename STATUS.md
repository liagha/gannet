# GANNET STATUS

## PHASE: Phase 4 — Cross-Network Discovery

### COMPLETED MODULES
- arp — raw ARP scanner (Linux) + passive /proc/net/arp fallback (Termux) — src/discovery/arp.rs
- sweep — ICMP + TCP SYN sweep for hosts outside ARP cache — src/discovery/sweep.rs
- mdns — unicast mDNS reverse, multicast passive, unicast DNS reverse + service extraction — src/discovery/mdns.rs
- fingerprint — TCP SYN/ACK stack analysis (Linux raw) + connect-only stub (Termux) — src/discovery/fingerprint.rs
- passive — auto-tiered listener: raw socket sniff > ARP table poll > mDNS join; subnet-filtered; mDNS service events — src/discovery/passive.rs
- survey — three-layer subnet discovery: passive gateway/DHCP detection, UPnP WAN/LAN interrogation, adjacent + common private sweep — src/discovery/survey.rs
- oui — MAC OUI vendor lookup from embedded CSV — src/identity/oui.rs
- device — unified Device struct with services field — src/identity/device.rs
- store — persistent JSON registry, MAC-key promotion, IP history, cross-scan merge, services merge — src/identity/store.rs
- namer — deterministic adjective‑noun tag generator (FNV seeded) — src/identity/namer.rs
- net/interface — find_interface / find_source_ip + LocalInterface with /sys/class/net fallback when pnet returns no IPv4 interfaces — src/net/interface.rs
- cli/commands — scan, survey, listen, tag, list; auto_subnet uses LocalInterface fallback; services column in output — src/cli/commands.rs
- main — thin CLI dispatch with scan, survey, listen, tag, list — src/main.rs

### IN PROGRESS
- None

### NEXT UP — Phase 4 (remaining)

#### 4b. Device classification
- Combine vendor OUI + OS hint + mDNS services → category label
- Categories: Phone, Laptop, Desktop, Router, IoT, Printer, TV/Streaming, Unknown
- mDNS service mapping: `_googlecast` → TV/Streaming, `_androidtvremote2` → TV, `_companion-link` → Phone, `_airplay` → Apple device, `_printer` → Printer, `_ssh`/`_workstation` → Laptop/Desktop
- Vendor hints: Samsung + Phone services → Phone, HUAWEI + no services → likely Router
- TTL hints: 64 → likely Linux/macOS/Android, 128 → Windows, 255 → network gear

#### 4c. Naming v2 — classification-aware tags
- Naming tiers (display priority):
  1. User alias — manual override label ("Alice's Xiaomi")
  2. mDNS hostname — self-reported name ("alice-phone.local")
  3. Classification tag — auto-generated based on category ("phone-frost-orbit")
  4. Raw tag — deterministic adjective-noun fallback ("frost-orbit")
- Stable key: MAC-based hash (never changes across IP reassignments)

#### 4d. Combined watch mode
- `gannet watch` — scan then listen, merging results live
- Immediate sweep for current state + ongoing passive collection
- Deduplication across scan and listen phases
- Live-updating table output

#### 4e. Export formats
- `--json` flag for structured output
- `--csv` flag for spreadsheet import
- Both apply to scan, list, survey, and watch

#### 4f. Interactive tagging
- `gannet tag` with no arguments → list devices, prompt for selection
- Select by number, IP, or MAC prefix
- Tag by MAC key so labels survive IP changes

### VISION — Naming Tiers
```
Layer 1: MAC hash → generated tag (always available, never changes)   "frost-orbit"
Layer 2: Vendor OUI → brand hint                                      "Xiaomi Communications Co Ltd"
Layer 3: mDNS hostname / DNS reverse → self-reported name             "alice-phone.local"
Layer 4: User alias → override label set by you                       "Alice's Xiaomi"
Layer 5: Classification → automatic category                           "Phone"
```

### VISION — Future Commands
| Command | Purpose |
|---------|---------|
| `gannet survey` | Scan beyond current subnet, discover adjacent networks |
| `gannet watch` | Combined scan + passive listen in one session |
| `gannet tag` (interactive) | Tag a device by MAC via fuzzy selection |
| `gannet classify` | Show categorized device list with categories |
| `gannet alias <tag> <name>` | Set persistent human-readable alias separate from generated tag |

### KNOWN ISSUES
- Without root/cap_net_raw, pnet can't enumerate interfaces OR open datalink channels; LocalInterface fallback reads /sys/class/net + `ip addr` for subnet detection, but raw scanning still needs root
- Termux ARP is passive only; finds only devices already in kernel cache
- Termux sweep (ICMP/TCP) fails silently without raw sockets
- Termux OS fingerprinting returns no hint (TTL inaccessible without raw sockets)
- macOS raw socket support untested (pnet datalink may fail)
- UPnP discovery requires gateway to expose IGD services; many consumer routers do but enterprise/firewalled may not
- Survey adjacent sweep probes up to ~60 subnets; full run can take 30-60 seconds depending on network latency

### SESSION NOTES
2026-05-12
- Implemented `gannet survey` with three-layer architecture:
  - Layer 1: Passive 30s listen capturing gateway IPs from ARP + DHCP server detection via UDP port 67
  - Layer 2: UPnP SSDP M-SEARCH for InternetGatewayDevice, fallback port scan for rootDesc.xml, SOAP queries for WANIPConnection/PPPConnection to extract external IPs and subnet masks
  - Layer 3: Adjacent subnet generation (up/down one /24 from current) plus common private ranges (10.x, 172.16-17.x, 192.168.x)
  - Each discovered subnet probed via sweep for live host count
- Added `url` crate dependency for UPnP URL parsing
- Survey results displayed with network, prefix, host count, discovery source, and gateway IP
- Discovered subnets with live hosts are upserted into the identity store
- No changes to existing discovery modules — survey is purely additive
