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
- classify — device category classification combining vendor OUI, OS hint, mDNS services, and hostname heuristics — src/identity/classify.rs
- device — unified Device struct with services field, classification method — src/identity/device.rs
- store — persistent JSON registry, MAC-key promotion, IP history, cross-scan merge, services merge, category persistence — src/identity/store.rs
- namer — deterministic adjective‑noun tag generator (FNV seeded) — src/identity/namer.rs
- net/interface — find_interface / find_source_ip + LocalInterface with /sys/class/net fallback when pnet returns no IPv4 interfaces — src/net/interface.rs
- cli/commands — scan, survey, listen, tag, list; classification integration in scan and list outputs — src/cli/commands.rs
- main — thin CLI dispatch with scan, survey, listen, tag, list — src/main.rs

### IN PROGRESS
- None

### NEXT UP — Phase 4 (remaining)

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
- Classification heuristics rely on vendor strings, mDNS service names, and OS hints — may misclassify devices with ambiguous signatures

### SESSION NOTES
2026-07-13
- Implemented device classification module (src/identity/classify.rs):
  - Seven categories: Phone, Laptop, Desktop, Router, IoT, Printer, TV/Streaming, Unknown
  - Multi-source classification pipeline: mDNS services > vendor OUI > hostname > OS hint > vendor keyword fallbacks
  - Service mappings: _googlecast/_androidtvremote2 → TV, _companion-link → Phone, _printer → Printer, _workstation/_ssh → Laptop
  - Vendor mappings: Cisco/Ubiquiti/TP-Link → Router, Raspberry/Espressif → IoT, Samsung/LG/Sony → TV
  - Hostname heuristics: "phone"/"iphone" → Phone, "tv"/"roku" → TV, "sensor"/"shelly" → IoT
  - OS hint heuristics: Windows → Desktop, Android/iOS → Phone, BSD/Solaris → Router, Embedded → IoT
  - Category enum serializes with serde for store persistence
- Integrated classification into Device struct:
  - Added `category: Option<Category>` field to Device
  - Added `classify()` method that runs the classification pipeline
  - Classification runs during scan after fingerprinting but before store upsert
- Updated Store to persist categories:
  - Added `category` field to Record
  - `merge_category()` helper prefers non-Unknown categories when merging records
  - Categories survive IP changes and cross-scan merges
- Updated CLI output:
  - scan: added Category column between OS Hint and Services
  - list: added Category column between Vendor and Hostname
  - Column widths adjusted for 160-char display in scan, 140-char in list
- All existing tests pass; no breaking changes to discovery modules
- Next: classification-aware tag generation (4c), watch mode (4d)