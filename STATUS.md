# GANNET STATUS

## PHASE: Phase 3 — Identity Resolution & Hardening

### COMPLETED MODULES
- arp — raw ARP scanner (Linux) + passive /proc/net/arp fallback (Termux) — src/discovery/arp.rs
- sweep — ICMP + TCP SYN sweep for hosts outside ARP cache — src/discovery/sweep.rs
- mdns — unicast mDNS reverse, multicast passive, unicast DNS reverse + service extraction — src/discovery/mdns.rs
- fingerprint — TCP SYN/ACK stack analysis (Linux raw) + connect-only stub (Termux) — src/discovery/fingerprint.rs
- passive — auto-tiered listener: raw socket sniff > ARP table poll > mDNS join; subnet-filtered; mDNS service events — src/discovery/passive.rs
- oui — MAC OUI vendor lookup from embedded CSV — src/identity/oui.rs
- device — unified Device struct with services field — src/identity/device.rs
- store — persistent JSON registry, MAC-key promotion, IP history, cross-scan merge, services merge — src/identity/store.rs
- namer — deterministic adjective‑noun tag generator (FNV seeded) — src/identity/namer.rs
- net/interface — find_interface / find_source_ip + LocalInterface with /sys/class/net fallback when pnet returns no IPv4 interfaces — src/net/interface.rs
- cli/commands — scan, listen, tag, list; auto_subnet uses LocalInterface fallback; services column in output — src/cli/commands.rs
- main — thin CLI dispatch with scan, listen, tag, list — src/main.rs

### IN PROGRESS
- None

### NEXT UP
- Device classification — combine vendor, OS hint, mDNS services into category label
- Deterministic naming v2 — classification-based tags (apple-tv, windows-pc) instead of random adjective-noun
- Export formats — --json, --csv output flags for scan

### KNOWN ISSUES
- Without root/cap_net_raw, pnet can't enumerate interfaces OR open datalink channels; LocalInterface fallback reads /sys/class/net + `ip addr` for subnet detection, but raw scanning still needs root
- Termux ARP is passive only; finds only devices already in kernel cache
- Termux sweep (ICMP/TCP) fails silently without raw sockets
- Termux OS fingerprinting returns no hint (TTL inaccessible without raw sockets)
- macOS raw socket support untested (pnet datalink may fail)
- `socket2` crate added for raw socket capability detection

### SESSION NOTES
2026‑05‑12
- Added LocalInterface with /sys/class/net fallback in net/interface.rs
- Fixed compile error: pnet::datalink::interfaces() is infallible (returns Vec, not Result); fallback trigger is now "pnet returned empty or no IPv4 interfaces" instead of "Result is Err"
- auto_subnet in commands.rs now tries pnet first, then LocalInterface fallback
