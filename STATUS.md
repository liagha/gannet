# GANNET STATUS

## PHASE: Phase 3 — Identity Resolution & Hardening

### COMPLETED MODULES
- arp — raw ARP scanner (Linux) + passive /proc/net/arp fallback (Termux) — src/discovery/arp.rs
- sweep — ICMP + TCP SYN sweep for hosts outside ARP cache — src/discovery/sweep.rs
- mdns — unicast mDNS reverse, multicast passive, unicast DNS reverse — src/discovery/mdns.rs
- fingerprint — TCP SYN/ACK stack analysis (Linux raw) + connect-only stub (Termux) — src/discovery/fingerprint.rs
- passive — auto-tiered listener: raw socket sniff > ARP table poll > mDNS join — src/discovery/passive.rs
- oui — MAC OUI vendor lookup from embedded CSV — src/identity/oui.rs
- device — unified Device struct with ARP/Sweep origin — src/identity/device.rs
- store — persistent JSON registry, MAC-key promotion, IP history, cross-scan merge — src/identity/store.rs
- namer — deterministic adjective‑noun tag generator (FNV seeded) — src/identity/namer.rs
- net/interface — find_interface / find_source_ip with optional name filter — src/net/interface.rs
- cli/commands — scan, listen, tag, list — src/cli/commands.rs
- main — thin CLI dispatch with scan, listen, tag, list — src/main.rs

### IN PROGRESS
- None

### NEXT UP
- mDNS service enumeration — capture service types for device classification
- Device classification — combine vendor, OS hint, mDNS services into category label

### KNOWN ISSUES
- Termux ARP is passive only; finds only devices already in kernel cache
- Termux sweep (ICMP/TCP) fails silently without raw sockets
- Termux OS fingerprinting returns no hint (TTL inaccessible without raw sockets)
- macOS raw socket support untested (pnet datalink may fail)
- passive::sniff_raw uses pnet datalink; requires root on Linux
- `socket2` crate added for raw socket capability detection; may need feature flag for termux

### SESSION NOTES
2026‑05‑12
- Added `src/discovery/passive.rs` with three auto-detected tiers:
    - RawSocket: pnet datalink promiscuous sniff of ARP, IPv4, IPv6, all Ethernet frames
    - ArpTable: periodic /proc/net/arp polling + mDNS multicast join
    - MdnsOnly: mDNS multicast join with periodic service queries
- Added `listen` subcommand to CLI with --verbose flag
- Capability detection uses socket2 raw socket probe and /proc/net/arp existence check
- Passive listener writes to same JSON store as scan; assigns tags via namer
- Ctrl-C handler for graceful shutdown
- Added `socket2` dependency to Cargo.toml
- Next: test on Linux root/non-root and Termux; then mDNS service classification