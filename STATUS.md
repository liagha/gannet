# GANNET STATUS

## PHASE: Phase 3 — Identity Resolution & Hardening

### COMPLETED MODULES
- arp — raw ARP scanner (Linux) + passive /proc/net/arp fallback (Termux) — src/discovery/arp.rs
- sweep — ICMP + TCP SYN sweep for hosts outside ARP cache — src/discovery/sweep.rs
- mdns — unicast mDNS reverse, multicast passive, unicast DNS reverse — src/discovery/mdns.rs
- fingerprint — TCP SYN/ACK stack analysis (Linux raw) + connect-only stub (Termux) — src/discovery/fingerprint.rs
- oui — MAC OUI vendor lookup from embedded CSV — src/identity/oui.rs
- device — unified Device struct with ARP/Sweep origin — src/identity/device.rs
- store — persistent JSON registry, MAC-key promotion, IP history, cross-scan merge — src/identity/store.rs
- namer — deterministic adjective‑noun tag generator (FNV seeded) — src/identity/namer.rs
- net/interface — find_interface / find_source_ip with optional name filter — src/net/interface.rs
- cli/commands — scan (--subnet, --interface, --verbose), tag, list — src/cli/commands.rs
- main — thin CLI dispatch — src/main.rs

### IN PROGRESS
- None

### NEXT UP
- Passive discovery mode — `gannet listen` for non‑root/Termux hotspot use
- mDNS service enumeration — capture service types for device classification
- Device classification — combine vendor, OS hint, mDNS services into category label
- Export formats — `--json`, `--csv` output flags for scan
- Active targeting — `gannet target <tag>` to resolve identity across scans

### KNOWN ISSUES
- Termux ARP is passive only; finds only devices already in kernel cache
- Termux sweep (ICMP/TCP) fails silently without raw sockets
- Termux OS fingerprinting returns no hint (TTL inaccessible without raw sockets)
- macOS raw socket support untested (pnet datalink may fail)

### SESSION NOTES
2026‑05‑11 (pass 7 — status rewrite)
- Documented Termux/hotspot limitations clearly
- Clarified that passive discovery is the critical next feature for mobile hotspot use
- Restructured NEXT UP to reflect identity resolution priorities from PROMPT.md