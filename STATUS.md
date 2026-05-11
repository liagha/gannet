# GANNET STATUS

## PHASE: Phase 2 - Identity Enrichment

### COMPLETED MODULES
- arp - async ARP scanner returning IP-to-MAC mappings - src/discovery/arp.rs
- main - CLI with scan command, auto-detects subnet, --verbose flag - src/main.rs
- discovery mod - module root - src/discovery/mod.rs
- mdns - hostname resolution via mDNS, unicast DNS, NetBIOS in parallel per IP - src/discovery/mdns.rs
- device - Device struct combining ARP + DNS + fingerprint data - src/identity/device.rs
- identity mod - module root - src/identity/mod.rs
- fingerprint - OS fingerprinting via parallel SYN probes on ports 443/80/22 - src/discovery/fingerprint.rs

### IN PROGRESS
- None

### NEXT UP
- store - persistent device storage with tags - src/identity/store.rs
- namer - human-readable tag assignment for devices - src/identity/namer.rs

### KNOWN ISSUES / BLOCKERS
- TCP fingerprint requires sudo; firewall may block all three fallback ports
- NBNS parser uses fixed offset (56 bytes); malformed responses may be silently dropped

### SESSION NOTES
2026-05-11
- ARP: dynamic quiet window (1.5s after last reply, 5s hard cap) replaces fixed 8s window
- mDNS: all IPs resolved in parallel via JoinSet; mDNS + unicast DNS + NBNS run in parallel threads per IP
- NetBIOS (NBNS) added as third hostname resolver covering Windows/IoT devices
- Fingerprint: parallel SYN probes on ports 443, 80, 22 per device; first SYN+ACK wins
- All devices fingerprinted in parallel via JoinSet
- --port flag removed; ports are now internal to fingerprint module
- Typical scan time reduced from ~10s to ~3-4s on quiet networks