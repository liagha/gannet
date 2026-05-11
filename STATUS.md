# GANNET STATUS

## PHASE: Phase 2 - Identity Enrichment

### COMPLETED MODULES
- arp - async ARP scanner, dynamic quiet window - src/discovery/arp.rs
- sweep - ICMP + TCP SYN sweep fallback for ARP-invisible hosts - src/discovery/sweep.rs
- mdns - per-IP unicast mDNS + multicast passive + DNS reverse fallback - src/discovery/mdns.rs
- fingerprint - parallel SYN probes on 443/80/22 - src/discovery/fingerprint.rs
- oui - MAC OUI vendor lookup from bundled IEEE database - src/identity/oui.rs
- device - Device struct with vendor, via, optional MAC - src/identity/device.rs
- main - scan command with Vendor column, split ARP/sweep output - src/main.rs

### IN PROGRESS
- None

### NEXT UP
- store - persistent device storage with tags - src/identity/store.rs
- namer - human-readable tag assignment for devices - src/identity/namer.rs

### KNOWN ISSUES / BLOCKERS
- ARP retry pass uses a fixed 1500ms delay before retry; could be adaptive
- transmute in oui.rs is safe but can be replaced with phf crate if preferred
- sweep thread count unbounded on large subnets
- fingerprinting still returning no OS hints; likely firewall on test devices

### SESSION NOTES
2026-05-11
- Diagnosed inconsistent device count: ARP quiet window too short for WiFi reply latency
- ARP: quiet window 1500->2500ms, hard cap 5->8s, added retry pass at 1.5s mark
- Diagnosed bad hostnames: passive multicast collect not filtered by source IP
- mDNS: switched to unicast queries sent directly to target IP:5353, filter recv by source
- Added TXT record parsing for fn=/n= friendly name fields (Chromecast/Android)
- Added is_service_label filter; best_hostname scorer prefers proper device names
- multicast_passive retained but now also filters by source IP