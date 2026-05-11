# GANNET STATUS

## PHASE: Phase 2 - Identity Enrichment

### COMPLETED MODULES
- arp - async ARP scanner, dynamic quiet window - src/discovery/arp.rs
- sweep - ICMP + TCP SYN sweep fallback for ARP-invisible hosts - src/discovery/sweep.rs
- mdns - mDNS service browse + passive collect + unicast DNS fallback - src/discovery/mdns.rs
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
- mDNS service browse collects names from all responders on multicast group, not per-IP matched
- transmute in oui.rs is safe but can be replaced with phf crate if preferred
- sweep thread count unbounded on large subnets

### SESSION NOTES
2026-05-11
- OUI vendor lookup: IEEE database bundled as src/data/oui.csv, included at compile time
- mDNS rewritten: service browse queries + passive collect window replaces reverse PTR
- Unicast DNS kept as fallback, NBNS dropped
- Vendor column added to output table
- ArpEntry.mac field used directly for OUI lookup in main