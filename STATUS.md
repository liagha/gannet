# GANNET STATUS

## PHASE: Phase 2 - Identity Enrichment

### COMPLETED MODULES
- arp - async ARP scanner, dynamic quiet window - src/discovery/arp.rs
- sweep - ICMP + TCP SYN sweep fallback for ARP-invisible hosts - src/discovery/sweep.rs
- mdns - per-IP unicast mDNS + multicast passive + DNS reverse fallback - src/discovery/mdns.rs
- fingerprint - parallel SYN probes on 443/80/22 - src/discovery/fingerprint.rs
- oui - MAC OUI vendor lookup from bundled IEEE database - src/identity/oui.rs
- device - Device struct with vendor, via, optional MAC - src/identity/device.rs
- store - persistent JSON registry; upsert, tag override, list - src/identity/store.rs
- namer - FNV-seeded adjective-noun tag generator - src/identity/namer.rs
- main - scan/tag/list commands with Tag column and store persistence - src/main.rs

### IN PROGRESS
- None

### NEXT UP
- cli refactor - move subcommand handlers out of main.rs into src/cli/ - src/cli/
- net/interface - shared interface/source-IP resolution (currently duplicated across arp/sweep/fingerprint)

### KNOWN ISSUES / BLOCKERS
- ARP retry pass uses a fixed 1500ms delay before retry; could be adaptive
- transmute in oui.rs is safe but can be replaced with phf crate if preferred
- sweep thread count unbounded on large subnets
- fingerprinting still returning no OS hints; likely firewall on test devices
- store.set_tag uses IP fallback key for sweep devices; a MAC lookup after the fact won't match

### SESSION NOTES
2026-05-11
- Implemented store: persistent JSON, keyed by MAC hex (or IP string for sweep), first/last seen timestamps, seen_count, tag
- Implemented namer: FNV hash of key -> adjective + noun, deterministic and stable across sessions
- main: added --store path, scan upserts all devices and shows Tag column, new `tag` subcommand overrides a device's name, new `list` subcommand dumps store sorted by recency
- Added serde + serde_json to Cargo.toml