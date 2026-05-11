# GANNET STATUS

## PHASE: Phase 2 - Identity Enrichment

### COMPLETED MODULES
- arp - raw ARP scanner (Linux) + /proc/net/arp reader (Termux) - src/discovery/arp.rs
- sweep - ICMP+TCP SYN (Linux) + TCP connect (Termux) - src/discovery/sweep.rs
- mdns - unicast mDNS + multicast passive + DNS reverse - src/discovery/mdns.rs
- fingerprint - SYN/ACK analysis (Linux) + connect-only stub (Termux) - src/discovery/fingerprint.rs
- oui - MAC OUI vendor lookup - src/identity/oui.rs
- device - Device struct - src/identity/device.rs
- store - persistent JSON registry - src/identity/store.rs
- namer - FNV-seeded adjective-noun tag generator - src/identity/namer.rs
- main - scan/tag/list commands with ASCII banner - src/main.rs

### IN PROGRESS
- None

### NEXT UP
- cli refactor - move subcommand handlers out of main.rs into src/cli/
- net/interface - deduplicate find_source_ip (copied across arp/sweep/fingerprint)

### KNOWN ISSUES / BLOCKERS
- Termux ARP is passive only (/proc/net/arp); won't find devices not yet in kernel cache
- Termux fingerprinting returns no OS hint; TTL not accessible without raw sockets
- transmute in oui.rs is safe but replaceable with phf
- sweep thread count unbounded on large subnets

### SESSION NOTES
2026-05-11 (pass 2)
- Removed stray top-level `use std::net::Ipv4Addr` from fingerprint.rs (only needed inside mod raw)
- Dropped probe_syn from pub use re-exports; probe_bulk is the only public surface, probe_syn is internal
- Made probe_syn private (no pub) in both raw and ttl_only modules
- Added #![allow(dead_code)] at crate root in main.rs to suppress scaffolding warnings for
  StackFingerprint fields, TcpOptionKind variants, FingerprintResult::syn_ack, Store::get
  (all intentional forward-looking API surface, not actual dead code)
- Both `cargo build --features raw` and `cargo build --features termux` now produce zero warnings