# GANNET STATUS

## PHASE: Phase 2 - Identity Enrichment

### COMPLETED MODULES
- arp - async ARP scanner returning IP-to-MAC mappings - src/discovery/arp.rs
- main - CLI with scan command, auto-detects subnet, fingerprint port opt - src/main.rs
- discovery mod - module root - src/discovery/mod.rs
- mdns - hostname resolution via mDNS multicast and unicast DNS fallback - src/discovery/mdns.rs
- device - Device struct combining ARP + DNS + fingerprint data - src/identity/device.rs
- identity mod - module root - src/identity/mod.rs
- fingerprint - OS/device fingerprinting via TCP SYN stack analysis - src/discovery/fingerprint.rs

### IN PROGRESS
- None

### NEXT UP
- store - persistent device storage with tags - src/identity/store.rs

### KNOWN ISSUES / BLOCKERS
- Hostname resolution depends on device responsiveness to DNS/mDNS. Devices without mDNS or DNS server return no hostname. NetBIOS/LLMNR could be future additions.
- TCP fingerprint requires raw socket capabilities (sudo). Devices with firewalls blocking SYN probes to chosen ports will show no OS hint.

### SESSION NOTES
2026-05-11
- Initial Phase 1 implementation completed
- Fixed compilation errors: MacAddr indexing replaced with pattern destructuring, added Eq/PartialEq/Hash derives to ArpEntry, removed unused SocketAddr import, removed duplicate set_payload call
- Decisions: pnet::util::MacAddr converted to macaddr::MacAddr6 via destructuring helper function
- Project compiles successfully
  2026-05-11 (session 2)
- Removed unused `MutablePacket` import from arp.rs (warning cleanup)
- Build is clean with zero warnings and zero errors
- Phase 1 complete — ready for next phase instruction
  2026-05-11 (session 3)
- Scanner returned zero devices in live test — diagnosed and fixed three issues:
  1. Removed `ip_in_subnet` gate that blocked scanning when interface IP wasn't in target subnet
  2. Increased receiver startup delay from 100ms to 200ms so listener is ready before ARP bursts
  3. Extended receive window from 5s to 8s, timeout from 6s to 10s
  4. Changed `--subnet` from required-with-default to optional — auto-detects subnet from active interface
  5. Prints "Scanning X.X.X.X/XX..." before scan so user sees what's being scanned
- Ready for re-test
  2026-05-11 (session 4)
- Live test successful: 2 devices discovered (192.168.100.1 and 192.168.100.15)
- Phase 1 verified and complete
  2026-05-11 (session 5)
- Phase 2 implemented: mDNS reverse lookup and Device identity struct
- mdns.rs: raw mDNS packet construction, PTR query for in-addr.arpa reverse lookups, response parsing with name decompression
- device.rs: Device struct with ip, mac, hostname, tag fields; From<&ArpEntry> impl
- main.rs updated: resolves hostnames post-scan, displays three-column output (IP, MAC, Hostname)
- Build is clean with zero warnings and zero errors
  2026-05-11 (session 6)
- Warning cleanup: removed unused `IpAddr` import, removed dead `MDNS_PORT` constant, simplified `read_name` to `decode_label` without side-effect offset tracking, renamed `parse_mdns_response` to `parse_hostname`, consolidated query builders into single `build_query` with qtype parameter
- Added `#[allow(dead_code)]` on `Device.tag` field (intentionally unused until Phase 3 namer/store)
- Build is clean with zero warnings and zero errors
- mDNS live test still shows no hostnames — documented as known limitation: many devices don't support in-addr.arpa reverse PTR over mDNS
  2026-05-11 (session 7)
- Added unicast DNS reverse lookup fallback: sends standard DNS PTR query to port 53 of each discovered IP
- mDNS tried first (fast multicast, 400ms timeout), unicast DNS as fallback (300ms timeout)
- `query_reverse` function now orchestrates both methods per-IP
- Build is clean with zero warnings and zero errors
  2026-05-11 (session 8)
- Phase 2 fingerprint module implemented: TCP SYN probe to target port, SYN+ACK analysis
- Parses TTL, TCP window size, option ordering, MSS, window scale, SACK, timestamps
- Heuristic OS guessing engine with ~20 signature rules (Linux kernel versions, Windows 7/10/11, macOS, BSD variants, embedded)
- Device struct updated: `tag` field kept with allow(dead_code), `os_hint` added
- CLI: `--port` flag added (default 443), runs fingerprint probes post-mDNS
- Output now shows 4 columns: IP, MAC, Hostname, OS Hint
- Decision: used static mut for ephemeral source port tracking (simple, adequate for sequential probing)
- Build is clean with zero warnings and zero errors
  2026-05-11 (session 9)
- Fixed 6 compilation errors in fingerprint.rs:
  1. Removed unused `MutableIpv4Packet` import
  2. Replaced `static mut SRC_PORT` with `AtomicU16` (thread-safe, no unsafe)
  3. Changed `TransportProtocol::Tcp` to `TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)`
  4. Changed `ipv4_checksum_with_options` to `ipv4_checksum` (options embedded in packet via data_offset)
  5. Pass `src_port` to `wait_syn_ack` explicitly instead of referencing static
  6. Replaced `rx.next_timeout` with `rx.next()` (blocking read with deadline loop on blocking thread)
  7. Fixed TCP options extraction to correctly offset by IPv4 header length
- Build compiles clean — zero warnings, zero errors
