# Gannet

Network device discovery and fingerprinting.

## What it does

- **ARP scan** — discover devices with MAC addresses
- **ICMP + TCP sweep** — find quieter hosts
- **mDNS resolution** — hostname discovery via unicast/multicast
- **TCP stack fingerprinting** — OS hints (TTL, window, options)
- **Persistent identity store** — tracks devices across IP changes with human-readable tags

## Status

Active development. Phase 3 complete — identity resolution working.

## Usage

```bash
# Full scan
gannet scan

# With custom subnet and interface
gannet scan --subnet 192.168.1.0/24 --interface eth0 --verbose

# List known devices
gannet list

# Tag a device
gannet tag 192.168.1.42 alice-laptop