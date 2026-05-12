// FILE: src/cli/commands.rs
// FILE: src/cli/commands.rs
// PURPOSE: Subcommand handlers for scan, survey, listen, tag, list
use crate::identity::device::{Device, Via};
use crate::identity::store::Store;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;

const BANNER: &str = r#"
  __ _  __ _ _ __  _ __   ___| |_
 / _` |/ _` | '_ \| '_ \ / _ \ __|
| (_| | (_| | | | | | | |  __/ |_
 \__, |\__,_|_| |_|_| |_|\___|\__|
 |___/
"#;

pub async fn scan(subnet: Option<String>, interface: Option<String>, verbose: bool, store_path: PathBuf) {
    println!("{}", BANNER);

    let (base, prefix) = match subnet {
        Some(ref input) => parse_subnet(input),
        None => auto_subnet(interface.as_deref()),
    };
    println!("Scanning {}/{}...\n", base, prefix);

    let iface_ref = interface.as_deref();

    let arp_entries = crate::discovery::arp::scan_subnet(base, prefix, iface_ref).await;
    let arp_ips: HashSet<Ipv4Addr> = arp_entries.iter().map(|e| e.ip).collect();
    let sweep_results =
        crate::discovery::sweep::sweep_subnet(base, prefix, &arp_ips, iface_ref, verbose).await;

    let all_ips: Vec<Ipv4Addr> = arp_entries
        .iter()
        .map(|e| e.ip)
        .chain(sweep_results.iter().copied())
        .collect();

    if all_ips.is_empty() {
        println!("No devices found.");
        return;
    }

    if verbose {
        eprintln!("Resolving hostnames...");
    }
    let mdns_results = crate::discovery::mdns::resolve_bulk(&all_ips, verbose).await;

    let mut devices: Vec<Device> = arp_entries
        .iter()
        .map(|e| {
            let mut d = Device::from(e);
            d.vendor = crate::identity::oui::lookup(e.mac).map(|s| s.to_string());
            if let Some(m) = mdns_results.get(&e.ip) {
                d.hostname = Some(m.hostname.clone());
                d.services = m.services.clone();
            }
            d
        })
        .chain(sweep_results.iter().map(|&ip| {
            let mut d = Device::from_sweep(ip);
            if let Some(m) = mdns_results.get(&ip) {
                d.hostname = Some(m.hostname.clone());
                d.services = m.services.clone();
            }
            d
        }))
        .collect();

    if verbose {
        eprintln!("Fingerprinting TCP stacks...");
    }
    let targets: Vec<(Ipv4Addr, u16)> = devices.iter().map(|d| (d.ip, 0)).collect();
    let fingerprints = crate::discovery::fingerprint::probe_bulk(&targets, iface_ref, verbose).await;

    for (ip, fp_result) in &fingerprints {
        if let Some(ref fp) = fp_result {
            if let Some(device) = devices.iter_mut().find(|d| d.ip == *ip) {
                device.apply_fingerprint(fp);
            }
        }
    }

    devices.sort_by_key(|d| u32::from(d.ip));

    let mut store = Store::load(&store_path);

    let tagged: Vec<(&Device, String)> = devices
        .iter()
        .map(|d| {
            let record = store.upsert(d, crate::identity::namer::generate);
            let tag = record.tag.clone().unwrap_or_else(|| "-".into());
            (d, tag)
        })
        .collect();

    if let Err(e) = store.save(&store_path) {
        eprintln!("Warning: could not save store: {}", e);
    }

    let (arp_tagged, sweep_tagged): (Vec<_>, Vec<_>) =
        tagged.iter().partition(|(d, _)| d.via == Via::Arp);

    let header = format!(
        "{:<16} {:<18} {:<26} {:<22} {:<20} {:<20} {}",
        "IP", "MAC", "Vendor", "Tag", "Hostname", "OS Hint", "Services"
    );
    let rule = "-".repeat(140);

    if !arp_tagged.is_empty() {
        println!("{}", header);
        println!("{}", rule);
        for (d, tag) in &arp_tagged {
            let mac = d.mac.map(|m| m.to_string()).unwrap_or_else(|| "-".into());
            let vendor = d.vendor.as_deref().unwrap_or("-");
            let hostname = d.hostname.as_deref().unwrap_or("-");
            let os = d.os_hint.as_deref().unwrap_or("-");
            let svc = if d.services.is_empty() {
                "-".to_string()
            } else {
                d.services.join(", ")
            };
            println!(
                "{:<16} {:<18} {:<26} {:<22} {:<20} {:<20} {}",
                d.ip, mac, vendor, tag, hostname, os, svc
            );
        }
    }

    if !sweep_tagged.is_empty() {
        println!("\nAdditional hosts (no MAC):");
        println!("{}", rule);
        for (d, tag) in &sweep_tagged {
            let hostname = d.hostname.as_deref().unwrap_or("-");
            let os = d.os_hint.as_deref().unwrap_or("-");
            let svc = if d.services.is_empty() {
                "-".to_string()
            } else {
                d.services.join(", ")
            };
            println!(
                "{:<16} {:<18} {:<26} {:<22} {:<20} {:<20} {}",
                d.ip, "-", "-", tag, hostname, os, svc
            );
        }
    }

    println!("\nFound {} device(s).", devices.len());
}

pub async fn survey(interface: Option<String>, verbose: bool, store_path: PathBuf) {
    println!("{}", BANNER);
    println!("Surveying networks...\n");

    let subnets = crate::discovery::survey::survey(interface, verbose).await;

    if subnets.is_empty() {
        println!("No additional networks discovered.");
        return;
    }

    let header = format!(
        "{:<20} {:<8} {:<10} {:<18} {:<18}",
        "Network", "Prefix", "Hosts", "Source", "Gateway"
    );
    let rule = "-".repeat(80);

    println!("{}", header);
    println!("{}", rule);

    let mut live_count = 0;
    for subnet in &subnets {
        let host_str = subnet.host_count.map(|c| c.to_string()).unwrap_or_else(|| "?".into());
        let source_str = format!("{:?}", subnet.source);
        let gateway_str = subnet.gateway.map(|g| g.to_string()).unwrap_or_else(|| "-".into());

        println!(
            "{:<20} /{:<7} {:<10} {:<18} {:<18}",
            subnet.network, subnet.prefix, host_str, source_str, gateway_str
        );

        if let Some(count) = subnet.host_count {
            live_count += count;
        }
    }

    let mut store = Store::load(&store_path);
    let mut discovered_any = false;

    for subnet in &subnets {
        if subnet.host_count.unwrap_or(0) > 0 {
            let device = Device::from_sweep(subnet.network);
            let _ = store.upsert(&device, crate::identity::namer::generate);
            discovered_any = true;
        }
    }

    if discovered_any {
        if let Err(e) = store.save(&store_path) {
            eprintln!("Warning: could not save store: {}", e);
        }
    }

    println!("\n{} network(s) found, {} live host(s).", subnets.len(), live_count);
}

pub async fn listen(interface: Option<String>, verbose: bool, store_path: PathBuf) {
    println!("{}", BANNER);
    crate::discovery::passive::listen(interface, verbose, store_path).await;
}

pub fn tag(ip: String, tag: String, store_path: PathBuf) {
    let mut store = Store::load(&store_path);
    let ip_addr = Ipv4Addr::from_str(&ip).unwrap_or_else(|_| {
        eprintln!("Invalid IP: {}", ip);
        std::process::exit(1);
    });
    if store.set_tag(None, ip_addr, tag.clone()) {
        store.save(&store_path).ok();
        println!("Tagged {} as \"{}\".", ip, tag);
    } else {
        println!("No record found for {}.", ip);
    }
}

pub fn list(store_path: PathBuf) {
    let store = Store::load(&store_path);
    let mut records: Vec<_> = store.all().collect();
    records.sort_by_key(|r| r.last_seen);
    records.reverse();

    let header = format!(
        "{:<22} {:<16} {:<18} {:<26} {:<20} {}",
        "Tag", "Last IP", "MAC", "Vendor", "Hostname", "Services"
    );
    let rule = "-".repeat(120);
    println!("{}", header);
    println!("{}", rule);
    for r in &records {
        let tag = r.tag.as_deref().unwrap_or("-");
        let mac = r.mac.as_deref().unwrap_or("-");
        let vendor = r.vendor.as_deref().unwrap_or("-");
        let hostname = r.hostname.as_deref().unwrap_or("-");
        let svc = if r.services.is_empty() {
            "-".to_string()
        } else {
            r.services.join(", ")
        };
        println!(
            "{:<22} {:<16} {:<18} {:<26} {:<20} {}",
            tag, r.last_ip, mac, vendor, hostname, svc
        );
    }
    println!("\n{} device(s) in store.", records.len());
}

fn auto_subnet(iface: Option<&str>) -> (Ipv4Addr, u8) {
    if let Some(iface) = crate::net::interface::find_interface(iface) {
        for ip in &iface.ips {
            if let std::net::IpAddr::V4(ipv4) = ip.ip() {
                let prefix = ip.prefix();
                let base = network_base(ipv4, prefix);
                return (base, prefix);
            }
        }
    }
    if let Some(local) = crate::net::interface::find_local_interface(iface) {
        if let Some((ip, prefix)) = local.ips.first() {
            return (network_base(*ip, *prefix), *prefix);
        }
    }
    eprintln!("No active IPv4 interface found. Using default 192.168.1.0/24.");
    (Ipv4Addr::new(192, 168, 1, 0), 24)
}

fn network_base(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = !((1u32 << (32 - prefix)) - 1);
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn parse_subnet(input: &str) -> (Ipv4Addr, u8) {
    if let Some((ip_str, prefix_str)) = input.split_once('/') {
        let ip = Ipv4Addr::from_str(ip_str).unwrap_or_else(|_| {
            eprintln!("Invalid IP: {}", ip_str);
            std::process::exit(1);
        });
        let prefix = prefix_str.parse::<u8>().unwrap_or_else(|_| {
            eprintln!("Invalid prefix: {}", prefix_str);
            std::process::exit(1);
        });
        if prefix > 32 {
            eprintln!("Prefix must be 0-32");
            std::process::exit(1);
        }
        (ip, prefix)
    } else {
        eprintln!("Invalid subnet format. Use: 192.168.1.0/24");
        std::process::exit(1);
    }
}