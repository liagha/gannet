// FILE: src/main.rs
// PURPOSE: Gannet CLI entry point
use clap::{Parser, Subcommand};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::str::FromStr;

mod discovery;
mod identity;

use identity::device::{Device, Via};

#[derive(Parser)]
#[command(name = "gannet")]
#[command(about = "Network device discovery and fingerprinting")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        #[arg(short, long)]
        subnet: Option<String>,
        #[arg(short, long)]
        verbose: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { subnet, verbose } => {
            let (base, prefix) = match subnet {
                Some(ref input) => parse_subnet(input),
                None => auto_subnet(),
            };
            println!("Scanning {}/{}...\n", base, prefix);

            let arp_entries = discovery::arp::scan_subnet(base, prefix).await;
            let arp_ips: HashSet<Ipv4Addr> = arp_entries.iter().map(|e| e.ip).collect();
            let sweep_results = discovery::sweep::sweep_subnet(base, prefix, &arp_ips, verbose).await;

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
            let mdns_results = discovery::mdns::resolve_bulk(&all_ips, verbose).await;

            let mut devices: Vec<Device> = arp_entries
                .iter()
                .map(|e| {
                    let mut d = Device::from(e);
                    d.vendor = identity::oui::lookup(e.mac).map(|s| s.to_string());
                    if let Some(m) = mdns_results.get(&e.ip) {
                        d.hostname = Some(m.hostname.clone());
                    }
                    d
                })
                .chain(sweep_results.iter().map(|&ip| {
                    let mut d = Device::from_sweep(ip);
                    if let Some(m) = mdns_results.get(&ip) {
                        d.hostname = Some(m.hostname.clone());
                    }
                    d
                }))
                .collect();

            if verbose {
                eprintln!("Fingerprinting TCP stacks...");
            }
            let targets: Vec<(Ipv4Addr, u16)> = devices.iter().map(|d| (d.ip, 0)).collect();
            let fingerprints = discovery::fingerprint::probe_bulk(&targets, verbose).await;

            for (ip, fp_result) in &fingerprints {
                if let Some(ref fp) = fp_result {
                    if let Some(device) = devices.iter_mut().find(|d| d.ip == *ip) {
                        device.apply_fingerprint(fp);
                    }
                }
            }

            devices.sort_by_key(|d| u32::from(d.ip));

            let (arp_devices, sweep_devices): (Vec<_>, Vec<_>) =
                devices.iter().partition(|d| d.via == Via::Arp);

            let header = format!(
                "{:<16} {:<18} {:<26} {:<30} {:<20}",
                "IP", "MAC", "Vendor", "Hostname", "OS Hint"
            );
            let rule = "-".repeat(110);

            if !arp_devices.is_empty() {
                println!("{}", header);
                println!("{}", rule);
                for d in &arp_devices {
                    let mac = d.mac.map(|m| m.to_string()).unwrap_or_else(|| "-".into());
                    let vendor = d.vendor.as_deref().unwrap_or("-");
                    let hostname = d.hostname.as_deref().unwrap_or("-");
                    let os = d.os_hint.as_deref().unwrap_or("-");
                    println!("{:<16} {:<18} {:<26} {:<30} {:<20}", d.ip, mac, vendor, hostname, os);
                }
            }

            if !sweep_devices.is_empty() {
                println!("\nAdditional hosts (no MAC):");
                println!("{}", rule);
                for d in &sweep_devices {
                    let hostname = d.hostname.as_deref().unwrap_or("-");
                    let os = d.os_hint.as_deref().unwrap_or("-");
                    println!("{:<16} {:<18} {:<26} {:<30} {:<20}", d.ip, "-", "-", hostname, os);
                }
            }

            println!("\nFound {} device(s).", devices.len());
        }
    }
}

fn auto_subnet() -> (Ipv4Addr, u8) {
    let interfaces = pnet::datalink::interfaces();
    for iface in &interfaces {
        if iface.is_up() && !iface.is_loopback() {
            for ip in &iface.ips {
                if let std::net::IpAddr::V4(ipv4) = ip.ip() {
                    let prefix = ip.prefix();
                    let base = network_base(ipv4, prefix);
                    return (base, prefix);
                }
            }
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