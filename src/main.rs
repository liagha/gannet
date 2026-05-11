// FILE: src/main.rs
// PURPOSE: Gannet CLI entry point
use clap::{Parser, Subcommand};
use std::net::Ipv4Addr;
use std::str::FromStr;

mod discovery;
mod identity;

use identity::device::Device;

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
        #[arg(short, long, default_value = "443")]
        port: u16,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { subnet, port } => {
            let (base, prefix) = match subnet {
                Some(ref input) => parse_subnet(input),
                None => auto_subnet(),
            };
            println!("Scanning {}/{}...\n", base, prefix);
            let entries = discovery::arp::scan_subnet(base, prefix).await;

            if entries.is_empty() {
                println!("No devices found.");
                return;
            }

            let ips: Vec<Ipv4Addr> = entries.iter().map(|e| e.ip).collect();
            println!("Resolving mDNS hostnames...");
            let mdns_results = discovery::mdns::resolve_bulk(&ips).await;

            let mut devices: Vec<Device> = entries
                .iter()
                .map(|e| {
                    let mut device = Device::from(e);
                    if let Some(mdns) = mdns_results.get(&e.ip) {
                        device.hostname = Some(mdns.hostname.clone());
                    }
                    device
                })
                .collect();

            println!("Fingerprinting TCP stacks (port {})...", port);
            let targets: Vec<(Ipv4Addr, u16)> = devices.iter().map(|d| (d.ip, port)).collect();
            let fingerprints = discovery::fingerprint::probe_bulk(&targets).await;

            for (ip, fp_result) in &fingerprints {
                if let Some(ref fp) = fp_result {
                    if let Some(device) = devices.iter_mut().find(|d| d.ip == *ip) {
                        device.apply_fingerprint(fp);
                    }
                }
            }

            devices.sort_by_key(|d| u32::from(d.ip));

            println!(
                "\n{:<16} {:<18} {:<30} {:<24}",
                "IP", "MAC", "Hostname", "OS Hint"
            );
            println!("{}", "-".repeat(88));
            for device in &devices {
                let hostname = device.hostname.as_deref().unwrap_or("-");
                let os_hint = device.os_hint.as_deref().unwrap_or("-");
                println!(
                    "{:<16} {:<18} {:<30} {:<24}",
                    device.ip, device.mac, hostname, os_hint
                );
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
