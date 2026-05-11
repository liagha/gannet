// FILE: src/discovery/arp.rs
// PURPOSE: Async ARP scanner for device discovery on local subnet
use macaddr::MacAddr6;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: MacAddr6,
}

fn get_interface() -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4()))
}

fn subnet_iter(subnet: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    let base = u32::from(subnet) & !((1u32 << (32 - prefix)) - 1);
    let count = 1u32 << (32 - prefix);
    (0..count)
        .map(|i| Ipv4Addr::from(base + i))
        .filter(|ip| {
            let octets = ip.octets();
            octets[3] != 0 && octets[3] != 255
        })
        .collect()
}

fn send_arp_request(
    interface: &NetworkInterface,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Option<()> {
    let mut tx = match datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, _)) => tx,
        _ => return None,
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)?;
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer)?;
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);
    ethernet_packet.set_payload(arp_packet.packet());

    match tx.send_to(ethernet_packet.packet(), None) {
        Some(Ok(())) => Some(()),
        _ => None,
    }
}

fn macaddr_to_macaddr6(mac: MacAddr) -> MacAddr6 {
    let MacAddr(a, b, c, d, e, f) = mac;
    MacAddr6::new(a, b, c, d, e, f)
}

async fn receive_arp_responses(
    interface: NetworkInterface,
    hard_cap: Duration,
    quiet_window: Duration,
) -> HashSet<ArpEntry> {
    let (tx, mut rx) = mpsc::unbounded_channel();

    std::thread::spawn(move || {
        let mut channel = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(_, rx)) => rx,
            _ => return,
        };
        let deadline = Instant::now() + hard_cap;
        while Instant::now() < deadline {
            match channel.next() {
                Ok(packet) => {
                    if let Some(ethernet) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                        if ethernet.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                                if arp.get_operation() == ArpOperations::Reply {
                                    let ip = Ipv4Addr::from(arp.get_sender_proto_addr());
                                    let mac = macaddr_to_macaddr6(arp.get_sender_hw_addr());
                                    let _ = tx.send(ArpEntry { ip, mac });
                                }
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut entries = HashSet::new();
    let start = Instant::now();
    let hard_deadline = start + hard_cap;
    let mut last_seen: Option<Instant> = None;

    loop {
        let now = Instant::now();
        if now >= hard_deadline {
            break;
        }

        let quiet_expired = last_seen
            .map(|t| now.duration_since(t) >= quiet_window)
            .unwrap_or(false);

        if quiet_expired {
            break;
        }

        let remaining = hard_deadline - now;
        let poll = tokio::time::sleep(Duration::from_millis(50));

        tokio::select! {
            Some(entry) = rx.recv() => {
                entries.insert(entry);
                last_seen = Some(Instant::now());
            }
            _ = poll => {}
            _ = tokio::time::sleep(remaining) => {
                break;
            }
        }
    }

    while let Ok(entry) = rx.try_recv() {
        entries.insert(entry);
    }

    entries
}

pub async fn scan_subnet(subnet: Ipv4Addr, prefix: u8) -> Vec<ArpEntry> {
    let interface = match get_interface() {
        Some(iface) => iface,
        None => return Vec::new(),
    };

    let source_ip = match interface.ips.iter().find(|ip| ip.is_ipv4()) {
        Some(ip) => match ip.ip() {
            IpAddr::V4(v4) => v4,
            _ => return Vec::new(),
        },
        None => return Vec::new(),
    };

    let source_mac = match interface.mac {
        Some(mac) => mac,
        None => return Vec::new(),
    };

    let targets = subnet_iter(subnet, prefix);
    let recv_interface = interface.clone();

    let recv_handle = tokio::spawn(async move {
        receive_arp_responses(
            recv_interface,
            Duration::from_secs(5),
            Duration::from_millis(1500),
        )
            .await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    for target_ip in &targets {
        send_arp_request(&interface, source_ip, source_mac, *target_ip);
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    let entries = match timeout(Duration::from_secs(6), recv_handle).await {
        Ok(Ok(set)) => set,
        _ => HashSet::new(),
    };

    let mut result: Vec<ArpEntry> = entries.into_iter().collect();
    result.sort_by_key(|e| u32::from(e.ip));
    result
}