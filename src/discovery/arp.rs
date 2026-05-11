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
use std::time::Duration;
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
    duration_secs: u64,
) -> HashSet<ArpEntry> {
    let (tx, mut rx) = mpsc::unbounded_channel();

    std::thread::spawn(move || {
        let mut rx = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(_, rx)) => rx,
            _ => return,
        };

        let deadline = std::time::Instant::now() + Duration::from_secs(duration_secs);

        while std::time::Instant::now() < deadline {
            match rx.next() {
                Ok(packet) => {
                    if let Some(ethernet) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                        if ethernet.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                                if arp.get_operation() == ArpOperations::Reply {
                                    let sender_ip = Ipv4Addr::from(arp.get_sender_proto_addr());
                                    let sender_mac = arp.get_sender_hw_addr();
                                    let mac = macaddr_to_macaddr6(sender_mac);
                                    let _ = tx.send(ArpEntry { ip: sender_ip, mac });
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
    let end = tokio::time::sleep(Duration::from_secs(duration_secs));
    tokio::pin!(end);

    loop {
        tokio::select! {
            Some(entry) = rx.recv() => {
                entries.insert(entry);
            }
            _ = &mut end => {
                break;
            }
        }
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
            IpAddr::V4(ipv4) => ipv4,
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
        receive_arp_responses(recv_interface, 8).await
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    for target_ip in &targets {
        send_arp_request(&interface, source_ip, source_mac, *target_ip);
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    let entries = match timeout(Duration::from_secs(10), recv_handle).await {
        Ok(Ok(set)) => set,
        _ => HashSet::new(),
    };

    let mut result: Vec<ArpEntry> = entries.into_iter().collect();
    result.sort_by_key(|e| u32::from(e.ip));
    result
}