// FILE: src/net/interface.rs
// PURPOSE: Shared network interface helpers for discovery modules
use pnet::datalink::NetworkInterface;
use std::net::{IpAddr, Ipv4Addr};

fn suitable(iface: &NetworkInterface) -> bool {
    iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4())
}

pub fn find_interface(name: Option<&str>) -> Option<NetworkInterface> {
    let interfaces = pnet::datalink::interfaces();
    match name {
        Some(n) => interfaces.into_iter().find(|i| i.name == n && suitable(i)),
        None => interfaces.into_iter().find(|i| suitable(i)),
    }
}

pub fn find_source_ip(name: Option<&str>) -> Option<Ipv4Addr> {
    find_interface(name).and_then(|iface| {
        iface.ips.iter().find(|ip| ip.is_ipv4()).and_then(|ip| match ip.ip() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
    })
}