// FILE: src/net/interface.rs
// PURPOSE: Shared network interface helpers for discovery modules
use pnet::datalink::NetworkInterface;
use std::net::{IpAddr, Ipv4Addr};

pub struct LocalInterface {
    pub name: String,
    pub ips: Vec<(Ipv4Addr, u8)>,
    pub mac: Option<pnet::util::MacAddr>,
    pub up: bool,
    pub loopback: bool,
}

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
    if let Some(iface) = find_interface(name) {
        return iface.ips.iter().find(|ip| ip.is_ipv4()).and_then(|ip| match ip.ip() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        });
    }
    find_local_source_ip(name)
}

pub fn local_interfaces() -> Vec<LocalInterface> {
    let pnet_ifaces = pnet::datalink::interfaces();
    if !pnet_ifaces.is_empty() {
        let has_any_ipv4 = pnet_ifaces.iter().any(|i| i.ips.iter().any(|ip| ip.is_ipv4()));
        if has_any_ipv4 {
            return pnet_interfaces_from(pnet_ifaces);
        }
    }
    sysfs_interfaces()
}

pub fn find_local_interface(name: Option<&str>) -> Option<LocalInterface> {
    let all = local_interfaces();
    match name {
        Some(n) => all.into_iter().find(|i| i.name == n && i.up && !i.loopback && !i.ips.is_empty()),
        None => all.into_iter().find(|i| i.up && !i.loopback && !i.ips.is_empty()),
    }
}

pub fn find_local_source_ip(name: Option<&str>) -> Option<Ipv4Addr> {
    find_local_interface(name).and_then(|iface| iface.ips.first().map(|(ip, _)| *ip))
}

fn pnet_interfaces_from(interfaces: Vec<NetworkInterface>) -> Vec<LocalInterface> {
    interfaces
        .into_iter()
        .map(|iface| {
            let ips: Vec<(Ipv4Addr, u8)> = iface.ips.iter().filter_map(|ip| {
                if let IpAddr::V4(v4) = ip.ip() {
                    Some((v4, ip.prefix()))
                } else {
                    None
                }
            }).collect();
            LocalInterface {
                name: iface.name.clone(),
                ips,
                mac: iface.mac,
                up: iface.is_up(),
                loopback: iface.is_loopback(),
            }
        })
        .collect()
}

fn sysfs_interfaces() -> Vec<LocalInterface> {
    let mut interfaces = Vec::new();
    let dirs = match std::fs::read_dir("/sys/class/net") {
        Ok(d) => d,
        Err(_) => return interfaces,
    };
    for entry in dirs.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let base = entry.path();

        let up = std::fs::read_to_string(base.join("operstate"))
            .map(|s| s.trim() == "up")
            .unwrap_or(false);
        let loopback = std::fs::read_to_string(base.join("flags"))
            .map(|s| {
                if let Ok(flags) = u32::from_str_radix(s.trim(), 16) {
                    flags & 0x8 != 0
                } else {
                    false
                }
            })
            .unwrap_or(false);

        let mac = std::fs::read_to_string(base.join("address"))
            .ok()
            .and_then(|s| parse_mac_str(s.trim()));

        let ips = read_ipv4_addrs(&name);

        interfaces.push(LocalInterface { name, ips, mac, up, loopback });
    }
    interfaces
}

fn read_ipv4_addrs(name: &str) -> Vec<(Ipv4Addr, u8)> {
    let output = match std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", name])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return read_ifconfig_addrs(name),
    };

    let mut addrs = Vec::new();
    for line in output.lines() {
        if let Some(inets) = line.split_whitespace().nth(3) {
            if let Some((ip_str, prefix_str)) = inets.split_once('/') {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    if let Ok(prefix) = prefix_str.parse::<u8>() {
                        addrs.push((ip, prefix));
                    }
                }
            }
        }
    }
    addrs
}

fn read_ifconfig_addrs(name: &str) -> Vec<(Ipv4Addr, u8)> {
    let output = match std::process::Command::new("ifconfig")
        .arg(name)
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return Vec::new(),
    };

    let mut addrs = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("inet ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            for (i, part) in parts.iter().enumerate() {
                if *part == "inet" {
                    if let Some(&ip_str) = parts.get(i + 1) {
                        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                            let prefix = parts
                                .get(i + 3)
                                .and_then(|s| s.strip_prefix("0x"))
                                .and_then(|s| u32::from_str_radix(s, 16).ok())
                                .map(|mask| mask.count_ones() as u8)
                                .unwrap_or(24);
                            addrs.push((ip, prefix));
                        }
                    }
                    break;
                }
            }
        }
    }
    addrs
}

fn parse_mac_str(s: &str) -> Option<pnet::util::MacAddr> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let bytes: Vec<u8> = parts.iter().filter_map(|p| u8::from_str_radix(p, 16).ok()).collect();
    if bytes.len() != 6 {
        return None;
    }
    Some(pnet::util::MacAddr(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]))
}
