// FILE: src/discovery/mdns.rs
// PURPOSE: Hostname resolution via mDNS service browse and passive announcement capture
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use tokio::task::JoinSet;

#[derive(Debug, Clone)]
pub struct MdnsResult {
    pub hostname: String,
}

const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

fn build_ptr_query(name: &str, transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    for label in name.split('.') {
        if label.is_empty() { continue; }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x0C]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet
}

fn decode_label(data: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut end_pos = None;
    loop {
        if pos >= data.len() { return None; }
        if !visited.insert(pos) { return None; }
        let byte = data[pos];
        if byte == 0x00 {
            if end_pos.is_none() { end_pos = Some(pos + 1); }
            break;
        }
        if byte & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() { return None; }
            if end_pos.is_none() { end_pos = Some(pos + 2); }
            let ptr = u16::from_be_bytes([byte & 0x3F, data[pos + 1]]) as usize;
            pos = ptr;
            continue;
        }
        let len = byte as usize;
        pos += 1;
        let end = pos + len;
        if end > data.len() { return None; }
        parts.push(String::from_utf8_lossy(&data[pos..end]).into_owned());
        pos = end;
    }
    Some((parts.join("."), end_pos.unwrap_or(pos + 1)))
}

fn extract_device_name(label: &str) -> Option<String> {
    let part = label.split('.').next()?;
    let cleaned = part.trim_start_matches('_');
    if cleaned.is_empty() || cleaned.starts_with("_") {
        return None;
    }
    Some(cleaned.to_string())
}

fn parse_mdns_names(data: &[u8]) -> Vec<String> {
    if data.len() < 12 { return Vec::new(); }

    let questions = u16::from_be_bytes([data[4], data[5]]) as usize;
    let answer_rrs = u16::from_be_bytes([data[6], data[7]]) as usize;
    let authority_rrs = u16::from_be_bytes([data[8], data[9]]) as usize;
    let additional_rrs = u16::from_be_bytes([data[10], data[11]]) as usize;
    let total_rrs = answer_rrs + authority_rrs + additional_rrs;

    if total_rrs == 0 { return Vec::new(); }

    let mut pos = 12usize;
    let mut names = Vec::new();

    for _ in 0..questions {
        if let Some((_, next)) = decode_label(data, pos) {
            pos = next + 4;
        } else {
            break;
        }
    }

    for _ in 0..total_rrs {
        if pos >= data.len() { break; }

        let name_result = decode_label(data, pos);
        let (name, next) = match name_result {
            Some(pair) => pair,
            None => break,
        };
        pos = next;

        if pos + 10 > data.len() { break; }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        match rtype {
            0x000C => {
                if let Some((rdata_name, _)) = decode_label(data, pos) {
                    if let Some(device) = extract_device_name(&rdata_name) {
                        if !device.is_empty() {
                            names.push(device);
                        }
                    }
                }
            }
            0x0021 => {
                if pos + 6 < data.len() {
                    if let Some((host, _)) = decode_label(data, pos + 6) {
                        let h = host.trim_end_matches(".local").trim_end_matches('.');
                        if !h.is_empty() {
                            names.push(h.to_string());
                        }
                    }
                }
            }
            0x0001 => {
                if !name.is_empty() && !name.starts_with('_') {
                    let h = name.trim_end_matches(".local").trim_end_matches('.');
                    if !h.is_empty() {
                        names.push(h.to_string());
                    }
                }
            }
            _ => {}
        }

        pos += rdlen;
    }

    names
}

fn mdns_socket() -> Option<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).ok()?;
    socket.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED).ok()?;
    socket.set_multicast_ttl_v4(255).ok()?;
    Some(socket)
}

fn query_service_browse(socket: &UdpSocket, service: &str) {
    let query = build_ptr_query(service, 0);
    let target = SocketAddr::new(IpAddr::V4(MULTICAST_ADDR), MDNS_PORT);
    let _ = socket.send_to(&query, target);
}

fn passive_collect(socket: &UdpSocket, window: Duration) -> Vec<String> {
    socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
    let deadline = std::time::Instant::now() + window;
    let mut names = Vec::new();
    let mut buf = [0u8; 4096];
    while std::time::Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => {
                names.extend(parse_mdns_names(&buf[..len]));
            }
            Err(_) => {}
        }
    }
    names
}

fn resolve_ip(ip: Ipv4Addr, verbose: bool) -> Option<String> {
    let socket = mdns_socket()?;
    socket.set_read_timeout(Some(Duration::from_millis(600))).ok()?;

    let services = [
        "_services._dns-sd._udp.local",
        "_apple-mobdev2._tcp.local",
        "_device-info._tcp.local",
        "_rdlink._tcp.local",
        "_http._tcp.local",
        "_workstation._tcp.local",
    ];

    let target = SocketAddr::new(IpAddr::V4(MULTICAST_ADDR), MDNS_PORT);
    for service in &services {
        let query = build_ptr_query(service, 0);
        let _ = socket.send_to(&query, target);
    }

    let octets = ip.octets();
    let reverse = format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);
    let query = build_ptr_query(&reverse, 1);
    let _ = socket.send_to(&query, target);

    if verbose {
        eprintln!("  [mDNS] {} -> service browse + reverse PTR", ip);
    }

    let names = passive_collect(&socket, Duration::from_millis(800));

    if verbose && !names.is_empty() {
        eprintln!("  [mDNS] {} <- candidates: {:?}", ip, names);
    }

    names.into_iter()
        .find(|n| !n.is_empty() && n.len() > 1)
}

fn unicast_reverse(ip: Ipv4Addr, verbose: bool) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_millis(300))).ok()?;

    let octets = ip.octets();
    let name = format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);

    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]);

    let target = format!("{}:53", ip);
    socket.send_to(&packet, &target).ok()?;

    if verbose {
        eprintln!("  [DNS] {} -> unicast reverse query", ip);
    }

    let mut buf = [0u8; 1500];
    match socket.recv_from(&mut buf) {
        Ok((len, _)) => {
            let names = parse_mdns_names(&buf[..len]);
            names.into_iter().find(|n| !n.is_empty())
        }
        Err(_) => None,
    }
}

fn query_ip(ip: Ipv4Addr, verbose: bool) -> Option<MdnsResult> {
    let mdns = std::thread::spawn(move || resolve_ip(ip, verbose));
    let dns = std::thread::spawn(move || unicast_reverse(ip, verbose));

    let mdns_result = mdns.join().ok().flatten();
    let dns_result = dns.join().ok().flatten();

    mdns_result.or(dns_result).map(|hostname| MdnsResult { hostname })
}

pub async fn resolve_bulk(ips: &[Ipv4Addr], verbose: bool) -> HashMap<Ipv4Addr, MdnsResult> {
    let mut set = JoinSet::new();
    for &ip in ips {
        set.spawn(async move {
            let result = tokio::task::spawn_blocking(move || query_ip(ip, verbose))
                .await
                .ok()
                .flatten();
            (ip, result)
        });
    }

    let mut results = HashMap::new();
    while let Some(Ok((ip, maybe))) = set.join_next().await {
        if let Some(result) = maybe {
            results.insert(ip, result);
        }
    }
    results
}