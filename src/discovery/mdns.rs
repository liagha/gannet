// FILE: src/discovery/mdns.rs
// PURPOSE: Hostname resolution via mDNS, unicast DNS, and NetBIOS in parallel
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;
use tokio::task::JoinSet;

#[derive(Debug, Clone)]
pub struct MdnsResult {
    pub hostname: String,
}

const MULTICAST_ADDR: &str = "224.0.0.251";
const MULTICAST_PORT: u16 = 5353;
const NBNS_PORT: u16 = 137;

fn build_reverse_query(ip: Ipv4Addr, transaction_id: u16) -> Vec<u8> {
    let octets = ip.octets();
    let name = format!(
        "{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]
    );
    build_query(&name, 0x000C, transaction_id)
}

fn build_query(name: &str, qtype: u16, transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x01]);
    packet
}

fn build_nbns_query(transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    let encoded = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00";
    packet.extend_from_slice(encoded);
    packet.extend_from_slice(&[0x00, 0x21]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet
}

fn parse_hostname(data: &[u8], verbose: bool) -> Option<String> {
    if data.len() < 12 {
        if verbose {
            eprintln!("    [parse] data too short: {} bytes", data.len());
        }
        return None;
    }

    let questions = u16::from_be_bytes([data[4], data[5]]) as usize;
    let answers = u16::from_be_bytes([data[6], data[7]]) as usize;

    if answers == 0 {
        return None;
    }

    let mut pos = 12usize;

    for _ in 0..questions {
        pos = skip_label(data, pos)?;
        pos += 4;
    }

    for i in 0..answers {
        pos = skip_label(data, pos)?;
        if pos + 10 > data.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if rtype == 0x000C {
            if let Some(name) = decode_label(data, pos) {
                let trimmed = name.trim_end_matches('.').to_string();
                if verbose {
                    eprintln!("    [parse] answer[{}] decoded name: '{}'", i, trimmed);
                }
                if !trimmed.is_empty() && trimmed != "in-addr.arpa" {
                    return Some(trimmed);
                }
            }
        }

        pos += rdlen;
    }

    None
}

fn parse_nbns_response(data: &[u8]) -> Option<String> {
    if data.len() < 57 {
        return None;
    }
    let answers = u16::from_be_bytes([data[6], data[7]]);
    if answers == 0 {
        return None;
    }
    let name_raw = &data[56..];
    let num_names = *name_raw.first()? as usize;
    let mut pos = 1usize;
    for _ in 0..num_names {
        if pos + 18 > name_raw.len() {
            break;
        }
        let name_bytes = &name_raw[pos..pos + 15];
        let flags = u16::from_be_bytes([name_raw[pos + 16], name_raw[pos + 17]]);
        let is_group = flags & 0x8000 != 0;
        if !is_group {
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end()
                .to_lowercase();
            if !name.is_empty() {
                return Some(name);
            }
        }
        pos += 18;
    }
    None
}

fn skip_label(data: &[u8], mut pos: usize) -> Option<usize> {
    while pos < data.len() {
        let byte = data[pos];
        if byte == 0x00 {
            return Some(pos + 1);
        }
        if byte & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + byte as usize;
    }
    None
}

fn decode_label(data: &[u8], mut pos: usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut visited = std::collections::HashSet::new();
    loop {
        if pos >= data.len() {
            return None;
        }
        if !visited.insert(pos) {
            return None;
        }
        let byte = data[pos];
        if byte == 0x00 {
            break;
        }
        if byte & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let ptr = u16::from_be_bytes([byte & 0x3F, data[pos + 1]]) as usize;
            pos = ptr;
            continue;
        }
        pos += 1;
        let end = pos + byte as usize;
        if end > data.len() {
            return None;
        }
        parts.push(String::from_utf8_lossy(&data[pos..end]).to_lowercase());
        pos = end;
    }
    Some(parts.join("."))
}

fn mdns_reverse(ip: Ipv4Addr, verbose: bool) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = socket.join_multicast_v4(
        &MULTICAST_ADDR.parse().unwrap(),
        &"0.0.0.0".parse().unwrap(),
    );
    socket.set_read_timeout(Some(Duration::from_millis(400))).ok()?;

    let query = build_reverse_query(ip, 1);
    let target = SocketAddrV4::new(MULTICAST_ADDR.parse().unwrap(), MULTICAST_PORT);
    socket.send_to(&query, target).ok()?;

    if verbose {
        let o = ip.octets();
        eprintln!("  [mDNS] {} -> multicast query for {}.{}.{}.{}.in-addr.arpa", ip, o[3], o[2], o[1], o[0]);
    }

    let mut buf = [0u8; 1500];
    match socket.recv_from(&mut buf) {
        Ok((len, src)) => {
            if verbose {
                eprintln!("  [mDNS] {} <- {} bytes from {}", ip, len, src);
            }
            parse_hostname(&buf[..len], verbose)
        }
        Err(_) => None,
    }
}

fn unicast_reverse(ip: Ipv4Addr, verbose: bool) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_millis(300))).ok()?;

    let query = build_reverse_query(ip, 2);
    let target = format!("{}:53", ip);
    socket.send_to(&query, &target).ok()?;

    if verbose {
        eprintln!("  [DNS] {} -> unicast query to {}", ip, target);
    }

    let mut buf = [0u8; 1500];
    match socket.recv_from(&mut buf) {
        Ok((len, src)) => {
            if verbose {
                eprintln!("  [DNS] {} <- {} bytes from {}", ip, len, src);
            }
            parse_hostname(&buf[..len], verbose)
        }
        Err(_) => None,
    }
}

fn nbns_query(ip: Ipv4Addr, verbose: bool) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_millis(400))).ok()?;

    let query = build_nbns_query(3);
    let target = SocketAddrV4::new(ip, NBNS_PORT);
    socket.send_to(&query, target).ok()?;

    if verbose {
        eprintln!("  [NBNS] {} -> NetBIOS name query", ip);
    }

    let mut buf = [0u8; 1500];
    match socket.recv_from(&mut buf) {
        Ok((len, src)) => {
            if verbose {
                eprintln!("  [NBNS] {} <- {} bytes from {}", ip, len, src);
            }
            parse_nbns_response(&buf[..len])
        }
        Err(_) => None,
    }
}

fn query_reverse(ip: Ipv4Addr, verbose: bool) -> Option<MdnsResult> {
    let mdns = std::thread::spawn(move || mdns_reverse(ip, verbose));
    let unicast = std::thread::spawn(move || unicast_reverse(ip, verbose));
    let nbns = std::thread::spawn(move || nbns_query(ip, verbose));

    let mdns_result = mdns.join().ok().flatten();
    let unicast_result = unicast.join().ok().flatten();
    let nbns_result = nbns.join().ok().flatten();

    mdns_result
        .or(unicast_result)
        .or(nbns_result)
        .map(|hostname| MdnsResult { hostname })
}

pub async fn resolve_bulk(ips: &[Ipv4Addr], verbose: bool) -> HashMap<Ipv4Addr, MdnsResult> {
    let mut set = JoinSet::new();

    for &ip in ips {
        set.spawn(async move {
            let result = tokio::task::spawn_blocking(move || query_reverse(ip, verbose))
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