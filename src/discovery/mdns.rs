// FILE: src/discovery/mdns.rs
// PURPOSE: Hostname resolution via mDNS and unicast DNS fallback
use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct MdnsResult {
    pub hostname: String,
}

const MULTICAST: &str = "224.0.0.251:5353";

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

fn hexdump(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_hostname(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        eprintln!("    [parse] data too short: {} bytes", data.len());
        return None;
    }

    let questions = u16::from_be_bytes([data[4], data[5]]) as usize;
    let answers = u16::from_be_bytes([data[6], data[7]]) as usize;
    let flags = u16::from_be_bytes([data[2], data[3]]);
    eprintln!(
        "    [parse] flags=0x{:04x} questions={} answers={}",
        flags, questions, answers
    );

    if answers == 0 {
        let rcode = flags & 0x000F;
        eprintln!("    [parse] no answers, rcode={}", rcode);
        return None;
    }

    let mut pos = 12usize;

    for i in 0..questions {
        let start = pos;
        pos = skip_label(data, pos)?;
        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        eprintln!(
            "    [parse] question[{}] @{}..{} qtype={} qclass={}",
            i,
            start,
            pos + 4,
            qtype,
            qclass
        );
        pos += 4;
    }

    for i in 0..answers {
        let name_start = pos;
        pos = skip_label(data, pos)?;
        if pos + 10 > data.len() {
            eprintln!("    [parse] answer[{}] truncated at pos {}", i, pos);
            return None;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        eprintln!(
            "    [parse] answer[{}] name@{} type={} class={} ttl={} rdlen={} rdata@{}",
            i, name_start, rtype, rclass, ttl, rdlen, rdata_start
        );
        eprintln!(
            "    [parse] answer[{}] rdata hex: {}",
            i,
            hexdump(&data[rdata_start..rdata_start + rdlen.min(64)])
        );
        pos += 10;

        if rtype == 0x000C {
            if let Some(name) = decode_label(data, pos) {
                let trimmed = name.trim_end_matches('.').to_string();
                eprintln!("    [parse] answer[{}] decoded name: '{}'", i, trimmed);
                if !trimmed.is_empty() && trimmed != "in-addr.arpa" {
                    return Some(trimmed);
                }
            } else {
                eprintln!("    [parse] answer[{}] decode_label failed at pos {}", i, pos);
            }
        }

        pos += rdlen;
    }

    eprintln!("    [parse] no PTR hostname found");
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

fn mdns_reverse(ip: Ipv4Addr) -> Option<String> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [mDNS] {} bind failed: {}", ip, e);
            return None;
        }
    };

    if socket.set_read_timeout(Some(Duration::from_millis(400))).is_err() {
        eprintln!("  [mDNS] {} set_read_timeout failed", ip);
        return None;
    }

    let query = build_reverse_query(ip, 1);
    let octets = ip.octets();
    let reverse_name = format!(
        "{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]
    );

    if socket.send_to(&query, MULTICAST).is_err() {
        eprintln!("  [mDNS] {} send to multicast failed", ip);
        return None;
    }

    eprintln!("  [mDNS] {} -> multicast query for {}", ip, reverse_name);

    let mut buf = [0u8; 1500];
    match socket.recv_from(&mut buf) {
        Ok((len, src)) => {
            eprintln!("  [mDNS] {} <- {} bytes from {}", ip, len, src);
            eprintln!("  [mDNS] {} response hex: {}", ip, hexdump(&buf[..len.min(128)]));
            let result = parse_hostname(&buf[..len]);
            eprintln!("  [mDNS] {} parse result: {:?}", ip, result);
            result
        }
        Err(e) => {
            eprintln!("  [mDNS] {} recv timeout/error: {:?}", ip, e.kind());
            None
        }
    }
}

fn unicast_reverse(ip: Ipv4Addr) -> Option<String> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [DNS] {} bind failed: {}", ip, e);
            return None;
        }
    };

    if socket.set_read_timeout(Some(Duration::from_millis(300))).is_err() {
        eprintln!("  [DNS] {} set_read_timeout failed", ip);
        return None;
    }

    let query = build_reverse_query(ip, 2);
    let target = format!("{}:53", ip);

    if socket.send_to(&query, &target).is_err() {
        eprintln!("  [DNS] {} send to {} failed", ip, target);
        return None;
    }

    eprintln!("  [DNS] {} -> unicast query to {}", ip, target);

    let mut buf = [0u8; 1500];
    match socket.recv_from(&mut buf) {
        Ok((len, src)) => {
            eprintln!("  [DNS] {} <- {} bytes from {}", ip, len, src);
            eprintln!("  [DNS] {} response hex: {}", ip, hexdump(&buf[..len.min(128)]));
            let result = parse_hostname(&buf[..len]);
            eprintln!("  [DNS] {} parse result: {:?}", ip, result);
            result
        }
        Err(e) => {
            eprintln!("  [DNS] {} recv timeout/error: {:?}", ip, e.kind());
            None
        }
    }
}

pub fn query_reverse(ip: Ipv4Addr) -> Option<MdnsResult> {
    if let Some(hostname) = mdns_reverse(ip) {
        return Some(MdnsResult { hostname });
    }

    if let Some(hostname) = unicast_reverse(ip) {
        return Some(MdnsResult { hostname });
    }

    None
}

pub async fn resolve_bulk(ips: &[Ipv4Addr]) -> HashMap<Ipv4Addr, MdnsResult> {
    let mut results = HashMap::new();
    for &ip in ips {
        if let Some(result) = query_reverse(ip) {
            results.insert(ip, result);
        }
    }
    results
}
