// FILE: src/discovery/mdns.rs
// PURPOSE: Hostname resolution via per-IP unicast mDNS queries with passive fallback
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use tokio::task::JoinSet;

#[derive(Debug, Clone)]
pub struct MdnsResult {
    pub hostname: String,
    pub services: Vec<String>,
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

fn build_a_query(name: &str, transaction_id: u16) -> Vec<u8> {
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
    packet.extend_from_slice(&[0x00, 0x01]);
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

fn is_service_label(s: &str) -> bool {
    const KNOWN_SERVICES: &[&str] = &[
        "local", "in-addr", "arpa",
        "androidtvremote2", "googlecast",
        "rc", "raop", "airplay", "privet",
        "spotify-connect", "companion-link",
        "sleep-proxy",
    ];
    s.starts_with('_')
        || s.contains("._tcp")
        || s.contains("._udp")
        || KNOWN_SERVICES.contains(&s.to_lowercase().as_str())
}

fn best_hostname(names: Vec<String>) -> Option<String> {
    let mut seen = std::collections::HashSet::new();
    let scored: Vec<(String, u8)> = names
        .into_iter()
        .filter(|n| !n.is_empty() && n.len() > 1 && !is_service_label(n))
        .filter(|n| seen.insert(n.clone()))
        .map(|n| {
            let score = if n.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) { 3u8 }
            else if n.contains('-') { 2 }
            else { 1 };
            (n, score)
        })
        .collect();

    scored.into_iter().max_by_key(|(_, s)| *s).map(|(n, _)| n)
}

fn extract_service_type(name: &str) -> Option<String> {
    if !name.starts_with('_') {
        return None;
    }
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() >= 2 {
        let service = parts[0];
        let proto = parts.get(1).copied().unwrap_or("");
        if (proto == "_tcp" || proto == "_udp") && service.len() > 1 {
            let clean = service.trim_start_matches('_').to_string();
            if !clean.is_empty() {
                return Some(clean);
            }
        }
    }
    None
}

struct ParseResult {
    names: Vec<String>,
    services: Vec<String>,
}

fn parse_mdns_records(data: &[u8]) -> ParseResult {
    if data.len() < 12 { return ParseResult { names: Vec::new(), services: Vec::new() }; }

    let questions = u16::from_be_bytes([data[4], data[5]]) as usize;
    let answer_rrs = u16::from_be_bytes([data[6], data[7]]) as usize;
    let authority_rrs = u16::from_be_bytes([data[8], data[9]]) as usize;
    let additional_rrs = u16::from_be_bytes([data[10], data[11]]) as usize;
    let total_rrs = answer_rrs + authority_rrs + additional_rrs;

    if total_rrs == 0 { return ParseResult { names: Vec::new(), services: Vec::new() }; }

    let mut pos = 12usize;
    let mut names = Vec::new();
    let mut services = Vec::new();

    for _ in 0..questions {
        if let Some((name, next)) = decode_label(data, pos) {
            if let Some(svc) = extract_service_type(&name) {
                services.push(svc);
            }
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

        if let Some(svc) = extract_service_type(&name) {
            services.push(svc);
        }

        if pos + 10 > data.len() { break; }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        match rtype {
            0x000C => {
                if let Some((rdata, _)) = decode_label(data, pos) {
                    if let Some(svc) = extract_service_type(&rdata) {
                        services.push(svc);
                    }
                    let parts: Vec<&str> = rdata.split('.').collect();
                    if let Some(instance) = parts.first() {
                        let s = instance.trim_start_matches('_').to_string();
                        if !s.is_empty() && !is_service_label(&s) {
                            names.push(s);
                        }
                    }
                }
            }
            0x0021 => {
                if pos + 6 <= data.len() {
                    if let Some((host, _)) = decode_label(data, pos + 6) {
                        let h = host
                            .trim_end_matches(".local")
                            .trim_end_matches('.')
                            .to_string();
                        if !h.is_empty() && !is_service_label(&h) {
                            names.push(h);
                        }
                    }
                }
            }
            0x0001 => {
                let clean = name
                    .trim_end_matches(".local")
                    .trim_end_matches('.')
                    .to_string();
                if !clean.is_empty() && !is_service_label(&clean) {
                    names.push(clean);
                }
            }
            0x0010 => {
                let end = (pos + rdlen).min(data.len());
                let mut p = pos;
                while p < end {
                    let len = data[p] as usize;
                    p += 1;
                    if p + len > end { break; }
                    if let Ok(txt) = std::str::from_utf8(&data[p..p + len]) {
                        if let Some(val) = txt.strip_prefix("fn=").or_else(|| txt.strip_prefix("n=")) {
                            names.push(val.to_string());
                        }
                    }
                    p += len;
                }
            }
            _ => {}
        }

        pos += rdlen;
    }

    let mut seen = std::collections::HashSet::new();
    services.retain(|s| seen.insert(s.clone()));

    ParseResult { names, services }
}

fn unicast_mdns(ip: Ipv4Addr, verbose: bool) -> Option<MdnsResult> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_millis(800))).ok()?;

    let target = SocketAddr::new(IpAddr::V4(ip), MDNS_PORT);

    let octets = ip.octets();
    let arpa = format!(
        "{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]
    );

    let queries: &[(&[u8], &str)] = &[
        (&build_ptr_query(&arpa, 1), "reverse PTR"),
        (&build_a_query("_workstation._tcp.local", 2), "_workstation"),
        (&build_a_query("_device-info._tcp.local", 3), "_device-info"),
    ];

    for (pkt, label) in queries {
        let _ = socket.send_to(pkt, target);
        if verbose {
            eprintln!("  [mDNS] {} -> unicast {} query", ip, label);
        }
    }

    let deadline = std::time::Instant::now() + Duration::from_millis(900);
    let mut buf = [0u8; 4096];
    let mut candidates = Vec::new();
    let mut services = Vec::new();

    while std::time::Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                let src_ip = match src {
                    SocketAddr::V4(s) => *s.ip(),
                    _ => continue,
                };
                if src_ip != ip { continue; }
                let parsed = parse_mdns_records(&buf[..len]);
                candidates.extend(parsed.names);
                services.extend(parsed.services);
            }
            Err(_) => break,
        }
    }

    if verbose && !candidates.is_empty() {
        eprintln!("  [mDNS] {} <- candidates: {:?}", ip, candidates);
    }
    if verbose && !services.is_empty() {
        eprintln!("  [mDNS] {} <- services: {:?}", ip, services);
    }

    best_hostname(candidates).map(|hostname| MdnsResult { hostname, services })
}

fn multicast_passive(ip: Ipv4Addr, verbose: bool) -> Option<MdnsResult> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).ok()?;
    socket.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED).ok()?;
    socket.set_multicast_ttl_v4(255).ok()?;
    socket.set_read_timeout(Some(Duration::from_millis(100))).ok()?;

    let target = SocketAddr::new(IpAddr::V4(MULTICAST_ADDR), MDNS_PORT);

    let services = [
        "_services._dns-sd._udp.local",
        "_apple-mobdev2._tcp.local",
        "_device-info._tcp.local",
        "_workstation._tcp.local",
        "_http._tcp.local",
    ];
    for service in &services {
        let query = build_ptr_query(service, 0);
        let _ = socket.send_to(&query, target);
    }

    if verbose {
        eprintln!("  [mDNS] {} -> multicast passive collect", ip);
    }

    let deadline = std::time::Instant::now() + Duration::from_millis(600);
    let mut buf = [0u8; 4096];
    let mut candidates = Vec::new();
    let mut svc_list = Vec::new();

    while std::time::Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                let src_ip = match src {
                    SocketAddr::V4(s) => *s.ip(),
                    _ => continue,
                };
                if src_ip != ip { continue; }
                let parsed = parse_mdns_records(&buf[..len]);
                candidates.extend(parsed.names);
                svc_list.extend(parsed.services);
            }
            Err(_) => {}
        }
    }

    if verbose && !candidates.is_empty() {
        eprintln!("  [mDNS] {} <- multicast candidates: {:?}", ip, candidates);
    }
    if verbose && !svc_list.is_empty() {
        eprintln!("  [mDNS] {} <- multicast services: {:?}", ip, svc_list);
    }

    best_hostname(candidates).map(|hostname| MdnsResult { hostname, services: svc_list })
}

fn unicast_dns_reverse(ip: Ipv4Addr, verbose: bool) -> Option<MdnsResult> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_millis(300))).ok()?;

    let octets = ip.octets();
    let name = format!(
        "{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]
    );

    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]);

    let _ = socket.send_to(&packet, format!("{}:53", ip));

    if verbose {
        eprintln!("  [DNS] {} -> unicast reverse query", ip);
    }

    let mut buf = [0u8; 1500];
    match socket.recv_from(&mut buf) {
        Ok((len, _)) => {
            let parsed = parse_mdns_records(&buf[..len]);
            best_hostname(parsed.names).map(|hostname| MdnsResult { hostname, services: parsed.services })
        }
        Err(_) => None,
    }
}

fn query_ip(ip: Ipv4Addr, verbose: bool) -> Option<MdnsResult> {
    let t1 = std::thread::spawn(move || unicast_mdns(ip, verbose));
    let t2 = std::thread::spawn(move || multicast_passive(ip, verbose));
    let t3 = std::thread::spawn(move || unicast_dns_reverse(ip, verbose));

    let r1 = t1.join().ok().flatten();
    let r2 = t2.join().ok().flatten();
    let r3 = t3.join().ok().flatten();

    if r1.is_some() { return r1; }
    if r2.is_some() { return r2; }
    r3
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
