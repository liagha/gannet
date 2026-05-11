// FILE: src/discovery/passive.rs
// PURPOSE: Auto-tiered passive listener; raw socket sniff, ARP table poll, mDNS join
use crate::discovery::arp::ArpEntry;
use macaddr::MacAddr6;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, UdpSocket, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Capability {
    RawSocket,
    ArpTable,
    MdnsOnly,
}

#[derive(Debug, Clone)]
pub struct MdnsServiceEvent {
    pub ip: Ipv4Addr,
    pub services: Vec<String>,
}

fn detect_capability() -> Capability {
    if raw_socket_available() {
        return Capability::RawSocket;
    }
    if arp_table_readable() {
        return Capability::ArpTable;
    }
    Capability::MdnsOnly
}

fn raw_socket_available() -> bool {
    let sock = socket2::Socket::new(
        socket2::Domain::PACKET,
        socket2::Type::RAW,
        Some(socket2::Protocol::from(0x0300)),
    );
    match sock {
        Ok(s) => {
            let _ = s.set_nonblocking(true);
            true
        }
        Err(_) => false,
    }
}

fn arp_table_readable() -> bool {
    std::fs::read_to_string("/proc/net/arp").is_ok()
}

fn parse_arp_table() -> Vec<ArpEntry> {
    let contents = match std::fs::read_to_string("/proc/net/arp") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut entries = Vec::new();
    for line in contents.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let ip = match parts[0].parse::<Ipv4Addr>() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let mac_str = parts[3];
        if mac_str.len() != 17 || mac_str == "00:00:00:00:00:00" {
            continue;
        }
        let mac = match mac_str.parse::<MacAddr6>() {
            Ok(m) => m,
            Err(_) => continue,
        };
        entries.push(ArpEntry { ip, mac });
    }
    entries
}

const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

fn build_mdns_query(service: &str, transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    for label in service.split('.') {
        if label.is_empty() {
            continue;
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x0C]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet
}

fn join_mdns_socket() -> Option<UdpSocket> {
    let sock = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MDNS_PORT)).ok()?;
    sock.set_nonblocking(true).ok()?;
    sock.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED).ok()?;
    sock.set_multicast_ttl_v4(255).ok()?;
    Some(sock)
}

fn send_mdns_queries(socket: &UdpSocket) {
    let services = [
        "_services._dns-sd._udp.local",
        "_apple-mobdev2._tcp.local",
        "_device-info._tcp.local",
        "_workstation._tcp.local",
        "_http._tcp.local",
        "_googlecast._tcp.local",
        "_spotify-connect._tcp.local",
        "_raop._tcp.local",
        "_airplay._tcp.local",
        "_companion-link._tcp.local",
        "_homekit._tcp.local",
        "_printer._tcp.local",
        "_scanner._tcp.local",
        "_smb._tcp.local",
        "_ssh._tcp.local",
        "_nfs._tcp.local",
    ];
    let target = SocketAddr::new(IpAddr::V4(MULTICAST_ADDR), MDNS_PORT);
    for (i, service) in services.iter().enumerate() {
        let query = build_mdns_query(service, i as u16);
        let _ = socket.send_to(&query, target);
    }
}

fn decode_label(data: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    let mut visited = HashSet::new();
    let mut end_pos = None;
    loop {
        if pos >= data.len() {
            return None;
        }
        if !visited.insert(pos) {
            return None;
        }
        let byte = data[pos];
        if byte == 0x00 {
            if end_pos.is_none() {
                end_pos = Some(pos + 1);
            }
            break;
        }
        if byte & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            let ptr = u16::from_be_bytes([byte & 0x3F, data[pos + 1]]) as usize;
            pos = ptr;
            continue;
        }
        let len = byte as usize;
        pos += 1;
        let end = pos + len;
        if end > data.len() {
            return None;
        }
        parts.push(String::from_utf8_lossy(&data[pos..end]).into_owned());
        pos = end;
    }
    Some((parts.join("."), end_pos.unwrap_or(pos + 1)))
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

fn parse_mdns_for_services(data: &[u8]) -> Vec<String> {
    if data.len() < 12 {
        return Vec::new();
    }
    let questions = u16::from_be_bytes([data[4], data[5]]) as usize;
    let answer_rrs = u16::from_be_bytes([data[6], data[7]]) as usize;
    let authority_rrs = u16::from_be_bytes([data[8], data[9]]) as usize;
    let additional_rrs = u16::from_be_bytes([data[10], data[11]]) as usize;
    let total_rrs = answer_rrs + authority_rrs + additional_rrs;

    let mut pos = 12usize;
    let mut services = Vec::new();

    for _ in 0..questions {
        if let Some((name, next)) = decode_label(data, pos) {
            if let Some(svc) = extract_service_type(&name) {
                services.push(svc);
            }
            pos = next + 4;
        } else {
            return services;
        }
    }

    for _ in 0..total_rrs {
        if pos >= data.len() {
            break;
        }
        let name_result = decode_label(data, pos);
        let (name, next) = match name_result {
            Some(pair) => pair,
            None => break,
        };
        pos = next;

        if let Some(svc) = extract_service_type(&name) {
            services.push(svc);
        }

        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if rtype == 0x000C {
            if let Some((rdata, _)) = decode_label(data, pos) {
                if let Some(svc) = extract_service_type(&rdata) {
                    services.push(svc);
                }
            }
        }

        pos += rdlen;
    }

    let mut seen = HashSet::new();
    services.retain(|s| seen.insert(s.clone()));
    services
}

fn subnet_from_interface(iface: &pnet::datalink::NetworkInterface) -> Option<(Ipv4Addr, u8)> {
    for ip in &iface.ips {
        if let IpAddr::V4(v4) = ip.ip() {
            let prefix = ip.prefix();
            let mask = !((1u32 << (32 - prefix)) - 1);
            let base = Ipv4Addr::from(u32::from(v4) & mask);
            return Some((base, prefix));
        }
    }
    None
}

fn ip_in_subnet(ip: Ipv4Addr, base: Ipv4Addr, prefix: u8) -> bool {
    let mask = !((1u32 << (32 - prefix)) - 1);
    (u32::from(ip) & mask) == (u32::from(base) & mask)
}

fn listen_mdns(
    tx: mpsc::UnboundedSender<ArpEntry>,
    service_tx: mpsc::UnboundedSender<MdnsServiceEvent>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    let socket = match join_mdns_socket() {
        Some(s) => s,
        None => return,
    };
    send_mdns_queries(&socket);

    let mut buf = [0u8; 4096];
    let mut last_query = std::time::Instant::now();

    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                let src_ip = match src {
                    SocketAddr::V4(s) => *s.ip(),
                    _ => continue,
                };
                let services = parse_mdns_for_services(&buf[..len]);
                if !services.is_empty() {
                    let _ = service_tx.send(MdnsServiceEvent { ip: src_ip, services });
                }
                let _ = tx.send(ArpEntry {
                    ip: src_ip,
                    mac: MacAddr6::broadcast(),
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        if last_query.elapsed() >= Duration::from_secs(30) {
            send_mdns_queries(&socket);
            last_query = std::time::Instant::now();
        }
    }
}

fn poll_arp_table(
    tx: mpsc::UnboundedSender<ArpEntry>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut seen = HashSet::new();
    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        let entries = parse_arp_table();
        for entry in entries {
            if seen.insert((entry.ip, entry.mac)) {
                let _ = tx.send(entry);
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn sniff_raw(
    tx: mpsc::UnboundedSender<ArpEntry>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    iface_name: Option<String>,
    verbose: bool,
) {
    let interfaces = pnet::datalink::interfaces();

    if verbose {
        eprintln!("[listen] available interfaces:");
        for iface in &interfaces {
            eprintln!(
                "  {:<12} up={} loopback={} ips={:?}",
                iface.name,
                iface.is_up(),
                iface.is_loopback(),
                iface.ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>()
            );
        }
    }

    let has_ipv4 = |iface: &&pnet::datalink::NetworkInterface| {
        iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4())
    };

    let iface = iface_name
        .as_deref()
        .and_then(|n| interfaces.iter().find(|i| i.name == n && has_ipv4(i)))
        .or_else(|| interfaces.iter().find(|i| has_ipv4(i)));

    let iface = match iface {
        Some(i) => {
            if verbose {
                eprintln!("[listen] selected interface: {}", i.name);
            }
            i.clone()
        }
        None => {
            eprintln!("[listen] no suitable interface with IPv4 found");
            return;
        }
    };

    let local_subnet = subnet_from_interface(&iface);

    let mut config = pnet::datalink::Config::default();
    config.read_timeout = Some(Duration::from_millis(500));

    let mut rx = match pnet::datalink::channel(&iface, config) {
        Ok(pnet::datalink::Channel::Ethernet(_, rx)) => {
            if verbose {
                eprintln!("[listen] datalink channel opened on {}", iface.name);
            }
            rx
        }
        other => {
            if verbose {
                eprintln!("[listen] datalink channel failed: {:?}", other.as_ref().err());
            }
            return;
        }
    };

    use pnet::packet::arp::ArpPacket;
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::Packet;

    let mut seen = HashSet::new();
    let mut packet_count: u64 = 0;

    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        match rx.next() {
            Ok(packet) => {
                packet_count += 1;
                if let Some(eth) = EthernetPacket::new(packet) {
                    let src_mac_raw = eth.get_source();
                    let src_mac = MacAddr6::new(
                        src_mac_raw.0, src_mac_raw.1, src_mac_raw.2,
                        src_mac_raw.3, src_mac_raw.4, src_mac_raw.5,
                    );
                    if src_mac.is_nil() || src_mac.is_broadcast() {
                        continue;
                    }
                    match eth.get_ethertype() {
                        EtherTypes::Arp => {
                            if let Some(arp) = ArpPacket::new(eth.payload()) {
                                let sender_ip = Ipv4Addr::from(arp.get_sender_proto_addr());
                                let sender_mac_raw = arp.get_sender_hw_addr();
                                let sender_mac = MacAddr6::new(
                                    sender_mac_raw.0, sender_mac_raw.1,
                                    sender_mac_raw.2, sender_mac_raw.3,
                                    sender_mac_raw.4, sender_mac_raw.5,
                                );
                                if !sender_ip.is_unspecified()
                                    && !sender_ip.is_loopback()
                                    && !sender_mac.is_nil()
                                {
                                    let allowed = local_subnet
                                        .map(|(base, prefix)| ip_in_subnet(sender_ip, base, prefix))
                                        .unwrap_or(true);
                                    if allowed && seen.insert((sender_ip, sender_mac)) {
                                        if verbose {
                                            eprintln!(
                                                "[listen] NEW sender {} -> {}",
                                                sender_ip, sender_mac
                                            );
                                        }
                                        let _ = tx.send(ArpEntry {
                                            ip: sender_ip,
                                            mac: sender_mac,
                                        });
                                    }
                                }
                                let target_ip = Ipv4Addr::from(arp.get_target_proto_addr());
                                let target_mac_raw = arp.get_target_hw_addr();
                                let target_mac = MacAddr6::new(
                                    target_mac_raw.0, target_mac_raw.1,
                                    target_mac_raw.2, target_mac_raw.3,
                                    target_mac_raw.4, target_mac_raw.5,
                                );
                                if !target_ip.is_unspecified()
                                    && !target_ip.is_loopback()
                                    && !target_mac.is_nil()
                                {
                                    let allowed = local_subnet
                                        .map(|(base, prefix)| ip_in_subnet(target_ip, base, prefix))
                                        .unwrap_or(true);
                                    if allowed && seen.insert((target_ip, target_mac)) {
                                        if verbose {
                                            eprintln!(
                                                "[listen] NEW target {} -> {}",
                                                target_ip, target_mac
                                            );
                                        }
                                        let _ = tx.send(ArpEntry {
                                            ip: target_ip,
                                            mac: target_mac,
                                        });
                                    }
                                }
                            }
                        }
                        EtherTypes::Ipv4 => {
                            if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                                let src_ip = Ipv4Addr::from(ipv4.get_source());
                                if !src_ip.is_unspecified()
                                    && !src_ip.is_loopback()
                                    && !src_ip.is_multicast()
                                {
                                    let allowed = local_subnet
                                        .map(|(base, prefix)| ip_in_subnet(src_ip, base, prefix))
                                        .unwrap_or(true);
                                    if allowed && seen.insert((src_ip, src_mac)) {
                                        if verbose {
                                            eprintln!(
                                                "[listen] NEW IPv4 {} <- {}",
                                                src_ip, src_mac
                                            );
                                        }
                                        let _ = tx.send(ArpEntry {
                                            ip: src_ip,
                                            mac: src_mac,
                                        });
                                    }
                                }
                            }
                        }
                        EtherTypes::Ipv6 => {
                            let placeholder_ip = Ipv4Addr::UNSPECIFIED;
                            if seen.insert((placeholder_ip, src_mac)) {
                                if verbose {
                                    eprintln!(
                                        "[listen] NEW IPv6 mac={}",
                                        src_mac
                                    );
                                }
                                let _ = tx.send(ArpEntry {
                                    ip: placeholder_ip,
                                    mac: src_mac,
                                });
                            }
                        }
                        _ => {
                            if seen.insert((Ipv4Addr::UNSPECIFIED, src_mac)) {
                                if verbose {
                                    eprintln!(
                                        "[listen] NEW ethertype=0x{:04x} mac={}",
                                        eth.get_ethertype().0,
                                        src_mac
                                    );
                                }
                                let _ = tx.send(ArpEntry {
                                    ip: Ipv4Addr::UNSPECIFIED,
                                    mac: src_mac,
                                });
                            }
                        }
                    }
                }
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    if verbose {
        eprintln!("[listen] sniff_raw exiting, {} packets seen", packet_count);
    }
}

pub async fn listen(
    iface: Option<String>,
    verbose: bool,
    store_path: std::path::PathBuf,
) {
    let cap = detect_capability();
    if verbose {
        eprintln!("[listen] capability: {:?}", cap);
    }

    let (tx, mut rx) = mpsc::unbounded_channel();
    let (service_tx, mut service_rx) = mpsc::unbounded_channel();
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let mut threads = Vec::new();

    match cap {
        Capability::RawSocket => {
            let tx_clone = tx.clone();
            let shutdown_clone = Arc::clone(&shutdown);
            let iface_clone = iface.clone();
            let verbose_clone = verbose;
            threads.push(std::thread::spawn(move || {
                sniff_raw(tx_clone, shutdown_clone, iface_clone, verbose_clone);
            }));
        }
        Capability::ArpTable => {
            let tx_clone = tx.clone();
            let shutdown_clone = Arc::clone(&shutdown);
            threads.push(std::thread::spawn(move || {
                poll_arp_table(tx_clone, shutdown_clone);
            }));
            let tx_clone = tx.clone();
            let service_tx_clone = service_tx.clone();
            let shutdown_clone = Arc::clone(&shutdown);
            threads.push(std::thread::spawn(move || {
                listen_mdns(tx_clone, service_tx_clone, shutdown_clone);
            }));
        }
        Capability::MdnsOnly => {
            let tx_clone = tx.clone();
            let service_tx_clone = service_tx.clone();
            let shutdown_clone = Arc::clone(&shutdown);
            threads.push(std::thread::spawn(move || {
                listen_mdns(tx_clone, service_tx_clone, shutdown_clone);
            }));
        }
    }

    use crate::identity::device::Device;
    use crate::identity::store::Store;
    use std::collections::HashMap;

    let mut store = Store::load(&store_path);
    let mut seen_local: HashMap<Ipv4Addr, MacAddr6> = HashMap::new();

    println!("Listening (capability: {:?}). Press Ctrl-C to stop.\n", cap);

    let ctrl_c_shutdown = Arc::clone(&shutdown);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        ctrl_c_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    loop {
        tokio::select! {
            Some(entry) = rx.recv() => {
                if entry.ip.is_unspecified() && !entry.mac.is_broadcast() {
                    if let Some(existing_ip) = seen_local.iter()
                        .find(|(_, m)| **m == entry.mac)
                        .map(|(ip, _)| *ip)
                    {
                        if verbose {
                            eprintln!(
                                "[listen] mac={} already seen via ip={}",
                                entry.mac, existing_ip
                            );
                        }
                        continue;
                    }
                    if verbose {
                        eprintln!("[listen] mac={} no associated ip yet", entry.mac);
                    }
                    continue;
                }
                if seen_local.contains_key(&entry.ip) {
                    continue;
                }
                seen_local.insert(entry.ip, entry.mac);

                let mut device = Device::from(&entry);
                device.vendor = crate::identity::oui::lookup(entry.mac).map(|s| s.to_string());

                let record = store.upsert(&device, crate::identity::namer::generate);
                let tag = record.tag.as_deref().unwrap_or("-");

                let mac_str = entry.mac.to_string();
                let vendor = device.vendor.as_deref().unwrap_or("-");

                println!(
                    "NEW  {:<16}  {:<18}  {:<26}  {:<22}",
                    entry.ip, mac_str, vendor, tag
                );

                if let Err(e) = store.save(&store_path) {
                    if verbose {
                        eprintln!("[listen] save error: {}", e);
                    }
                }
            }
            Some(service_event) = service_rx.recv() => {
                if let Some(&mac) = seen_local.get(&service_event.ip) {
                    let mut device = Device {
                        ip: service_event.ip,
                        mac: Some(mac),
                        vendor: None,
                        hostname: None,
                        os_hint: None,
                        services: service_event.services.clone(),
                        via: crate::identity::device::Via::Arp,
                        tag: None,
                    };
                    device.vendor = crate::identity::oui::lookup(mac).map(|s| s.to_string());
                    store.upsert(&device, crate::identity::namer::generate);

                    println!(
                        "SVC  {:<16}  {:?}",
                        service_event.ip, service_event.services
                    );

                    if let Err(e) = store.save(&store_path) {
                        if verbose {
                            eprintln!("[listen] save error: {}", e);
                        }
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
            }
        }
    }

    for thread in threads {
        let _ = thread.join();
    }

    println!("\nListener stopped. {} device(s) captured.", seen_local.len());
}