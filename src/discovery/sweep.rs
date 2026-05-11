use pnet::packet::icmp::{self, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpOption};
use pnet::packet::Packet;
use pnet::transport::{self, TransportChannelType, TransportProtocol};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinSet;

const TCP_PROBE_PORTS: &[u16] = &[80, 443];

fn find_source_ip() -> Option<Ipv4Addr> {
    pnet::datalink::interfaces()
        .iter()
        .find(|i| i.is_up() && !i.is_loopback())
        .and_then(|i| i.ips.iter().find(|ip| ip.is_ipv4()))
        .and_then(|ip| match ip.ip() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
}

fn next_probe_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static PORT: AtomicU16 = AtomicU16::new(51000);
    let mut current = PORT.load(Ordering::Relaxed);
    loop {
        let next = if current >= 60000 { 51000 } else { current + 1 };
        match PORT.compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return next,
            Err(actual) => current = actual,
        }
    }
}

fn icmp_probe(target: Ipv4Addr) -> bool {
    let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = match transport::transport_channel(1024, protocol) {
        Ok(pair) => pair,
        Err(_) => return false,
    };

    let mut buf = [0u8; 8];
    let mut pkt = match MutableIcmpPacket::new(&mut buf) {
        Some(p) => p,
        None => return false,
    };
    pkt.set_icmp_type(IcmpTypes::EchoRequest);
    pkt.set_icmp_code(icmp::IcmpCode(0));
    pkt.set_checksum(0);
    let cksum = icmp::checksum(&pkt.to_immutable());
    pkt.set_checksum(cksum);

    if tx.send_to(pkt, IpAddr::V4(target)).is_err() {
        return false;
    }

    let deadline = std::time::Instant::now() + Duration::from_millis(800);
    let mut iter = transport::icmp_packet_iter(&mut rx);

    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining = deadline - now;
        match iter.next_with_timeout(remaining) {
            Ok(Some((pkt, addr))) => {
                if pkt.get_icmp_type() == IcmpTypes::EchoReply {
                    if let IpAddr::V4(src) = addr {
                        if src == target {
                            return true;
                        }
                    }
                }
            }
            _ => return false,
        }
    }
}

fn tcp_probe(target: Ipv4Addr, port: u16, src_ip: Ipv4Addr) -> bool {
    let src_port = next_probe_port();
    let src = SocketAddrV4::new(src_ip, src_port);
    let dst = SocketAddrV4::new(target, port);
    let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));

    let (mut tx, mut rx) = match transport::transport_channel(4096, protocol) {
        Ok(pair) => pair,
        Err(_) => return false,
    };

    let mut buf = [0u8; 40];
    let mut pkt = match MutableTcpPacket::new(&mut buf) {
        Some(p) => p,
        None => return false,
    };
    pkt.set_source(src_port);
    pkt.set_destination(port);
    pkt.set_sequence(12345);
    pkt.set_acknowledgement(0);
    pkt.set_data_offset(10);
    pkt.set_flags(TcpFlags::SYN);
    pkt.set_window(65535);
    pkt.set_urgent_ptr(0);
    pkt.set_options(&[
        TcpOption::mss(1460),
        TcpOption::sack_perm(),
        TcpOption::timestamp(0, 0),
        TcpOption::nop(),
        TcpOption::wscale(7),
    ]);
    let cksum = tcp::ipv4_checksum(&pkt.to_immutable(), src.ip(), dst.ip());
    pkt.set_checksum(cksum);

    if tx.send_to(pkt, IpAddr::V4(target)).is_err() {
        return false;
    }

    let deadline = std::time::Instant::now() + Duration::from_millis(800);
    let mut iter = transport::ipv4_packet_iter(&mut rx);

    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining = deadline - now;
        match iter.next_with_timeout(remaining) {
            Ok(Some((ipv4, _))) => {
                if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                    continue;
                }
                if let Some(tcp) = tcp::TcpPacket::new(ipv4.payload()) {
                    if tcp.get_destination() == src_port && tcp.get_source() == port {
                        let flags = tcp.get_flags();
                        if flags & TcpFlags::RST != 0 || (flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0) {
                            return true;
                        }
                    }
                }
            }
            _ => return false,
        }
    }
}

fn probe_host(target: Ipv4Addr, src_ip: Ipv4Addr) -> bool {
    let icmp_target = target;
    let icmp = std::thread::spawn(move || icmp_probe(icmp_target));

    let tcp_src = src_ip;
    let tcp_results: Vec<_> = TCP_PROBE_PORTS
        .iter()
        .map(|&port| {
            let t = target;
            std::thread::spawn(move || tcp_probe(t, port, tcp_src))
        })
        .collect();

    if icmp.join().unwrap_or(false) {
        return true;
    }
    tcp_results.into_iter().any(|h| h.join().unwrap_or(false))
}

pub async fn sweep_subnet(
    subnet: Ipv4Addr,
    prefix: u8,
    known: &HashSet<Ipv4Addr>,
    verbose: bool,
) -> HashSet<Ipv4Addr> {
    let src_ip = match find_source_ip() {
        Some(ip) => ip,
        None => return HashSet::new(),
    };

    let base = u32::from(subnet) & !((1u32 << (32 - prefix)) - 1);
    let count = 1u32 << (32 - prefix);
    let targets: Vec<Ipv4Addr> = (0..count)
        .map(|i| Ipv4Addr::from(base + i))
        .filter(|ip| {
            let o = ip.octets();
            o[3] != 0 && o[3] != 255 && !known.contains(ip) && *ip != src_ip
        })
        .collect();

    if verbose {
        eprintln!("  [sweep] probing {} hosts via ICMP + TCP...", targets.len());
    }

    let found = Arc::new(Mutex::new(HashSet::new()));
    let mut set = JoinSet::new();

    for target in targets {
        let found = Arc::clone(&found);
        set.spawn(tokio::task::spawn_blocking(move || {
            if probe_host(target, src_ip) {
                found.lock().unwrap().insert(target);
                if verbose {
                    eprintln!("  [sweep] {} responded", target);
                }
            }
        }));
    }

    while set.join_next().await.is_some() {}

    Arc::try_unwrap(found).unwrap().into_inner().unwrap()
}