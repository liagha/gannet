// FILE: src/discovery/fingerprint.rs
// PURPOSE: OS/device fingerprinting; TCP SYN analysis on Linux, TTL-only on Termux

#[derive(Debug, Clone)]
pub struct StackFingerprint {
    pub ttl: u8,
    pub window: u16,
    pub options: Vec<TcpOptionKind>,
    pub mss: Option<u16>,
    pub scale: Option<u8>,
    pub sack_ok: bool,
    pub nop_count: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOptionKind {
    Mss,
    WindowScale,
    SackPermitted,
    Timestamp,
    Nop,
    Unknown(u8),
}

#[derive(Debug, Clone)]
pub struct FingerprintResult {
    pub syn_ack: Option<StackFingerprint>,
    pub os_hint: Option<String>,
}

#[cfg(not(feature = "termux"))]
pub use raw::probe_bulk;

#[cfg(feature = "termux")]
pub use ttl_only::probe_bulk;

#[cfg(not(feature = "termux"))]
mod raw {
    use super::{FingerprintResult, StackFingerprint, TcpOptionKind};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpOption};
    use pnet::packet::Packet;
    use pnet::transport::{
        self, ipv4_packet_iter, TransportChannelType, TransportProtocol, TransportReceiver,
        TransportSender,
    };
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::Duration;
    use tokio::task::JoinSet;
    use tokio::time::timeout;

    const FALLBACK_PORTS: &[u16] = &[443, 80, 22];

    fn parse_tcp_options(data: &[u8]) -> Vec<TcpOptionKind> {
        let mut kinds = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let kind = data[pos];
            if kind == 0 { break; }
            if kind == 1 {
                kinds.push(TcpOptionKind::Nop);
                pos += 1;
                continue;
            }
            if pos + 1 >= data.len() { break; }
            let len = data[pos + 1] as usize;
            if len < 2 || pos + len > data.len() { break; }
            kinds.push(match kind {
                2 => TcpOptionKind::Mss,
                3 => TcpOptionKind::WindowScale,
                4 => TcpOptionKind::SackPermitted,
                8 => TcpOptionKind::Timestamp,
                _ => TcpOptionKind::Unknown(kind),
            });
            pos += len;
        }
        kinds
    }

    fn parse_stack_fingerprint(ttl: u8, window: u16, options_raw: &[u8]) -> StackFingerprint {
        let option_kinds = parse_tcp_options(options_raw);
        let nop_count = option_kinds.iter().filter(|k| **k == TcpOptionKind::Nop).count() as u8;
        let sack_ok = option_kinds.contains(&TcpOptionKind::SackPermitted);

        let mut mss = None;
        let mut scale = None;
        let mut pos = 0;

        while pos < options_raw.len() {
            let kind = options_raw[pos];
            if kind == 0 { break; }
            if kind == 1 { pos += 1; continue; }
            if pos + 1 >= options_raw.len() { break; }
            let len = options_raw[pos + 1] as usize;
            if len < 2 || pos + len > options_raw.len() { break; }
            match kind {
                2 if len >= 4 => {
                    mss = Some(u16::from_be_bytes([options_raw[pos + 2], options_raw[pos + 3]]));
                }
                3 if len >= 3 => {
                    scale = Some(options_raw[pos + 2]);
                }
                _ => {}
            }
            pos += len;
        }

        StackFingerprint { ttl, window, options: option_kinds, mss, scale, sack_ok, nop_count }
    }

    fn guess_os(fp: &StackFingerprint) -> Option<String> {
        let mut scores: Vec<(&str, u8)> = Vec::new();

        let has_timestamp = fp.options.contains(&TcpOptionKind::Timestamp);
        let has_sack = fp.options.contains(&TcpOptionKind::SackPermitted);

        if fp.ttl <= 64 { scores.push(("Linux", 3)); }
        if fp.ttl <= 64 && fp.window == 65535 && fp.mss == Some(1460) && fp.scale.is_some() {
            scores.push(("Linux (kernel 4.x+)", 8));
        }
        if fp.ttl <= 64 && fp.window == 29200 && fp.mss == Some(1460) {
            scores.push(("Linux (kernel 3.x)", 6));
        }
        if fp.ttl == 64 && fp.window == 65535 && has_timestamp && has_sack {
            scores.push(("macOS 10.15+", 9));
        }
        if fp.ttl == 64 && fp.window == 65535 && fp.mss == Some(1460) {
            scores.push(("macOS 10.15+", 7));
        }
        if fp.ttl == 64 { scores.push(("macOS/Linux", 3)); }
        if fp.ttl == 128 { scores.push(("Windows", 3)); }
        if fp.ttl == 128 && fp.window == 8192 { scores.push(("Windows 7/2008", 7)); }
        if fp.ttl == 128 && fp.window == 65535 && fp.scale == Some(8) {
            scores.push(("Windows 10/11", 8));
        }
        if fp.ttl == 128 && fp.window == 65535 && has_timestamp && has_sack && fp.scale == Some(8) {
            scores.push(("Windows 10/11", 9));
        }
        if fp.ttl == 255 { scores.push(("BSD/Solaris/Network Device", 4)); }
        if fp.ttl == 255 && fp.window == 16384 { scores.push(("OpenBSD", 7)); }
        if fp.ttl == 255 && fp.window == 65535 { scores.push(("FreeBSD", 6)); }
        if fp.ttl <= 32 { scores.push(("Embedded/IoT", 3)); }

        scores.sort_by_key(|(_, s)| std::cmp::Reverse(*s));
        scores.first().map(|(name, _)| name.to_string())
    }

    fn tcp_send_syn(
        tx: &mut TransportSender,
        src: SocketAddrV4,
        dst: SocketAddrV4,
        seq: u32,
    ) -> std::io::Result<usize> {
        let mut tcp_buf = [0u8; 40];
        let mut tcp_pkt = MutableTcpPacket::new(&mut tcp_buf).unwrap();
        tcp_pkt.set_source(src.port());
        tcp_pkt.set_destination(dst.port());
        tcp_pkt.set_sequence(seq);
        tcp_pkt.set_acknowledgement(0);
        tcp_pkt.set_data_offset(10);
        tcp_pkt.set_flags(TcpFlags::SYN);
        tcp_pkt.set_window(65535);
        tcp_pkt.set_urgent_ptr(0);
        tcp_pkt.set_options(&[
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::timestamp(0, 0),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ]);
        let cksum = tcp::ipv4_checksum(&tcp_pkt.to_immutable(), src.ip(), dst.ip());
        tcp_pkt.set_checksum(cksum);
        tx.send_to(tcp_pkt, std::net::IpAddr::V4(*dst.ip()))
    }

    fn wait_syn_ack(
        rx: &mut TransportReceiver,
        src_port: u16,
        dst_port: u16,
        wait: Duration,
    ) -> Option<(u8, u16, Vec<u8>)> {
        let deadline = std::time::Instant::now() + wait;
        let mut iter = ipv4_packet_iter(rx);

        loop {
            let now = std::time::Instant::now();
            if now >= deadline { return None; }
            let remaining = deadline - now;

            match iter.next_with_timeout(remaining) {
                Ok(Some((ipv4, _addr))) => {
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                        let ttl = ipv4.get_ttl();
                        if let Some(tcp) = tcp::TcpPacket::new(ipv4.payload()) {
                            if tcp.get_destination() == src_port && tcp.get_source() == dst_port {
                                if tcp.get_flags() & TcpFlags::SYN != 0
                                    && tcp.get_flags() & TcpFlags::ACK != 0
                                {
                                    let window = tcp.get_window();
                                    let data_offset = tcp.get_data_offset() as usize * 4;
                                    let payload = ipv4.payload();
                                    let tcp_start = (ipv4.get_header_length() as usize) * 4;
                                    let opts_len = data_offset.saturating_sub(20);
                                    let opts = if opts_len > 0
                                        && payload.len() >= tcp_start + data_offset
                                    {
                                        payload[tcp_start + 20..tcp_start + 20 + opts_len].to_vec()
                                    } else {
                                        Vec::new()
                                    };
                                    return Some((ttl, window, opts));
                                }
                                if tcp.get_flags() & TcpFlags::RST != 0 {
                                    return None;
                                }
                            }
                        }
                    }
                }
                Ok(None) => return None,
                Err(_) => return None,
            }

            if remaining < Duration::from_millis(10) { return None; }
        }
    }

    fn next_src_port() -> u16 {
        use std::sync::atomic::{AtomicU16, Ordering};
        static PORT: AtomicU16 = AtomicU16::new(43210);
        let mut current = PORT.load(Ordering::Relaxed);
        loop {
            let next = if current >= 50000 { 43210 } else { current + 1 };
            match PORT.compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return next,
                Err(actual) => current = actual,
            }
        }
    }

    fn find_source_ip() -> Option<Ipv4Addr> {
        pnet::datalink::interfaces()
            .iter()
            .find(|i| i.is_up() && !i.is_loopback())
            .and_then(|i| i.ips.iter().find(|ip| ip.is_ipv4()))
            .and_then(|ip| match ip.ip() {
                std::net::IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
    }

    fn probe_port_blocking(
        target: Ipv4Addr,
        port: u16,
        src_ip: Ipv4Addr,
        verbose: bool,
    ) -> Option<(u8, u16, Vec<u8>)> {
        let src_port = next_src_port();
        let src = SocketAddrV4::new(src_ip, src_port);
        let dst = SocketAddrV4::new(target, port);
        let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(
            IpNextHeaderProtocols::Tcp,
        ));

        let (mut tx, mut rx) = match transport::transport_channel(4096, protocol) {
            Ok(pair) => pair,
            Err(e) => {
                if verbose {
                    eprintln!("  [fingerprint] {} port {} transport failed: {}", target, port, e);
                }
                return None;
            }
        };

        if tcp_send_syn(&mut tx, src, dst, 31337).is_err() {
            return None;
        }

        if verbose {
            eprintln!("  [fingerprint] {} -> SYN to port {}", target, port);
        }

        wait_syn_ack(&mut rx, src_port, port, Duration::from_secs(2))
    }

    async fn probe_syn(target: Ipv4Addr, verbose: bool) -> Option<FingerprintResult> {
        let src_ip = match find_source_ip() {
            Some(ip) => ip,
            None => return None,
        };

        let mut set = JoinSet::new();
        for &port in FALLBACK_PORTS {
            set.spawn(tokio::task::spawn_blocking(move || {
                probe_port_blocking(target, port, src_ip, verbose)
            }));
        }

        let result = timeout(Duration::from_secs(3), async {
            while let Some(joined) = set.join_next().await {
                if let Ok(Ok(Some(syn_ack))) = joined {
                    return Some(syn_ack);
                }
            }
            None
        })
            .await
            .ok()
            .flatten();

        set.abort_all();

        match result {
            Some((ttl, window, opts)) => {
                if verbose {
                    eprintln!("  [fingerprint] {} <- SYN+ACK ttl={} window={}", target, ttl, window);
                }
                let fp = parse_stack_fingerprint(ttl, window, &opts);
                let os_hint = guess_os(&fp);
                if verbose {
                    eprintln!("  [fingerprint] {} os_hint={:?}", target, os_hint);
                }
                Some(FingerprintResult { syn_ack: Some(fp), os_hint })
            }
            None => {
                if verbose {
                    eprintln!("  [fingerprint] {} no SYN+ACK on any port", target);
                }
                Some(FingerprintResult { syn_ack: None, os_hint: None })
            }
        }
    }

    pub async fn probe_bulk(
        targets: &[(Ipv4Addr, u16)],
        verbose: bool,
    ) -> HashMap<Ipv4Addr, Option<FingerprintResult>> {
        let mut set = JoinSet::new();
        for &(ip, _) in targets {
            set.spawn(async move {
                let result = probe_syn(ip, verbose).await;
                (ip, result)
            });
        }

        let mut results = HashMap::new();
        while let Some(Ok((ip, result))) = set.join_next().await {
            results.insert(ip, result);
        }
        results
    }
}

#[cfg(feature = "termux")]
mod ttl_only {
    use super::FingerprintResult;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::time::Duration;
    use tokio::task::JoinSet;

    const PORTS: &[u16] = &[80, 443, 22];

    fn connect_and_hint(target: Ipv4Addr) -> Option<String> {
        for &port in PORTS {
            let addr = SocketAddr::new(IpAddr::V4(target), port);
            if TcpStream::connect_timeout(&addr, Duration::from_millis(800)).is_ok() {
                return None;
            }
        }
        None
    }

    async fn probe_syn(target: Ipv4Addr, _verbose: bool) -> Option<FingerprintResult> {
        let hint = tokio::task::spawn_blocking(move || connect_and_hint(target))
            .await
            .ok()
            .flatten();
        Some(FingerprintResult { syn_ack: None, os_hint: hint })
    }

    pub async fn probe_bulk(
        targets: &[(Ipv4Addr, u16)],
        _verbose: bool,
    ) -> HashMap<Ipv4Addr, Option<FingerprintResult>> {
        let mut set = JoinSet::new();
        for &(ip, _) in targets {
            set.spawn(async move {
                let result = probe_syn(ip, false).await;
                (ip, result)
            });
        }
        let mut results = HashMap::new();
        while let Some(Ok((ip, result))) = set.join_next().await {
            results.insert(ip, result);
        }
        results
    }
}