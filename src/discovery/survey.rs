// FILE: src/discovery/survey.rs
// PURPOSE: Three-layer subnet survey — passive gateway detection, UPnP interrogation, active sweep
use crate::discovery::sweep;
use pnet::datalink;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::str::FromStr;
use std::time::Duration;
use tokio::task::JoinSet;

#[derive(Debug, Clone)]
pub struct DiscoveredSubnet {
    pub network: Ipv4Addr,
    pub prefix: u8,
    pub host_count: Option<usize>,
    pub source: SubnetSource,
    pub gateway: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubnetSource {
    GatewayRoute,
    DhcpOffer,
    UpnpDiscovery,
    AdjacentSweep,
    CommonPrivate,
}

#[derive(Debug, Clone)]
struct GatewayInfo {
    ip: Ipv4Addr,
    mac: [u8; 6],
    subnet: Option<(Ipv4Addr, u8)>,
}

fn detect_gateways_passive(iface_name: &str, duration: Duration, verbose: bool) -> Vec<GatewayInfo> {
    let interfaces = datalink::interfaces();
    let iface = match interfaces.iter().find(|i| i.name == iface_name && i.is_up() && !i.is_loopback()) {
        Some(i) => i.clone(),
        None => return Vec::new(),
    };

    let local_subnet = subnet_from_interface(&iface);
    let mut config = datalink::Config::default();
    config.read_timeout = Some(Duration::from_millis(200));

    let mut rx = match datalink::channel(&iface, config) {
        Ok(datalink::Channel::Ethernet(_, rx)) => rx,
        _ => return Vec::new(),
    };

    let deadline = std::time::Instant::now() + duration;
    let mut gateways: HashMap<Ipv4Addr, [u8; 6]> = HashMap::new();
    let mut dhcp_servers: HashSet<Ipv4Addr> = HashSet::new();

    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    match eth.get_ethertype() {
                        EtherTypes::Arp => {
                            if let Some(arp) = ArpPacket::new(eth.payload()) {
                                let sender = Ipv4Addr::from(arp.get_sender_proto_addr());
                                let target = Ipv4Addr::from(arp.get_target_proto_addr());
                                let sm = arp.get_sender_hw_addr();
                                let sender_mac = [sm.0, sm.1, sm.2, sm.3, sm.4, sm.5];

                                if sender_mac == [0, 0, 0, 0, 0, 0] {
                                    continue;
                                }

                                let in_local = local_subnet
                                    .map(|(b, p)| ip_in_subnet(sender, b, p))
                                    .unwrap_or(true);

                                if in_local && sender != Ipv4Addr::UNSPECIFIED && sender != Ipv4Addr::new(0, 0, 0, 0) {
                                    let is_gateway = sender.octets()[3] == 1
                                        || sender.octets()[3] == 254;
                                    if is_gateway {
                                        gateways.entry(sender).or_insert(sender_mac);
                                    }
                                }

                                if in_local && target != Ipv4Addr::UNSPECIFIED && target != Ipv4Addr::new(0, 0, 0, 0) {
                                    let is_gateway = target.octets()[3] == 1
                                        || target.octets()[3] == 254;
                                    if is_gateway {
                                        let tm = arp.get_target_hw_addr();
                                        let target_mac = [tm.0, tm.1, tm.2, tm.3, tm.4, tm.5];
                                        if target_mac != [0, 0, 0, 0, 0, 0] {
                                            gateways.entry(target).or_insert(target_mac);
                                        }
                                    }
                                }
                            }
                        }
                        EtherTypes::Ipv4 => {
                            if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                                if ipv4.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Udp {
                                    if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                        if udp.get_source() == 67 || udp.get_destination() == 67 {
                                            let src = Ipv4Addr::from(ipv4.get_source());
                                            if !src.is_unspecified() {
                                                dhcp_servers.insert(src);
                                            }
                                            let dst = Ipv4Addr::from(ipv4.get_destination());
                                            if !dst.is_unspecified() {
                                                dhcp_servers.insert(dst);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    let mut result: Vec<GatewayInfo> = gateways
        .into_iter()
        .map(|(ip, mac)| GatewayInfo {
            ip,
            mac,
            subnet: local_subnet,
        })
        .collect();

    for dhcp_ip in dhcp_servers {
        if !result.iter().any(|g| g.ip == dhcp_ip) {
            result.push(GatewayInfo {
                ip: dhcp_ip,
                mac: [0, 0, 0, 0, 0, 0],
                subnet: local_subnet,
            });
        }
    }

    if verbose {
        eprintln!("  [survey:passive] found {} gateway/DHCP candidate(s)", result.len());
        for g in &result {
            eprintln!("    gateway={} subnet={:?}", g.ip, g.subnet);
        }
    }

    result
}

fn subnet_from_interface(iface: &datalink::NetworkInterface) -> Option<(Ipv4Addr, u8)> {
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

fn probe_gateway_upnp(gateway: Ipv4Addr, verbose: bool) -> Vec<(Ipv4Addr, u8, SubnetSource)> {
    let mut discovered = Vec::new();

    let wan_subnets = query_upnp_wan(gateway, verbose);
    discovered.extend(wan_subnets);

    let route_subnets = query_upnp_routes(gateway, verbose);
    discovered.extend(route_subnets);

    discovered
}

fn upnp_soap_body(action: &str, service: &str, args: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\r\n\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n\
         <s:Body>\r\n\
         <u:{action} xmlns:u=\"{service}\">\r\n\
         {args}\r\n\
         </u:{action}>\r\n\
         </s:Body>\r\n\
         </s:Envelope>\r\n",
        action = action,
        service = service,
        args = args
    )
}

fn upnp_http_post(url: &str, soap: &str, timeout: Duration) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port().unwrap_or(80);

    let mut stream = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::new(IpAddr::V4(host.parse().ok()?), port),
        timeout,
    )
        .ok()?;

    use std::io::{Read, Write};
    stream.set_read_timeout(Some(timeout)).ok()?;

    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         Content-Type: text/xml; charset=\"utf-8\"\r\n\
         SOAPAction: \"{}#{}\"\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        parsed.path(),
        host,
        port,
        parsed.path().rsplit('/').next().unwrap_or(""),
        parsed.path().rsplit('/').next().unwrap_or(""),
        soap.len(),
        soap
    );

    stream.write_all(request.as_bytes()).ok()?;

    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;

    let body_start = response.find("\r\n\r\n")?;
    Some(response[body_start + 4..].to_string())
}

fn discover_upnp_services(gateway: Ipv4Addr, timeout: Duration, verbose: bool) -> Vec<String> {
    let ssdp_target = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    socket.set_read_timeout(Some(Duration::from_millis(600))).ok();

    let ssdp_msearch = "M-SEARCH * HTTP/1.1\r\n\
                        Host: 239.255.255.250:1900\r\n\
                        Man: \"ssdp:discover\"\r\n\
                        MX: 2\r\n\
                        ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                        \r\n";

    let _ = socket.send_to(ssdp_msearch.as_bytes(), ssdp_target);

    let mut buf = [0u8; 2048];
    let mut locations = Vec::new();
    let deadline = std::time::Instant::now() + timeout;

    while std::time::Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                if let std::net::SocketAddr::V4(s) = src {
                    if *s.ip() == gateway {
                        let data = String::from_utf8_lossy(&buf[..len]);
                        for line in data.lines() {
                            if line.to_lowercase().starts_with("location:") {
                                let url = line[9..].trim().to_string();
                                if verbose {
                                    eprintln!("  [survey:upnp] SSDP from {} -> {}", gateway, url);
                                }
                                locations.push(url);
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }

    if locations.is_empty() {
        let common_ports = &[5000u16, 49152, 49153, 49154, 49155, 1780, 8080];
        for &port in common_ports {
            let test_url = format!("http://{}:{}/rootDesc.xml", gateway, port);
            if let Some(body) = upnp_http_post(&test_url, "", Duration::from_millis(400)) {
                if body.contains("InternetGatewayDevice") || body.contains("WANDevice") {
                    if verbose {
                        eprintln!("  [survey:upnp] found IGD at {}", test_url);
                    }
                    return vec![test_url.trim_end_matches("rootDesc.xml").to_string()];
                }
            }
        }
    }

    locations
}

fn query_upnp_wan(gateway: Ipv4Addr, verbose: bool) -> Vec<(Ipv4Addr, u8, SubnetSource)> {
    let mut subnets = Vec::new();
    let services = discover_upnp_services(gateway, Duration::from_secs(3), verbose);

    if services.is_empty() {
        return subnets;
    }

    let base_urls: Vec<String> = services.into_iter().map(|url| {
        if url.ends_with("rootDesc.xml") {
            url.trim_end_matches("rootDesc.xml").to_string()
        } else if url.ends_with('/') {
            url
        } else {
            format!("{}/", url)
        }
    }).collect();

    let wan_services = &[
        ("WANIPConnection:1", "/WANIPConnCtrlURL", "GetExternalIPAddress", ""),
        ("WANPPPConnection:1", "/WANPPPConnCtrlURL", "GetExternalIPAddress", ""),
    ];

    let lan_services = &[
        ("LANHostConfigManagement:1", "/LANHostCfgURL", "GetSubnetMask", ""),
        ("LANHostConfigManagement:1", "/LANHostCfgURL", "GetIPRoutersList", ""),
        ("Layer3Forwarding:1", "/L3FwdURL", "GetDefaultConnectionService", ""),
    ];

    for base in &base_urls {
        for (service, control_path, action, _args) in wan_services {
            let soap = upnp_soap_body(action, &format!("urn:schemas-upnp-org:service:{}", service), "");
            let url = format!("{}{}", base.trim_end_matches('/'), control_path);
            if let Some(response) = upnp_http_post(&url, &soap, Duration::from_millis(800)) {
                if let Some(ip_str) = extract_xml_value(&response, "NewExternalIPAddress") {
                    if let Ok(wan_ip) = Ipv4Addr::from_str(&ip_str) {
                        if !wan_ip.is_unspecified() && !wan_ip.is_private() {
                            if verbose {
                                eprintln!("  [survey:upnp] WAN IP from {}: {}", gateway, wan_ip);
                            }
                            for common_prefix in &[24u8, 28, 29, 30] {
                                let base = network_base(wan_ip, *common_prefix);
                                subnets.push((base, *common_prefix, SubnetSource::UpnpDiscovery));
                            }
                        }
                    }
                }
                if let Some(subnet_mask) = extract_xml_value(&response, "NewSubnetMask") {
                    if let Ok(mask) = Ipv4Addr::from_str(&subnet_mask) {
                        let prefix = mask_to_prefix(mask);
                        if let Some(wan_ip_str) = extract_xml_value(&response, "NewExternalIPAddress") {
                            if let Ok(wan_ip) = Ipv4Addr::from_str(&wan_ip_str) {
                                let base = network_base(wan_ip, prefix);
                                subnets.push((base, prefix, SubnetSource::UpnpDiscovery));
                                if verbose {
                                    eprintln!("  [survey:upnp] WAN subnet: {}/{}", base, prefix);
                                }
                            }
                        }
                    }
                }
            }
        }

        for (service, control_path, action, _) in lan_services {
            let soap = upnp_soap_body(action, &format!("urn:schemas-upnp-org:service:{}", service), "");
            let url = format!("{}{}", base.trim_end_matches('/'), control_path);
            if let Some(response) = upnp_http_post(&url, &soap, Duration::from_millis(800)) {
                if *action == "GetIPRoutersList" {
                    if let Some(routers) = extract_xml_value(&response, "NewIPRouters") {
                        for ip_str in routers.split(',') {
                            if let Ok(router_ip) = Ipv4Addr::from_str(ip_str.trim()) {
                                if verbose {
                                    eprintln!("  [survey:upnp] secondary router from {}: {}", gateway, router_ip);
                                }
                                subnets.push((router_ip, 24, SubnetSource::UpnpDiscovery));
                                subnets.push((router_ip, 16, SubnetSource::UpnpDiscovery));
                            }
                        }
                    }
                }
            }
        }
    }

    subnets
}

fn query_upnp_routes(gateway: Ipv4Addr, verbose: bool) -> Vec<(Ipv4Addr, u8, SubnetSource)> {
    let mut subnets = Vec::new();

    let wan_common = &[
        ("WANCommonInterfaceConfig:1", "/WANCommonIfCfgURL", "GetCommonLinkProperties", ""),
    ];

    let services = discover_upnp_services(gateway, Duration::from_secs(2), verbose);
    let base_urls: Vec<String> = services.into_iter().map(|url| {
        if url.ends_with("rootDesc.xml") {
            url.trim_end_matches("rootDesc.xml").to_string()
        } else if url.ends_with('/') {
            url
        } else {
            format!("{}/", url)
        }
    }).collect();

    for base in &base_urls {
        for (service, control_path, action, _) in wan_common {
            let soap = upnp_soap_body(action, &format!("urn:schemas-upnp-org:service:{}", service), "");
            let url = format!("{}{}", base.trim_end_matches('/'), control_path);
            if let Some(response) = upnp_http_post(&url, &soap, Duration::from_millis(800)) {
                if let Some(wan_access) = extract_xml_value(&response, "NewWANAccessType") {
                    if verbose {
                        eprintln!("  [survey:upnp] WAN type from {}: {}", gateway, wan_access);
                    }
                }
            }
        }
    }

    subnets
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);

    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)?;
    Some(xml[start..start + end].to_string())
}

fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

fn network_base(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = !((1u32 << (32 - prefix)) - 1);
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn adjacent_subnets_from(base: Ipv4Addr, prefix: u8) -> Vec<(Ipv4Addr, u8, SubnetSource)> {
    if prefix != 24 {
        return vec![
            (base, prefix, SubnetSource::AdjacentSweep),
        ];
    }

    let octets = base.octets();
    let second = octets[1] as u32;
    let third = octets[2] as u32;

    let mut candidates = Vec::new();

    let adjacent = [
        second.saturating_sub(1),
        second,
        second + 1,
    ];

    for &b in &adjacent {
        if b <= 255 {
            candidates.push((b, third));
        }
    }

    for i in 0..=255u32 {
        if candidates.len() >= 3 && (i < third.saturating_sub(1) || i > third + 1) {
            continue;
        }
        for &b in &adjacent {
            candidates.push((b, i));
        }
    }

    let seen: HashSet<(u32, u32)> = candidates.into_iter().collect();
    let mut subnets: Vec<(Ipv4Addr, u8, SubnetSource)> = seen
        .into_iter()
        .filter(|(b, c)| {
            !(*b == second && *c == third)
        })
        .map(|(b, c)| {
            let network = Ipv4Addr::new(octets[0], b as u8, c as u8, 0);
            (network, 24, SubnetSource::AdjacentSweep)
        })
        .collect();

    let common_private = &[
        (10, 0, 0), (10, 0, 1), (10, 0, 10), (10, 10, 0), (10, 10, 10),
        (172, 16, 0), (172, 16, 1), (172, 17, 0),
        (192, 168, 0), (192, 168, 1), (192, 168, 10), (192, 168, 100),
    ];

    for &(a, b, c) in common_private {
        let network = Ipv4Addr::new(a, b, c, 0);
        let is_current = octets[0] == a && octets[1] == b && octets[2] == c;
        let already_included = subnets.iter().any(|(n, _, _)| *n == network);
        if !is_current && !already_included {
            subnets.push((network, 24, SubnetSource::CommonPrivate));
        }
    }

    subnets
}

async fn probe_subnet_for_hosts(
    network: Ipv4Addr,
    prefix: u8,
    iface: Option<String>,
    verbose: bool,
) -> Option<usize> {
    if prefix < 24 || prefix > 30 {
        return None;
    }

    let known: HashSet<Ipv4Addr> = HashSet::new();
    let found = sweep::sweep_subnet(network, prefix, &known, iface.as_deref(), verbose).await;
    let count = found.len();

    if count > 0 || verbose {
        let arp_results = crate::discovery::arp::scan_subnet(network, prefix, iface.as_deref()).await;
        let total = std::cmp::max(count, arp_results.len());
        Some(total)
    } else {
        Some(0)
    }
}

pub async fn survey(iface: Option<String>, verbose: bool) -> Vec<DiscoveredSubnet> {
    let iface_name = match crate::net::interface::find_interface(iface.as_deref()) {
        Some(i) => i.name.clone(),
        None => {
            eprintln!("No suitable interface found.");
            return Vec::new();
        }
    };

    if verbose {
        eprintln!("[survey] Layer 1: passive gateway detection (30s)...");
    }
    let gateways = tokio::task::spawn_blocking(move || {
        detect_gateways_passive(&iface_name, Duration::from_secs(30), verbose)
    })
        .await
        .unwrap_or_default();

    let mut all_subnets: HashMap<(Ipv4Addr, u8), SubnetSource> = HashMap::new();
    let mut gateway_map: HashMap<(Ipv4Addr, u8), Ipv4Addr> = HashMap::new();

    for gw in &gateways {
        if let Some((net, pref)) = gw.subnet {
            all_subnets.entry((net, pref)).or_insert(SubnetSource::GatewayRoute);
            gateway_map.entry((net, pref)).or_insert(gw.ip);
        }
    }

    if verbose {
        eprintln!("[survey] Layer 2: UPnP gateway interrogation...");
    }
    for gw in &gateways {
        let upnp_subnets = probe_gateway_upnp(gw.ip, verbose);
        for (net, pref, source) in upnp_subnets {
            all_subnets.entry((net, pref)).or_insert(source);
            gateway_map.entry((net, pref)).or_insert(gw.ip);
        }
    }

    let local_subnet = {
        let local_iface = crate::net::interface::find_interface(iface.as_deref());
        local_iface.and_then(|i| {
            i.ips.iter().find(|ip| ip.is_ipv4()).map(|ip| {
                if let IpAddr::V4(v4) = ip.ip() {
                    let prefix = ip.prefix();
                    let base = network_base(v4, prefix);
                    (base, prefix)
                } else {
                    (Ipv4Addr::new(192, 168, 1, 0), 24)
                }
            })
        }).unwrap_or((Ipv4Addr::new(192, 168, 1, 0), 24))
    };

    if verbose {
        eprintln!("[survey] Layer 3: generating adjacent sweep targets...");
    }
    let adjacent = adjacent_subnets_from(local_subnet.0, local_subnet.1);
    for (net, pref, source) in adjacent {
        all_subnets.entry((net, pref)).or_insert(source);
    }

    if verbose {
        eprintln!("[survey] Probing {} candidate subnet(s)...", all_subnets.len());
    }

    let mut discovered = Vec::new();
    let mut probe_tasks = JoinSet::new();

    for ((net, pref), source) in &all_subnets {
        let net = *net;
        let pref = *pref;
        let source = source.clone();
        let iface_clone = iface.clone();
        let verbose_clone = verbose;

        probe_tasks.spawn(async move {
            let host_count = probe_subnet_for_hosts(net, pref, iface_clone, verbose_clone).await;
            (net, pref, source, host_count)
        });
    }

    while let Some(result) = probe_tasks.join_next().await {
        if let Ok((net, pref, source, host_count)) = result {
            let gateway = gateway_map.get(&(net, pref)).copied();
            let entry = DiscoveredSubnet {
                network: net,
                prefix: pref,
                host_count,
                source,
                gateway,
            };
            if verbose {
                eprintln!(
                    "  [survey] {}/{} {:?} hosts={:?} gw={:?}",
                    net, pref, entry.source, host_count, gateway
                );
            }
            discovered.push(entry);
        }
    }

    discovered.sort_by_key(|s| match s.source {
        SubnetSource::GatewayRoute => 0,
        SubnetSource::DhcpOffer => 1,
        SubnetSource::UpnpDiscovery => 2,
        SubnetSource::AdjacentSweep => 3,
        SubnetSource::CommonPrivate => 4,
    });

    discovered
}