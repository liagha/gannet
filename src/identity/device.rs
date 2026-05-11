use crate::discovery::arp::ArpEntry;
use crate::discovery::fingerprint::FingerprintResult;
use macaddr::MacAddr6;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct Device {
    pub ip: Ipv4Addr,
    pub mac: MacAddr6,
    pub hostname: Option<String>,
    pub os_hint: Option<String>,
    #[allow(dead_code)]
    pub tag: Option<String>,
}

impl From<&ArpEntry> for Device {
    fn from(entry: &ArpEntry) -> Self {
        Device {
            ip: entry.ip,
            mac: entry.mac,
            hostname: None,
            os_hint: None,
            tag: None,
        }
    }
}

impl Device {
    pub fn apply_fingerprint(&mut self, fp: &FingerprintResult) {
        self.os_hint = fp.os_hint.clone();
    }
}
