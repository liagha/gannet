// FILE: src/identity/device.rs
// PURPOSE: Unified device model combining discovery and enrichment data
use crate::discovery::arp::ArpEntry;
use crate::discovery::fingerprint::FingerprintResult;
use macaddr::MacAddr6;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    Arp,
    Sweep,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub ip: Ipv4Addr,
    pub mac: Option<MacAddr6>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub os_hint: Option<String>,
    pub via: Via,
    #[allow(dead_code)]
    pub tag: Option<String>,
}

impl From<&ArpEntry> for Device {
    fn from(entry: &ArpEntry) -> Self {
        Device {
            ip: entry.ip,
            mac: Some(entry.mac),
            vendor: None,
            hostname: None,
            os_hint: None,
            via: Via::Arp,
            tag: None,
        }
    }
}

impl Device {
    pub fn from_sweep(ip: Ipv4Addr) -> Self {
        Device {
            ip,
            mac: None,
            vendor: None,
            hostname: None,
            os_hint: None,
            via: Via::Sweep,
            tag: None,
        }
    }

    pub fn apply_fingerprint(&mut self, fp: &FingerprintResult) {
        self.os_hint = fp.os_hint.clone();
    }
}