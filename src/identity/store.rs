// FILE: src/identity/store.rs
// PURPOSE: Persistent JSON device registry keyed by stable identity (MAC or IP)
use crate::identity::device::Device;
use macaddr::MacAddr6;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub key: String,
    pub mac: Option<String>,
    pub last_ip: String,
    pub tag: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub os_hint: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub seen_count: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Store {
    records: HashMap<String, Record>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn make_key(mac: Option<MacAddr6>, ip: Ipv4Addr) -> String {
    match mac {
        Some(m) => {
            let b = m.as_bytes();
            format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
        }
        None => ip.to_string(),
    }
}

impl Store {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }

    pub fn upsert(&mut self, device: &Device, tag_gen: impl Fn(&str) -> String) -> &Record {
        let key = make_key(device.mac, device.ip);
        let now = now_secs();

        let record = self.records.entry(key.clone()).or_insert_with(|| Record {
            key: key.clone(),
            mac: device.mac.map(|m| m.to_string()),
            last_ip: device.ip.to_string(),
            tag: Some(tag_gen(&key)),
            vendor: device.vendor.clone(),
            hostname: device.hostname.clone(),
            os_hint: device.os_hint.clone(),
            first_seen: now,
            last_seen: now,
            seen_count: 0,
        });

        record.last_ip = device.ip.to_string();
        record.last_seen = now;
        record.seen_count += 1;

        if device.vendor.is_some() {
            record.vendor = device.vendor.clone();
        }
        if device.hostname.is_some() {
            record.hostname = device.hostname.clone();
        }
        if device.os_hint.is_some() {
            record.os_hint = device.os_hint.clone();
        }

        &self.records[&key]
    }

    pub fn get(&self, mac: Option<MacAddr6>, ip: Ipv4Addr) -> Option<&Record> {
        let key = make_key(mac, ip);
        self.records.get(&key)
    }

    pub fn all(&self) -> impl Iterator<Item = &Record> {
        self.records.values()
    }

    pub fn set_tag(&mut self, mac: Option<MacAddr6>, ip: Ipv4Addr, tag: String) -> bool {
        let key = make_key(mac, ip);
        if let Some(r) = self.records.get_mut(&key) {
            r.tag = Some(tag);
            true
        } else {
            false
        }
    }
}