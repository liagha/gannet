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
    pub ips: Vec<String>,
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

fn mac_key(mac: MacAddr6) -> String {
    let b = mac.as_bytes();
    format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
}

fn ip_key(ip: Ipv4Addr) -> String {
    ip.to_string()
}

fn insert_record(records: &mut HashMap<String, Record>, mut record: Record) -> &Record {
    let key = record.key.clone();
    records.insert(key.clone(), record);
    &records[&key]
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
        let now = now_secs();
        let ip_str = device.ip.to_string();

        match device.mac {
            Some(mac) => {
                let mkey = mac_key(mac);

                let existing_by_ip = self.records.values().find(|r| r.last_ip == ip_str && r.key != mkey).map(|r| r.key.clone());
                let existing_by_ip = existing_by_ip.or_else(|| {
                    if self.records.contains_key(&ip_str) { Some(ip_str.clone()) } else { None }
                });

                if let Some(old_key) = existing_by_ip {
                    if let Some(mut old) = self.records.remove(&old_key) {
                        if !old.ips.contains(&ip_str) {
                            old.ips.push(ip_str.clone());
                        }
                        old.last_ip = ip_str.clone();
                        old.last_seen = now;
                        old.seen_count += 1;
                        if old.mac.is_none() {
                            old.mac = Some(mac.to_string());
                            old.key = mkey.clone();
                            if device.vendor.is_some() { old.vendor = device.vendor.clone(); }
                            if device.hostname.is_some() { old.hostname = device.hostname.clone(); }
                            if device.os_hint.is_some() { old.os_hint = device.os_hint.clone(); }
                        }
                        if device.vendor.is_some() { old.vendor = device.vendor.clone(); }
                        if device.hostname.is_some() { old.hostname = device.hostname.clone(); }
                        if device.os_hint.is_some() { old.os_hint = device.os_hint.clone(); }
                        return insert_record(&mut self.records, old);
                    }
                }

                let record = self.records.entry(mkey.clone()).or_insert_with(|| {
                    let mut ips = vec![ip_str.clone()];
                    Record {
                        key: mkey.clone(),
                        mac: Some(mac.to_string()),
                        last_ip: ip_str.clone(),
                        ips,
                        tag: Some(tag_gen(&mkey)),
                        vendor: device.vendor.clone(),
                        hostname: device.hostname.clone(),
                        os_hint: device.os_hint.clone(),
                        first_seen: now,
                        last_seen: now,
                        seen_count: 0,
                    }
                });

                record.last_ip = ip_str.clone();
                record.last_seen = now;
                record.seen_count += 1;
                if !record.ips.contains(&ip_str) {
                    record.ips.push(ip_str.clone());
                }
                if device.vendor.is_some() { record.vendor = device.vendor.clone(); }
                if device.hostname.is_some() { record.hostname = device.hostname.clone(); }
                if device.os_hint.is_some() { record.os_hint = device.os_hint.clone(); }

                &self.records[&mkey]
            }
            None => {
                let ikey = ip_key(device.ip);

                let record = self.records.entry(ikey.clone()).or_insert_with(|| Record {
                    key: ikey.clone(),
                    mac: None,
                    last_ip: ip_str.clone(),
                    ips: vec![ip_str.clone()],
                    tag: Some(tag_gen(&ikey)),
                    vendor: device.vendor.clone(),
                    hostname: device.hostname.clone(),
                    os_hint: device.os_hint.clone(),
                    first_seen: now,
                    last_seen: now,
                    seen_count: 0,
                });

                record.last_ip = ip_str.clone();
                record.last_seen = now;
                record.seen_count += 1;
                if !record.ips.contains(&ip_str) {
                    record.ips.push(ip_str.clone());
                }
                if device.vendor.is_some() { record.vendor = device.vendor.clone(); }
                if device.hostname.is_some() { record.hostname = device.hostname.clone(); }
                if device.os_hint.is_some() { record.os_hint = device.os_hint.clone(); }

                &self.records[&ikey]
            }
        }
    }

    pub fn get(&self, mac: Option<MacAddr6>, ip: Ipv4Addr) -> Option<&Record> {
        if let Some(m) = mac {
            let key = mac_key(m);
            if let Some(r) = self.records.get(&key) {
                return Some(r);
            }
        }
        self.records.get(&ip.to_string())
    }

    pub fn all(&self) -> impl Iterator<Item = &Record> {
        self.records.values()
    }

    pub fn set_tag(&mut self, mac: Option<MacAddr6>, ip: Ipv4Addr, tag: String) -> bool {
        if let Some(m) = mac {
            let key = mac_key(m);
            if let Some(r) = self.records.get_mut(&key) {
                r.tag = Some(tag);
                return true;
            }
        }
        let key = ip.to_string();
        if let Some(r) = self.records.get_mut(&key) {
            r.tag = Some(tag);
            true
        } else {
            false
        }
    }
}