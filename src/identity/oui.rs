use macaddr::MacAddr6;
use std::collections::HashMap;
use std::sync::OnceLock;

static TABLE: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();

const RAW: &str = include_str!("../../src/data/oui.csv");

fn table() -> &'static HashMap<u32, &'static str> {
    TABLE.get_or_init(|| {
        let mut map = HashMap::new();
        for line in RAW.lines() {
            if let Some((hex, name)) = line.split_once(',') {
                if let Ok(n) = u32::from_str_radix(hex.trim(), 16) {
                    map.insert(n, unsafe {
                        std::mem::transmute::<&str, &'static str>(name)
                    });
                }
            }
        }
        map
    })
}

pub fn lookup(mac: MacAddr6) -> Option<&'static str> {
    let bytes = mac.as_bytes();
    let oui = (bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | bytes[2] as u32;
    table().get(&oui).copied()
}