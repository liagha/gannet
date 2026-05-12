// FILE: src/identity/classify.rs
// PURPOSE: Device category classification from vendor, OS hint, and mDNS services
use crate::identity::device::Device;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    Phone,
    Laptop,
    Desktop,
    Router,
    IoT,
    Printer,
    TvStreaming,
    Unknown,
}

impl Category {
    pub fn as_str(&self) -> &str {
        match self {
            Category::Phone => "Phone",
            Category::Laptop => "Laptop",
            Category::Desktop => "Desktop",
            Category::Router => "Router",
            Category::IoT => "IoT",
            Category::Printer => "Printer",
            Category::TvStreaming => "TV/Streaming",
            Category::Unknown => "Unknown",
        }
    }
}

pub fn classify(device: &Device) -> Category {
    let vendor_lower = device.vendor.as_deref().unwrap_or("").to_lowercase();
    let os_lower = device.os_hint.as_deref().unwrap_or("").to_lowercase();
    let hostname_lower = device.hostname.as_deref().unwrap_or("").to_lowercase();
    let services: Vec<String> = device.services.iter().map(|s| s.to_lowercase()).collect();

    let service_hints = service_category(&services);
    let vendor_hint = vendor_category(&vendor_lower);
    let os_hint = os_category(&os_lower);
    let hostname_hint = hostname_category(&hostname_lower);

    if let Some(cat) = service_hints {
        return cat;
    }

    if let Some(cat) = vendor_hint {
        if let Some(sc) = service_hints {
            return sc;
        }
        return cat;
    }

    if let Some(cat) = hostname_hint {
        return cat;
    }

    if let Some(cat) = os_hint {
        return cat;
    }

    if vendor_lower.contains("router")
        || vendor_lower.contains("gateway")
        || vendor_lower.contains("network")
        || vendor_lower.contains("switch")
        || vendor_lower.contains("access point")
    {
        return Category::Router;
    }

    if vendor_lower.contains("printer") || vendor_lower.contains("brother") || vendor_lower.contains("epson") {
        return Category::Printer;
    }

    if vendor_lower.contains("samsung")
        || vendor_lower.contains("xiaomi")
        || vendor_lower.contains("huawei")
        || vendor_lower.contains("oneplus")
        || vendor_lower.contains("google")
        || vendor_lower.contains("motorola")
    {
        if services.is_empty() {
            return Category::Phone;
        }
    }

    if vendor_lower.contains("apple") {
        if services.contains(&"_companion-link".to_string()) || services.contains(&"_apple-mobdev2".to_string()) {
            return Category::Phone;
        }
        return Category::Laptop;
    }

    if vendor_lower.contains("intel")
        || vendor_lower.contains("dell")
        || vendor_lower.contains("lenovo")
        || vendor_lower.contains("hp")
        || vendor_lower.contains("asus")
        || vendor_lower.contains("acer")
        || vendor_lower.contains("msi")
        || vendor_lower.contains("gigabyte")
        || vendor_lower.contains("framework")
    {
        return Category::Laptop;
    }

    if vendor_lower.contains("raspberry")
        || vendor_lower.contains("arduino")
        || vendor_lower.contains("espressif")
        || vendor_lower.contains("nodemcu")
        || vendor_lower.contains("sonoff")
        || vendor_lower.contains("shelly")
        || vendor_lower.contains("tasmota")
        || vendor_lower.contains("tuya")
        || vendor_lower.contains("esp")
    {
        return Category::IoT;
    }

    if vendor_lower.contains("lg")
        || vendor_lower.contains("sony")
        || vendor_lower.contains("tcl")
        || vendor_lower.contains("roku")
        || vendor_lower.contains("philips")
        || vendor_lower.contains("nvidia")
    {
        return Category::TvStreaming;
    }

    Category::Unknown
}

fn service_category(services: &[String]) -> Option<Category> {
    if services.is_empty() {
        return None;
    }

    let tv_services = [
        "_googlecast", "googlecast", "androidtvremote2", "_androidtvremote2",
        "_raop", "raop", "_airplay", "airplay",
        "_spotify-connect", "spotify-connect", "spotifyconnect",
        "privet", "_privet",
    ];

    let phone_services = [
        "_companion-link", "companion-link", "companionlink",
    ];

    let printer_services = [
        "_printer", "printer", "_scanner", "scanner",
        "_ipp", "ipp", "_ipps", "ipps",
    ];

    let laptop_services = [
        "_workstation", "workstation",
        "_ssh", "ssh",
        "_smb", "smb",
        "_nfs", "nfs",
    ];

    for svc in services {
        let s = svc.to_lowercase();

        if tv_services.iter().any(|t| s.contains(t)) {
            return Some(Category::TvStreaming);
        }

        if phone_services.iter().any(|p| s.contains(p)) {
            return Some(Category::Phone);
        }

        if printer_services.iter().any(|p| s.contains(p)) {
            return Some(Category::Printer);
        }

        if laptop_services.iter().any(|l| s.contains(l)) {
            return Some(Category::Laptop);
        }
    }

    if services.iter().any(|s| s.contains("_apple-mobdev2") || s.contains("apple-mobdev2")) {
        return Some(Category::Phone);
    }

    None
}

fn vendor_category(vendor: &str) -> Option<Category> {
    let v = vendor.to_lowercase();

    if v.contains("cisco")
        || v.contains("mikrotik")
        || v.contains("ubiquiti")
        || v.contains("zyxel")
        || v.contains("d-link")
        || v.contains("dlink")
        || v.contains("netgear")
        || v.contains("tp-link")
        || v.contains("tplink")
        || v.contains("linksys")
        || v.contains("asus")
        || v.contains("fritz")
        || v.contains("avm")
    {
        return Some(Category::Router);
    }

    if v.contains("brother")
        || v.contains("epson")
        || v.contains("canon")
        || v.contains("xerox")
        || v.contains("printer")
    {
        return Some(Category::Printer);
    }

    if v.contains("sony")
        || v.contains("samsung")
        || v.contains("lg electronics")
        || v.contains("roku")
        || v.contains("nvidia")
        || v.contains("philips")
        || v.contains("tcl")
    {
        return Some(Category::TvStreaming);
    }

    if v.contains("raspberry")
        || v.contains("arduino")
        || v.contains("espressif")
        || v.contains("sonoff")
        || v.contains("shelly")
        || v.contains("tuya")
    {
        return Some(Category::IoT);
    }

    if v.contains("xiaomi")
        || v.contains("huawei")
        || v.contains("oneplus")
        || v.contains("motorola")
        || v.contains("google")
        || v.contains("pixel")
    {
        return Some(Category::Phone);
    }

    if v.contains("apple") {
        return Some(Category::Laptop);
    }

    None
}

fn os_category(os_hint: &str) -> Option<Category> {
    let o = os_hint.to_lowercase();

    if o.contains("windows") {
        return Some(Category::Desktop);
    }

    if o.contains("android") || o.contains("ios") {
        return Some(Category::Phone);
    }

    if o.contains("linux") || o.contains("macos") {
        return None;
    }

    if o.contains("bsd") || o.contains("solaris") || o.contains("network device") {
        return Some(Category::Router);
    }

    if o.contains("embedded") || o.contains("iot") {
        return Some(Category::IoT);
    }

    None
}

fn hostname_category(hostname: &str) -> Option<Category> {
    let h = hostname.to_lowercase();

    if h.contains("phone")
        || h.contains("iphone")
        || h.contains("android")
        || h.contains("pixel")
        || h.contains("galaxy")
        || h.contains("oneplus")
    {
        return Some(Category::Phone);
    }

    if h.contains("laptop")
        || h.contains("macbook")
        || h.contains("thinkpad")
        || h.contains("xps")
        || h.contains("precision")
        || h.contains("latitude")
    {
        return Some(Category::Laptop);
    }

    if h.contains("desktop")
        || h.contains("gaming")
        || h.contains("workstation")
    {
        return Some(Category::Desktop);
    }

    if h.contains("router")
        || h.contains("gateway")
        || h.contains("fritz")
        || h.contains("ap-")
        || h.contains("mesh")
    {
        return Some(Category::Router);
    }

    if h.contains("tv")
        || h.contains("shield")
        || h.contains("roku")
        || h.contains("chromecast")
        || h.contains("firetv")
    {
        return Some(Category::TvStreaming);
    }

    if h.contains("printer")
        || h.contains("inkjet")
        || h.contains("laser")
    {
        return Some(Category::Printer);
    }

    if h.contains("sensor")
        || h.contains("light")
        || h.contains("plug")
        || h.contains("bulb")
        || h.contains("switch")
        || h.contains("esp")
        || h.contains("shelly")
        || h.contains("sonoff")
    {
        return Some(Category::IoT);
    }

    None
}
