//! mDNS LAN discovery: advertise `_runner._tcp.local` with live node
//! metrics (cores, RAM, slots) in TXT records and browse for peers.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

/// Service type advertised by mesh nodes on the LAN.
pub const MESH_SERVICE_TYPE: &str = "_runner._tcp.local.";
/// mDNS announcement port (mesh control plane).
pub const MESH_MDNS_PORT: u16 = 9_535;

/// Node capacity metrics broadcast in TXT records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanMetrics {
    pub cores: u32,
    pub ram_mb: u64,
    pub slots: u32,
}

/// Encode metrics as TXT properties (pure; unit-tested).
pub fn encode_metrics(metrics: &LanMetrics) -> [(&'static str, String); 4] {
    [
        ("version", env!("CARGO_PKG_VERSION").to_string()),
        ("cores", metrics.cores.to_string()),
        ("ram_mb", metrics.ram_mb.to_string()),
        ("slots", metrics.slots.to_string()),
    ]
}

/// Decode metrics from resolved TXT properties (pure; unit-tested).
pub fn decode_metrics(props: &HashMap<String, String>) -> Option<LanMetrics> {
    Some(LanMetrics {
        cores: props.get("cores")?.parse().ok()?,
        ram_mb: props.get("ram_mb")?.parse().ok()?,
        slots: props.get("slots")?.parse().ok()?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredNode {
    pub instance: String,
    pub host: String,
    pub port: u16,
    pub addrs: Vec<IpAddr>,
    pub metrics: Option<LanMetrics>,
}

/// Zero-config LAN presence: register this node and browse for peers.
pub struct LanDiscovery {
    daemon: ServiceDaemon,
    fullname: String,
}

impl LanDiscovery {
    /// Start advertising `instance` on the LAN with initial metrics.
    pub fn advertise(
        instance: &str,
        host: &str,
        ip: IpAddr,
        metrics: &LanMetrics,
    ) -> Result<Self, String> {
        let daemon = ServiceDaemon::new().map_err(|e| format!("mdns daemon: {e}"))?;
        let props = encode_metrics(metrics);
        let prop_refs: Vec<(&str, &str)> =
            props.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let info = ServiceInfo::new(MESH_SERVICE_TYPE, instance, host, ip, MESH_MDNS_PORT, &prop_refs[..])
            .map_err(|e| format!("mdns service info: {e}"))?;
        let fullname = info.get_fullname().to_string();
        daemon.register(info).map_err(|e| format!("mdns register: {e}"))?;
        Ok(Self { daemon, fullname })
    }

    /// Re-publish metrics (re-registering the same instance updates it).
    pub fn update_metrics(
        &self,
        instance: &str,
        host: &str,
        ip: IpAddr,
        metrics: &LanMetrics,
    ) -> Result<(), String> {
        let props = encode_metrics(metrics);
        let prop_refs: Vec<(&str, &str)> =
            props.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let info = ServiceInfo::new(MESH_SERVICE_TYPE, instance, host, ip, MESH_MDNS_PORT, &prop_refs[..])
            .map_err(|e| format!("mdns service info: {e}"))?;
        self.daemon.register(info).map_err(|e| format!("mdns update: {e}"))?;
        Ok(())
    }

    /// Browse until `timeout`, collecting resolved peers (excluding self).
    pub fn browse_timeout(&self, timeout: Duration) -> Result<Vec<DiscoveredNode>, String> {
        let receiver = self
            .daemon
            .browse(MESH_SERVICE_TYPE)
            .map_err(|e| format!("mdns browse: {e}"))?;
        let deadline = std::time::Instant::now() + timeout;
        let mut nodes: HashMap<String, DiscoveredNode> = HashMap::new();
        while let Ok(event) = receiver.recv_deadline(deadline) {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    if info.get_fullname() == self.fullname {
                        continue;
                    }
                    let mut props = HashMap::new();
                    for key in ["cores", "ram_mb", "slots"] {
                        if let Some(value) = info.get_property_val_str(key) {
                            props.insert(key.to_string(), value.to_string());
                        }
                    }
                    nodes.insert(
                        info.get_fullname().to_string(),
                        DiscoveredNode {
                            instance: info.get_fullname().to_string(),
                            host: info.get_hostname().to_string(),
                            port: info.get_port(),
                            addrs: info.get_addresses().iter().map(|ip| ip.to_ip_addr()).collect(),
                            metrics: decode_metrics(&props),
                        },
                    );
                }
                ServiceEvent::ServiceRemoved(_, fullname) => {
                    nodes.remove(&fullname);
                }
                _ => {}
            }
        }
        Ok(nodes.into_values().collect())
    }

    /// Browse-only probe: no advertisement, collect peers until timeout.
    pub fn browse_only(timeout: Duration) -> Result<Vec<DiscoveredNode>, String> {
        let daemon = ServiceDaemon::new().map_err(|e| format!("mdns daemon: {e}"))?;
        let receiver = daemon
            .browse(MESH_SERVICE_TYPE)
            .map_err(|e| format!("mdns browse: {e}"))?;
        let deadline = std::time::Instant::now() + timeout;
        let mut nodes: HashMap<String, DiscoveredNode> = HashMap::new();
        while let Ok(event) = receiver.recv_deadline(deadline) {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    let mut props = HashMap::new();
                    for key in ["cores", "ram_mb", "slots"] {
                        if let Some(value) = info.get_property_val_str(key) {
                            props.insert(key.to_string(), value.to_string());
                        }
                    }
                    nodes.insert(
                        info.get_fullname().to_string(),
                        DiscoveredNode {
                            instance: info.get_fullname().to_string(),
                            host: info.get_hostname().to_string(),
                            port: info.get_port(),
                            addrs: info.get_addresses().iter().map(|ip| ip.to_ip_addr()).collect(),
                            metrics: decode_metrics(&props),
                        },
                    );
                }
                ServiceEvent::ServiceRemoved(_, fullname) => {
                    nodes.remove(&fullname);
                }
                _ => {}
            }
        }
        daemon.shutdown().map_err(|e| format!("mdns shutdown: {e}"))?;
        Ok(nodes.into_values().collect())
    }

    /// Stop advertising.
    pub fn shutdown(self) -> Result<(), String> {
        self.daemon
            .unregister(&self.fullname)
            .map_err(|e| format!("mdns unregister: {e}"))?;
        self.daemon.shutdown().map_err(|e| format!("mdns shutdown: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_txt_roundtrip() {
        let metrics = LanMetrics { cores: 8, ram_mb: 16384, slots: 4 };
        let encoded = encode_metrics(&metrics);
        let map: HashMap<String, String> = encoded
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        assert_eq!(decode_metrics(&map), Some(metrics));
    }

    #[test]
    fn missing_metrics_decode_to_none() {
        assert_eq!(decode_metrics(&HashMap::new()), None);
    }
}
