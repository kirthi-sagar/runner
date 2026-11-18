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
    /// Cache proxy port when this node serves LAN cache hits.
    pub cache_port: Option<u16>,
    /// Whether LAN cache federation is active on this node.
    pub cache_enabled: bool,
    /// Stable-ish node identity for cache attribution.
    pub node_id: String,
    /// This node's cache bearer token, broadcast so LAN peers can
    /// query it. Trusted-LAN assumption: anyone observing mDNS sees
    /// this (consistent with mDNS itself being unauthenticated
    /// broadcast); it scopes independent meshes apart and keeps
    /// off-LAN attackers out, nothing more.
    pub cache_token: String,
}

/// Encode metrics as TXT properties (pure; unit-tested).
pub fn encode_metrics(metrics: &LanMetrics) -> Vec<(&'static str, String)> {
    let mut props = vec![
        ("version", env!("CARGO_PKG_VERSION").to_string()),
        ("cores", metrics.cores.to_string()),
        ("ram_mb", metrics.ram_mb.to_string()),
        ("slots", metrics.slots.to_string()),
        ("cache_enabled", (metrics.cache_enabled as u8).to_string()),
        ("node_id", metrics.node_id.clone()),
    ];
    if let Some(port) = metrics.cache_port {
        props.push(("cache_port", port.to_string()));
    }
    if !metrics.cache_token.is_empty() {
        props.push(("cache_token", metrics.cache_token.clone()));
    }
    props
}

/// Decode metrics from resolved TXT properties (pure; unit-tested).
/// Cache fields are optional: pre-federation peers lack them.
pub fn decode_metrics(props: &HashMap<String, String>) -> Option<LanMetrics> {
    Some(LanMetrics {
        cores: props.get("cores")?.parse().ok()?,
        ram_mb: props.get("ram_mb")?.parse().ok()?,
        slots: props.get("slots")?.parse().ok()?,
        cache_port: props.get("cache_port").and_then(|p| p.parse().ok()),
        cache_enabled: props.get("cache_enabled").is_some_and(|v| v == "1"),
        node_id: props.get("node_id").cloned().unwrap_or_default(),
        cache_token: props.get("cache_token").cloned().unwrap_or_default(),
    })
}

/// Primary outbound LAN IP via the UDP-socket trick: "connecting" a
/// datagram socket (no packets sent) reveals the source address the
/// kernel would route with. `None` when offline.
pub fn primary_lan_ip() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// True when a `host:port` listen string binds a LAN-reachable
/// address (explicit LAN IP or a wildcard), not loopback.
pub fn listen_is_lan(listen: &str) -> bool {
    let host = listen
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(listen)
        .trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() || host == "0.0.0.0" || host == "::" {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => !ip.is_loopback(),
        // Hostnames resolve at bind time; assume reachable, let bind fail.
        Err(_) => true,
    }
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
        let prop_refs: Vec<(&str, &str)> = props.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let info = ServiceInfo::new(
            MESH_SERVICE_TYPE,
            instance,
            host,
            ip,
            MESH_MDNS_PORT,
            &prop_refs[..],
        )
        .map_err(|e| format!("mdns service info: {e}"))?;
        let fullname = info.get_fullname().to_string();
        daemon
            .register(info)
            .map_err(|e| format!("mdns register: {e}"))?;
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
        let prop_refs: Vec<(&str, &str)> = props.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let info = ServiceInfo::new(
            MESH_SERVICE_TYPE,
            instance,
            host,
            ip,
            MESH_MDNS_PORT,
            &prop_refs[..],
        )
        .map_err(|e| format!("mdns service info: {e}"))?;
        self.daemon
            .register(info)
            .map_err(|e| format!("mdns update: {e}"))?;
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
                    for key in [
                        "cores",
                        "ram_mb",
                        "slots",
                        "cache_port",
                        "cache_enabled",
                        "node_id",
                        "cache_token",
                    ] {
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
                            addrs: info
                                .get_addresses()
                                .iter()
                                .map(|ip| ip.to_ip_addr())
                                .collect(),
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
                    for key in [
                        "cores",
                        "ram_mb",
                        "slots",
                        "cache_port",
                        "cache_enabled",
                        "node_id",
                        "cache_token",
                    ] {
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
                            addrs: info
                                .get_addresses()
                                .iter()
                                .map(|ip| ip.to_ip_addr())
                                .collect(),
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
        daemon
            .shutdown()
            .map_err(|e| format!("mdns shutdown: {e}"))?;
        Ok(nodes.into_values().collect())
    }

    /// Stop advertising.
    pub fn shutdown(self) -> Result<(), String> {
        self.daemon
            .unregister(&self.fullname)
            .map_err(|e| format!("mdns unregister: {e}"))?;
        self.daemon
            .shutdown()
            .map_err(|e| format!("mdns shutdown: {e}"))?;
        Ok(())
    }

    /// Continuous presence for cache federation: advertise once, then
    /// refresh metrics every 60s until the process exits. Best-effort:
    /// failures log and retry next heartbeat, never fatal.
    pub async fn advertise_loop(
        state: crate::governor::supervisor::SharedState,
        node_id: String,
        ip: IpAddr,
        cache_port: u16,
        cache_token: String,
    ) {
        let host = format!("{node_id}.local");
        let metrics = Self::live_metrics(&state, &node_id, cache_port, &cache_token).await;
        let Ok(discovery) = Self::advertise(&node_id, &host, ip, &metrics) else {
            eprintln!("runner: mDNS advertise failed; LAN cache federation disabled");
            return;
        };
        eprintln!("runner: advertising LAN cache on {ip}:{cache_port} as {node_id}");
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let metrics = Self::live_metrics(&state, &node_id, cache_port, &cache_token).await;
            if let Err(e) = discovery.update_metrics(&node_id, &host, ip, &metrics) {
                eprintln!("runner: mDNS heartbeat failed ({e}); retrying");
            }
        }
    }

    /// Current metrics snapshot for advertisement (slots are live).
    async fn live_metrics(
        state: &crate::governor::supervisor::SharedState,
        node_id: &str,
        cache_port: u16,
        cache_token: &str,
    ) -> LanMetrics {
        let slots = state.read().await.last_slots;
        let cores = crate::governor::topology::detect_topology()
            .map(|t| t.logical)
            .unwrap_or(0);
        let ram_mb = crate::governor::topology::read_meminfo_mb()
            .map(|(total, _)| total)
            .unwrap_or(0);
        LanMetrics {
            cores,
            ram_mb,
            slots,
            cache_port: Some(cache_port),
            cache_enabled: true,
            node_id: node_id.to_string(),
            cache_token: cache_token.to_string(),
        }
    }
}

/// Generate a boot-unique mDNS instance name (`runner-<hex8>`).
pub fn generate_node_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("runner-{}", hex::encode(bytes))
}

/// Hex-encode bytes without a hex crate (lowercase, no prefix).
mod hex {
    pub fn encode(bytes: [u8; 4]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_txt_roundtrip() {
        let metrics = LanMetrics {
            cores: 8,
            ram_mb: 16384,
            slots: 4,
            cache_port: Some(8787),
            cache_enabled: true,
            node_id: "runner-abc123".to_string(),
            cache_token: "tok".to_string(),
        };
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

    #[test]
    fn legacy_peers_without_cache_fields_still_decode() {
        let map: HashMap<String, String> = [("cores", "4"), ("ram_mb", "8192"), ("slots", "2")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let decoded = decode_metrics(&map).expect("capacity keys suffice");
        assert_eq!(decoded.cache_port, None);
        assert!(!decoded.cache_enabled);
        assert!(decoded.node_id.is_empty());
        assert!(decoded.cache_token.is_empty());
    }

    #[test]
    fn listen_lan_detection() {
        assert!(listen_is_lan("0.0.0.0:8787"));
        assert!(listen_is_lan("[::]:8787"));
        assert!(listen_is_lan("192.168.1.5:8787"));
        assert!(!listen_is_lan("127.0.0.1:8787"));
        assert!(!listen_is_lan("[::1]:8787"));
    }

    #[test]
    fn node_ids_are_unique_and_prefixed() {
        let a = generate_node_id();
        let b = generate_node_id();
        assert!(a.starts_with("runner-") && a.len() == 15);
        assert_ne!(a, b);
    }

    #[test]
    fn primary_lan_ip_is_sane_when_present() {
        // Environment-dependent: assert shape, not presence.
        if let Some(ip) = primary_lan_ip() {
            assert!(!ip.is_loopback());
            assert!(!ip.is_unspecified());
        }
    }
}
