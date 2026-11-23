//! mDNS LAN discovery: advertise `_runner._tcp.local` with live node
//! metrics (cores, RAM, slots) in TXT records and browse for peers.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Once, RwLock};
use std::time::{Duration, Instant};

use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

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

/// Decode one resolved mDNS record into a node (shared by the
/// one-shot browses and the continuous peer table).
fn node_from_info(info: &ResolvedService) -> DiscoveredNode {
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
    let addrs = info
        .get_addresses()
        .iter()
        .map(|ip| ip.to_ip_addr())
        .collect();
    assemble_node(
        info.get_fullname().to_string(),
        info.get_hostname().to_string(),
        info.get_port(),
        addrs,
        props,
    )
}

/// Assemble a node from decoded parts (pure; unit-tested).
fn assemble_node(
    instance: String,
    host: String,
    port: u16,
    addrs: Vec<IpAddr>,
    props: HashMap<String, String>,
) -> DiscoveredNode {
    DiscoveredNode {
        instance,
        host,
        port,
        addrs,
        metrics: decode_metrics(&props),
    }
}

/// Peer heartbeat time-to-live: 3x the 60s advertise cadence, so a
/// single missed re-announcement never flaps a live peer out of the
/// table. Clean exits still vanish promptly via goodbye packets
/// (`ServiceRemoved`); the TTL only covers crash-silence.
pub const PEER_HEARTBEAT_TTL: Duration = Duration::from_secs(180);

/// One table row: last-seen resolved node plus its heartbeat stamp.
#[derive(Debug, Clone)]
struct PeerEntry {
    node: DiscoveredNode,
    last_seen: Instant,
}

#[derive(Debug, Default)]
struct PeerTableInner {
    peers: HashMap<String, PeerEntry>,
    own_node_id: Option<String>,
}

/// Continuous background registry of LAN cache peers, fed by mDNS
/// resolve/remove events. Cheap-clone handle: the daemon owns one,
/// the resolver snapshots it on every cache miss with no I/O.
#[derive(Debug, Clone)]
pub struct MdnsCachePeerTable {
    inner: Arc<RwLock<PeerTableInner>>,
    started: Arc<Once>,
}

impl Default for MdnsCachePeerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MdnsCachePeerTable {
    /// Empty table; the background browse starts on
    /// [`start_background_loop`](Self::start_background_loop), never
    /// here, so unit tests stay side-effect-free.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(PeerTableInner::default())),
            started: Arc::new(Once::new()),
        }
    }

    /// Dedup key: the stable broadcast node id, falling back to the
    /// mDNS instance name for legacy peers without one.
    pub fn node_key(node: &DiscoveredNode) -> &str {
        match &node.metrics {
            Some(metrics) if !metrics.node_id.is_empty() => &metrics.node_id,
            _ => &node.instance,
        }
    }

    /// Exclude our own advertisement from snapshots (self is not a
    /// peer; without this every miss would re-query our own cache
    /// over the LAN first).
    pub fn set_own_node_id(&self, node_id: &str) {
        if let Ok(mut inner) = self.inner.write() {
            inner.own_node_id = Some(node_id.to_string());
        }
    }

    /// Record a resolve heartbeat: insert new peers, refresh
    /// addresses and stamps on known ones.
    pub fn register_heartbeat(&self, node: DiscoveredNode, now: Instant) {
        let key = Self::node_key(&node).to_string();
        if let Ok(mut inner) = self.inner.write() {
            inner.peers.insert(
                key,
                PeerEntry {
                    node,
                    last_seen: now,
                },
            );
        }
    }

    /// Drop the row whose mDNS instance said goodbye.
    pub fn remove_instance(&self, instance_fullname: &str) {
        if let Ok(mut inner) = self.inner.write() {
            inner
                .peers
                .retain(|_, entry| entry.node.instance != instance_fullname);
        }
    }

    /// Prune rows whose heartbeat is older than
    /// [`PEER_HEARTBEAT_TTL`].
    pub fn sweep_expired(&self, now: Instant) {
        if let Ok(mut inner) = self.inner.write() {
            inner
                .peers
                .retain(|_, entry| now.duration_since(entry.last_seen) <= PEER_HEARTBEAT_TTL);
        }
    }

    /// Instant snapshot of live, non-self peers. Read lock only, no
    /// mutation or I/O: safe on the cache-miss hot path. Expired
    /// rows are filtered here even between sweeps, so the TTL is a
    /// hard visibility bound, not a sweep-schedule artifact.
    pub fn snapshot(&self, now: Instant) -> Vec<DiscoveredNode> {
        self.snapshot_with_seen(now)
            .into_iter()
            .map(|(node, _)| node)
            .collect()
    }

    /// Snapshot plus per-row heartbeat age (for CLI inspection).
    /// Same live/non-self filter as [`snapshot`](Self::snapshot).
    pub fn snapshot_with_seen(&self, now: Instant) -> Vec<(DiscoveredNode, Duration)> {
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };
        inner
            .peers
            .values()
            .filter(|entry| now.duration_since(entry.last_seen) <= PEER_HEARTBEAT_TTL)
            .filter(|entry| match &inner.own_node_id {
                Some(own) => Self::node_key(&entry.node) != own,
                None => true,
            })
            .map(|entry| (entry.node.clone(), now.duration_since(entry.last_seen)))
            .collect()
    }

    /// Spawn the continuous browse thread (idempotent: the first
    /// call wins, later calls are no-ops). Fail-open: when mDNS is
    /// unavailable the table simply stays empty and cache misses
    /// fall through to upstream, exactly like a failed one-shot
    /// browse today.
    pub fn start_background_loop(&self) {
        let table = self.clone();
        self.started.call_once(move || {
            std::thread::Builder::new()
                .name("mdns-peer-table".to_string())
                .spawn(move || Self::browse_loop(&table))
                .inspect_err(|e| eprintln!("runner: peer table browse thread failed ({e})"))
                .ok();
        });
    }

    /// Blocking browse forever: heartbeats in, goodbyes out, TTL
    /// sweep on every quiet tick. Runs off the async runtime on its
    /// own OS thread (multicast recv is blocking by nature).
    fn browse_loop(table: &Self) {
        let daemon = match ServiceDaemon::new() {
            Ok(daemon) => daemon,
            Err(e) => {
                eprintln!("runner: peer table mDNS unavailable ({e}); LAN federation off");
                return;
            }
        };
        let receiver = match daemon.browse(MESH_SERVICE_TYPE) {
            Ok(receiver) => receiver,
            Err(e) => {
                eprintln!("runner: peer table browse failed ({e}); LAN federation off");
                return;
            }
        };
        loop {
            match receiver.recv_timeout(Duration::from_secs(10)) {
                Ok(ServiceEvent::ServiceResolved(info)) => {
                    table.register_heartbeat(node_from_info(&info), Instant::now());
                }
                Ok(ServiceEvent::ServiceRemoved(_, fullname)) => {
                    table.remove_instance(&fullname);
                }
                Ok(_) => {}
                Err(_) => table.sweep_expired(Instant::now()),
            }
        }
    }
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
                    nodes.insert(info.get_fullname().to_string(), node_from_info(&info));
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
                    nodes.insert(info.get_fullname().to_string(), node_from_info(&info));
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

    fn table_node(instance: &str, node_id: &str, ip: &str) -> DiscoveredNode {
        DiscoveredNode {
            instance: instance.to_string(),
            host: format!("{node_id}.local"),
            port: MESH_MDNS_PORT,
            addrs: vec![ip.parse().unwrap()],
            metrics: Some(LanMetrics {
                cores: 8,
                ram_mb: 16384,
                slots: 4,
                cache_port: Some(8787),
                cache_enabled: true,
                node_id: node_id.to_string(),
                cache_token: "tok".to_string(),
            }),
        }
    }

    #[test]
    fn peer_table_registers_and_snapshots() {
        let table = MdnsCachePeerTable::new();
        let now = Instant::now();
        assert!(table.snapshot(now).is_empty());
        table.register_heartbeat(
            table_node("a._runner._tcp.local.", "node-a", "10.0.0.2"),
            now,
        );
        table.register_heartbeat(
            table_node("b._runner._tcp.local.", "node-b", "10.0.0.3"),
            now,
        );
        let snap = table.snapshot(now + Duration::from_secs(1));
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn peer_table_heartbeat_updates_addresses_in_place() {
        let table = MdnsCachePeerTable::new();
        let now = Instant::now();
        table.register_heartbeat(
            table_node("a._runner._tcp.local.", "node-a", "10.0.0.2"),
            now,
        );
        // Same stable id, new address (DHCP renumber): one row, new IP.
        table.register_heartbeat(
            table_node("a._runner._tcp.local.", "node-a", "10.0.0.9"),
            now + Duration::from_secs(5),
        );
        let snap = table.snapshot(now + Duration::from_secs(6));
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].addrs, vec!["10.0.0.9".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn peer_table_expires_and_sweeps_stale_rows() {
        let table = MdnsCachePeerTable::new();
        let now = Instant::now();
        table.register_heartbeat(
            table_node("a._runner._tcp.local.", "node-a", "10.0.0.2"),
            now,
        );
        // Past the TTL the row is invisible even before any sweep.
        let stale = now + PEER_HEARTBEAT_TTL + Duration::from_secs(1);
        assert!(table.snapshot(stale).is_empty());
        table.sweep_expired(stale);
        // Still gone after the sweep; a fresh heartbeat re-adds it.
        assert!(table.snapshot(stale).is_empty());
        table.register_heartbeat(
            table_node("a._runner._tcp.local.", "node-a", "10.0.0.2"),
            stale,
        );
        assert_eq!(table.snapshot(stale).len(), 1);
    }

    #[test]
    fn peer_table_removes_goodbye_instances() {
        let table = MdnsCachePeerTable::new();
        let now = Instant::now();
        table.register_heartbeat(
            table_node("a._runner._tcp.local.", "node-a", "10.0.0.2"),
            now,
        );
        table.register_heartbeat(
            table_node("b._runner._tcp.local.", "node-b", "10.0.0.3"),
            now,
        );
        table.remove_instance("a._runner._tcp.local.");
        let snap = table.snapshot(now);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].instance, "b._runner._tcp.local.");
        // Unknown goodbye is a no-op.
        table.remove_instance("ghost._runner._tcp.local.");
        assert_eq!(table.snapshot(now).len(), 1);
    }

    #[test]
    fn peer_table_excludes_own_advertisement() {
        let table = MdnsCachePeerTable::new();
        table.set_own_node_id("node-a");
        let now = Instant::now();
        table.register_heartbeat(
            table_node("a._runner._tcp.local.", "node-a", "10.0.0.2"),
            now,
        );
        table.register_heartbeat(
            table_node("b._runner._tcp.local.", "node-b", "10.0.0.3"),
            now,
        );
        let snap = table.snapshot(now);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].instance, "b._runner._tcp.local.");
    }

    #[test]
    fn snapshot_with_seen_reports_heartbeat_ages() {
        let table = MdnsCachePeerTable::new();
        let now = Instant::now();
        table.register_heartbeat(
            table_node("a._runner._tcp.local.", "node-a", "10.0.0.2"),
            now,
        );
        table.register_heartbeat(
            table_node("b._runner._tcp.local.", "node-b", "10.0.0.3"),
            now + Duration::from_secs(20),
        );
        let snap = table.snapshot_with_seen(now + Duration::from_secs(30));
        assert_eq!(snap.len(), 2);
        for (node, age) in &snap {
            if node.instance == "a._runner._tcp.local." {
                assert_eq!(*age, Duration::from_secs(30));
            } else {
                assert_eq!(*age, Duration::from_secs(10));
            }
        }
        // Expired rows stay out of the aged snapshot too (past the
        // later heartbeat's TTL).
        let stale = now + Duration::from_secs(20) + PEER_HEARTBEAT_TTL + Duration::from_secs(1);
        assert!(table.snapshot_with_seen(stale).is_empty());
    }

    #[test]
    fn node_key_prefers_stable_id_with_instance_fallback() {
        let with_id = table_node("a._runner._tcp.local.", "node-a", "10.0.0.2");
        assert_eq!(MdnsCachePeerTable::node_key(&with_id), "node-a");
        let legacy = DiscoveredNode {
            metrics: None,
            ..table_node("legacy._runner._tcp.local.", "", "10.0.0.4")
        };
        assert_eq!(
            MdnsCachePeerTable::node_key(&legacy),
            "legacy._runner._tcp.local."
        );
        let empty_id = table_node("empty._runner._tcp.local.", "", "10.0.0.5");
        assert_eq!(
            MdnsCachePeerTable::node_key(&empty_id),
            "empty._runner._tcp.local."
        );
    }

    #[test]
    fn assemble_node_carries_identity_and_metrics() {
        let props: HashMap<String, String> = [
            ("cores", "8"),
            ("ram_mb", "16384"),
            ("slots", "4"),
            ("cache_enabled", "1"),
            ("node_id", "node-a"),
            ("cache_port", "8787"),
            ("cache_token", "tok"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let node = assemble_node(
            "node-a._runner._tcp.local.".to_string(),
            "node-a.local.".to_string(),
            MESH_MDNS_PORT,
            vec!["10.0.0.2".parse::<IpAddr>().unwrap()],
            props,
        );
        assert_eq!(node.instance, "node-a._runner._tcp.local.");
        assert_eq!(node.host, "node-a.local.");
        assert_eq!(node.port, MESH_MDNS_PORT);
        assert_eq!(node.addrs, vec!["10.0.0.2".parse::<IpAddr>().unwrap()]);
        let metrics = node.metrics.expect("capacity keys suffice");
        assert_eq!(metrics.cores, 8);
        assert!(metrics.cache_enabled);
        assert_eq!(metrics.cache_port, Some(8787));
        assert_eq!(metrics.node_id, "node-a");
        assert_eq!(metrics.cache_token, "tok");
    }
}
