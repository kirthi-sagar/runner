//! NAT-traversal hermetic tests: mock STUN servers and a simulated
//! NAT proxy prove reflexive discovery, endpoint selection, JoinAccept
//! delivery, and full join→dispatch→result flows through cone and
//! symmetric mappings — all on loopback, no external network.
//!
//! Layout: the peer transport talks to the coordinator and the mock
//! STUN server only through the proxy's inside ports; the proxy
//! rewrites sources to outside mappings (fresh ephemeral ports) like a
//! home router. In cone mode one mapping serves every destination; in
//! symmetric mode each (inside, destination) pair gets its own.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use runner::config::DonorConfig;
use runner::governor::supervisor::new_shared_state;
use runner::mesh::invite::{InviteAuthority, InviteCaps, InviteRole, InviteToken};
use runner::mesh::peer::generate_keypair;
use runner::mesh::proto::{
    encode_plaintext, JobOffer, JobResult, JoinAnnounce, PeerMessage, PROTO_TAG,
};
use runner::mesh::roles::{CoordinatorRole, PeerExecutor, PeerRole};
use runner::mesh::stun::{
    build_binding_response, classify_nat, discover_reflexive_addr, discover_via_transport,
    local_addr_for, resolve_stun_servers, select_endpoint, stun_servers, NatClass,
    STUN_MAGIC_COOKIE, STUN_TXID_LEN,
};
use runner::mesh::transport::{PeerHandler, PeerTransport, TransportConfig};

/// Stub executor: proves transport end-to-end without GitHub credentials.
struct StubExecutor;

impl PeerExecutor for StubExecutor {
    fn execute<'a>(
        &'a self,
        offer: &'a JobOffer,
    ) -> Pin<Box<dyn std::future::Future<Output = JobResult> + Send + 'a>> {
        let (provider, job_id) = (offer.provider.clone(), offer.job_id);
        Box::pin(async move {
            JobResult {
                proto: PROTO_TAG.to_string(),
                provider,
                job_id,
                exit_code: Some(0),
                killed: false,
            }
        })
    }
}

fn authority() -> InviteAuthority {
    InviteAuthority::new(vec![7u8; 32]).unwrap()
}

fn invite_token(authority: &InviteAuthority) -> String {
    authority
        .mint(&InviteToken {
            role: InviteRole::Donor,
            caps: InviteCaps {
                max_cores: 4,
                max_ram_mb: 8192,
            },
            ttl_secs: 3600,
            name: "bob".to_string(),
        })
        .unwrap()
}

fn donor_config() -> runner::config::RunnerConfig {
    runner::config::RunnerConfig {
        donor: Some(DonorConfig {
            max_cores: 4,
            max_ram_mb: 8192,
        }),
        ..runner::config::RunnerConfig::default()
    }
}

fn offer(job_id: u64) -> JobOffer {
    JobOffer {
        proto: PROTO_TAG.to_string(),
        provider: "github".to_string(),
        job_id,
        run_id: 100,
        name: "wan-job".to_string(),
        labels: vec!["self-hosted".to_string(), "runner".to_string()],
        jit_blob: "BLOB".to_string(),
        worker_version: "2.338.2".to_string(),
        timeout_secs: 60,
    }
}

/// Mock STUN server: answers Binding Requests with the observed source
/// as `XOR-MAPPED-ADDRESS`. Runs on a blocking thread; the handle keeps
/// it alive for the test.
struct MockStun {
    addr: SocketAddr,
    _thread: JoinHandle<()>,
}

fn serve_mock_stun() -> MockStun {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let mut buf = vec![0u8; 512];
        while let Ok((n, src)) = socket.recv_from(&mut buf) {
            if n < 20 || u16::from_be_bytes([buf[0], buf[1]]) != 0x0001 {
                continue;
            }
            if u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) != STUN_MAGIC_COOKIE {
                continue;
            }
            let mut txid = [0u8; STUN_TXID_LEN];
            txid.copy_from_slice(&buf[8..20]);
            let _ = socket.send_to(&build_binding_response(&txid, src), src);
        }
    });
    MockStun {
        addr,
        _thread: thread,
    }
}

/// Simulated NAT mapping behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NatMode {
    /// One outside mapping per inside address (all destinations share).
    Cone,
    /// One outside mapping per (inside, destination) pair.
    Symmetric,
}

/// Simulated NAT proxy: inside ports forward to fixed destinations
/// with rewritten sources, like a home router. Single-client (the
/// tests run one peer behind it).
struct SimNat {
    mode: NatMode,
    mappings: Mutex<HashMap<(SocketAddr, Option<SocketAddr>), std::net::UdpSocket>>,
    /// Destination → inside listener, so return traffic exits the
    /// entry port the client addressed (like a NAT restoring the
    /// server's source address).
    routes: Mutex<HashMap<SocketAddr, std::net::UdpSocket>>,
}

impl SimNat {
    /// Spawn the proxy: returns the inside entry points for the
    /// coordinator and STUN paths. Threads are detached workers kept
    /// alive by the returned handles.
    fn run(mode: NatMode, coord_addr: SocketAddr, stun_addr: SocketAddr) -> SimNatEndpoint {
        let nat = Arc::new(Self {
            mode,
            mappings: Mutex::new(HashMap::new()),
            routes: Mutex::new(HashMap::new()),
        });
        let inside_coord = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let inside_stun = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        nat.routes
            .lock()
            .unwrap()
            .insert(coord_addr, inside_coord.try_clone().unwrap());
        nat.routes
            .lock()
            .unwrap()
            .insert(stun_addr, inside_stun.try_clone().unwrap());
        let coord_entry = inside_coord.local_addr().unwrap();
        let stun_entry = inside_stun.local_addr().unwrap();
        let mut threads = Vec::new();
        for (inside, dest) in [(inside_coord, coord_addr), (inside_stun, stun_addr)] {
            let nat = nat.clone();
            threads.push(std::thread::spawn(move || {
                let mut buf = vec![0u8; 65535];
                while let Ok((n, src)) = inside.recv_from(&mut buf) {
                    let outside = nat.mapping_for(src, dest, &inside);
                    let _ = outside.send_to(&buf[..n], dest);
                }
            }));
        }
        SimNatEndpoint {
            coord_entry,
            stun_entry,
            _threads: threads,
            _nat: nat,
        }
    }

    /// Outside socket for one mapping, spawning its return-path
    /// forwarder on first use.
    fn mapping_for(
        &self,
        inside_addr: SocketAddr,
        dest: SocketAddr,
        inside: &std::net::UdpSocket,
    ) -> std::net::UdpSocket {
        let key = match self.mode {
            NatMode::Cone => (inside_addr, None),
            NatMode::Symmetric => (inside_addr, Some(dest)),
        };
        let mut mappings = self.mappings.lock().unwrap();
        if let Some(sock) = mappings.get(&key) {
            return sock.try_clone().unwrap();
        }
        let outside = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let back = outside.try_clone().unwrap();
        let ret = inside.try_clone().unwrap();
        let routes: HashMap<SocketAddr, std::net::UdpSocket> = self
            .routes
            .lock()
            .unwrap()
            .iter()
            .map(|(dest, sock)| (*dest, sock.try_clone().unwrap()))
            .collect();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, src)) = back.recv_from(&mut buf) {
                // Replies exit the entry port their destination was
                // addressed through (unknown servers fall back to the
                // creating listener).
                let via = routes.get(&src).unwrap_or(&ret);
                let _ = via.send_to(&buf[..n], inside_addr);
            }
        });
        mappings.insert(key, outside.try_clone().unwrap());
        outside
    }
}

struct SimNatEndpoint {
    coord_entry: SocketAddr,
    stun_entry: SocketAddr,
    _threads: Vec<JoinHandle<()>>,
    _nat: Arc<SimNat>,
}

async fn wait_for_active(state: &runner::governor::supervisor::SharedState, node_id: &str) -> bool {
    for _ in 0..300 {
        let peers = state.read().await.peers();
        if peers
            .iter()
            .any(|p| p.node_id == node_id && p.status == "active")
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test]
async fn mock_stun_server_reports_observed_source() {
    let server = serve_mock_stun();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let reflexive = discover_reflexive_addr(&socket, server.addr, Duration::from_millis(500))
        .await
        .unwrap();
    // Loopback has no NAT: the mapping is the socket itself.
    assert_eq!(reflexive, socket.local_addr().unwrap());
}

#[tokio::test]
async fn pump_routed_discovery_classifies_loopback_as_cone() {
    let first = serve_mock_stun();
    let second = serve_mock_stun();
    let state = new_shared_state();
    let role = Arc::new(CoordinatorRole::new(authority(), state, None));
    let tx = PeerTransport::spawn(
        TransportConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            keys: generate_keypair(),
        },
        role,
    )
    .await
    .unwrap();
    // STUN responses share the transport socket: interception (not a
    // second reader) must deliver them.
    let found = discover_via_transport(&tx, &[first.addr, second.addr])
        .await
        .unwrap();
    assert_eq!(found.reflexive, tx.local_addr());
    assert_eq!(found.nat, Some(NatClass::Cone));
}

#[tokio::test]
async fn selection_prefers_lan_only_on_same_subnet() {
    let src: SocketAddr = "203.0.113.9:45001".parse().unwrap();
    let local: IpAddr = "192.168.1.5".parse().unwrap();
    let announce_with = |lan: Option<&str>| JoinAnnounce {
        proto: PROTO_TAG.to_string(),
        node_id: "bob".to_string(),
        pubkey_b64: "KEY".to_string(),
        token: "runner1.e30.sig".to_string(),
        listen_port: 40001,
        max_cores: 4,
        max_ram_mb: 8192,
        reflexive: None,
        lan: lan.map(str::to_string),
    };
    // Same /24: direct LAN dial.
    let (endpoint, via) = select_endpoint(src, &announce_with(Some("192.168.1.10:40001")), local);
    assert_eq!(endpoint, "192.168.1.10:40001".parse().unwrap());
    assert_eq!(via, "lan");
    // Different subnet: observed source (NAT binding), not the LAN claim.
    let (endpoint, via) = select_endpoint(src, &announce_with(Some("10.99.0.5:40001")), local);
    assert_eq!(endpoint, src);
    assert_eq!(via, "observed");
    // No candidates at all (pre-v1.6.0 peer): observed source.
    let (endpoint, via) = select_endpoint(src, &announce_with(None), local);
    assert_eq!(endpoint, src);
    assert_eq!(via, "observed");
    // Garbage LAN candidate never diverts routing.
    let (endpoint, via) = select_endpoint(src, &announce_with(Some("not-an-addr")), local);
    assert_eq!(endpoint, src);
    assert_eq!(via, "observed");
    // The outbound-interface probe finds loopback toward loopback.
    let target: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    assert_eq!(local_addr_for(target), Some("127.0.0.1".parse().unwrap()));
}

#[tokio::test]
async fn stun_server_resolution_skips_bad_entries() {
    let addrs = resolve_stun_servers(&[
        "127.0.0.1:3478".to_string(),
        // Unparsable port: lookup fails locally, no DNS involved.
        "127.0.0.1:99999".to_string(),
    ])
    .await;
    // The literal resolves; the bogus entry is skipped loudly, not fatal.
    assert_eq!(addrs, vec!["127.0.0.1:3478".parse().unwrap()]);
    // Disabled STUN resolves to nothing.
    let mesh = runner::config::MeshConfig {
        stun_servers: Some(vec![]),
        ..Default::default()
    };
    assert!(stun_servers(&mesh).is_empty());
    assert!(resolve_stun_servers(&stun_servers(&mesh)).await.is_empty());
}

async fn spawn_coordinator() -> (
    PeerTransport,
    runner::governor::supervisor::SharedState,
    SocketAddr,
    String,
) {
    let state = new_shared_state();
    let role = Arc::new(CoordinatorRole::new(authority(), state.clone(), None));
    let keys = generate_keypair();
    let tx = PeerTransport::spawn(
        TransportConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            keys: keys.clone(),
        },
        role,
    )
    .await
    .unwrap();
    let addr = tx.local_addr();
    (tx, state, addr, keys.public_b64)
}

async fn spawn_peer() -> (
    PeerTransport,
    runner::governor::supervisor::SharedState,
    SocketAddr,
    String,
) {
    let state = new_shared_state();
    state.write().await.seed_from_config(&donor_config());
    let role = Arc::new(PeerRole::new(Arc::new(StubExecutor), state.clone()));
    let keys = generate_keypair();
    let tx = PeerTransport::spawn(
        TransportConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            keys: keys.clone(),
        },
        role,
    )
    .await
    .unwrap();
    let addr = tx.local_addr();
    (tx, state, addr, keys.public_b64)
}

#[tokio::test]
async fn coordinator_honors_lan_candidate_on_loopback() {
    let (_coord_tx, coord_state, coord_addr, _coord_pubkey) = spawn_coordinator().await;
    let peer_keys = generate_keypair();
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let lan = sock.local_addr().unwrap();
    // Announce from one socket, advertise a same-subnet LAN address:
    // the coordinator must dial the LAN candidate, not the source.
    let announce = PeerMessage::JoinAnnounce(JoinAnnounce {
        proto: PROTO_TAG.to_string(),
        node_id: "bob".to_string(),
        pubkey_b64: peer_keys.public_b64,
        token: invite_token(&authority()),
        listen_port: lan.port(),
        max_cores: 4,
        max_ram_mb: 8192,
        reflexive: None,
        lan: Some(lan.to_string()),
    });
    sock.send_to(&encode_plaintext(&announce).unwrap(), coord_addr)
        .await
        .unwrap();
    for _ in 0..100 {
        if !coord_state.read().await.peers().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let peers = coord_state.read().await.peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].endpoint, Some(lan.to_string()));
}

#[tokio::test]
async fn coordinator_rejects_malformed_candidates() {
    let (_coord_tx, coord_state, coord_addr, _coord_pubkey) = spawn_coordinator().await;
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let announce = PeerMessage::JoinAnnounce(JoinAnnounce {
        proto: PROTO_TAG.to_string(),
        node_id: "mallory".to_string(),
        pubkey_b64: generate_keypair().public_b64,
        token: invite_token(&authority()),
        listen_port: 40001,
        max_cores: 4,
        max_ram_mb: 8192,
        reflexive: Some("not-an-addr".to_string()),
        lan: None,
    });
    sock.send_to(&encode_plaintext(&announce).unwrap(), coord_addr)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(coord_state.read().await.peers().is_empty());
}

/// Handler that only records inbound encrypted messages.
struct MessageRecorder {
    messages: Mutex<Vec<(String, PeerMessage)>>,
}

impl PeerHandler for MessageRecorder {
    fn on_announce<'a>(
        &'a self,
        _tx: &'a PeerTransport,
        _announce: JoinAnnounce,
        _src: SocketAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {})
    }

    fn on_established<'a>(
        &'a self,
        _tx: &'a PeerTransport,
        _node_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {})
    }

    fn on_message<'a>(
        &'a self,
        _tx: &'a PeerTransport,
        node_id: &'a str,
        msg: PeerMessage,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let node_id = node_id.to_string();
        Box::pin(async move {
            self.messages.lock().unwrap().push((node_id, msg));
        })
    }
}

#[tokio::test]
async fn join_accept_reaches_peer_after_establishment() {
    let (_coord_tx, coord_state, coord_addr, coord_pubkey) = spawn_coordinator().await;
    let recorder = Arc::new(MessageRecorder {
        messages: Mutex::new(Vec::new()),
    });
    let peer_keys = generate_keypair();
    let peer_tx = PeerTransport::spawn(
        TransportConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            keys: peer_keys.clone(),
        },
        recorder.clone(),
    )
    .await
    .unwrap();
    let peer_addr = peer_tx.local_addr();
    peer_tx
        .add_session("coordinator", &coord_pubkey, coord_addr)
        .await
        .unwrap();
    peer_tx
        .announce(
            coord_addr,
            JoinAnnounce {
                proto: PROTO_TAG.to_string(),
                node_id: "bob".to_string(),
                pubkey_b64: peer_keys.public_b64,
                token: invite_token(&authority()),
                listen_port: peer_addr.port(),
                max_cores: 4,
                max_ram_mb: 8192,
                reflexive: None,
                lan: None,
            },
        )
        .await
        .unwrap();
    assert!(wait_for_active(&coord_state, "bob").await);
    for _ in 0..100 {
        if !recorder.messages.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let messages = recorder.messages.lock().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0, "coordinator");
    let PeerMessage::JoinAccept(accept) = &messages[0].1 else {
        panic!("expected JoinAccept, got {:?}", messages[0].1);
    };
    assert!(accept.accepted);
}

/// Full join→offer→result through the simulated NAT in either mode.
/// Returns (recorded endpoint, advertised reflexive).
async fn run_nat_flow(mode: NatMode) -> (SocketAddr, SocketAddr) {
    let (coord_tx, coord_state, coord_addr, coord_pubkey) = spawn_coordinator().await;
    let (peer_tx, _peer_state, _peer_addr, peer_pubkey) = spawn_peer().await;
    let stun = serve_mock_stun();
    let _proxy = SimNat::run(mode, coord_addr, stun.addr);

    // Reflexive discovery through the NAT's STUN path, as the daemon's
    // announce loop does.
    let found = discover_via_transport(&peer_tx, &[_proxy.stun_entry])
        .await
        .unwrap();
    assert_eq!(found.nat, None); // one server: no classification yet
    let reflexive = found.reflexive;

    peer_tx
        .add_session("coordinator", &coord_pubkey, _proxy.coord_entry)
        .await
        .unwrap();
    peer_tx
        .announce(
            _proxy.coord_entry,
            JoinAnnounce {
                proto: PROTO_TAG.to_string(),
                node_id: "bob".to_string(),
                pubkey_b64: peer_pubkey,
                token: invite_token(&authority()),
                listen_port: 40001,
                max_cores: 4,
                max_ram_mb: 8192,
                reflexive: Some(reflexive.to_string()),
                lan: None,
            },
        )
        .await
        .unwrap();
    assert!(
        wait_for_active(&coord_state, "bob").await,
        "peer never activated through {mode:?} NAT"
    );
    let endpoint: SocketAddr = coord_state
        .read()
        .await
        .peers()
        .into_iter()
        .find(|p| p.node_id == "bob")
        .unwrap()
        .endpoint
        .unwrap()
        .parse()
        .unwrap();

    // The mesh must actually work through the mapping, not just shake hands.
    coord_state
        .write()
        .await
        .job_started("github", "7", "wan-job");
    let accept = coord_tx
        .offer("bob", offer(7), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(accept.accepted, "offer rejected: {}", accept.reason);
    for _ in 0..300 {
        let jobs = coord_state.read().await.in_flight_jobs();
        if !jobs.iter().any(|j| j.provider == "github" && j.id == "7") {
            return (endpoint, reflexive);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("result never crossed the {mode:?} NAT");
}

#[tokio::test]
async fn cone_nat_flow_routes_to_shared_mapping() {
    let (endpoint, reflexive) = run_nat_flow(NatMode::Cone).await;
    // Cone NAT: one mapping for every destination, so the advertised
    // reflexive address IS the observed endpoint.
    assert_eq!(endpoint, reflexive);
    assert_eq!(classify_nat(endpoint, reflexive), NatClass::Cone);
}

#[tokio::test]
async fn symmetric_nat_flow_routes_via_observed_source() {
    let (endpoint, reflexive) = run_nat_flow(NatMode::Symmetric).await;
    // Symmetric NAT: the STUN path's mapping differs from the
    // coordinator path's — routing must follow the observed source,
    // never the reflexive advertisement.
    assert_ne!(endpoint, reflexive);
    assert_eq!(classify_nat(endpoint, reflexive), NatClass::Symmetric);
}

#[tokio::test]
async fn stun_silence_fails_closed_without_stall() {
    // Nothing listens on discard ports: both discovery paths must fail
    // fast with diagnostics, never hang the caller.
    let blackhole: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let start = std::time::Instant::now();
    let err = discover_reflexive_addr(&socket, blackhole, Duration::from_millis(100))
        .await
        .unwrap_err();
    assert!(err.contains("silent"), "{err}");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "STUN retry stalled"
    );

    // The pump-routed path surfaces the same failure through the caller
    // timeout, and the pump keeps serving afterwards.
    let (_coord_tx, _state, _addr, _pubkey) = spawn_coordinator().await;
    let err = tokio::time::timeout(
        Duration::from_millis(300),
        _coord_tx.discover_stun(blackhole),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("deadline"), "{err}");
}
