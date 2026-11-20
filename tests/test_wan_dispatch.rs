//! WAN dispatch loopback tests: two transports on 127.0.0.1 (ephemeral
//! ports) prove join-announce, Noise handshake, offer/accept, and result
//! delivery without any multi-machine network.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use runner::config::DonorConfig;
use runner::governor::supervisor::new_shared_state;
use runner::mesh::invite::{InviteAuthority, InviteCaps, InviteRole, InviteToken};
use runner::mesh::peer::generate_keypair;
use runner::mesh::proto::{
    encode_message, encode_plaintext, JobOffer, JobResult, JoinAnnounce, PeerMessage,
    MAX_MESSAGE_BYTES, PROTO_TAG,
};
use runner::mesh::roles::{CoordinatorRole, PeerExecutor, PeerRole};
use runner::mesh::transport::{PeerTransport, TransportConfig};

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
        repo: Some("o/r".to_string()),
    }
}

async fn spawn_pair() -> (
    PeerTransport,
    PeerTransport,
    runner::governor::supervisor::SharedState,
    runner::governor::supervisor::SharedState,
    SocketAddr,
    SocketAddr,
    String,
    String,
) {
    let coord_state = new_shared_state();
    let coord_role = Arc::new(CoordinatorRole::new(authority(), coord_state.clone(), None));
    let coord_keys = generate_keypair();
    let coord_tx = PeerTransport::spawn(
        TransportConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            keys: coord_keys.clone(),
        },
        coord_role,
    )
    .await
    .unwrap();
    let coord_addr = coord_tx.local_addr();

    let peer_state = new_shared_state();
    peer_state.write().await.seed_from_config(&donor_config());
    let peer_role = Arc::new(PeerRole::new(Arc::new(StubExecutor), peer_state.clone()));
    let peer_keys = generate_keypair();
    let peer_tx = PeerTransport::spawn(
        TransportConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            keys: peer_keys.clone(),
        },
        peer_role,
    )
    .await
    .unwrap();
    let peer_addr = peer_tx.local_addr();
    (
        coord_tx,
        peer_tx,
        coord_state,
        peer_state,
        coord_addr,
        peer_addr,
        coord_keys.public_b64,
        peer_keys.public_b64,
    )
}

async fn wait_for_active(state: &runner::governor::supervisor::SharedState, node_id: &str) -> bool {
    for _ in 0..250 {
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
async fn loopback_join_offer_accept_and_result() {
    let (
        coord_tx,
        peer_tx,
        coord_state,
        _peer_state,
        coord_addr,
        peer_addr,
        coord_pubkey,
        peer_pubkey,
    ) = spawn_pair().await;
    let token = invite_token(&authority());

    // Peer registers the coordinator session, then announces.
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
                // Must match the peer transport's own keys (as in
                // production, where both derive from mesh.node_key).
                pubkey_b64: peer_pubkey,
                token,
                listen_port: peer_addr.port(),
                max_cores: 4,
                max_ram_mb: 8192,
                reflexive: None,
                lan: None,
            },
        )
        .await
        .unwrap();

    // Handshake completes; coordinator learns the endpoint and activates.
    assert!(
        wait_for_active(&coord_state, "bob").await,
        "peer never activated"
    );
    let record = coord_state
        .read()
        .await
        .peers()
        .into_iter()
        .find(|p| p.node_id == "bob")
        .unwrap();
    assert_eq!(
        record.endpoint,
        Some(format!("127.0.0.1:{}", peer_addr.port()))
    );

    // Offer → accept → stub execution → result → job finished.
    coord_state
        .write()
        .await
        .job_started("github", "7", "wan-job");
    let accept = coord_tx
        .offer("bob", offer(7), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(accept.accepted, "offer rejected: {}", accept.reason);
    for _ in 0..250 {
        let jobs = coord_state.read().await.in_flight_jobs();
        if !jobs.iter().any(|j| j.provider == "github" && j.id == "7") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("result never applied job_finished");
}

#[tokio::test]
async fn loopback_rejects_bad_token_and_replayed_nonce() {
    let (coord_tx, _peer_tx, coord_state, _peer_state, coord_addr, _, _, _) = spawn_pair().await;
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let announce = |node_id: &str, token: String| {
        PeerMessage::JoinAnnounce(JoinAnnounce {
            proto: PROTO_TAG.to_string(),
            node_id: node_id.to_string(),
            pubkey_b64: generate_keypair().public_b64,
            token,
            listen_port: 40001,
            max_cores: 4,
            max_ram_mb: 8192,
            reflexive: None,
            lan: None,
        })
    };

    // Garbage token: no record is created.
    let bad = encode_plaintext(&announce("mallory", "runner1.bad.sig".to_string())).unwrap();
    sock.send_to(&bad, coord_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(coord_state.read().await.peers().is_empty());

    // Valid token, first presentation: record created (joining).
    let token = invite_token(&authority());
    let first = encode_plaintext(&announce("bob", token.clone())).unwrap();
    sock.send_to(&first, coord_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(coord_state.read().await.peers().len(), 1);

    // Same token from another node: replay rejected, no second record.
    let replay = encode_plaintext(&announce("mallory", token.clone())).unwrap();
    sock.send_to(&replay, coord_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let peers = coord_state.read().await.peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].node_id, "bob");

    drop(coord_tx);
}

#[tokio::test]
async fn loopback_refuses_oversized_offer_before_send() {
    let (coord_tx, _peer_tx, _coord_state, _peer_state, _, _, _, _) = spawn_pair().await;
    let mut big_offer = offer(9);
    big_offer.jit_blob = "x".repeat(MAX_MESSAGE_BYTES + 1);
    // Refused at encode time, before any socket use.
    let err = encode_message(&PeerMessage::JobOffer(big_offer.clone())).unwrap_err();
    assert!(err.contains("too large"), "error: {err}");
    let err = coord_tx
        .offer("nobody", big_offer, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(err.contains("too large"), "error: {err}");
}

async fn join_bob(
    peer_tx: &PeerTransport,
    coord_addr: SocketAddr,
    coord_pubkey: &str,
    peer_addr: SocketAddr,
    peer_pubkey: String,
    token: String,
) {
    peer_tx
        .add_session("coordinator", coord_pubkey, coord_addr)
        .await
        .unwrap();
    peer_tx
        .announce(
            coord_addr,
            JoinAnnounce {
                proto: PROTO_TAG.to_string(),
                node_id: "bob".to_string(),
                pubkey_b64: peer_pubkey,
                token,
                listen_port: peer_addr.port(),
                max_cores: 4,
                max_ram_mb: 8192,
                reflexive: None,
                lan: None,
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn loopback_peer_rejects_without_caps_or_slots() {
    let (
        coord_tx,
        peer_tx,
        coord_state,
        peer_state,
        coord_addr,
        peer_addr,
        coord_pubkey,
        peer_pubkey,
    ) = spawn_pair().await;
    join_bob(
        &peer_tx,
        coord_addr,
        &coord_pubkey,
        peer_addr,
        peer_pubkey,
        invite_token(&authority()),
    )
    .await;
    assert!(wait_for_active(&coord_state, "bob").await);

    // Above-minimum labels are declined fast (no slot consumed).
    let mut big = offer(21);
    big.labels.push("cpu-9999".to_string());
    let accept = coord_tx
        .offer("bob", big, Duration::from_secs(10))
        .await
        .unwrap();
    assert!(!accept.accepted, "over-minimum offer accepted");

    // No free slots are declined.
    peer_state.write().await.last_slots = 0;
    let accept = coord_tx
        .offer("bob", offer(22), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(!accept.accepted, "slotless offer accepted");

    // A non-donor peer declines everything (fresh state, never joined).
    let zed_state = new_shared_state();
    let zed_role = Arc::new(PeerRole::new(Arc::new(StubExecutor), zed_state));
    let zed_keys = generate_keypair();
    let zed_tx = PeerTransport::spawn(
        TransportConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            keys: zed_keys.clone(),
        },
        zed_role,
    )
    .await
    .unwrap();
    let zed_addr = zed_tx.local_addr();
    zed_tx
        .add_session("coordinator", &coord_pubkey, coord_addr)
        .await
        .unwrap();
    zed_tx
        .announce(
            coord_addr,
            JoinAnnounce {
                proto: PROTO_TAG.to_string(),
                node_id: "zed".to_string(),
                pubkey_b64: zed_keys.public_b64,
                token: invite_token(&authority()),
                listen_port: zed_addr.port(),
                max_cores: 4,
                max_ram_mb: 8192,
                reflexive: None,
                lan: None,
            },
        )
        .await
        .unwrap();
    assert!(wait_for_active(&coord_state, "zed").await);
    let accept = coord_tx
        .offer("zed", offer(23), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(!accept.accepted, "non-donor offer accepted");
}

/// Minimal scripted GitHub API: queued run + job + JIT mint.
async fn serve_github_stub() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 8192];
                let Ok(n) = stream.read(&mut buf).await else {
                    return;
                };
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let line = head.lines().next().unwrap_or("").to_string();
                let body = if line.starts_with("GET") && line.contains("/jobs") {
                    serde_json::json!({"jobs": [{
                        "id": 42, "run_id": 100, "name": "e2e",
                        "status": "queued", "labels": ["self-hosted", "runner"],
                    }]})
                } else if line.starts_with("GET") {
                    serde_json::json!({"workflow_runs": [{"id": 100}]})
                } else if line.starts_with("POST") && line.contains("generate-jitconfig") {
                    serde_json::json!({
                        "runner": {"id": 1, "name": "stub"},
                        "encoded_jit_config": "RkFLRQ==",
                    })
                } else {
                    serde_json::json!({})
                };
                let body = serde_json::to_string(&body).unwrap();
                let _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    (base, handle)
}

/// Executor that records offers for assertions.
struct RecordingExecutor {
    seen: std::sync::Mutex<Vec<u64>>,
}

impl PeerExecutor for RecordingExecutor {
    fn execute<'a>(
        &'a self,
        offer: &'a JobOffer,
    ) -> Pin<Box<dyn std::future::Future<Output = JobResult> + Send + 'a>> {
        self.seen.lock().unwrap().push(offer.job_id);
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

#[tokio::test]
async fn loopback_coordinator_loop_dispatches_to_peer() {
    use runner::github::client::GithubClient;
    use runner::github::webhooks::{run_coordinator, DispatchContext, JitScope, QueuePoller};
    use runner::governor::cgroup::CgroupSlice;

    let (base, stub) = serve_github_stub().await;

    // Coordinator side: transport + role + zero local slots (force peer route).
    let coord_state = new_shared_state();
    coord_state.write().await.last_slots = 0;
    let coord_role = Arc::new(CoordinatorRole::new(authority(), coord_state.clone(), None));
    let coord_keys = generate_keypair();
    let coord_tx = PeerTransport::spawn(
        TransportConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            keys: coord_keys.clone(),
        },
        coord_role,
    )
    .await
    .unwrap();
    let coord_addr = coord_tx.local_addr();
    coord_state
        .write()
        .await
        .set_peer_transport(coord_tx.clone());

    // Peer side with a recording executor.
    let recorder = Arc::new(RecordingExecutor {
        seen: std::sync::Mutex::new(Vec::new()),
    });
    let peer_state = new_shared_state();
    peer_state.write().await.seed_from_config(&donor_config());
    let peer_role = Arc::new(PeerRole::new(recorder.clone(), peer_state));
    let peer_keys = generate_keypair();
    let peer_tx = PeerTransport::spawn(
        TransportConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            keys: peer_keys.clone(),
        },
        peer_role,
    )
    .await
    .unwrap();
    let peer_addr = peer_tx.local_addr();
    peer_tx
        .add_session("coordinator", &coord_keys.public_b64, coord_addr)
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

    // Drive the real coordinator loop against the stub GitHub API.
    let mk_client = || {
        GithubClient::new("stub-token")
            .unwrap()
            .with_base_url(base.clone())
    };
    let poller = QueuePoller::new(mk_client(), "o".to_string(), "r".to_string())
        .with_interval(Duration::from_secs(3600));
    let dispatch = DispatchContext {
        github: mk_client(),
        scope: JitScope::Repo {
            owner: "o".to_string(),
            repo: "r".to_string(),
        },
        runner_group_id: 1,
        worker_version: "2.338.2".to_string(),
        sandboxed: false,
        timeout: Duration::from_secs(60),
        cache_url: None,
        cache_token: None,
        repo_slug: Some("o/r".to_string()),
    };
    let coding = tokio::spawn(run_coordinator(
        poller,
        Some(dispatch),
        None,
        coord_state.clone(),
        CgroupSlice::system_default(),
    ));
    coord_state.read().await.wakeup().notify_one();

    // Evidence: the peer executed the job AND the coordinator applied
    // the result (in-flight entry released).
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let seen = recorder.seen.lock().unwrap().contains(&42);
        let jobs = coord_state.read().await.in_flight_jobs();
        let released = !jobs.iter().any(|j| j.provider == "github" && j.id == "42");
        if seen && released {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "e2e stalled (seen={seen}, released={released})"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    coding.abort();
    stub.abort();
}
