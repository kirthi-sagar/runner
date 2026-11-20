//! WAN peer transport: Noise-encrypted UDP datagrams between mesh nodes.
//!
//! One pump task owns the socket and all Noise sessions; everything else
//! talks to it over a channel. Job payloads ride framed inside boringtun
//! data messages; join-announces alone travel plaintext (recognized by
//! the leading `{`, since WireGuard datagrams start with bytes 1-4).
//!
//! Routing: datagrams from known addresses feed their session; unknown
//! addresses trial every session in node-id order and adopt on the
//! first non-`Invalid` result — except handshake initiations (0x01),
//! which are dropped unless the sender is already known. Initiations
//! are structurally accepted by any session by Noise design, so
//! trialing them would misattribute peers; unknown nodes must announce
//! first (plaintext, token-verified). STUN Binding Responses share the
//! socket (only the mapped source port sees the reply), so the pump
//! intercepts them by shape + transaction id before WireGuard routing:
//! a response's leading `0x01` would otherwise read as a handshake
//! initiation. Reflexive discovery is diagnostic/candidate input only;
//! the return path is always the observed source. Roaming re-adopts on
//! data, and a 60s re-announce loop heals the rest. Trusted small
//! meshes only; boringtun's internal rate limiter is the DoS backstop,
//! and there is deliberately no TUN — the daemon stays unprivileged.
//!
//! Delivery is at-least-once with dedup windows, mirroring the cloud
//! burst path (which likewise gets no completion signal): offers await
//! an accept with timeout, results complete jobs, and expired leases
//! re-dispatch. A lost accept/result after the peer started executing
//! can duplicate work; single-use JITs bound the blast radius.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use super::peer::{Keypair, SessionEvent, WireGuardSession, DEFAULT_KEEPALIVE_SECS};
use super::proto::{
    decode_message, decode_plaintext, encode_message, encode_plaintext, JobAccept, JoinAnnounce,
    PeerMessage,
};
use super::stun::{
    build_binding_request, looks_like_stun_response, parse_binding_response, random_txid,
    STUN_HEADER_LEN,
};

/// Role callbacks for inbound traffic. Manual futures (no async-trait
/// macro) so integration tests can implement roles without it.
/// Callbacks run detached from the pump task: they may call back into
/// [`PeerTransport`] (which round-trips the pump) without deadlocking,
/// but must be internally synchronized.
pub trait PeerHandler: Send + Sync {
    fn on_announce<'a>(
        &'a self,
        tx: &'a PeerTransport,
        announce: JoinAnnounce,
        src: SocketAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
    fn on_established<'a>(
        &'a self,
        tx: &'a PeerTransport,
        node_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
    fn on_message<'a>(
        &'a self,
        tx: &'a PeerTransport,
        node_id: &'a str,
        msg: PeerMessage,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
}

/// Transport endpoint identity + bind address.
pub struct TransportConfig {
    pub listen: SocketAddr,
    pub keys: Keypair,
}

/// Pump tick: Noise timers + queue drain + waiter pruning.
const PUMP_TICK: Duration = Duration::from_secs(1);
/// Max inbound UDP datagram (plaintext announces stay far below).
const MAX_DATAGRAM: usize = 64 * 1024;
/// Backstop lifetime for pump-routed STUN transactions (callers time
/// out sooner; this only bounds leaks when a caller vanishes).
const STUN_PENDING_TTL: Duration = Duration::from_secs(5);

enum Cmd {
    AddSession {
        node_id: String,
        pubkey_b64: String,
        endpoint: SocketAddr,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Send {
        node_id: String,
        msg: PeerMessage,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Offer {
        node_id: String,
        offer: super::proto::JobOffer,
        timeout: Duration,
        reply: oneshot::Sender<Result<JobAccept, String>>,
    },
    Announce {
        target: SocketAddr,
        announce: JoinAnnounce,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Initiate {
        node_id: String,
        reply: oneshot::Sender<Result<(), String>>,
    },
    DiscoverStun {
        server: SocketAddr,
        reply: oneshot::Sender<Result<SocketAddr, String>>,
    },
}

struct SessionEntry {
    session: WireGuardSession,
    endpoint: SocketAddr,
    established: bool,
}

struct Waiter {
    reply: Option<oneshot::Sender<Result<JobAccept, String>>>,
    deadline: Instant,
}

/// One in-flight STUN transaction (matched by transaction id).
struct StunPending {
    txid: [u8; super::stun::STUN_TXID_LEN],
    reply: Option<oneshot::Sender<Result<SocketAddr, String>>>,
    deadline: Instant,
}

/// Cloneable handle to a running pump task.
#[derive(Debug, Clone)]
pub struct PeerTransport {
    cmd: mpsc::UnboundedSender<Cmd>,
    local_addr: SocketAddr,
}

impl PeerTransport {
    /// Bind and spawn the pump. `handler` receives announces,
    /// establishment notices, and inbound messages on detached tasks.
    pub async fn spawn(
        config: TransportConfig,
        handler: Arc<dyn PeerHandler>,
    ) -> Result<Self, String> {
        let socket = UdpSocket::bind(config.listen)
            .await
            .map_err(|e| format!("bind peer transport {}: {e}", config.listen))?;
        let local_addr = socket
            .local_addr()
            .map_err(|e| format!("peer transport addr: {e}"))?;
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let this = Self {
            cmd: cmd_tx.clone(),
            local_addr,
        };
        tokio::spawn(pump(Pump {
            socket,
            keys: config.keys,
            handler,
            cmd_rx,
            tx: this.clone(),
            sessions: BTreeMap::new(),
            addr_to_node: HashMap::new(),
            waiters: HashMap::new(),
            stun_pending: Vec::new(),
        }));
        Ok(this)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    async fn roundtrip<T>(
        cmd: &mpsc::UnboundedSender<Cmd>,
        make: impl FnOnce(oneshot::Sender<Result<T, String>>) -> Cmd,
    ) -> Result<T, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        cmd.send(make(reply_tx))
            .map_err(|_| "peer transport task is gone".to_string())?;
        reply_rx
            .await
            .map_err(|_| "peer transport task is gone".to_string())?
    }

    /// Register (or replace) a peer session. Replaces any session for
    /// the node: re-announces re-key cleanly.
    pub async fn add_session(
        &self,
        node_id: &str,
        pubkey_b64: &str,
        endpoint: SocketAddr,
    ) -> Result<(), String> {
        let node_id = node_id.to_string();
        let pubkey_b64 = pubkey_b64.to_string();
        Self::roundtrip(&self.cmd, |reply| Cmd::AddSession {
            node_id,
            pubkey_b64,
            endpoint,
            reply,
        })
        .await
    }

    /// Send one message on an established-or-not session (pre-handshake
    /// payloads queue inside boringtun and flush on completion).
    pub async fn send(&self, node_id: &str, msg: PeerMessage) -> Result<(), String> {
        let node_id = node_id.to_string();
        Self::roundtrip(&self.cmd, |reply| Cmd::Send {
            node_id,
            msg,
            reply,
        })
        .await
    }

    /// Send an offer and await its accept (caller times out; the pump
    /// also prunes the waiter past `timeout`).
    pub async fn offer(
        &self,
        node_id: &str,
        offer: super::proto::JobOffer,
        timeout: Duration,
    ) -> Result<JobAccept, String> {
        let node_id = node_id.to_string();
        let fut = Self::roundtrip(&self.cmd, |reply| Cmd::Offer {
            node_id,
            offer,
            timeout,
            reply,
        });
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| format!("offer accept timed out after {}s", timeout.as_secs()))?
    }

    /// Send a plaintext join-announce (no session needed).
    pub async fn announce(&self, target: SocketAddr, announce: JoinAnnounce) -> Result<(), String> {
        Self::roundtrip(&self.cmd, |reply| Cmd::Announce {
            target,
            announce,
            reply,
        })
        .await
    }

    /// Proactively start the Noise handshake (post-announce on the
    /// coordinator side, so activation doesn't wait for an offer).
    pub async fn initiate(&self, node_id: &str) -> Result<(), String> {
        let node_id = node_id.to_string();
        Self::roundtrip(&self.cmd, |reply| Cmd::Initiate { node_id, reply }).await
    }

    /// One STUN Binding transaction over the shared socket (single
    /// attempt; callers retry with timeout bounds, e.g. via
    /// [`super::stun::discover_via_transport`]).
    pub async fn discover_stun(&self, server: SocketAddr) -> Result<SocketAddr, String> {
        Self::roundtrip(&self.cmd, |reply| Cmd::DiscoverStun { server, reply }).await
    }
}

struct Pump {
    socket: UdpSocket,
    keys: Keypair,
    handler: Arc<dyn PeerHandler>,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    tx: PeerTransport,
    sessions: BTreeMap<String, SessionEntry>,
    addr_to_node: HashMap<SocketAddr, String>,
    waiters: HashMap<u64, Waiter>,
    stun_pending: Vec<StunPending>,
}

async fn pump(mut p: Pump) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut tick = tokio::time::interval(PUMP_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = p.socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, src)) => p.on_datagram(src, &buf[..n]).await,
                    Err(e) => eprintln!("runner: peer transport recv: {e}"),
                }
            }
            cmd = p.cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                p.on_cmd(cmd).await;
            }
            _ = tick.tick() => {
                p.on_tick().await;
            }
        }
    }
}

impl Pump {
    async fn transmit(&self, endpoint: SocketAddr, bytes: &[u8]) {
        if let Err(e) = self.socket.send_to(bytes, endpoint).await {
            eprintln!("runner: peer transport send to {endpoint}: {e}");
        }
    }

    /// Flush one session's queued handshake/data packets, one datagram each.
    async fn flush(&mut self, node_id: &str) {
        let endpoint = match self.sessions.get(node_id) {
            Some(entry) => entry.endpoint,
            None => return,
        };
        loop {
            let next = self
                .sessions
                .get_mut(node_id)
                .and_then(|entry| entry.session.poll_outgoing());
            match next {
                Some(bytes) => self.transmit(endpoint, &bytes).await,
                None => break,
            }
        }
    }

    async fn on_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::AddSession {
                node_id,
                pubkey_b64,
                endpoint,
                reply,
            } => {
                let result = WireGuardSession::new(
                    &self.keys.private_b64,
                    &pubkey_b64,
                    DEFAULT_KEEPALIVE_SECS,
                );
                match result {
                    Ok(session) => {
                        self.addr_to_node.retain(|_, v| *v != node_id);
                        self.addr_to_node.insert(endpoint, node_id.clone());
                        self.sessions.insert(
                            node_id,
                            SessionEntry {
                                session,
                                endpoint,
                                established: false,
                            },
                        );
                        let _ = reply.send(Ok(()));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(format!("bad peer key: {e}")));
                    }
                }
            }
            Cmd::Send {
                node_id,
                msg,
                reply,
            } => {
                let result = self.send_message(&node_id, &msg).await;
                let _ = reply.send(result);
            }
            Cmd::Offer {
                node_id,
                offer,
                timeout,
                reply,
            } => {
                let result = self
                    .send_message(&node_id, &PeerMessage::JobOffer(offer.clone()))
                    .await;
                if let Err(e) = result {
                    let _ = reply.send(Err(e));
                    return;
                }
                self.waiters.insert(
                    offer.job_id,
                    Waiter {
                        reply: Some(reply),
                        deadline: Instant::now() + timeout,
                    },
                );
            }
            Cmd::Announce {
                target,
                announce,
                reply,
            } => match encode_plaintext(&PeerMessage::JoinAnnounce(announce)) {
                Ok(bytes) => {
                    self.transmit(target, &bytes).await;
                    let _ = reply.send(Ok(()));
                }
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            },
            Cmd::Initiate { node_id, reply } => {
                let result = match self.sessions.get_mut(&node_id) {
                    Some(entry) => match entry.session.initiate_handshake() {
                        Ok(bytes) => {
                            let endpoint = entry.endpoint;
                            self.transmit(endpoint, &bytes).await;
                            Ok(())
                        }
                        Err(e) => Err(e),
                    },
                    None => Err(format!("unknown peer node: {node_id}")),
                };
                let _ = reply.send(result);
            }
            Cmd::DiscoverStun { server, reply } => {
                let txid = random_txid();
                let request = build_binding_request(&txid);
                self.stun_pending.push(StunPending {
                    txid,
                    reply: Some(reply),
                    deadline: Instant::now() + STUN_PENDING_TTL,
                });
                self.transmit(server, &request).await;
            }
        }
    }

    /// Encode + encrypt + transmit one message on a known session.
    async fn send_message(&mut self, node_id: &str, msg: &PeerMessage) -> Result<(), String> {
        let frame = encode_message(msg)?;
        let entry = self
            .sessions
            .get_mut(node_id)
            .ok_or_else(|| format!("unknown peer node: {node_id}"))?;
        let bytes = entry.session.encrypt(&frame)?;
        let endpoint = entry.endpoint;
        self.transmit(endpoint, &bytes).await;
        self.flush(node_id).await;
        Ok(())
    }

    async fn on_datagram(&mut self, src: SocketAddr, bytes: &[u8]) {
        // STUN responses ride the same socket: intercept first, before
        // the leading-`0x01` initiation guard below can eat them.
        if looks_like_stun_response(bytes) {
            self.on_stun_response(bytes);
            return;
        }
        // Plaintext path: join-announces only (leading `{` can never be
        // a WireGuard datagram, whose first byte is 1-4).
        if bytes.first() == Some(&b'{') {
            match decode_plaintext(bytes) {
                Ok(announce) => {
                    let (handler, tx) = (Arc::clone(&self.handler), self.tx.clone());
                    tokio::spawn(async move {
                        handler.on_announce(&tx, announce, src).await;
                    });
                }
                Err(e) => eprintln!("runner: bad plaintext datagram from {src}: {e}"),
            }
            return;
        }
        // Known address: feed its session directly.
        if let Some(node_id) = self.addr_to_node.get(&src).cloned() {
            self.feed(&node_id, src, bytes).await;
            return;
        }
        // Unknown address: never trial handshake initiations (any
        // session accepts them structurally, which would misattribute
        // peers); unknown nodes must announce first.
        if bytes.first() == Some(&1) {
            return;
        }
        // Trial across sessions in node-id order for roaming/data.
        for node_id in self.sessions.keys().cloned().collect::<Vec<_>>() {
            if self.feed_trial(&node_id, src, bytes).await {
                self.adopt(src, &node_id);
                return;
            }
        }
        // Undecryptable by every session: drop silently (probing noise).
    }

    /// Route a STUN response to its pending transaction (matched by
    /// transaction id; stray or late replies are dropped silently).
    fn on_stun_response(&mut self, bytes: &[u8]) {
        let pos = self
            .stun_pending
            .iter()
            .position(|pending| bytes.len() >= STUN_HEADER_LEN && bytes[8..20] == pending.txid);
        let Some(pos) = pos else {
            return;
        };
        let pending = self.stun_pending.remove(pos);
        if let Some(reply) = pending.reply {
            let _ = reply.send(parse_binding_response(bytes, &pending.txid));
        }
    }

    /// Feed one datagram to a session; returns true when accepted.
    async fn feed_trial(&mut self, node_id: &str, src: SocketAddr, bytes: &[u8]) -> bool {
        let Some(entry) = self.sessions.get_mut(node_id) else {
            return false;
        };
        !matches!(
            entry.session.handle_datagram(Some(src.ip()), bytes),
            SessionEvent::Invalid
        )
    }

    async fn feed(&mut self, node_id: &str, src: SocketAddr, bytes: &[u8]) {
        let first = bytes.first().copied().unwrap_or(0);
        let event = match self.sessions.get_mut(node_id) {
            Some(entry) => entry.session.handle_datagram(Some(src.ip()), bytes),
            None => return,
        };
        match event {
            SessionEvent::Reply(out) => {
                let endpoint = self.sessions[node_id].endpoint;
                self.transmit(endpoint, &out).await;
                self.flush(node_id).await;
                // A answered handshake (either direction) proves the
                // session: response received (initiator) or initiation
                // answered (responder).
                if first == 1 || first == 2 {
                    self.mark_established(node_id).await;
                }
            }
            SessionEvent::ToTunnel(packet) => {
                self.mark_established(node_id).await;
                self.adopt(src, node_id);
                match decode_message(&packet) {
                    Ok(PeerMessage::JobAccept(accept)) => {
                        if let Some(waiter) = self.waiters.remove(&accept.job_id) {
                            if let Some(reply) = waiter.reply {
                                let _ = reply.send(Ok(accept));
                            }
                        }
                        // Late/duplicate accepts (no waiter) are dropped:
                        // the coordinator already fell back on timeout.
                    }
                    Ok(msg) => {
                        let (handler, tx) = (Arc::clone(&self.handler), self.tx.clone());
                        let node_id = node_id.to_string();
                        tokio::spawn(async move {
                            handler.on_message(&tx, &node_id, msg).await;
                        });
                    }
                    Err(e) => eprintln!("runner: bad peer message from {node_id}: {e}"),
                }
                self.flush(node_id).await;
            }
            SessionEvent::Quiet => {
                self.flush(node_id).await;
            }
            SessionEvent::Invalid => {}
        }
    }

    /// Adopt a roaming source address for a session.
    fn adopt(&mut self, src: SocketAddr, node_id: &str) {
        if let Some(entry) = self.sessions.get_mut(node_id) {
            self.addr_to_node.retain(|_, v| v != node_id);
            self.addr_to_node.insert(src, node_id.to_string());
            entry.endpoint = src;
        }
    }

    async fn mark_established(&mut self, node_id: &str) {
        let newly = match self.sessions.get_mut(node_id) {
            Some(entry) if !entry.established => {
                entry.established = true;
                true
            }
            _ => false,
        };
        if newly {
            let (handler, tx) = (Arc::clone(&self.handler), self.tx.clone());
            let node_id = node_id.to_string();
            tokio::spawn(async move {
                handler.on_established(&tx, &node_id).await;
            });
        }
    }

    async fn on_tick(&mut self) {
        // Noise timers + queue drain per session.
        for node_id in self.sessions.keys().cloned().collect::<Vec<_>>() {
            let timer_bytes = self
                .sessions
                .get_mut(&node_id)
                .and_then(|entry| entry.session.update_timers());
            if let Some(bytes) = timer_bytes {
                let endpoint = self.sessions[&node_id].endpoint;
                self.transmit(endpoint, &bytes).await;
            }
            self.flush(&node_id).await;
        }
        // Expire STUN transactions whose caller vanished (live
        // callers time out sooner and retry with a fresh id).
        let now = Instant::now();
        self.stun_pending.retain_mut(|pending| {
            if pending.deadline <= now {
                if let Some(reply) = pending.reply.take() {
                    let _ = reply.send(Err("STUN discovery timed out".to_string()));
                }
                false
            } else {
                true
            }
        });
        // Expire offer waiters (the handle side also times out; the
        // second completion is silently dropped by the oneshot).
        let mut expired = Vec::new();
        self.waiters.retain(|job_id, waiter| {
            if waiter.deadline <= now {
                expired.push(*job_id);
                if let Some(reply) = waiter.reply.take() {
                    let _ = reply.send(Err(format!("offer accept timed out for job {job_id}")));
                }
                false
            } else {
                true
            }
        });
        for job_id in expired {
            eprintln!("runner: dropped expired offer waiter for job {job_id}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recording handler for pump mechanics (roles are covered by the
    /// loopback integration test with real roles).
    struct Recorder {
        announces: std::sync::Mutex<Vec<(JoinAnnounce, SocketAddr)>>,
        messages: std::sync::Mutex<Vec<(String, PeerMessage)>>,
    }

    impl PeerHandler for Recorder {
        fn on_announce<'a>(
            &'a self,
            _tx: &'a PeerTransport,
            announce: JoinAnnounce,
            src: SocketAddr,
        ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            Box::pin(async move {
                self.announces.lock().unwrap().push((announce, src));
            })
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

    fn test_keys() -> super::super::peer::Keypair {
        super::super::peer::generate_keypair()
    }

    async fn spawn_recorder() -> (PeerTransport, Arc<Recorder>, SocketAddr) {
        let recorder = Arc::new(Recorder {
            announces: std::sync::Mutex::new(Vec::new()),
            messages: std::sync::Mutex::new(Vec::new()),
        });
        let tx = PeerTransport::spawn(
            TransportConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                keys: test_keys(),
            },
            recorder.clone(),
        )
        .await
        .unwrap();
        let addr = tx.local_addr();
        (tx, recorder, addr)
    }

    #[tokio::test]
    async fn unknown_node_sends_fail_closed() {
        let (tx, _, _) = spawn_recorder().await;
        let err = tx
            .send(
                "ghost",
                PeerMessage::JobAccept(super::super::proto::JobAccept {
                    proto: super::super::proto::PROTO_TAG.to_string(),
                    job_id: 1,
                    accepted: true,
                    reason: String::new(),
                }),
            )
            .await
            .unwrap_err();
        assert!(err.contains("unknown peer node"), "{err}");
        let err = tx.initiate("ghost").await.unwrap_err();
        assert!(err.contains("unknown peer node"), "{err}");
    }

    #[tokio::test]
    async fn announce_reaches_handler_plaintext() {
        let (tx, recorder, addr) = spawn_recorder().await;
        let announce = JoinAnnounce {
            proto: super::super::proto::PROTO_TAG.to_string(),
            node_id: "bob".to_string(),
            pubkey_b64: "KEY".to_string(),
            token: "runner1.e30.sig".to_string(),
            listen_port: 40001,
            max_cores: 4,
            max_ram_mb: 8192,
            reflexive: None,
            lan: None,
        };
        tx.announce(addr, announce.clone()).await.unwrap();
        for _ in 0..100 {
            if !recorder.announces.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let got = recorder.announces.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.node_id, "bob");
    }

    #[tokio::test]
    async fn offer_to_silent_peer_times_out() {
        let (tx, _, _) = spawn_recorder().await;
        // Session exists but nobody listens there: handshake never
        // completes, so the waiter must expire (not hang).
        tx.add_session(
            "ghost",
            &test_keys().public_b64,
            "127.0.0.1:9".parse().unwrap(),
        )
        .await
        .unwrap();
        let err = tx
            .offer(
                "ghost",
                super::super::proto::JobOffer {
                    proto: super::super::proto::PROTO_TAG.to_string(),
                    provider: "github".to_string(),
                    job_id: 3,
                    run_id: 100,
                    name: "t".to_string(),
                    labels: vec![],
                    jit_blob: "B".to_string(),
                    worker_version: "2.338.2".to_string(),
                    timeout_secs: 60,
                },
                Duration::from_millis(150),
            )
            .await
            .unwrap_err();
        assert!(err.contains("timed out"), "{err}");
    }
}
