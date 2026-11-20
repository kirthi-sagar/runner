//! WAN mesh roles: coordinator (dispatch + results) and peer (execute).
//!
//! Both roles implement [`PeerHandler`]; daemons combine them with
//! [`MeshRoles`] so one node can coordinate and donate at once.
//! Fail-closed throughout: unknown tokens, replayed nonces, missing
//! donor caps, full slots, and oversized messages all refuse loudly.

use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::Mutex;

use super::invite::{InviteAuthority, InvitePayload};
use super::peer::parse_job_minimums;
use super::proto::{
    JobAccept, JobOffer, JobResult, JoinAccept, JoinAnnounce, PeerMessage, PROTO_TAG,
};
use super::stun::{local_addr_for, select_endpoint};
use super::transport::{PeerHandler, PeerTransport};
use crate::config::{PeerRecord, RunnerConfig};
use crate::governor::supervisor::SharedState;

/// Peer-side job executor (real worker in providers, stub in tests).
pub trait PeerExecutor: Send + Sync {
    fn execute<'a>(
        &'a self,
        offer: &'a JobOffer,
    ) -> Pin<Box<dyn std::future::Future<Output = JobResult> + Send + 'a>>;
}

/// Coordinator side: verifies joins, activates peers, applies results.
pub struct CoordinatorRole {
    authority: InviteAuthority,
    state: SharedState,
    persist_path: Option<PathBuf>,
    /// Consumed invitation nonces → token expiry (pruned, so the set
    /// stays bounded by the live TTL window, not history).
    used_nonces: Mutex<HashMap<String, u64>>,
    /// This coordinator's STUN-discovered reflexive address, published
    /// in JoinAccept replies (`None` until daemon self-discovery runs).
    reflexive: Mutex<Option<String>>,
}

impl CoordinatorRole {
    pub fn new(
        authority: InviteAuthority,
        state: SharedState,
        persist_path: Option<PathBuf>,
    ) -> Self {
        Self {
            authority,
            state,
            persist_path,
            used_nonces: Mutex::new(HashMap::new()),
            reflexive: Mutex::new(None),
        }
    }

    /// Record this coordinator's reflexive address for JoinAccept replies.
    pub async fn set_reflexive(&self, addr: std::net::SocketAddr) {
        *self.reflexive.lock().await = Some(addr.to_string());
    }

    /// Verify an announce: token signature + TTL always; nonce
    /// single-use only for unknown nodes (known node+pubkey pairs
    /// re-announce freely, e.g. after coordinator restart). Announced
    /// caps must match the signed token exactly (tamper evidence).
    async fn verify_announce(&self, announce: &JoinAnnounce) -> Result<InvitePayload, String> {
        let payload = self.authority.verify(&announce.token)?;
        if payload.max_cores != announce.max_cores || payload.max_ram_mb != announce.max_ram_mb {
            return Err("announced caps differ from invitation".to_string());
        }
        if let Some(reflexive) = &announce.reflexive {
            reflexive
                .parse::<std::net::SocketAddr>()
                .map_err(|_| "announced reflexive is not a socket address".to_string())?;
        }
        if let Some(lan) = &announce.lan {
            lan.parse::<std::net::SocketAddr>()
                .map_err(|_| "announced lan is not a socket address".to_string())?;
        }
        let known = self
            .state
            .read()
            .await
            .peers()
            .iter()
            .any(|p| p.node_id == announce.node_id && p.public_key == announce.pubkey_b64);
        if !known {
            let mut nonces = self.used_nonces.lock().await;
            nonces.retain(|_, expires_at| *expires_at > payload.issued_at);
            if nonces.contains_key(&payload.nonce) {
                return Err("invitation token already used".to_string());
            }
            nonces.insert(payload.nonce.clone(), payload.expires_at);
        }
        Ok(payload)
    }

    /// Persist a peer record (best effort; `None` path skips, for tests).
    /// Records persist as `joining` forever: only a live handshake proves
    /// liveness, so restarts re-prove it and `active` never goes stale.
    fn persist_peer(&self, record: &PeerRecord) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let mut stored = match RunnerConfig::load_from(path) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("runner: load config for peer persist failed: {e}");
                return;
            }
        };
        if let Some(existing) = stored
            .peers
            .iter_mut()
            .find(|p| p.node_id == record.node_id)
        {
            *existing = record.clone();
        } else {
            stored.peers.push(record.clone());
        }
        if let Err(e) = stored.save_to(path) {
            eprintln!("runner: persist peer {} failed: {e}", record.node_id);
        }
    }
}

impl PeerHandler for CoordinatorRole {
    fn on_announce<'a>(
        &'a self,
        tx: &'a PeerTransport,
        announce: JoinAnnounce,
        src: std::net::SocketAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let payload = match self.verify_announce(&announce).await {
                Ok(payload) => payload,
                Err(e) => {
                    eprintln!("runner: rejected join-announce from {src}: {e}");
                    return;
                }
            };
            // Endpoint selection: the joiner's LAN address when it
            // shares our subnet (direct dial, no NAT in the way), else
            // the observed source — the NAT binding the announce itself
            // opened, valid through every NAT type including symmetric.
            // The advertised reflexive address is diagnostic context
            // only: behind symmetric NAT it names a mapping that does
            // not reach us.
            let local_ip = local_addr_for(src).unwrap_or_else(|| src.ip());
            let (endpoint, via) = select_endpoint(src, &announce, local_ip);
            eprintln!(
                "runner: join-announce from {} at {src} (reflexive {:?}, route via {via} to {endpoint})",
                announce.node_id, announce.reflexive
            );
            let record = PeerRecord {
                node_id: announce.node_id.clone(),
                public_key: announce.pubkey_b64.clone(),
                endpoint: Some(endpoint.to_string()),
                max_cores: payload.max_cores,
                max_ram_mb: payload.max_ram_mb,
                status: "joining".to_string(),
            };
            self.state.write().await.add_peer(record.clone());
            self.persist_peer(&record);
            if let Err(e) = tx
                .add_session(&record.node_id, &record.public_key, endpoint)
                .await
            {
                eprintln!("runner: peer session for {} failed: {e}", record.node_id);
                return;
            }
            // Initiate immediately so activation doesn't wait for an offer.
            if let Err(e) = tx.initiate(&record.node_id).await {
                eprintln!("runner: peer handshake with {} failed: {e}", record.node_id);
            }
        })
    }

    fn on_established<'a>(
        &'a self,
        tx: &'a PeerTransport,
        node_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let node_id = node_id.to_string();
        Box::pin(async move {
            let mut guard = self.state.write().await;
            if let Some(mut record) = guard.peers().into_iter().find(|p| p.node_id == node_id) {
                if record.status != "active" {
                    record.status = "active".to_string();
                    guard.add_peer(record);
                    eprintln!("runner: peer {node_id} active");
                }
            }
            drop(guard);
            // Acceptance notice + our reflexive address (diagnostics for
            // the joiner; idempotent across re-establishment).
            let accept = PeerMessage::JoinAccept(JoinAccept {
                proto: PROTO_TAG.to_string(),
                accepted: true,
                reason: String::new(),
                reflexive: self.reflexive.lock().await.clone(),
            });
            if let Err(e) = tx.send(&node_id, accept).await {
                eprintln!("runner: join-accept to {node_id} failed: {e}");
            }
        })
    }

    fn on_message<'a>(
        &'a self,
        _tx: &'a PeerTransport,
        node_id: &'a str,
        msg: PeerMessage,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let node_id = node_id.to_string();
        Box::pin(async move {
            // Accepts route to offer waiters inside the pump; anything
            // else here is unexpected and ignored.
            let PeerMessage::JobResult(result) = msg else {
                eprintln!("runner: unexpected {node_id} message ignored");
                return;
            };
            let id = result.job_id.to_string();
            let mut guard = self.state.write().await;
            guard.release_peer_lease(&result.provider, &id);
            guard.job_finished(&result.provider, &id);
            eprintln!(
                "runner: peer job {id} finished: exit={:?} killed={}",
                result.exit_code, result.killed
            );
        })
    }
}

/// Peer side: validates offers against donor caps and slots, executes
/// accepted jobs through the injected executor, reports results.
pub struct PeerRole {
    executor: Arc<dyn PeerExecutor>,
    state: SharedState,
}

impl PeerRole {
    pub fn new(executor: Arc<dyn PeerExecutor>, state: SharedState) -> Self {
        Self { executor, state }
    }

    async fn accept(tx: &PeerTransport, node_id: &str, job_id: u64, accepted: bool, reason: &str) {
        let msg = PeerMessage::JobAccept(JobAccept {
            proto: PROTO_TAG.to_string(),
            job_id,
            accepted,
            reason: reason.to_string(),
        });
        if let Err(e) = tx.send(node_id, msg).await {
            eprintln!("runner: accept reply to {node_id} failed: {e}");
        }
    }
}

impl PeerHandler for PeerRole {
    fn on_announce<'a>(
        &'a self,
        _tx: &'a PeerTransport,
        announce: JoinAnnounce,
        src: std::net::SocketAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            eprintln!(
                "runner: ignoring join-announce from {} at {src} (peers don't accept joins)",
                announce.node_id
            );
        })
    }

    fn on_established<'a>(
        &'a self,
        _tx: &'a PeerTransport,
        node_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let node_id = node_id.to_string();
        Box::pin(async move {
            eprintln!("runner: peer session with {node_id} established");
        })
    }

    fn on_message<'a>(
        &'a self,
        tx: &'a PeerTransport,
        node_id: &'a str,
        msg: PeerMessage,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let node_id = node_id.to_string();
        Box::pin(async move {
            let PeerMessage::JobOffer(offer) = msg else {
                if let PeerMessage::JoinAccept(accept) = msg {
                    eprintln!(
                        "runner: join accepted by {node_id} (coordinator reflexive {:?})",
                        accept.reflexive
                    );
                }
                return;
            };
            let id = offer.job_id.to_string();
            // Donor + capacity gates under one write lock.
            let decision = {
                let mut guard = self.state.write().await;
                if !guard.is_donor() {
                    Err("not a donor".to_string())
                } else if guard
                    .in_flight_jobs()
                    .iter()
                    .any(|j| j.provider == "wan" && j.id == id)
                {
                    Err("already running".to_string())
                } else {
                    let (min_cores, min_ram) = parse_job_minimums(&offer.labels);
                    let caps_ok = guard.donor_caps().is_some_and(|(cores, ram)| {
                        f64::from(cores) >= min_cores && ram >= min_ram
                    });
                    if !caps_ok {
                        Err("below donor minimums".to_string())
                    } else if !guard.try_reserve_slot() {
                        Err("no free slots".to_string())
                    } else {
                        guard.job_started("wan", &id, &offer.name);
                        Ok(())
                    }
                }
            };
            match decision {
                Err(reason) => Self::accept(tx, &node_id, offer.job_id, false, &reason).await,
                Ok(()) => {
                    Self::accept(tx, &node_id, offer.job_id, true, "").await;
                    let (executor, state, tx, offer) = (
                        Arc::clone(&self.executor),
                        self.state.clone(),
                        tx.clone(),
                        offer.clone(),
                    );
                    tokio::spawn(async move {
                        let result = executor.execute(&offer).await;
                        let mut guard = state.write().await;
                        guard.release_slot_reservation();
                        guard.job_finished(&result.provider, &result.job_id.to_string());
                        drop(guard);
                        if let Err(e) = tx
                            .send(&node_id, PeerMessage::JobResult(result.clone()))
                            .await
                        {
                            eprintln!("runner: result reply to {node_id} failed: {e}");
                        }
                    });
                }
            }
        })
    }
}

/// One node acting as both coordinator and donor (the standard daemon).
pub struct MeshRoles {
    pub coordinator: CoordinatorRole,
    pub peer: PeerRole,
}

impl MeshRoles {
    pub fn new(coordinator: CoordinatorRole, peer: PeerRole) -> Self {
        Self { coordinator, peer }
    }
}

impl PeerHandler for MeshRoles {
    fn on_announce<'a>(
        &'a self,
        tx: &'a PeerTransport,
        announce: JoinAnnounce,
        src: std::net::SocketAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            self.coordinator.on_announce(tx, announce, src).await;
        })
    }

    fn on_established<'a>(
        &'a self,
        tx: &'a PeerTransport,
        node_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            self.coordinator.on_established(tx, node_id).await;
            self.peer.on_established(tx, node_id).await;
        })
    }

    fn on_message<'a>(
        &'a self,
        tx: &'a PeerTransport,
        node_id: &'a str,
        msg: PeerMessage,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match &msg {
                PeerMessage::JobOffer(_) => self.peer.on_message(tx, node_id, msg).await,
                PeerMessage::JobResult(_) => self.coordinator.on_message(tx, node_id, msg).await,
                _ => {}
            }
        })
    }
}
