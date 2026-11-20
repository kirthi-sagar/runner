//! WireGuard P2P overlay for trusted peer nodes (friends & family).
//!
//! Embedded userspace WireGuard via `boringtun`: x25519 identities,
//! Noise handshake sessions with NAT-traversal keepalive, and standard
//! `[Interface]/[Peer]` config rendering.
//!
//! Phase 3 delivers session crypto (handshake + transport encryption +
//! keepalive timers, all exercised in-memory in tests). The UDP socket
//! pump and TUN device wiring need `CAP_NET_ADMIN` and land in
//! production hardening.

use std::net::IpAddr;

use base64::Engine;

use boringtun::noise::{Tunn, TunnResult};

/// Default keepalive for NAT traversal.
pub const DEFAULT_KEEPALIVE_SECS: u16 = 25;
/// Maximum WireGuard datagram scratch space.
pub const WG_BUF_SIZE: usize = 2048;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// x25519 WireGuard identity (base64 standard encoding, like `wg`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keypair {
    pub private_b64: String,
    pub public_b64: String,
}

/// Generate a fresh identity from the OS RNG.
pub fn generate_keypair() -> Keypair {
    let secret = boringtun::x25519::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = boringtun::x25519::PublicKey::from(&secret);
    Keypair {
        private_b64: b64().encode(secret.as_bytes()),
        public_b64: b64().encode(public.as_bytes()),
    }
}

/// Whether the text parses as a 32-byte base64 WireGuard key.
pub fn valid_public_key(text: &str) -> bool {
    decode_key(text).is_ok()
}

fn decode_key(text: &str) -> Result<[u8; 32], String> {
    let bytes = b64()
        .decode(text)
        .map_err(|_| "malformed base64 key".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "wireguard keys must be 32 bytes".to_string())
}

/// Load this node's WireGuard identity from mesh config, generating and
/// storing one (in memory; the caller persists) when absent. A stored
/// malformed key is a hard error, never silently replaced.
pub fn ensure_node_keypair(config: &mut crate::config::RunnerConfig) -> Result<Keypair, String> {
    if let Some(private_b64) = config.mesh.node_key.clone() {
        let secret = decode_key(&private_b64)?;
        let secret_key = boringtun::x25519::StaticSecret::from(secret);
        let public = boringtun::x25519::PublicKey::from(&secret_key);
        return Ok(Keypair {
            private_b64,
            public_b64: b64().encode(public.as_bytes()),
        });
    }
    let keys = generate_keypair();
    config.mesh.node_key = Some(keys.private_b64.clone());
    Ok(keys)
}

/// Render a `wg-quick`-style config for this host's interface + one peer.
pub fn render_config(
    local_private_b64: &str,
    peer_public_b64: &str,
    allowed_ips: &[&str],
    endpoint: Option<&str>,
    keepalive_secs: u16,
) -> String {
    let mut config = format!(
        "[Interface]\nPrivateKey = {local_private_b64}\n\n\
         [Peer]\nPublicKey = {peer_public_b64}\n\
         AllowedIPs = {}\nPersistentKeepalive = {keepalive_secs}\n",
        allowed_ips.join(", "),
    );
    if let Some(endpoint) = endpoint {
        config.push_str(&format!("Endpoint = {endpoint}\n"));
    }
    config
}

/// Outcome of feeding one network datagram to a session.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// Nothing to do.
    Quiet,
    /// Exactly one datagram to send back (handshake reply or keepalive).
    /// Single-step by construction: boringtun yields one packet per
    /// call, and this function never concatenates, so every `Reply`
    /// is safe to transmit as one UDP datagram. Call
    /// [`WireGuardSession::poll_outgoing`] to drain follow-ups.
    Reply(Vec<u8>),
    /// Decrypted inner packet bound for the tunnel interface.
    ToTunnel(Vec<u8>),
    /// Datagram rejected (not for this session, or corrupt). Callers
    /// routing across sessions treat this as "try the next session".
    Invalid,
}

/// Point-to-point encrypted session (Noise handshake + transport).
pub struct WireGuardSession {
    tunn: Tunn,
}

impl WireGuardSession {
    /// Create a session from our private key and the peer's public key.
    /// `keepalive_secs` of 0 disables persistent keepalives.
    pub fn new(
        local_private_b64: &str,
        peer_public_b64: &str,
        keepalive_secs: u16,
    ) -> Result<Self, String> {
        let private = decode_key(local_private_b64)?;
        let peer = decode_key(peer_public_b64)?;
        let keepalive = if keepalive_secs == 0 {
            None
        } else {
            Some(keepalive_secs)
        };
        let index = rand::random::<u32>();
        let tunn = Tunn::new(private.into(), peer.into(), None, keepalive, index, None);
        Ok(Self { tunn })
    }

    /// Begin (or re-begin) the handshake; returns initiation bytes.
    pub fn initiate_handshake(&mut self) -> Result<Vec<u8>, String> {
        let mut dst = vec![0u8; WG_BUF_SIZE];
        match self.tunn.encapsulate(&[], &mut dst) {
            TunnResult::WriteToNetwork(bytes) => Ok(bytes.to_vec()),
            TunnResult::Done => Ok(Vec::new()),
            TunnResult::Err(e) => Err(format!("handshake failed: {e:?}")),
            _ => Err("unexpected handshake result".to_string()),
        }
    }

    /// Feed one UDP datagram (source optional until roaming) into the
    /// session. Single-step: exactly one boringtun call, so a `Reply`
    /// is always exactly one transmittable datagram.
    pub fn handle_datagram(&mut self, src: Option<IpAddr>, datagram: &[u8]) -> SessionEvent {
        let mut dst = vec![0u8; WG_BUF_SIZE];
        match self.tunn.decapsulate(src, datagram, &mut dst) {
            TunnResult::WriteToNetwork(bytes) => SessionEvent::Reply(bytes.to_vec()),
            TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                SessionEvent::ToTunnel(bytes.to_vec())
            }
            TunnResult::Done => SessionEvent::Quiet,
            TunnResult::Err(_) => SessionEvent::Invalid,
        }
    }

    /// Emit at most one queued outgoing datagram (post-handshake flush,
    /// retransmits): boringtun's empty-datagram protocol as an explicit
    /// poll step. Returns `None` when the queue is drained.
    pub fn poll_outgoing(&mut self) -> Option<Vec<u8>> {
        match self.handle_datagram(None, &[]) {
            SessionEvent::Reply(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// Drive keepalive/handshake timers; returns bytes to transmit, if any.
    pub fn update_timers(&mut self) -> Option<Vec<u8>> {
        let mut dst = vec![0u8; WG_BUF_SIZE];
        match self.tunn.update_timers(&mut dst) {
            TunnResult::WriteToNetwork(bytes) => Some(bytes.to_vec()),
            _ => None,
        }
    }

    /// Drive boringtun's empty-datagram protocol: flushes payloads queued
    /// before the handshake completed. Call after handshake progress and
    /// on the pump tick; returns bytes to transmit, if any.
    pub fn drain_queue(&mut self) -> SessionEvent {
        self.handle_datagram(None, &[])
    }

    /// Encrypt one inner packet for the peer. Before the handshake
    /// completes the payload queues and initiation bytes return
    /// instead (flush via [`Self::poll_outgoing`] after progress).
    pub fn encrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>, String> {
        // boringtun needs src.len() + 32 for data but at least 148
        // bytes when formatting a handshake initiation instead.
        let mut dst = vec![0u8; (packet.len() + 64).max(148)];
        match self.tunn.encapsulate(packet, &mut dst) {
            TunnResult::WriteToNetwork(bytes) => Ok(bytes.to_vec()),
            TunnResult::Done => Ok(Vec::new()),
            TunnResult::Err(e) => Err(format!("encrypt failed: {e:?}")),
            _ => Err("unexpected encrypt result".to_string()),
        }
    }
}

/// Clamp parallel slots to donor caps (trusted peer safety).
///
/// The donor donates *up to* `max_cores`/`max_ram_mb`; slots are bounded by
/// the same per-job minima as the local formula and never drop below 1
/// when at least one slot was available.
pub fn apply_donor_caps(slots: u32, max_cores: u32, max_ram_mb: u64) -> u32 {
    if slots == 0 {
        return 0;
    }
    let cpu_bound = ((max_cores as f64) / crate::governor::topology::JOB_MIN_CORES).floor() as u32;
    let mem_bound = (max_ram_mb / crate::governor::topology::JOB_MIN_MEM_MB) as u32;
    slots.min(cpu_bound.max(1)).min(mem_bound.max(1))
}

/// Maximum concurrent peer jobs from donor caps alone (load-unaware).
pub fn peer_max_jobs(max_cores: u32, max_ram_mb: u64) -> u32 {
    apply_donor_caps(u32::MAX, max_cores, max_ram_mb)
}

/// Parse per-job hardware minimums from workflow labels (`cpu-N`,
/// `ram-Ngb` per spec §5.2). Malformed entries impose no requirement.
pub fn parse_job_minimums(labels: &[String]) -> (f64, u64) {
    let mut cores = 0.0f64;
    let mut ram_mb = 0u64;
    for label in labels {
        let text = label.trim().to_ascii_lowercase();
        if let Some(n) = text.strip_prefix("cpu-") {
            if let Ok(v) = n.parse::<f64>() {
                if v > 0.0 {
                    cores = cores.max(v);
                }
            }
        } else if let Some(n) = text.strip_prefix("ram-").and_then(|s| s.strip_suffix("gb")) {
            if let Ok(gb) = n.parse::<u64>() {
                ram_mb = ram_mb.max(gb.saturating_mul(1024));
            }
        }
    }
    (cores, ram_mb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_yields_valid_32_byte_keys() {
        let keys = generate_keypair();
        assert!(decode_key(&keys.private_b64).is_ok());
        assert!(decode_key(&keys.public_b64).is_ok());
        assert_ne!(generate_keypair().public_b64, keys.public_b64);
        assert!(valid_public_key(&keys.public_b64));
        assert!(!valid_public_key("not-a-key"));
        assert!(!valid_public_key(""));
    }

    #[test]
    fn config_renders_keepalive_and_endpoint() {
        let config = render_config("PRIV", "PUB", &["10.9.0.2/32"], Some("1.2.3.4:51820"), 25);
        assert!(config.contains("PrivateKey = PRIV"));
        assert!(config.contains("PublicKey = PUB"));
        assert!(config.contains("PersistentKeepalive = 25"));
        assert!(config.contains("Endpoint = 1.2.3.4:51820"));
    }

    #[test]
    fn donor_caps_clamp_slots() {
        assert_eq!(apply_donor_caps(4, 4, 8192), 2);
        assert_eq!(apply_donor_caps(4, 64, 1_000_000), 4);
        assert_eq!(apply_donor_caps(4, 1, 1024), 1);
        assert_eq!(apply_donor_caps(0, 4, 8192), 0);
    }

    #[test]
    fn label_minimums_parse_and_ignore_garbage() {
        let labels = |ls: &[&str]| ls.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(parse_job_minimums(&labels(&["cpu-4"])), (4.0, 0));
        assert_eq!(parse_job_minimums(&labels(&["ram-8gb"])), (0.0, 8192));
        assert_eq!(
            parse_job_minimums(&labels(&["self-hosted", "cpu-2", "ram-4gb"])),
            (2.0, 4096)
        );
        // Case-insensitive; max wins; garbage imposes nothing.
        assert_eq!(
            parse_job_minimums(&labels(&["CPU-2", "cpu-6", "RAM-1GB"])),
            (6.0, 1024)
        );
        assert_eq!(
            parse_job_minimums(&labels(&["cpu-x", "cpu-0", "ram-", "ram-4mb", "runner"])),
            (0.0, 0)
        );
        assert_eq!(peer_max_jobs(4, 8192), 2);
        assert_eq!(peer_max_jobs(64, 1_000_000), 42);
    }

    #[test]
    fn two_sessions_complete_handshake_in_memory() {
        let alice_keys = generate_keypair();
        let bob_keys = generate_keypair();
        let mut alice =
            WireGuardSession::new(&alice_keys.private_b64, &bob_keys.public_b64, 25).unwrap();
        let mut bob =
            WireGuardSession::new(&bob_keys.private_b64, &alice_keys.public_b64, 25).unwrap();

        // Alice -> Bob: initiation; Bob -> Alice: response.
        let init = alice.initiate_handshake().unwrap();
        assert!(!init.is_empty());
        let reply = bob.handle_datagram(None, &init);
        let SessionEvent::Reply(response) = reply else {
            panic!("expected handshake response, got {reply:?}");
        };
        // Alice consumes the response (may emit keepalive/data quietly).
        let _ = alice.handle_datagram(None, &response);

        // Encrypted round trip: inner packet must be a plausible IPv4
        // datagram (>= 20-byte header, total-length field set).
        let inner = vec![
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 9, 0, 2, 10, 9, 0, 1,
        ];
        let sealed = alice.encrypt(&inner).unwrap();
        assert!(!sealed.is_empty());
        let event = bob.handle_datagram(None, &sealed);
        assert_eq!(event, SessionEvent::ToTunnel(inner));
    }

    /// Drive a full handshake by shuttling single datagrams, as the pump does.
    fn establish(a: &mut WireGuardSession, b: &mut WireGuardSession) {
        let init = a.initiate_handshake().unwrap();
        let reply = b.handle_datagram(None, &init);
        let SessionEvent::Reply(response) = reply else {
            panic!("expected handshake response, got {reply:?}");
        };
        // Initiator consumes the response (emits a keepalive) and the
        // responder acks it quietly; both sides are established after.
        if let SessionEvent::Reply(keepalive) = a.handle_datagram(None, &response) {
            let _ = b.handle_datagram(None, &keepalive);
        }
        while a.poll_outgoing().is_some() {}
        while b.poll_outgoing().is_some() {}
    }

    #[test]
    fn queued_payload_flushes_after_handshake() {
        let alice_keys = generate_keypair();
        let bob_keys = generate_keypair();
        let mut alice =
            WireGuardSession::new(&alice_keys.private_b64, &bob_keys.public_b64, 25).unwrap();
        let mut bob =
            WireGuardSession::new(&bob_keys.private_b64, &alice_keys.public_b64, 25).unwrap();

        // Encrypt before any handshake: boringtun queues the payload and
        // returns initiation bytes instead of failing.
        let inner = vec![
            0x45, 0, 0, 24, 0, 0, 0, 0, 64, 253, 0, 0, 10, 9, 0, 1, 10, 9, 0, 2, 1, 2, 3, 4,
        ];
        let first = alice.encrypt(&inner).unwrap();
        assert!(!first.is_empty());

        // Complete the handshake through the queued initiation.
        let reply = bob.handle_datagram(None, &first);
        let SessionEvent::Reply(response) = reply else {
            panic!("expected handshake response, got {reply:?}");
        };
        let _ = alice.handle_datagram(None, &response);

        // The queued payload flushes as its own datagram (never glued):
        // first byte 4 marks a WireGuard transport-data message.
        let flushed = alice.poll_outgoing().expect("queued payload lost");
        assert_eq!(flushed[0], 4);
        let event = bob.handle_datagram(None, &flushed);
        assert_eq!(event, SessionEvent::ToTunnel(inner));
        assert!(alice.poll_outgoing().is_none());
    }

    #[test]
    fn undecryptable_datagrams_are_invalid_not_quiet() {
        let alice_keys = generate_keypair();
        let bob_keys = generate_keypair();
        let mut alice =
            WireGuardSession::new(&alice_keys.private_b64, &bob_keys.public_b64, 25).unwrap();
        let mut bob =
            WireGuardSession::new(&bob_keys.private_b64, &alice_keys.public_b64, 25).unwrap();
        establish(&mut alice, &mut bob);

        // A data packet fed to a session with no handshake state cannot
        // decrypt: Invalid is how the pump routes across sessions.
        // (Handshake initiations are structurally accepted by any
        // session by Noise design, so routing keys off data + address.)
        let mut stranger =
            WireGuardSession::new(&bob_keys.private_b64, &alice_keys.public_b64, 25).unwrap();
        let inner = vec![
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 9, 0, 2, 10, 9, 0, 1,
        ];
        let sealed = alice.encrypt(&inner).unwrap();
        assert_eq!(
            stranger.handle_datagram(None, &sealed),
            SessionEvent::Invalid
        );
        // Garbage is invalid too.
        assert_eq!(
            bob.handle_datagram(None, b"\xff\x00garbage"),
            SessionEvent::Invalid
        );
    }

    #[test]
    fn node_identity_round_trips_through_config() {
        let mut config = crate::config::RunnerConfig::default();
        let first = ensure_node_keypair(&mut config).unwrap();
        assert!(config.mesh.node_key.is_some());
        let second = ensure_node_keypair(&mut config).unwrap();
        assert_eq!(first, second);

        config.mesh.node_key = Some("definitely-not-base64!!!".to_string());
        assert!(ensure_node_keypair(&mut config).is_err());
    }
}
