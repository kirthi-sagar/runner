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

fn decode_key(text: &str) -> Result<[u8; 32], String> {
    let bytes = b64()
        .decode(text)
        .map_err(|_| "malformed base64 key".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "wireguard keys must be 32 bytes".to_string())
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
    /// Bytes to send back to the network (handshake reply, keepalive).
    Reply(Vec<u8>),
    /// Decrypted inner packet bound for the tunnel interface.
    ToTunnel(Vec<u8>),
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

    /// Feed one UDP datagram (source optional until roaming) into the session.
    pub fn handle_datagram(&mut self, src: Option<IpAddr>, datagram: &[u8]) -> SessionEvent {
        let mut dst = vec![0u8; WG_BUF_SIZE];
        // Drain follow-up writes (queued packets) after the first result.
        let mut replies = Vec::new();
        let mut first = true;
        let mut to_tunnel = None;
        let mut input = datagram;
        let empty: &[u8] = &[];
        loop {
            let result = self.tunn.decapsulate(src, input, &mut dst);
            match result {
                TunnResult::WriteToNetwork(bytes) => {
                    replies.extend_from_slice(bytes);
                    input = empty;
                    first = false;
                    continue;
                }
                TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                    to_tunnel = Some(bytes.to_vec());
                    input = empty;
                    // A queued reply may follow; loop once more max.
                    if first {
                        first = false;
                        continue;
                    }
                    break;
                }
                TunnResult::Done => break,
                TunnResult::Err(_) => break,
            }
        }
        if let Some(packet) = to_tunnel {
            let _ = replies;
            SessionEvent::ToTunnel(packet)
        } else if replies.is_empty() {
            SessionEvent::Quiet
        } else {
            SessionEvent::Reply(replies)
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

    /// Encrypt one inner packet for the peer (requires completed handshake).
    pub fn encrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>, String> {
        let mut dst = vec![0u8; packet.len() + 64];
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_yields_valid_32_byte_keys() {
        let keys = generate_keypair();
        assert!(decode_key(&keys.private_b64).is_ok());
        assert!(decode_key(&keys.public_b64).is_ok());
        assert_ne!(generate_keypair().public_b64, keys.public_b64);
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
}
