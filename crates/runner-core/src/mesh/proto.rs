//! WAN peer message protocol: job dispatch over Noise-encrypted UDP.
//!
//! Messages ride inside boringtun sessions wrapped in a framing-only
//! IPv4 header — boringtun rejects non-IP inner bytes (`InvalidPacket`),
//! so `wrap_ipv4` prepends a minimal 20-byte header (10.9.x overlay
//! addresses, protocol 253 experimental) that `unwrap_ipv4` strips.
//! The header is never routed; it exists only to satisfy the WG data
//! path. `JoinAnnounce` alone travels plaintext (no session exists yet).

use serde::{Deserialize, Serialize};

/// Protocol tag carried by every message (wire-compat sentinel).
pub const PROTO_TAG: &str = "wan1";
/// IPv4 protocol number for framed payloads (experimental use).
pub const FRAME_PROTO: u8 = 253;
/// Framing-only overlay addresses (match the `10.9.0.0/24` convention
/// printed by `runner join`; never routed).
pub const FRAME_SRC: [u8; 4] = [10, 9, 0, 1];
pub const FRAME_DST: [u8; 4] = [10, 9, 0, 2];
/// Minimal IPv4 header length (no options).
pub const FRAME_HEADER_LEN: usize = 20;
/// Maximum JSON payload per datagram (single-datagram messages only;
/// larger offers fail closed rather than fragmenting).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

/// Join request (plaintext UDP): proves invitation, publishes identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinAnnounce {
    pub proto: String,
    pub node_id: String,
    pub pubkey_b64: String,
    pub token: String,
    pub listen_port: u16,
    pub max_cores: u32,
    pub max_ram_mb: u64,
}

/// One job offered for remote execution (encrypted).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobOffer {
    pub proto: String,
    pub provider: String,
    pub job_id: u64,
    pub run_id: u64,
    pub name: String,
    pub labels: Vec<String>,
    pub jit_blob: String,
    pub worker_version: String,
    pub timeout_secs: u64,
}

/// Immediate accept/reject for an offer (encrypted).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobAccept {
    pub proto: String,
    pub job_id: u64,
    pub accepted: bool,
    pub reason: String,
}

/// Final outcome (encrypted; the worker reports logs to GitHub itself,
/// so only completion status crosses the mesh).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobResult {
    pub proto: String,
    pub provider: String,
    pub job_id: u64,
    pub exit_code: Option<i32>,
    pub killed: bool,
}

/// Any wire message; the `kind` tag makes parsing unambiguous.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum PeerMessage {
    JoinAnnounce(JoinAnnounce),
    JobOffer(JobOffer),
    JobAccept(JobAccept),
    JobResult(JobResult),
}

/// Prepend the framing-only IPv4 header (version 4, IHL 5, exact total
/// length, protocol 253). boringtun checks only nibble + minimum size +
/// length bound — no checksum — so this passes validation untouched.
pub(crate) fn wrap_ipv4(payload: &[u8]) -> Vec<u8> {
    let total = FRAME_HEADER_LEN + payload.len();
    let mut frame = vec![0u8; total];
    frame[0] = 0x45;
    frame[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    frame[8] = 64; // TTL (never routed; nonzero for well-formedness)
    frame[9] = FRAME_PROTO;
    frame[12..16].copy_from_slice(&FRAME_SRC);
    frame[16..20].copy_from_slice(&FRAME_DST);
    frame[FRAME_HEADER_LEN..].copy_from_slice(payload);
    frame
}

/// Strip and strictly validate the framing header.
pub(crate) fn unwrap_ipv4(frame: &[u8]) -> Result<Vec<u8>, String> {
    if frame.len() < FRAME_HEADER_LEN {
        return Err(format!("frame too short: {} bytes", frame.len()));
    }
    if frame[0] != 0x45 {
        return Err("frame is not a v4/IHL5 header".to_string());
    }
    if frame[9] != FRAME_PROTO {
        return Err(format!("unexpected frame protocol {}", frame[9]));
    }
    let total = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    if total != frame.len() {
        return Err(format!(
            "frame length mismatch: header says {total}, got {}",
            frame.len()
        ));
    }
    Ok(frame[FRAME_HEADER_LEN..].to_vec())
}

/// Serialize + frame one message, enforcing the size cap.
pub fn encode_message(msg: &PeerMessage) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(msg).map_err(|e| format!("encode peer message: {e}"))?;
    if json.len() > MAX_MESSAGE_BYTES {
        return Err(format!(
            "peer message too large: {} bytes (max {MAX_MESSAGE_BYTES})",
            json.len()
        ));
    }
    Ok(wrap_ipv4(&json))
}

/// Serialize one message as plaintext JSON (join-announce path only:
/// no session exists yet, so framing is skipped and the datagram is
/// recognized by its leading `{`).
pub fn encode_plaintext(msg: &PeerMessage) -> Result<Vec<u8>, String> {
    match msg {
        PeerMessage::JoinAnnounce(_) => {}
        other => {
            return Err(format!(
                "only JoinAnnounce may travel plaintext, got {other:?}"
            ))
        }
    }
    let json = serde_json::to_vec(msg).map_err(|e| format!("encode peer message: {e}"))?;
    if json.len() > MAX_MESSAGE_BYTES {
        return Err(format!(
            "peer message too large: {} bytes (max {MAX_MESSAGE_BYTES})",
            json.len()
        ));
    }
    Ok(json)
}

/// Parse one framed message.
pub fn decode_message(frame: &[u8]) -> Result<PeerMessage, String> {
    let payload = unwrap_ipv4(frame)?;
    serde_json::from_slice(&payload).map_err(|e| format!("decode peer message: {e}"))
}

/// Parse one plaintext datagram (must be a join-announce).
pub fn decode_plaintext(datagram: &[u8]) -> Result<JoinAnnounce, String> {
    if datagram.first() != Some(&b'{') {
        return Err("plaintext datagram is not JSON".to_string());
    }
    match serde_json::from_slice::<PeerMessage>(datagram)
        .map_err(|e| format!("decode peer message: {e}"))?
    {
        PeerMessage::JoinAnnounce(announce) => Ok(announce),
        other => Err(format!(
            "only JoinAnnounce may travel plaintext, got {other:?}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_offer() -> PeerMessage {
        PeerMessage::JobOffer(JobOffer {
            proto: PROTO_TAG.to_string(),
            provider: "github".to_string(),
            job_id: 7,
            run_id: 100,
            name: "wan-job".to_string(),
            labels: vec!["self-hosted".to_string()],
            jit_blob: "BLOB".to_string(),
            worker_version: "2.338.2".to_string(),
            timeout_secs: 60,
        })
    }

    #[test]
    fn framing_round_trips_and_validates_strictly() {
        let frame = wrap_ipv4(b"hello");
        assert_eq!(frame[0], 0x45);
        assert_eq!(frame[9], FRAME_PROTO);
        assert_eq!(unwrap_ipv4(&frame).unwrap(), b"hello");

        assert!(unwrap_ipv4(&frame[..10]).is_err());
        let mut bad_nibble = frame.clone();
        bad_nibble[0] = 0x60;
        assert!(unwrap_ipv4(&bad_nibble).is_err());
        let mut bad_proto = frame.clone();
        bad_proto[9] = 6;
        assert!(unwrap_ipv4(&bad_proto).is_err());
        let mut bad_len = frame.clone();
        bad_len[2..4].copy_from_slice(&9999u16.to_be_bytes());
        assert!(unwrap_ipv4(&bad_len).is_err());
    }

    #[test]
    fn messages_round_trip_with_kind_tags() {
        let msg = sample_offer();
        let frame = encode_message(&msg).unwrap();
        assert_eq!(decode_message(&frame).unwrap(), msg);

        let announce = PeerMessage::JoinAnnounce(JoinAnnounce {
            proto: PROTO_TAG.to_string(),
            node_id: "bob".to_string(),
            pubkey_b64: "KEY".to_string(),
            token: "runner1.e30.sig".to_string(),
            listen_port: 40001,
            max_cores: 4,
            max_ram_mb: 8192,
        });
        let plain = encode_plaintext(&announce).unwrap();
        assert_eq!(plain[0], b'{');
        assert_eq!(decode_plaintext(&plain).unwrap().node_id, "bob");

        // Unknown fields and wrong plaintext kinds fail loudly.
        assert!(decode_plaintext(b"{\"kind\":\"JobOffer\"}").is_err());
        assert!(encode_plaintext(&msg).is_err());
        assert!(decode_plaintext(b"not json").is_err());
    }

    #[test]
    fn oversized_messages_fail_closed() {
        let mut big = sample_offer();
        let PeerMessage::JobOffer(ref mut offer) = big else {
            panic!("test setup");
        };
        offer.jit_blob = "x".repeat(MAX_MESSAGE_BYTES + 1);
        let err = encode_message(&big).unwrap_err();
        assert!(err.contains("too large"), "{err}");
    }
}
