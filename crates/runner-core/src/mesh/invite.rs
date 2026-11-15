//! Cryptographic invitation tokens and donor caps.
//!
//! Pre-auth-key pattern: `runner mesh invite` mints a single token carrying
//! role + donor caps + TTL, HMAC-signed by the coordinator secret:
//!
//! ```text
//! runner1.<base64url(payload)>.<base64url(hmac-sha256)>
//! ```
//!
//! Expiry bounds *joining*, not access — donor caps and node draining are
//! enforced separately at runtime. `runner join` validates structure and
//! expiry offline; the coordinator re-verifies the signature when the
//! joiner presents the token over the mesh transport.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Token envelope version prefix.
pub const TOKEN_PREFIX: &str = "runner1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InviteRole {
    Donor,
    Worker,
}

impl std::str::FromStr for InviteRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "donor" => Ok(Self::Donor),
            "worker" => Ok(Self::Worker),
            _ => Err(format!("role must be \"donor\" or \"worker\", got {s:?}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCaps {
    pub max_cores: u32,
    pub max_ram_mb: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteToken {
    pub role: InviteRole,
    pub caps: InviteCaps,
    /// Time-to-live in seconds (e.g. 7d = 604800).
    pub ttl_secs: u64,
    pub name: String,
}

impl InviteToken {
    pub fn validate(&self) -> Result<(), String> {
        if self.caps.max_cores == 0 {
            return Err("max-cores must be >= 1".to_string());
        }
        if self.caps.max_ram_mb == 0 {
            return Err("max-ram must be >= 1MB".to_string());
        }
        if self.ttl_secs == 0 {
            return Err("ttl must be > 0".to_string());
        }
        Ok(())
    }
}

/// Signed payload embedded in the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitePayload {
    pub role: InviteRole,
    pub max_cores: u32,
    pub max_ram_mb: u64,
    pub name: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Mint and verify invitation tokens with the coordinator secret.
pub struct InviteAuthority {
    secret: Vec<u8>,
}

impl InviteAuthority {
    pub fn new(secret: Vec<u8>) -> Result<Self, String> {
        if secret.len() < 16 {
            return Err("mesh secret must be at least 16 bytes".to_string());
        }
        Ok(Self { secret })
    }

    /// Mint a signed token for the given invite.
    pub fn mint(&self, token: &InviteToken) -> Result<String, String> {
        token.validate()?;
        let issued_at = now_secs();
        let payload = InvitePayload {
            role: token.role.clone(),
            max_cores: token.caps.max_cores,
            max_ram_mb: token.caps.max_ram_mb,
            name: token.name.clone(),
            issued_at,
            expires_at: issued_at.saturating_add(token.ttl_secs),
            nonce: nonce_hex(),
        };
        self.encode(&payload)
    }

    /// Verify signature + expiry, returning the payload.
    pub fn verify(&self, token: &str) -> Result<InvitePayload, String> {
        let payload = self.decode(token)?;
        if now_secs() >= payload.expires_at {
            return Err("invitation token has expired".to_string());
        }
        Ok(payload)
    }

    /// Decode without the secret (structure only; used by `join` before
    /// presenting the token to the coordinator for verification).
    pub fn decode_unverified(token: &str) -> Result<InvitePayload, String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 || parts[0] != TOKEN_PREFIX {
            return Err("malformed invitation token".to_string());
        }
        let json = b64()
            .decode(parts[1])
            .map_err(|_| "malformed invitation payload".to_string())?;
        serde_json::from_slice(&json).map_err(|_| "malformed invitation payload".to_string())
    }

    fn encode(&self, payload: &InvitePayload) -> Result<String, String> {
        use hmac::{Hmac, Mac};
        let json = serde_json::to_vec(payload).map_err(|e| format!("encode invite: {e}"))?;
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&self.secret)
            .map_err(|_| "bad mesh secret".to_string())?;
        mac.update(&json);
        let sig = mac.finalize().into_bytes();
        Ok(format!(
            "{}.{}.{}",
            TOKEN_PREFIX,
            b64().encode(json),
            b64().encode(sig)
        ))
    }

    fn decode(&self, token: &str) -> Result<InvitePayload, String> {
        use hmac::{Hmac, Mac};
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 || parts[0] != TOKEN_PREFIX {
            return Err("malformed invitation token".to_string());
        }
        let json = b64()
            .decode(parts[1])
            .map_err(|_| "malformed invitation payload".to_string())?;
        let sig = b64()
            .decode(parts[2])
            .map_err(|_| "malformed invitation signature".to_string())?;
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&self.secret)
            .map_err(|_| "bad mesh secret".to_string())?;
        mac.update(&json);
        mac.verify_slice(&sig)
            .map_err(|_| "invitation signature mismatch".to_string())?;
        serde_json::from_slice(&json).map_err(|_| "malformed invitation payload".to_string())
    }
}

fn nonce_hex() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate a fresh 32-byte mesh secret, hex-encoded.
pub fn generate_secret_hex() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex secret into bytes.
pub fn secret_from_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("malformed mesh secret".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "malformed mesh secret".to_string())
        })
        .collect()
}

/// Parse a RAM cap like `8G`, `512M` into MiB.
pub fn parse_size_mb(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let (num, mult) = match text.chars().last() {
        Some('G' | 'g') => (&text[..text.len() - 1], 1024u64),
        Some('M' | 'm') => (&text[..text.len() - 1], 1u64),
        Some(c) if c.is_ascii_digit() => (text, 1u64),
        _ => return Err(format!("bad size {text:?}: use like 8G or 512M")),
    };
    let num: u64 = num.parse().map_err(|_| format!("bad size {text:?}"))?;
    num.checked_mul(mult)
        .ok_or_else(|| format!("bad size {text:?}"))
}

/// Parse a TTL like `7d`, `1h`, `30m`, `60s` into seconds.
pub fn parse_ttl_secs(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let (num, mult) = match text.chars().last() {
        Some('d') => (&text[..text.len() - 1], 86_400u64),
        Some('h') => (&text[..text.len() - 1], 3_600u64),
        Some('m') => (&text[..text.len() - 1], 60u64),
        Some('s') => (&text[..text.len() - 1], 1u64),
        Some(c) if c.is_ascii_digit() => (text, 1u64),
        _ => return Err(format!("bad ttl {text:?}: use like 7d, 1h, 30m")),
    };
    let num: u64 = num.parse().map_err(|_| format!("bad ttl {text:?}"))?;
    num.checked_mul(mult)
        .ok_or_else(|| format!("bad ttl {text:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> InviteAuthority {
        InviteAuthority::new(vec![7u8; 32]).unwrap()
    }

    fn sample() -> InviteToken {
        InviteToken {
            role: InviteRole::Donor,
            caps: InviteCaps {
                max_cores: 4,
                max_ram_mb: 8192,
            },
            ttl_secs: 604_800,
            name: "alice".to_string(),
        }
    }

    #[test]
    fn mint_verify_roundtrip() {
        let token = authority().mint(&sample()).unwrap();
        assert!(token.starts_with("runner1."));
        let payload = authority().verify(&token).unwrap();
        assert_eq!(payload.max_cores, 4);
        assert_eq!(payload.max_ram_mb, 8192);
        assert_eq!(payload.role, InviteRole::Donor);
    }

    #[test]
    fn tampered_payload_fails_signature() {
        let token = authority().mint(&sample()).unwrap();
        let mut tampered = token.clone();
        // Flip a char inside the payload segment.
        let dot = tampered.find('.').unwrap() + 1;
        let replacement = if tampered.as_bytes()[dot] == b'A' {
            b'B'
        } else {
            b'A'
        };
        tampered.replace_range(dot..dot + 1, &(replacement as char).to_string());
        assert!(authority().verify(&tampered).is_err());
    }

    #[test]
    fn wrong_secret_fails() {
        let token = authority().mint(&sample()).unwrap();
        let other = InviteAuthority::new(vec![9u8; 32]).unwrap();
        assert!(other.verify(&token).is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let mut token = sample();
        token.ttl_secs = 1;
        let minted = authority().mint(&token).unwrap();
        // Decode, backdate expiry, re-encode with same authority.
        let mut payload = authority().decode(&minted).unwrap();
        payload.expires_at = 1;
        let reencoded = authority().encode(&payload).unwrap();
        assert!(authority().verify(&reencoded).is_err());
    }

    #[test]
    fn rejects_empty_caps() {
        let mut token = sample();
        token.caps.max_cores = 0;
        assert!(token.validate().is_err());
        assert!(authority().mint(&token).is_err());
    }

    #[test]
    fn parses_sizes_and_ttls() {
        assert_eq!(parse_size_mb("8G").unwrap(), 8192);
        assert_eq!(parse_size_mb("512M").unwrap(), 512);
        assert_eq!(parse_ttl_secs("7d").unwrap(), 604_800);
        assert_eq!(parse_ttl_secs("1h").unwrap(), 3600);
        assert!(parse_size_mb("8X").is_err());
        assert!(parse_ttl_secs("soon").is_err());
    }
}
