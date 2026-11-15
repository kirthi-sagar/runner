//! Enterprise OIDC single sign-on (Okta, Keycloak, Google Workspace).
//!
//! Authorization-code flow with real RS256 ID-token verification against
//! the issuer's JWKS document, plus short-lived in-memory bearer sessions
//! for the control plane API.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Identity provider configuration (Super Admin provisioned).
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Issuer base URL, e.g. `https://tenant.okta.com`.
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    /// Registered callback, e.g. `https://runner.internal/auth/callback`.
    pub redirect_uri: String,
}

/// Verified ID-token claims subset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    pub exp: u64,
}

/// Minimal percent-encoding for query parameters (RFC 3986 unreserved set).
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    kty: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
    #[serde(default)]
    access_token: String,
}

/// OIDC flow driver: authorize URL, code exchange, JWT verification.
#[derive(Debug, Clone)]
pub struct OidcManager {
    config: OidcConfig,
    http: reqwest::Client,
}

impl OidcManager {
    pub fn new(config: OidcConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    /// Authorization redirect target with caller-supplied state + nonce.
    pub fn authorization_url(&self, state: &str, nonce: &str) -> String {
        format!(
            "{}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}\
             &scope=openid%20email%20profile&state={}&nonce={}",
            self.config.issuer_url.trim_end_matches('/'),
            percent_encode(&self.config.client_id),
            percent_encode(&self.config.redirect_uri),
            percent_encode(state),
            percent_encode(nonce),
        )
    }

    /// Exchange an authorization code for ID/access tokens.
    pub async fn exchange_code(&self, code: &str) -> Result<(String, String), String> {
        let res = self
            .http
            .post(format!(
                "{}/oauth/token",
                self.config.issuer_url.trim_end_matches('/')
            ))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.config.redirect_uri.as_str()),
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("oidc token exchange failed: {e}"))?;
        if !res.status().is_success() {
            return Err(format!("oidc token exchange: HTTP {}", res.status()));
        }
        let body: TokenResponse = res
            .json()
            .await
            .map_err(|e| format!("oidc token body: {e}"))?;
        Ok((body.id_token, body.access_token))
    }

    /// Decode JWT claims without signature checks (structure/expiry
    /// pre-validation; pure apart from the clock).
    pub fn decode_claims_unverified(token: &str) -> Result<Claims, String> {
        use base64::Engine;
        let payload_b64 = token.split('.').nth(1).ok_or("malformed jwt")?;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| "malformed jwt payload")?;
        let claims: Claims =
            serde_json::from_slice(&payload).map_err(|_| "malformed jwt claims")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if claims.exp <= now {
            return Err("jwt expired".to_string());
        }
        Ok(claims)
    }

    /// Verify an RS256 ID token against the issuer JWKS (signature +
    /// expiry + audience) and return its claims.
    pub async fn verify_id_token(&self, token: &str) -> Result<Claims, String> {
        let header = jsonwebtoken::decode_header(token).map_err(|e| format!("jwt header: {e}"))?;
        let kid = header.kid.ok_or("jwt missing kid")?;
        let issuer = self.config.issuer_url.trim_end_matches('/');
        let discovery: DiscoveryDocument = self
            .http
            .get(format!("{issuer}/.well-known/openid-configuration"))
            .send()
            .await
            .map_err(|e| format!("oidc discovery failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("oidc discovery body: {e}"))?;
        let jwks: JwksDocument = self
            .http
            .get(&discovery.jwks_uri)
            .send()
            .await
            .map_err(|e| format!("jwks fetch failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("jwks body: {e}"))?;
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(&kid) && k.kty.as_deref() == Some("RSA"))
            .ok_or("no matching RSA key in jwks")?;
        let (n, e) = match (&jwk.n, &jwk.e) {
            (Some(n), Some(e)) => (n, e),
            _ => return Err("jwks RSA key missing n/e".to_string()),
        };
        let key = jsonwebtoken::DecodingKey::from_rsa_components(n, e)
            .map_err(|e| format!("bad jwks key: {e}"))?;
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[self.config.client_id.as_str()]);
        validation.set_issuer(&[issuer]);
        let data = jsonwebtoken::decode::<Claims>(token, &key, &validation)
            .map_err(|e| format!("jwt verification failed: {e}"))?;
        Ok(data.claims)
    }
}

/// Generate random hex (session tokens, OAuth state/nonce).
pub fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Short-lived control plane bearer session.
#[derive(Debug, Clone)]
pub struct SessionToken {
    pub token: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub expires_at: Instant,
}

/// In-memory session store with TTL eviction.
#[derive(Debug)]
pub struct SessionStore {
    ttl: Duration,
    sessions: tokio::sync::Mutex<HashMap<String, SessionToken>>,
    /// Recently issued OAuth states awaiting callback (CSRF check).
    pending_states: tokio::sync::Mutex<HashSet<String>>,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            sessions: tokio::sync::Mutex::new(HashMap::new()),
            pending_states: tokio::sync::Mutex::new(HashSet::new()),
        }
    }

    pub fn issue_state(&self) -> String {
        random_hex(16)
    }

    pub async fn remember_state(&self, state: String) {
        self.pending_states.lock().await.insert(state);
    }

    /// Consume a state once; false = unknown or replayed.
    pub async fn take_state(&self, state: &str) -> bool {
        self.pending_states.lock().await.remove(state)
    }

    pub async fn create(&self, email: Option<String>, groups: Vec<String>) -> SessionToken {
        let session = SessionToken {
            token: random_hex(32),
            email,
            groups,
            expires_at: Instant::now() + self.ttl,
        };
        self.sessions
            .lock()
            .await
            .insert(session.token.clone(), session.clone());
        session
    }

    pub async fn validate(&self, token: &str) -> Option<SessionToken> {
        let mut guard = self.sessions.lock().await;
        match guard.get(token) {
            Some(session) if session.expires_at > Instant::now() => Some(session.clone()),
            Some(_) => {
                guard.remove(token);
                None
            }
            None => None,
        }
    }

    pub async fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let mut guard = self.sessions.lock().await;
        let before = guard.len();
        guard.retain(|_, session| session.expires_at > now);
        before - guard.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> OidcManager {
        OidcManager::new(OidcConfig {
            issuer_url: "https://idp.example.com".to_string(),
            client_id: "cid".to_string(),
            client_secret: "sec".to_string(),
            redirect_uri: "https://runner.internal/auth/callback".to_string(),
        })
    }

    #[test]
    fn auth_url_carries_state_and_nonce() {
        let url = manager().authorization_url("state-1", "nonce-2");
        assert!(url.starts_with("https://idp.example.com/oauth/authorize?"));
        assert!(url.contains("state=state-1"));
        assert!(url.contains("nonce=nonce-2"));
        assert!(url.contains("client_id=cid"));
        assert!(url.contains("scope=openid%20email%20profile"));
    }

    fn unsigned_jwt(exp: u64) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            b64.encode(r#"{"alg":"none"}"#),
            b64.encode(format!(
                r#"{{"sub":"u1","email":"a@b.c","groups":["ops"],"exp":{exp}}}"#
            )),
            b64.encode("sig")
        )
    }

    #[test]
    fn unverified_decode_checks_expiry() {
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let claims = OidcManager::decode_claims_unverified(&unsigned_jwt(future)).unwrap();
        assert_eq!(claims.sub, "u1");
        assert_eq!(claims.groups, vec!["ops".to_string()]);
        assert!(OidcManager::decode_claims_unverified(&unsigned_jwt(1)).is_err());
        assert!(OidcManager::decode_claims_unverified("bogus").is_err());
    }

    #[tokio::test]
    async fn sessions_validate_and_expire() {
        let store = SessionStore::new(Duration::from_millis(50));
        let session = store.create(Some("a@b.c".to_string()), vec![]).await;
        assert!(store.validate(&session.token).await.is_some());
        assert!(store.validate("bogus").await.is_none());
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(store.validate(&session.token).await.is_none());
    }

    #[tokio::test]
    async fn oauth_states_are_single_use() {
        let store = SessionStore::new(Duration::from_secs(60));
        store.remember_state("s1".to_string()).await;
        assert!(store.take_state("s1").await);
        assert!(!store.take_state("s1").await);
    }
}
