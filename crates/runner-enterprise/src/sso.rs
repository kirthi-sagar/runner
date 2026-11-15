//! SSO provider hooks: [`SsoProvider`] abstracts identity providers so
//! OIDC (shipped, via [`crate::control_plane::auth::OidcManager`]) and
//! future SAML integrations plug into the same login flow.

use crate::control_plane::auth::{Claims, OidcConfig, OidcManager};

/// Identity-provider integration for the control-plane login flow.
pub trait SsoProvider: Send + Sync {
    /// Machine-readable provider name (`oidc`, `saml`, ...).
    fn name(&self) -> &'static str;
    /// Build the IdP authorization redirect for a login attempt.
    fn authorization_url(&self, state: &str, nonce: &str) -> Result<String, String>;
}

/// OIDC SSO backed by the control-plane [`OidcManager`]
/// (Okta, Keycloak, Google Workspace, ...).
pub struct OidcProvider {
    manager: OidcManager,
}

impl OidcProvider {
    pub fn new(config: OidcConfig) -> Self {
        Self {
            manager: OidcManager::new(config),
        }
    }

    /// Parse (unverified) claims from an ID token.
    pub fn decode_claims_unverified(token: &str) -> Result<Claims, String> {
        OidcManager::decode_claims_unverified(token)
    }
}

impl SsoProvider for OidcProvider {
    fn name(&self) -> &'static str {
        "oidc"
    }

    fn authorization_url(&self, state: &str, nonce: &str) -> Result<String, String> {
        let url = self.manager.authorization_url(state, nonce);
        if url.trim().is_empty() {
            return Err(
                "OIDC authorization URL is empty (issuer/client misconfigured?)".to_string(),
            );
        }
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> OidcProvider {
        OidcProvider::new(OidcConfig {
            issuer_url: "https://idp.example.com".to_string(),
            client_id: "runner".to_string(),
            client_secret: String::new(),
            redirect_uri: "http://localhost:8080/auth/callback".to_string(),
        })
    }

    #[test]
    fn oidc_hook_builds_stateful_login_url() {
        let provider = provider();
        assert_eq!(provider.name(), "oidc");
        let url = provider.authorization_url("state-1", "nonce-1").unwrap();
        assert!(url.contains("state-1"), "missing state: {url}");
        assert!(url.contains("nonce-1"), "missing nonce: {url}");
        assert!(
            url.starts_with("https://idp.example.com"),
            "wrong issuer: {url}"
        );
    }
}
