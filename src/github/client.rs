//! GitHub API client (PAT with `administration:write` for JIT issuance).

/// GitHub REST API base.
pub const API_BASE: &str = "https://api.github.com";

/// Token scope verdict for JIT issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeVerdict {
    /// Classic PAT advertises a sufficient scope (`admin:org` or `repo`).
    ClassicSufficient,
    /// Fine-grained PAT or GitHub App token: scopes are not advertised in
    /// `x-oauth-scopes`, so sufficiency is proven only by the API call
    /// itself (403/404 on failure).
    UnverifiableOffline,
    /// Classic PAT with an insufficient scope set.
    Insufficient { scopes: String },
}

/// Check a classic `x-oauth-scopes` header value for JIT rights (pure).
/// An empty header means fine-grained/App token (unverifiable offline).
pub fn classic_scopes_verdict(header: &str) -> ScopeVerdict {
    let header = header.trim();
    if header.is_empty() {
        return ScopeVerdict::UnverifiableOffline;
    }
    let scopes: Vec<&str> = header.split(',').map(str::trim).collect();
    if scopes.iter().any(|s| *s == "admin:org" || *s == "repo") {
        ScopeVerdict::ClassicSufficient
    } else {
        ScopeVerdict::Insufficient { scopes: header.to_string() }
    }
}

/// Minimal client holding auth + base URL.
#[derive(Debug, Clone)]
pub struct GithubClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl GithubClient {
    /// Build a client. The token must have `administration:write`
    /// (classic PAT with `repo` scope / `admin:org`, or fine-grained PAT
    /// with Administration R&W) to call `generate-jitconfig`.
    pub fn new(token: impl Into<String>) -> Result<Self, String> {
        let token = token.into();
        if token.trim().is_empty() {
            return Err("github token must not be empty".to_string());
        }
        Ok(Self {
            base_url: API_BASE.to_string(),
            token,
            http: reqwest::Client::new(),
        })
    }

    /// Point the client at a custom API base (tests, GHES).
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub fn auth_header_value(&self) -> String {
        format!("Bearer {}", self.token)
    }

    pub(crate) fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.bearer_auth(&self.token)
    }

    pub fn org_jit_url(&self, org: &str) -> String {
        format!(
            "{}{}",
            self.base_url,
            crate::github::jit::org_jit_path(org)
        )
    }

    pub fn repo_jit_url(&self, owner: &str, repo: &str) -> String {
        format!(
            "{}{}",
            self.base_url,
            crate::github::jit::repo_jit_path(owner, repo)
        )
    }

    /// Validate token scope via the advertised `x-oauth-scopes` header on a
    /// cheap authenticated call. Fine-grained tokens carry no header, so
    /// they report [`ScopeVerdict::UnverifiableOffline`] and are proven by
    /// the JIT call itself.
    pub async fn validate_token_scope(&self) -> Result<ScopeVerdict, String> {
        let res = self
            .authed(self.http.get(format!("{}/rate_limit", self.base_url)))
            .send()
            .await
            .map_err(|e| format!("scope check failed: {e}"))?;
        if res.status() == reqwest::StatusCode::UNAUTHORIZED
            || res.status() == reqwest::StatusCode::FORBIDDEN
        {
            return Ok(ScopeVerdict::Insufficient { scopes: "(rejected)".to_string() });
        }
        let header = res
            .headers()
            .get("x-oauth-scopes")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        Ok(classic_scopes_verdict(header))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_token() {
        assert!(GithubClient::new("").is_err());
        assert!(GithubClient::new("ghp_x").is_ok());
    }

    #[test]
    fn scope_header_verdicts() {
        assert_eq!(classic_scopes_verdict("admin:org, repo"), ScopeVerdict::ClassicSufficient);
        assert_eq!(classic_scopes_verdict("repo"), ScopeVerdict::ClassicSufficient);
        assert_eq!(classic_scopes_verdict(""), ScopeVerdict::UnverifiableOffline);
        assert!(matches!(
            classic_scopes_verdict("read:org"),
            ScopeVerdict::Insufficient { .. }
        ));
    }
}
