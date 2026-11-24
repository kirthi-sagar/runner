//! RFC 8628 Device Authorization Grant client: browserless login
//! for CLI agents. The forge issues a one-time user code; the user
//! approves it in a browser (or pastes it on a headless host); this
//! client polls until the grant lands, backs off, expires, or is
//! denied. Secrets (device codes, tokens) never appear in `Debug`
//! output. Endpoints and sleeps inject so the whole matrix runs
//! hermetically against a loopback mock.

use std::time::{Duration, Instant};

const DEVICE_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// RFC 8628 backoff step: `slow_down` adds five seconds.
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);
/// Poll floor: forges rate-limit faster loops (GitHub: 5s).
const MIN_POLL_INTERVAL: Duration = Duration::from_secs(5);

pub const GITHUB_DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
pub const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
pub const GITHUB_USER_URL: &str = "https://api.github.com/user";
/// Requested GitHub OAuth scopes (space-separated per RFC 6749).
pub const GITHUB_SCOPES: &str = "repo";
/// Default GitLab instance base URL (self-hosted overrides via flag).
pub const GITLAB_DEFAULT_BASE_URL: &str = "https://gitlab.com";
/// Requested GitLab OAuth scopes (runner registration needs API).
pub const GITLAB_SCOPES: &str = "api";
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Join an instance base URL with an absolute API path (query
/// strings and fragments stripped so pasted browser-bar URLs never
/// malform endpoints; trailing slashes never double up).
pub fn join_base_url(base: &str, path: &str) -> String {
    format!("{}{}", strip_url_suffix(base).trim_end_matches('/'), path)
}

/// Cut a URL at the first query or fragment marker (both live after
/// any path, so authority and path survive intact).
fn strip_url_suffix(url: &str) -> &str {
    let cut = url.find(&['?', '#'][..]).unwrap_or(url.len());
    &url[..cut]
}

/// True for loopback authorities (exact host or host-plus-port;
/// suffix lookalikes like `localhost.evil.com` never match).
fn is_loopback_authority(authority: &str) -> bool {
    let lower = authority.to_ascii_lowercase();
    lower == "localhost"
        || lower.starts_with("localhost:")
        || lower == "127.0.0.1"
        || lower.starts_with("127.0.0.1:")
        || lower == "[::1]"
        || lower.starts_with("[::1]:")
}

/// Forge host key for credential storage: URL authority (host plus
/// explicit port), lowercased. Transport security: `https` everywhere,
/// `http` strictly for loopback (hermetic mock testing) — anything
/// else fails closed before any network or disk write.
pub fn forge_host_from_url(url: &str) -> Result<String, String> {
    let clean = strip_url_suffix(url.trim());
    if let Some(rest) = clean.strip_prefix("https://") {
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() {
            return Err(format!("forge URL has no host: '{url}'"));
        }
        return Ok(authority.to_ascii_lowercase());
    }
    if let Some(rest) = clean.strip_prefix("http://") {
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() {
            return Err(format!("forge URL has no host: '{url}'"));
        }
        if !is_loopback_authority(authority) {
            return Err(format!(
                "forge URL must use https (http is loopback-only): '{url}'"
            ));
        }
        return Ok(authority.to_ascii_lowercase());
    }
    Err(format!("forge URL must use http(s): '{url}'"))
}

/// Device-flow HTTP endpoints (GitHub production or a test mock).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEndpoints {
    pub device_code_url: String,
    pub token_url: String,
    pub user_url: String,
}

impl DeviceEndpoints {
    pub fn github() -> Self {
        Self {
            device_code_url: GITHUB_DEVICE_CODE_URL.to_string(),
            token_url: GITHUB_TOKEN_URL.to_string(),
            user_url: GITHUB_USER_URL.to_string(),
        }
    }
}

/// Issued device authorization: show `user_code` plus
/// `verification_uri` to the operator, then poll with
/// `device_code`. The code mints access, so `Debug` redacts it.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in_secs: u64,
    pub interval_secs: u64,
}

impl std::fmt::Debug for DeviceCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCode")
            .field("device_code", &"<redacted>")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("expires_in_secs", &self.expires_in_secs)
            .field("interval_secs", &self.interval_secs)
            .finish()
    }
}

/// One token-poll verdict. The granted token is redacted from
/// `Debug` like every other bearer in this crate.
#[derive(Clone, PartialEq, Eq)]
pub enum TokenPoll {
    Granted {
        access_token: String,
        scope: String,
    },
    /// Keep polling after the interval.
    Pending,
    /// Back off (interval grows by five seconds), then retry.
    SlowDown,
    /// The device code lapsed; restart the flow for a fresh code.
    Expired,
    /// The user rejected the authorization.
    Denied,
}

impl std::fmt::Debug for TokenPoll {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Granted { scope, .. } => f
                .debug_struct("Granted")
                .field("access_token", &"<redacted>")
                .field("scope", scope)
                .finish(),
            Self::Pending => write!(f, "Pending"),
            Self::SlowDown => write!(f, "SlowDown"),
            Self::Expired => write!(f, "Expired"),
            Self::Denied => write!(f, "Denied"),
        }
    }
}

/// Parse a device-code response (`device_code`, `user_code`,
/// `verification_uri` required; expiry/interval default when the
/// forge omits them).
pub fn parse_device_code_response(body: &serde_json::Value) -> Result<DeviceCode, String> {
    if let Some(error) = body.get("error").and_then(|e| e.as_str()) {
        return Err(format!("device authorization failed: {error}"));
    }
    let text = |key: &str| {
        body.get(key)
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("device authorization response lacks '{key}'"))
    };
    Ok(DeviceCode {
        device_code: text("device_code")?,
        user_code: text("user_code")?,
        verification_uri: text("verification_uri")?,
        expires_in_secs: body
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(900),
        interval_secs: body.get("interval").and_then(|v| v.as_u64()).unwrap_or(5),
    })
}

/// Parse one token-poll response: a granted token, a transient
/// RFC 8628 state, a terminal denial/expiry, or a protocol error.
pub fn parse_token_response(body: &serde_json::Value) -> Result<TokenPoll, String> {
    if let Some(token) = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
    {
        return Ok(TokenPoll::Granted {
            access_token: token.to_string(),
            scope: body
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        });
    }
    match body.get("error").and_then(|v| v.as_str()).unwrap_or("") {
        "authorization_pending" => Ok(TokenPoll::Pending),
        "slow_down" => Ok(TokenPoll::SlowDown),
        "expired_token" => Ok(TokenPoll::Expired),
        "access_denied" => Ok(TokenPoll::Denied),
        "" => Err("token response carries neither a token nor an error".to_string()),
        other => Err(format!("token request failed: {other}")),
    }
}

/// Live polling state: current interval plus the grant deadline.
/// Pure (no I/O): the driver loop consults it per poll outcome.
#[derive(Debug, Clone)]
pub struct PollState {
    interval: Duration,
    deadline: Instant,
}

impl PollState {
    pub fn new(device: &DeviceCode, now: Instant) -> Self {
        Self {
            interval: Duration::from_secs(device.interval_secs).max(MIN_POLL_INTERVAL),
            deadline: now + Duration::from_secs(device.expires_in_secs),
        }
    }

    pub fn expired(&self, now: Instant) -> bool {
        now >= self.deadline
    }

    /// Wait before the next poll for one outcome (`None` when the
    /// outcome is terminal). `slow_down` lengthens the interval.
    pub fn wait_for(&mut self, outcome: &TokenPoll) -> Option<Duration> {
        match outcome {
            TokenPoll::Pending => Some(self.interval),
            TokenPoll::SlowDown => {
                self.interval += SLOW_DOWN_STEP;
                Some(self.interval)
            }
            TokenPoll::Granted { .. } | TokenPoll::Expired | TokenPoll::Denied => None,
        }
    }
}

/// Split a granted scope string (GitHub joins with commas, RFC 6749
/// with spaces; accept both, drop empties).
pub fn split_scopes(scope: &str) -> Vec<String> {
    scope
        .split([',', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Device-flow client: forge name, storage host key, endpoint set
/// plus the forge OAuth client id. Construct [`github`](Self::github)
/// or [`gitlab`](Self::gitlab) for production, [`custom`](Self::custom)
/// for hermetic tests.
#[derive(Debug, Clone)]
pub struct DeviceFlowClient {
    forge: String,
    host: String,
    client_id: String,
    endpoints: DeviceEndpoints,
    http: reqwest::Client,
}

impl DeviceFlowClient {
    pub fn github(client_id: String) -> Self {
        Self::custom("github", client_id, "github.com", DeviceEndpoints::github())
    }

    /// GitLab client for gitlab.com or a self-hosted base URL (slash
    /// normalized; non-http(s) bases fail closed).
    pub fn gitlab(client_id: String, base_url: &str) -> Result<Self, String> {
        Ok(Self::custom(
            "gitlab",
            client_id,
            forge_host_from_url(base_url)?,
            DeviceEndpoints {
                device_code_url: join_base_url(base_url, "/oauth/authorize_device"),
                token_url: join_base_url(base_url, "/oauth/token"),
                user_url: join_base_url(base_url, "/api/v4/user"),
            },
        ))
    }

    pub fn custom(
        forge: impl Into<String>,
        client_id: impl Into<String>,
        host: impl Into<String>,
        endpoints: DeviceEndpoints,
    ) -> Self {
        Self {
            forge: forge.into(),
            host: host.into(),
            client_id: client_id.into(),
            endpoints,
            http: reqwest::Client::builder()
                .user_agent("runner")
                .timeout(DEVICE_HTTP_TIMEOUT)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    /// Request a device code for `scopes` (RFC 8628 §3.1).
    pub async fn request_code(&self, scopes: &str) -> Result<DeviceCode, String> {
        let body: serde_json::Value = self
            .http
            .post(&self.endpoints.device_code_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[("client_id", self.client_id.as_str()), ("scope", scopes)])
            .send()
            .await
            .map_err(|e| format!("device code request failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("device code response is not JSON: {e}"))?;
        parse_device_code_response(&body)
    }

    /// One token poll for `device_code` (RFC 8628 §3.5).
    pub async fn poll_token(&self, device_code: &str) -> Result<TokenPoll, String> {
        let body: serde_json::Value = self
            .http
            .post(&self.endpoints.token_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("device_code", device_code),
                ("grant_type", DEVICE_GRANT_TYPE),
            ])
            .send()
            .await
            .map_err(|e| format!("token poll failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("token response is not JSON: {e}"))?;
        parse_token_response(&body)
    }

    /// Resolve the bearer to `(username, granted scopes)` for the
    /// stored credential, across forge shapes: the username reads
    /// `login` or `username`, whichever the identity endpoint
    /// returns; scopes prefer the OAuth scopes response header and
    /// fall back to the granted `scope` string (missing everywhere
    /// reads empty, never fatal).
    pub async fn fetch_identity(
        &self,
        access_token: &str,
        granted_scope: &str,
    ) -> Result<(String, Vec<String>), String> {
        let response = self
            .http
            .get(&self.endpoints.user_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {access_token}"),
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| format!("identity request failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "identity request failed: HTTP {}",
                response.status()
            ));
        }
        let header_scopes = response
            .headers()
            .get("x-oauth-scopes")
            .and_then(|v| v.to_str().ok())
            .map(split_scopes)
            .unwrap_or_default();
        let scopes = if header_scopes.is_empty() {
            split_scopes(granted_scope)
        } else {
            header_scopes
        };
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("identity response is not JSON: {e}"))?;
        let username = ["login", "username"]
            .iter()
            .filter_map(|key| body.get(key).and_then(|v| v.as_str()))
            .find(|v| !v.is_empty())
            .ok_or_else(|| "identity response lacks a username".to_string())?;
        Ok((username.to_string(), scopes))
    }

    /// Full login: request a code, hand it to `notify` (print + open
    /// browser), poll until grant/denial/expiry (sleeping through
    /// `sleep`, injected for hermetic tests), then resolve identity
    /// into a storable [`DeviceCredential`](super::store::DeviceCredential).
    pub async fn login<F, Fut>(
        &self,
        scopes: &str,
        notify: impl Fn(&DeviceCode),
        sleep: F,
    ) -> Result<super::store::DeviceCredential, String>
    where
        F: Fn(Duration) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let device = self.request_code(scopes).await?;
        notify(&device);
        let mut state = PollState::new(&device, Instant::now());
        loop {
            if state.expired(Instant::now()) {
                return Err(
                    "device code expired before approval; run login again for a fresh code"
                        .to_string(),
                );
            }
            match self.poll_token(&device.device_code).await? {
                TokenPoll::Granted {
                    access_token,
                    scope,
                } => {
                    let (username, scopes) = self.fetch_identity(&access_token, &scope).await?;
                    return Ok(super::store::DeviceCredential {
                        forge: self.forge.clone(),
                        host: self.host.clone(),
                        username,
                        scopes,
                        access_token,
                    });
                }
                TokenPoll::Expired => {
                    return Err(
                        "device code expired before approval; run login again for a fresh code"
                            .to_string(),
                    )
                }
                TokenPoll::Denied => return Err("authorization denied in the browser".to_string()),
                outcome @ (TokenPoll::Pending | TokenPoll::SlowDown) => {
                    if let Some(wait) = state.wait_for(&outcome) {
                        sleep(wait).await;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn device_code_parses_and_rejects() {
        let code = parse_device_code_response(&serde_json::json!({
            "device_code": "dev-1", "user_code": "ABCD-1234",
            "verification_uri": "https://example.test/activate",
            "expires_in": 900, "interval": 5,
        }))
        .unwrap();
        assert_eq!(code.user_code, "ABCD-1234");
        assert_eq!(code.interval_secs, 5);
        // Missing/invalid shapes fail closed.
        assert!(parse_device_code_response(&serde_json::json!({})).is_err());
        assert!(parse_device_code_response(&serde_json::json!({
            "device_code": "d", "user_code": " ", "verification_uri": "u",
        }))
        .is_err());
        assert!(parse_device_code_response(&serde_json::json!({
            "error": "unsupported_grant_type",
        }))
        .is_err());
        // Omitted timers take RFC-typical defaults.
        let code = parse_device_code_response(&serde_json::json!({
            "device_code": "d", "user_code": "u", "verification_uri": "v",
        }))
        .unwrap();
        assert_eq!((code.expires_in_secs, code.interval_secs), (900, 5));
    }

    #[test]
    fn token_response_matrix() {
        assert_eq!(
            parse_token_response(&serde_json::json!({
                "access_token": "gho_x", "scope": "repo",
            }))
            .unwrap(),
            TokenPoll::Granted {
                access_token: "gho_x".to_string(),
                scope: "repo".to_string(),
            }
        );
        for (error, expected) in [
            ("authorization_pending", TokenPoll::Pending),
            ("slow_down", TokenPoll::SlowDown),
            ("expired_token", TokenPoll::Expired),
            ("access_denied", TokenPoll::Denied),
        ] {
            assert_eq!(
                parse_token_response(&serde_json::json!({ "error": error })).unwrap(),
                expected,
                "{error}"
            );
        }
        assert!(parse_token_response(&serde_json::json!({})).is_err());
        assert!(parse_token_response(&serde_json::json!({ "error": "weird" })).is_err());
    }

    #[test]
    fn poll_state_matrix_backs_off_and_expires() {
        let device = DeviceCode {
            device_code: "d".to_string(),
            user_code: "u".to_string(),
            verification_uri: "v".to_string(),
            expires_in_secs: 100,
            interval_secs: 0,
        };
        let start = Instant::now();
        let mut state = PollState::new(&device, start);
        // Zero interval floors to the 5s minimum; slow_down adds 5s.
        assert_eq!(
            state.wait_for(&TokenPoll::Pending),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            state.wait_for(&TokenPoll::SlowDown),
            Some(Duration::from_secs(10))
        );
        // Terminal outcomes never wait.
        for terminal in [TokenPoll::Expired, TokenPoll::Denied] {
            assert_eq!(state.wait_for(&terminal), None);
        }
        assert!(!state.expired(start));
        assert!(state.expired(start + Duration::from_secs(100)));
    }

    #[test]
    fn scopes_split_commas_and_spaces() {
        assert_eq!(split_scopes("repo,read:user"), vec!["repo", "read:user"]);
        assert_eq!(split_scopes("repo workflow"), vec!["repo", "workflow"]);
        assert!(split_scopes("").is_empty());
    }

    #[test]
    fn secrets_stay_out_of_debug() {
        let code = DeviceCode {
            device_code: "SECRET-DEVICE".to_string(),
            user_code: "ABCD-1234".to_string(),
            verification_uri: "v".to_string(),
            expires_in_secs: 1,
            interval_secs: 1,
        };
        let rendered = format!("{code:?}");
        assert!(!rendered.contains("SECRET-DEVICE"), "{rendered}");
        assert!(rendered.contains("ABCD-1234"), "{rendered}");
        let poll = TokenPoll::Granted {
            access_token: "SECRET-TOKEN".to_string(),
            scope: String::new(),
        };
        assert!(!format!("{poll:?}").contains("SECRET-TOKEN"));
    }

    /// Loopback forge: scripted token-poll responses plus a fixed
    /// identity; request bodies drained per Content-Length.
    struct MockForge {
        base: String,
    }

    struct MockSpec {
        device_path: &'static str,
        token_path: &'static str,
        user_path: &'static str,
        user_body: serde_json::Value,
        scope_header: Option<&'static str>,
    }

    fn github_spec() -> MockSpec {
        MockSpec {
            device_path: "/login/device/code",
            token_path: "/login/oauth/access_token",
            user_path: "/user",
            user_body: serde_json::json!({ "login": "octocat" }),
            scope_header: Some("repo,read:user"),
        }
    }

    fn gitlab_spec() -> MockSpec {
        MockSpec {
            device_path: "/oauth/authorize_device",
            token_path: "/oauth/token",
            user_path: "/api/v4/user",
            user_body: serde_json::json!({ "username": "dev" }),
            scope_header: None,
        }
    }

    async fn respond(sock: &mut tokio::net::TcpStream, status: &str, extra: &str, body: &str) {
        use tokio::io::AsyncWriteExt;
        let raw = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n{extra}\r\n{body}",
            body.len()
        );
        let _ = sock.write_all(raw.as_bytes()).await;
    }

    fn content_length(head: &str) -> usize {
        head.lines()
            .filter_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim().eq_ignore_ascii_case("content-length"))
                    .then(|| value.trim().parse().unwrap_or(0))
            })
            .next()
            .unwrap_or(0)
    }

    async fn spawn_mock_forge(token_script: Vec<serde_json::Value>) -> MockForge {
        spawn_mock_forge_with(github_spec(), token_script).await
    }

    async fn spawn_mock_forge_with(
        spec: MockSpec,
        token_script: Vec<serde_json::Value>,
    ) -> MockForge {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");
        let hits = Arc::new(AtomicUsize::new(0));
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let device_route = format!("POST {}", spec.device_path);
            let token_route = format!("POST {}", spec.token_path);
            let user_route = format!("GET {}", spec.user_path);
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while head.len() < 8192 {
                    match sock.read(&mut byte).await {
                        Ok(1) => {
                            head.push(byte[0]);
                            if head.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let mut body = vec![0u8; content_length(&head)];
                let _ = sock.read_exact(&mut body).await;
                if head.contains(&device_route) {
                    respond(
                        &mut sock,
                        "200 OK",
                        "",
                        &serde_json::json!({
                            "device_code": "mock-device", "user_code": "MOCK-1",
                            "verification_uri": "http://127.0.0.1/activate",
                            "expires_in": 900, "interval": 0,
                        })
                        .to_string(),
                    )
                    .await;
                } else if head.contains(&token_route) {
                    let hit = hits.fetch_add(1, Ordering::SeqCst);
                    let body = token_script.get(hit).cloned().unwrap_or_else(|| {
                        token_script
                            .last()
                            .cloned()
                            .unwrap_or(serde_json::json!({}))
                    });
                    respond(&mut sock, "200 OK", "", &body.to_string()).await;
                } else if head.contains(&user_route) {
                    let mut extra = String::new();
                    if let Some(scopes) = spec.scope_header {
                        extra = format!("x-oauth-scopes: {scopes}\r\n");
                    }
                    respond(&mut sock, "200 OK", &extra, &spec.user_body.to_string()).await;
                } else {
                    respond(&mut sock, "404 Not Found", "", "").await;
                }
                let _ = sock.shutdown().await;
            }
        });
        MockForge { base }
    }

    fn mock_client(forge: &MockForge) -> DeviceFlowClient {
        DeviceFlowClient::custom(
            "test-forge",
            "test-client",
            forge.base.strip_prefix("http://").unwrap_or("127.0.0.1"),
            DeviceEndpoints {
                device_code_url: format!("{}/login/device/code", forge.base),
                token_url: format!("{}/login/oauth/access_token", forge.base),
                user_url: format!("{}/user", forge.base),
            },
        )
    }

    fn mock_gitlab_client(forge: &MockForge) -> DeviceFlowClient {
        DeviceFlowClient::gitlab("test-client".to_string(), &forge.base).unwrap()
    }

    #[tokio::test]
    async fn login_flows_through_mock_forge_with_backoff() {
        let forge = spawn_mock_forge(vec![
            serde_json::json!({ "error": "authorization_pending" }),
            serde_json::json!({ "error": "slow_down" }),
            serde_json::json!({ "access_token": "gho_win", "scope": "repo" }),
        ])
        .await;
        let client = mock_client(&forge);
        let shown = Arc::new(Mutex::new(Vec::new()));
        let shown_at_notify = shown.clone();
        let sleeps = Arc::new(Mutex::new(Vec::new()));
        let sleeps_at_wait = sleeps.clone();
        let credential = client
            .login(
                "repo",
                move |code| {
                    shown_at_notify.lock().unwrap().push(code.user_code.clone());
                },
                move |wait| {
                    let sleeps = sleeps_at_wait.clone();
                    async move {
                        sleeps.lock().unwrap().push(wait);
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(shown.lock().unwrap().as_slice(), ["MOCK-1"]);
        // Pending waits the 5s floor; slow_down extends to 10s.
        assert_eq!(
            sleeps.lock().unwrap().as_slice(),
            [Duration::from_secs(5), Duration::from_secs(10)]
        );
        assert_eq!(credential.forge, "test-forge");
        assert!(
            credential.host.starts_with("127.0.0.1:"),
            "{}",
            credential.host
        );
        assert_eq!(credential.username, "octocat");
        assert_eq!(credential.scopes, vec!["repo", "read:user"]);
        assert_eq!(credential.access_token, "gho_win");
    }

    #[test]
    fn forge_urls_join_normalize_and_validate() {
        assert_eq!(
            join_base_url("https://git.example.com/", "/oauth/token"),
            "https://git.example.com/oauth/token"
        );
        assert_eq!(
            join_base_url("https://git.example.com", "/oauth/token"),
            "https://git.example.com/oauth/token"
        );
        assert_eq!(
            forge_host_from_url("https://Git.Example.COM:8443/x").unwrap(),
            "git.example.com:8443"
        );
        assert_eq!(
            forge_host_from_url("http://127.0.0.1:9/").unwrap(),
            "127.0.0.1:9"
        );
        for bad in ["", "ftp://x/y", "git.example.com", "https://", "https:///x"] {
            assert!(forge_host_from_url(bad).is_err(), "{bad:?}");
        }
        let _client =
            DeviceFlowClient::gitlab("id".to_string(), "https://git.example.com/").unwrap();
        assert!(DeviceFlowClient::gitlab("id".to_string(), "gopher://x").is_err());
    }

    #[test]
    fn plain_http_is_loopback_only() {
        // Loopback in every form (exact or host-plus-port).
        for ok in [
            "http://localhost/x",
            "http://localhost:8080/x",
            "http://127.0.0.1/x",
            "http://127.0.0.1:9/",
            "http://[::1]/x",
            "http://[::1]:9/x",
        ] {
            assert!(forge_host_from_url(ok).is_ok(), "{ok}");
        }
        // Suffix lookalikes and LAN hosts never pass as loopback.
        for bad in [
            "http://localhost.evil.com/x",
            "http://127.0.0.10/x",
            "http://10.0.0.2/x",
            "http://git.example.com/x",
        ] {
            let err = forge_host_from_url(bad).unwrap_err();
            assert!(err.contains("loopback-only"), "{bad}: {err}");
        }
        // https is unrestricted.
        assert!(forge_host_from_url("https://git.example.com/x").is_ok());
    }

    #[test]
    fn url_suffixes_never_malform_endpoints() {
        assert_eq!(
            join_base_url("https://git.example.com/?x=1#y", "/oauth/token"),
            "https://git.example.com/oauth/token"
        );
        assert_eq!(forge_host_from_url("https://h/x?next=/y#z").unwrap(), "h");
        // Even a bare query-only URL keys cleanly.
        assert_eq!(forge_host_from_url("https://h?x").unwrap(), "h");
    }

    #[tokio::test]
    async fn gitlab_login_resolves_username_and_grant_scopes() {
        let forge = spawn_mock_forge_with(
            gitlab_spec(),
            vec![
                serde_json::json!({ "error": "authorization_pending" }),
                serde_json::json!({ "access_token": "glpat_win", "scope": "api" }),
            ],
        )
        .await;
        let client = mock_gitlab_client(&forge);
        let credential = client.login("api", |_| {}, |_| async {}).await.unwrap();
        assert_eq!(credential.forge, "gitlab");
        assert!(
            credential.host.starts_with("127.0.0.1:"),
            "{}",
            credential.host
        );
        // GitLab shape: `username` field, no scopes header — the
        // grant body supplies scopes via fallback.
        assert_eq!(credential.username, "dev");
        assert_eq!(credential.scopes, vec!["api"]);
        assert_eq!(credential.access_token, "glpat_win");
    }

    #[tokio::test]
    async fn login_denial_and_expiry_fail_closed() {
        for (script, marker) in [
            (
                vec![serde_json::json!({ "error": "access_denied" })],
                "denied",
            ),
            (
                vec![serde_json::json!({ "error": "expired_token" })],
                "expired",
            ),
        ] {
            let forge = spawn_mock_forge(script).await;
            let client = mock_client(&forge);
            let err = client
                .login("repo", |_| {}, |_| async {})
                .await
                .unwrap_err();
            assert!(err.contains(marker), "{err}");
        }
    }
}
