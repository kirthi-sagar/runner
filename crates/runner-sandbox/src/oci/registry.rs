//! Daemonless OCI registry client: reference parsing, bearer auth
//! negotiation, and manifest/platform resolution. Pulls run over
//! plain HTTPS (reqwest); digests verify with sha2. No dockerd, no
//! podman, no new crates.
//!
//! Phase 1 resolves references to verified layer descriptors;
//! download + assembly land in a later phase.

use std::collections::HashMap;

/// Docker Hub registry endpoint for implicit references.
pub const DOCKER_HUB_REGISTRY: &str = "registry-1.docker.io";
/// Default tag when none is given.
pub const DEFAULT_TAG: &str = "latest";

/// Parsed OCI image reference (`[registry/]repo[:tag][@digest]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciReference {
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

fn is_registry_host(component: &str) -> bool {
    // Registries carry a dot/port, or the localhost convention;
    // anything else is a Docker Hub path component.
    component.contains('.') || component.contains(':') || component == "localhost"
}

fn valid_repo_name(name: &str) -> bool {
    // OCI distribution-spec repository grammar (lowercase).
    !name.is_empty()
        && name.len() <= 255
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-' | b'/')
        })
        && !name.starts_with('/')
        && !name.ends_with('/')
        && !name.contains("//")
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 128
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_digest(digest: &str) -> bool {
    // `sha256:<64 lowercase hex>` only (what registries serve).
    digest.len() == 7 + 64
        && digest.starts_with("sha256:")
        && digest[7..].bytes().all(|b| b.is_ascii_hexdigit())
}

impl OciReference {
    /// Parse `name[:tag][@digest]` with registry/repo normalization:
    /// bare names land on Docker Hub (`ubuntu` → `library/ubuntu`),
    /// `host[:port]/…` prefixes select a custom registry.
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("empty image reference".to_string());
        }
        // Split an optional @digest pin first (digests contain ':').
        let (name_tag, digest) = match input.split_once('@') {
            Some((name, digest)) => {
                if !valid_digest(digest) {
                    return Err(format!(
                        "invalid digest pin '{digest}' (want sha256:<64 hex>)"
                    ));
                }
                (name, Some(digest.to_string()))
            }
            None => (input, None),
        };
        // The tag colon trails the final path component only.
        let (path, tag) = match name_tag.rsplit_once(':') {
            Some((path, tag)) if !tag.contains('/') => {
                if !valid_tag(tag) {
                    return Err(format!("invalid tag '{tag}'"));
                }
                (path, Some(tag.to_string()))
            }
            _ => (name_tag, None),
        };
        if path.is_empty() {
            return Err(format!("invalid image reference '{input}'"));
        }
        let mut parts = path.splitn(2, '/');
        let first = parts.next().unwrap_or_default();
        let rest = parts.next();
        let (registry, repository) = match rest {
            Some(rest) if is_registry_host(first) => (first.to_string(), rest.to_string()),
            _ => (
                DOCKER_HUB_REGISTRY.to_string(),
                match rest {
                    // Explicit namespace (`owner/repo`).
                    Some(_) => path.to_string(),
                    // Official image (`ubuntu` → `library/ubuntu`).
                    None => format!("library/{path}"),
                },
            ),
        };
        if registry.trim().is_empty() || registry.chars().any(char::is_whitespace) {
            return Err(format!("invalid registry '{registry}'"));
        }
        if !valid_repo_name(&repository) {
            return Err(format!(
                "invalid repository '{repository}' (want lowercase path)"
            ));
        }
        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// Manifest address: digest pins win, else the tag, else `latest`.
    pub fn manifest_ref(&self) -> String {
        if let Some(digest) = &self.digest {
            return digest.clone();
        }
        self.tag.clone().unwrap_or_else(|| DEFAULT_TAG.to_string())
    }

    /// Canonical display/key form: `registry/repo:tag` or
    /// `registry/repo@digest`.
    pub fn normalized(&self) -> String {
        if let Some(digest) = &self.digest {
            format!("{}/{}@{}", self.registry, self.repository, digest)
        } else {
            format!(
                "{}/{}:{}",
                self.registry,
                self.repository,
                self.tag.clone().unwrap_or_else(|| DEFAULT_TAG.to_string())
            )
        }
    }

    /// `http` for loopback registries (tests), `https` elsewhere —
    /// the same localhost exception docker itself honors.
    pub fn scheme(&self) -> &'static str {
        let host = self.registry.split(':').next().unwrap_or_default();
        if host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1" {
            "http"
        } else {
            "https"
        }
    }

    fn base_url(&self) -> String {
        format!(
            "{}://{}/v2/{}",
            self.scheme(),
            self.registry,
            self.repository
        )
    }
}

/// Parsed `WWW-Authenticate: Bearer …` registry challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerChallenge {
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

/// Parse one Bearer challenge header (key="value" pairs; unknown
/// keys ignored, realm required).
pub fn parse_bearer_challenge(header: &str) -> Result<BearerChallenge, String> {
    let trimmed = header.trim();
    let rest = trimmed.strip_prefix("Bearer ").or_else(|| {
        let (scheme, rest) = trimmed.split_once(' ')?;
        scheme.eq_ignore_ascii_case("bearer").then_some(rest)
    });
    let rest = rest.ok_or_else(|| format!("not a Bearer challenge: '{header}'"))?;
    let mut pairs = HashMap::new();
    for part in rest.split(',') {
        let part = part.trim();
        let Some((key, mut value)) = part.split_once('=') else {
            continue;
        };
        value = value.trim();
        if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
            value = &value[1..value.len() - 1];
        }
        pairs.insert(key.trim().to_ascii_lowercase(), value.to_string());
    }
    let realm = pairs
        .remove("realm")
        .filter(|realm| !realm.is_empty())
        .ok_or_else(|| format!("Bearer challenge lacks a realm: '{header}'"))?;
    Ok(BearerChallenge {
        realm,
        service: pairs.remove("service"),
        scope: pairs.remove("scope"),
    })
}

/// Extract the bearer token from an auth-realm JSON body (Docker Hub
/// answers `token`, others `access_token`).
pub fn parse_token_response(body: &serde_json::Value) -> Result<String, String> {
    body.get("token")
        .or_else(|| body.get("access_token"))
        .and_then(|token| token.as_str())
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "token response carries no token".to_string())
}

/// Loopback host spellings (names and literals, bracketed or bare).
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "[::1]"
        || host == "::1"
}

/// Non-routable or internal IP literals a token realm must never
/// point at: RFC 1918 ranges, loopback, link-local (the classic
/// cloud-metadata SSRF target), and unique-local / unspecified.
/// Manual octet matching keeps this free of toolchain-gated APIs.
fn is_blocked_realm_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || o[0] == 127
                || (o[0] == 169 && o[1] == 254)
                || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 || v6.is_loopback()
        }
    }
}

/// Strip an explicit port from a registry host (`host:port`,
/// `[v6]:port`); bare names and unbracketed IPv6 literals pass
/// through untouched.
fn registry_bare_host(registry: &str) -> &str {
    if let Some(rest) = registry.strip_prefix('[') {
        if let Some((inner, _)) = rest.split_once(']') {
            return inner;
        }
        return registry;
    }
    match registry.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && !port.is_empty() => host,
        _ => registry,
    }
}

/// Realm/registry host pairing rule: exact equality, plus the two
/// known split-host auth pairs (Hub serves auth from
/// `auth.docker.io`; GitLab serves it from `gitlab.com` or a
/// `gitlab.com` subdomain). No suffix slicing of any kind: naive
/// registrable domains let `collector.attacker.co.uk` match
/// `forge.company.co.uk`. Split-host self-hosted forges fail closed
/// here (colocated instances match by equality).
fn realm_host_allowed(realm_host: &str, reg_host: &str) -> bool {
    if realm_host.eq_ignore_ascii_case(reg_host) {
        return true;
    }
    let realm = realm_host.to_ascii_lowercase();
    let reg = reg_host.to_ascii_lowercase();
    matches!(
        (reg.as_str(), realm.as_str()),
        ("registry-1.docker.io", "auth.docker.io") | ("registry.gitlab.com", "gitlab.com")
    ) || (reg == "registry.gitlab.com" && realm.ends_with(".gitlab.com"))
}

/// Validate a challenge realm before any fetch (SSRF defense): the
/// realm is registry-supplied, so a hostile registry must not
/// bounce the token request at intranet or cloud-metadata targets.
/// Rules: `https` everywhere except loopback-to-loopback `http`
/// (hermetic mocks); no userinfo; no IP literals except a loopback
/// registry's own loopback; the realm host must equal the registry
/// host or be a known split-host auth pair (see
/// `realm_host_allowed`).
pub fn validate_token_realm(realm: &str, registry_host: &str) -> Result<reqwest::Url, String> {
    let parsed =
        reqwest::Url::parse(realm.trim()).map_err(|_| "token realm is not a URL".to_string())?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("token realm must not contain user credentials".to_string());
    }
    let realm_host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "token realm has no host".to_string())?;
    let registry_loopback = is_loopback_host(registry_bare_host(registry_host));
    match parsed.scheme() {
        "https" => {}
        "http" if is_loopback_host(realm_host) && registry_loopback => {}
        _ => {
            return Err("token realm must use https (http is loopback-only)".to_string());
        }
    }
    if is_loopback_host(realm_host) {
        // Loopback realms answer only loopback registries (a remote
        // registry bouncing at localhost is DNS-rebinding class).
        return if registry_loopback {
            Ok(parsed)
        } else {
            Err("token realm must not target loopback for a remote registry".to_string())
        };
    }
    // Loopback literals were handled above; every other IP —
    // blocked ranges and public IPs alike (registries serve auth
    // over DNS, never bare IPs) — fails closed.
    if let Ok(ip) = realm_host
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<std::net::IpAddr>()
    {
        return Err(if is_blocked_realm_ip(ip) {
            "token realm points at a blocked address".to_string()
        } else {
            "token realm must use a DNS name, not a bare IP".to_string()
        });
    }
    let reg_host = registry_bare_host(registry_host);
    if realm_host_allowed(realm_host, reg_host) {
        return Ok(parsed);
    }
    Err(format!(
        "token realm host '{realm_host}' does not match registry '{registry_host}'"
    ))
}

/// Hash manifest bytes against the expected `sha256:` digest (the
/// distribution spec's tamper check: clients using the digest MUST
/// verify it matches the returned document).
fn verify_manifest_bytes(bytes: &[u8], expected: &str) -> Result<(), String> {
    use sha2::Digest;
    let want = expected
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("invalid manifest digest '{expected}' (want sha256:<64 hex>)"))?;
    let actual = format!("{:x}", sha2::Sha256::digest(bytes));
    if actual != want {
        return Err(format!(
            "manifest digest mismatch for {expected} (bytes hashed to sha256:{actual})"
        ));
    }
    Ok(())
}

/// Verify digest-addressed bytes: they must hash to the requested
/// digest, and a present `Docker-Content-Digest` header must agree
/// with it (a disagreeing header is a confused or lying registry).
fn verify_pinned_manifest(bytes: &[u8], pinned: &str, header: Option<&str>) -> Result<(), String> {
    verify_manifest_bytes(bytes, pinned)?;
    if let Some(seen) = header {
        if seen != pinned {
            return Err(format!(
                "manifest digest header '{seen}' disagrees with requested '{pinned}'"
            ));
        }
    }
    Ok(())
}

/// Retry a token request anonymously exactly when credentials were
/// sent and rejected (401/403). Anonymous rejections and other
/// statuses fail loud (no retry loops: the anonymous attempt is
/// terminal either way).
fn retry_anonymously(creds_sent: bool, status: reqwest::StatusCode) -> bool {
    creds_sent
        && matches!(
            status,
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        )
}

/// Resolve the trusted digest for a tag-addressed fetch: a present
/// header is verified against the bytes; an absent header falls back
/// to hashing the bytes directly (older registries omit the header,
/// so absence degrades tamper-evidence instead of failing — loudly).
fn tag_manifest_digest(bytes: &[u8], header: Option<&str>) -> Result<String, String> {
    match header {
        Some(seen) => {
            verify_manifest_bytes(bytes, seen)?;
            Ok(seen.to_string())
        }
        None => {
            use sha2::Digest;
            eprintln!(
                "[runner::oci] manifest lacks Docker-Content-Digest header; continuing without tamper evidence"
            );
            Ok(format!("sha256:{:x}", sha2::Sha256::digest(bytes)))
        }
    }
}

/// One content descriptor (config or layer).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct OciDescriptor {
    #[serde(rename = "mediaType", default)]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

/// Container platform selector.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct OciPlatform {
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub architecture: String,
}

/// One index entry (OCI image index / Docker manifest list).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct OciIndexEntry {
    pub digest: String,
    #[serde(default)]
    pub platform: Option<OciPlatform>,
}

/// OCI image index / Docker manifest list (shape-sniffed: the only
/// manifest document carrying `manifests`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct OciIndex {
    #[serde(default)]
    pub manifests: Vec<OciIndexEntry>,
}

/// OCI image manifest (shape-sniffed: the document carrying `layers`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct OciManifest {
    pub config: OciDescriptor,
    #[serde(default)]
    pub layers: Vec<OciDescriptor>,
}

/// Host container platform: Linux guests on the host architecture
/// (containers execute as Linux guests on every host; unknown
/// architectures fail closed — no platform to match).
pub fn host_platform() -> Result<(String, String), String> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => return Err(format!("unsupported container architecture '{other}'")),
    };
    Ok(("linux".to_string(), arch.to_string()))
}

/// Pick the index digest matching `os/architecture`, naming every
/// available platform when nothing matches.
pub fn select_platform(index: &OciIndex, os: &str, arch: &str) -> Result<String, String> {
    for entry in &index.manifests {
        if let Some(platform) = &entry.platform {
            if platform.os == os && platform.architecture == arch {
                return Ok(entry.digest.clone());
            }
        }
    }
    let available: Vec<String> = index
        .manifests
        .iter()
        .filter_map(|entry| {
            entry
                .platform
                .as_ref()
                .map(|platform| format!("{}/{}", platform.os, platform.architecture))
        })
        .collect();
    Err(format!(
        "no {os}/{arch} image in index (available: {})",
        if available.is_empty() {
            "none".to_string()
        } else {
            available.join(", ")
        }
    ))
}

/// Fully resolved pull target: verified descriptors, ready to fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImage {
    pub reference: OciReference,
    pub manifest_digest: String,
    pub config: OciDescriptor,
    pub layers: Vec<OciDescriptor>,
}

/// Per-operation HTTP budget for registry metadata (manifests and
/// tokens are small). Applied per call, never client-wide: blob
/// streams outlive any fixed total and pace themselves with an idle
/// watchdog instead.
const REGISTRY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Minimal registry client with a single-flight token cache (one
/// cached token: clients are short-lived per pull). Optional Basic
/// credentials ride the realm token request only, never the bearer
/// dance itself (deliberately no `Debug`: the password is a forge
/// device token). Token fetches use a redirect-free client: a
/// validated realm must not bounce at a second, unvalidated URL.
pub struct RegistryClient {
    http: reqwest::Client,
    token_http: reqwest::Client,
    cached: tokio::sync::Mutex<Option<(String, String)>>,
    basic: Option<(String, String)>,
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .user_agent("runner")
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            token_http: reqwest::Client::builder()
                .user_agent("runner")
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| {
                    // Builder failure is environmental (proxy
                    // config); the fallback keeps the no-redirect
                    // property — a default client here would
                    // silently re-enable realm bounces.
                    reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .build()
                        .unwrap_or_else(|_| reqwest::Client::new())
                }),
            cached: tokio::sync::Mutex::new(None),
            basic: None,
        }
    }

    /// Attach Basic credentials (forge username + device token) for
    /// the realm token request. Sent only to `https` realms; anonymous
    /// registries and loopback mocks stay credential-free.
    pub fn with_basic_auth(mut self, username: String, password: String) -> Self {
        self.basic = Some((username, password));
        self
    }

    /// Basic credentials for a realm of this scheme: `Some` only for
    /// `https` with credentials configured (device tokens never ride
    /// plaintext, not even to loopback).
    fn basic_for_realm(&self, scheme: &str) -> Option<(&str, &str)> {
        if scheme == "https" {
            self.basic
                .as_ref()
                .map(|(username, password)| (username.as_str(), password.as_str()))
        } else {
            None
        }
    }

    /// Fetch a bearer token for one challenge (cached per scope,
    /// bounded per call). The realm is validated before anything
    /// else: a hostile challenge fails even on a cache hit.
    async fn token_for(
        &self,
        challenge: &BearerChallenge,
        registry_host: &str,
    ) -> Result<String, String> {
        tokio::time::timeout(
            REGISTRY_TIMEOUT,
            self.token_for_inner(challenge, registry_host),
        )
        .await
        .map_err(|_| "token request timed out".to_string())?
    }

    async fn token_for_inner(
        &self,
        challenge: &BearerChallenge,
        registry_host: &str,
    ) -> Result<String, String> {
        let realm_url = validate_token_realm(&challenge.realm, registry_host)?;
        let scope = challenge.scope.clone().unwrap_or_default();
        if let Some((cached_scope, token)) = self.cached.lock().await.clone() {
            if cached_scope == scope {
                return Ok(token);
            }
        }
        let mut url = challenge.realm.clone();
        let mut sep = if url.contains('?') { '&' } else { '?' };
        for (key, value) in [
            ("service", challenge.service.as_deref()),
            ("scope", challenge.scope.as_deref()),
        ] {
            if let Some(value) = value {
                url.push(sep);
                url.push_str(key);
                url.push('=');
                url.push_str(value);
                sep = '&';
            }
        }
        let mut request = self.token_http.get(&url);
        let creds_sent =
            if let Some((username, password)) = self.basic_for_realm(realm_url.scheme()) {
                request = request.basic_auth(username, Some(password));
                true
            } else {
                false
            };
        let response = request
            .send()
            .await
            .map_err(|e| format!("token request failed: {e}"))?;
        // Rejected credentials fall back to anonymous exactly once,
        // so public images on credential-gated registries still pull;
        // anything else (or a second rejection) fails loud.
        let response = if retry_anonymously(creds_sent, response.status()) {
            self.token_http
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("token request failed: {e}"))?
        } else {
            response
        };
        if !response.status().is_success() {
            return Err(format!("token request failed: HTTP {}", response.status()));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("token response is not JSON: {e}"))?;
        let token = parse_token_response(&body)?;
        *self.cached.lock().await = Some((scope, token.clone()));
        Ok(token)
    }

    /// GET with the bearer dance: one anonymous attempt, then a single
    /// challenged retry. Returns the live response; the caller maps
    /// statuses and streams the body.
    async fn get_authed(
        &self,
        url: &str,
        accept: Option<&str>,
    ) -> Result<reqwest::Response, String> {
        let attempt = |token: Option<String>| {
            let http = &self.http;
            let url = url.to_string();
            let accept = accept.map(str::to_string);
            async move {
                let mut request = http.get(&url);
                if let Some(accept) = accept {
                    request = request.header(reqwest::header::ACCEPT, accept);
                }
                if let Some(token) = token {
                    request =
                        request.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
                }
                request
                    .send()
                    .await
                    .map_err(|e| format!("registry request failed: {e}"))
            }
        };
        let response = attempt(None).await?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            let challenge = response
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| "registry 401 without a bearer challenge".to_string())?;
            let challenge = parse_bearer_challenge(challenge)?;
            // The request URL is built from the resolved reference,
            // so its host is the registry the challenge must match.
            let registry_host = reqwest::Url::parse(url)
                .ok()
                .and_then(|parsed| parsed.host_str().map(str::to_string))
                .ok_or_else(|| format!("registry URL has no host: '{url}'"))?;
            let token = self.token_for(&challenge, &registry_host).await?;
            attempt(Some(token)).await
        } else {
            Ok(response)
        }
    }

    /// GET one manifest document with Accept + bearer dance, bounded.
    /// Returns the parsed document, its raw bytes, and the validated
    /// `Docker-Content-Digest` header when the registry sent one.
    async fn get_manifest_doc(
        &self,
        url: &str,
    ) -> Result<(serde_json::Value, Vec<u8>, Option<String>), String> {
        const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
            application/vnd.oci.image.manifest.v1+json, \
            application/vnd.docker.distribution.manifest.list.v2+json, \
            application/vnd.docker.distribution.manifest.v2+json";
        let fetch = async {
            let response = self.get_authed(url, Some(ACCEPT)).await?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Err(format!("manifest not found: {url}"));
            }
            if !response.status().is_success() {
                return Err(format!(
                    "registry request failed: HTTP {}",
                    response.status()
                ));
            }
            let header = response
                .headers()
                .get("docker-content-digest")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|digest| !digest.is_empty())
                .map(str::to_string);
            if let Some(digest) = &header {
                if !valid_digest(digest) {
                    return Err(format!("manifest digest header is malformed: '{digest}'"));
                }
            }
            let bytes = response
                .bytes()
                .await
                .map_err(|e| format!("manifest response has no body: {e}"))?
                .to_vec();
            let doc = serde_json::from_slice(&bytes)
                .map_err(|e| format!("manifest response is not JSON: {e}"))?;
            Ok((doc, bytes, header))
        };
        tokio::time::timeout(REGISTRY_TIMEOUT, fetch)
            .await
            .map_err(|_| format!("manifest request timed out: {url}"))?
    }

    /// GET one blob with the bearer dance, returning the live response
    /// for streaming. No total timeout: the caller paces the stream
    /// with an idle watchdog instead.
    pub(crate) async fn get_blob(&self, url: &str) -> Result<reqwest::Response, String> {
        let response = self.get_authed(url, None).await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(format!("blob not found: {url}"));
        }
        if !response.status().is_success() {
            return Err(format!("blob request failed: HTTP {}", response.status()));
        }
        Ok(response)
    }

    fn check_descriptor(descriptor: &OciDescriptor, role: &str) -> Result<(), String> {
        if !valid_digest(&descriptor.digest) {
            return Err(format!(
                "invalid {role} digest '{}' (want sha256:<64 hex>)",
                descriptor.digest
            ));
        }
        Ok(())
    }

    /// Resolve a reference to verified layer descriptors: fetch the
    /// manifest document, follow indices to the host platform, and
    /// validate every digest shape.
    pub async fn resolve(&self, reference: &OciReference) -> Result<ResolvedImage, String> {
        let base = reference.base_url();
        let address = format!("{}/manifests/{}", base, reference.manifest_ref());
        let (doc, bytes, header) = self.get_manifest_doc(&address).await?;
        // Evidence rule: digest-addressed fetches verify against the
        // requested digest; tag fetches verify against the header and
        // fall back to hashing the bytes when it is absent (with a
        // loud warning: no tamper evidence on that path).
        let proven = match &reference.digest {
            Some(pinned) => {
                verify_pinned_manifest(&bytes, pinned, header.as_deref())?;
                pinned.clone()
            }
            None => tag_manifest_digest(&bytes, header.as_deref())?,
        };
        // Index or manifest? Shape-sniff: only indices carry `manifests`.
        let (manifest_digest, manifest) = if doc.get("manifests").is_some() {
            let index: OciIndex =
                serde_json::from_value(doc).map_err(|e| format!("invalid image index: {e}"))?;
            let (os, arch) = host_platform()?;
            let digest = select_platform(&index, &os, &arch)?;
            let (doc, bytes, header) = self
                .get_manifest_doc(&format!("{}/manifests/{}", base, digest))
                .await?;
            verify_pinned_manifest(&bytes, &digest, header.as_deref())?;
            let manifest: OciManifest =
                serde_json::from_value(doc).map_err(|e| format!("invalid image manifest: {e}"))?;
            (digest, manifest)
        } else if doc.get("layers").is_some() {
            let manifest: OciManifest =
                serde_json::from_value(doc).map_err(|e| format!("invalid image manifest: {e}"))?;
            (proven, manifest)
        } else {
            let snippet = doc.to_string();
            let snippet = snippet.chars().take(120).collect::<String>();
            return Err(format!("unexpected manifest document: {snippet}"));
        };
        Self::check_descriptor(&manifest.config, "config")?;
        for layer in &manifest.layers {
            Self::check_descriptor(layer, "layer")?;
        }
        Ok(ResolvedImage {
            reference: reference.clone(),
            manifest_digest,
            config: manifest.config,
            layers: manifest.layers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_normalization_matrix() {
        // Bare image: Docker Hub + library prefix + latest tag.
        let parsed = OciReference::parse("node").unwrap();
        assert_eq!(parsed.registry, DOCKER_HUB_REGISTRY);
        assert_eq!(parsed.repository, "library/node");
        assert_eq!(parsed.tag, None);
        assert_eq!(parsed.manifest_ref(), "latest");
        // Official name with tag.
        let parsed = OciReference::parse("ubuntu:latest").unwrap();
        assert_eq!(parsed.repository, "library/ubuntu");
        assert_eq!(parsed.manifest_ref(), "latest");
        let parsed = OciReference::parse("node:20").unwrap();
        assert_eq!(parsed.registry, DOCKER_HUB_REGISTRY);
        assert_eq!(parsed.repository, "library/node");
        assert_eq!(parsed.manifest_ref(), "20");
        // Namespaced Hub image: no library prefix.
        let parsed = OciReference::parse("kirthi-sagar/runner:latest").unwrap();
        assert_eq!(parsed.registry, DOCKER_HUB_REGISTRY);
        assert_eq!(parsed.repository, "kirthi-sagar/runner");
        // Custom registries keep their paths verbatim.
        let parsed = OciReference::parse("ghcr.io/kirthi-sagar/runner:latest").unwrap();
        assert_eq!(parsed.registry, "ghcr.io");
        assert_eq!(parsed.repository, "kirthi-sagar/runner");
        let parsed = OciReference::parse("quay.io/fedora/fedora:40").unwrap();
        assert_eq!(parsed.registry, "quay.io");
        assert_eq!(parsed.repository, "fedora/fedora");
        assert_eq!(parsed.manifest_ref(), "40");
        // Registry with port.
        let parsed = OciReference::parse("localhost:5000/team/app:rc1").unwrap();
        assert_eq!(parsed.registry, "localhost:5000");
        assert_eq!(parsed.repository, "team/app");
        assert_eq!(parsed.manifest_ref(), "rc1");
        // Digest pinning wins over tags.
        let digest = format!("sha256:{}", "a".repeat(64));
        let parsed = OciReference::parse(&format!("node@{}", digest)).unwrap();
        assert_eq!(parsed.digest.as_deref(), Some(digest.as_str()));
        assert_eq!(parsed.manifest_ref(), digest);
        let parsed = OciReference::parse(&format!("node:20@{}", digest)).unwrap();
        assert_eq!(parsed.manifest_ref(), digest);
        // Garbage fails closed.
        for bad in [
            "",
            "   ",
            "UPPERCASE",
            "node:",
            ":latest",
            "node@sha256:xyz",
            "node@md5:d41d8cd98f00b204e9800998ecf8427e",
            "a//b",
            "/leading",
        ] {
            assert!(OciReference::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn loopback_scheme_is_plain_http() {
        assert_eq!(
            OciReference::parse("localhost:5000/a/b:c")
                .unwrap()
                .scheme(),
            "http"
        );
        assert_eq!(
            OciReference::parse("127.0.0.1:5000/a/b:c")
                .unwrap()
                .scheme(),
            "http"
        );
        assert_eq!(OciReference::parse("node:20").unwrap().scheme(), "https");
        assert_eq!(
            OciReference::parse("ghcr.io/a/b:c").unwrap().scheme(),
            "https"
        );
    }

    #[test]
    fn bearer_challenge_parses_and_rejects() {
        let challenge = parse_bearer_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/node:pull""#,
        )
        .unwrap();
        assert_eq!(challenge.realm, "https://auth.docker.io/token");
        assert_eq!(challenge.service.as_deref(), Some("registry.docker.io"));
        assert_eq!(
            challenge.scope.as_deref(),
            Some("repository:library/node:pull")
        );
        // Minimal realm-only challenge.
        let challenge = parse_bearer_challenge(r#"Bearer realm="https://x/token""#).unwrap();
        assert_eq!(challenge.realm, "https://x/token");
        assert_eq!(challenge.service, None);
        // Garbage fails closed.
        for bad in [
            "",
            "Basic realm=\"x\"",
            "Bearer realm=",
            "Bearer scope=\"x\"",
            "Bearer realm=\"\"",
        ] {
            assert!(parse_bearer_challenge(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn token_realm_accepts_matching_hosts() {
        // Same host, well-known split pairs, and loopback mocks.
        for (realm, registry) in [
            ("https://ghcr.io/token", "ghcr.io"),
            ("https://GHCR.IO/token", "ghcr.io"),
            ("https://auth.docker.io/token", "registry-1.docker.io"),
            ("https://gitlab.com/jwt/auth", "registry.gitlab.com"),
            ("https://jwt.gitlab.com/jwt/auth", "registry.gitlab.com"),
            (
                "https://registry.corp.com:8443/token",
                "registry.corp.com:8443",
            ),
            ("http://127.0.0.1:5000/token", "127.0.0.1:5000"),
            ("http://localhost:5000/token", "localhost:5000"),
        ] {
            assert!(
                validate_token_realm(realm, registry).is_ok(),
                "{realm} vs {registry}"
            );
        }
    }

    #[test]
    fn token_realm_rejects_ssrf_shapes() {
        // Wrong scheme, foreign hosts, intranet literals, userinfo.
        for (realm, registry) in [
            ("http://ghcr.io/token", "ghcr.io"),
            ("https://evil.example.com/token", "ghcr.io"),
            ("https://ghcr.io.evil.com/token", "ghcr.io"),
            // Multi-part TLD sharing is NOT a match (no suffix slicing).
            (
                "https://collector.attacker.co.uk/token",
                "forge.company.co.uk",
            ),
            ("https://auth.company.co.uk/token", "forge.company.co.uk"),
            // Split-host self-hosted forges fail closed (colocated
            // instances match by equality instead).
            ("https://gitlab.corp.com/jwt/auth", "registry.corp.com"),
            (
                "https://registry.gitlab.com.evil.com/jwt/auth",
                "registry.gitlab.com",
            ),
            ("http://127.0.0.1:5000/token", "ghcr.io"),
            ("https://127.0.0.1/token", "ghcr.io"),
            ("https://10.0.0.9/token", "ghcr.io"),
            ("https://172.16.4.4/token", "ghcr.io"),
            ("https://192.168.1.7/token", "ghcr.io"),
            ("https://169.254.169.254/token", "ghcr.io"),
            ("https://[fc00::1]/token", "ghcr.io"),
            ("https://[fe80::1]/token", "ghcr.io"),
            ("https://203.0.113.9/token", "ghcr.io"),
            ("https://user:pass@ghcr.io/token", "ghcr.io"),
            ("https://ghcr.io/token", "127.0.0.1:5000"),
            ("not a url", "ghcr.io"),
            ("https://", "ghcr.io"),
        ] {
            assert!(
                validate_token_realm(realm, registry).is_err(),
                "{realm} vs {registry}"
            );
        }
    }

    #[test]
    fn token_body_accepts_both_keys() {
        assert_eq!(
            parse_token_response(&serde_json::json!({"token": "abc"})).unwrap(),
            "abc"
        );
        assert_eq!(
            parse_token_response(&serde_json::json!({"access_token": "def"})).unwrap(),
            "def"
        );
        assert!(parse_token_response(&serde_json::json!({})).is_err());
        assert!(parse_token_response(&serde_json::json!({"token": ""})).is_err());
    }

    fn digest(byte: u8) -> String {
        format!(
            "sha256:{}",
            [byte; 32]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }

    #[test]
    fn index_selects_host_platform_or_names_options() {
        // Docker manifest-list shape.
        let list: OciIndex = serde_json::from_value(serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
            "manifests": [
                {"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                 "digest": digest(1), "size": 100,
                 "platform": {"os": "linux", "architecture": "amd64"}},
                {"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                 "digest": digest(2), "size": 100,
                 "platform": {"os": "linux", "architecture": "arm64"}},
            ],
        }))
        .unwrap();
        assert_eq!(select_platform(&list, "linux", "amd64").unwrap(), digest(1));
        assert_eq!(select_platform(&list, "linux", "arm64").unwrap(), digest(2));
        let err = select_platform(&list, "linux", "riscv64").unwrap_err();
        assert!(err.contains("linux/amd64"), "{err}");
        assert!(err.contains("linux/arm64"), "{err}");
        // OCI index shape (no per-entry media type required).
        let index: OciIndex = serde_json::from_value(serde_json::json!({
            "schemaVersion": 2,
            "manifests": [
                {"digest": digest(3), "size": 50,
                 "platform": {"os": "linux", "architecture": "arm64"}},
            ],
        }))
        .unwrap();
        assert_eq!(
            select_platform(&index, "linux", "arm64").unwrap(),
            digest(3)
        );
        assert!(select_platform(&index, "linux", "amd64").is_err());
        // Entries without platforms never match.
        let bare: OciIndex = serde_json::from_value(serde_json::json!({
            "schemaVersion": 2, "manifests": [{"digest": digest(4), "size": 10}],
        }))
        .unwrap();
        assert!(select_platform(&bare, "linux", "amd64").is_err());
    }

    #[test]
    fn manifest_layers_validate() {
        let manifest: OciManifest = serde_json::from_value(serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": digest(9), "size": 100},
            "layers": [
                {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                 "digest": digest(10), "size": 1000},
                {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                 "digest": digest(11), "size": 2000},
            ],
        }))
        .unwrap();
        assert_eq!(manifest.layers.len(), 2);
        RegistryClient::check_descriptor(&manifest.config, "config").unwrap();
        for layer in &manifest.layers {
            RegistryClient::check_descriptor(layer, "layer").unwrap();
        }
        let bad = OciDescriptor {
            media_type: String::new(),
            digest: "sha256:xyz".to_string(),
            size: 1,
        };
        assert!(RegistryClient::check_descriptor(&bad, "layer").is_err());
    }

    #[test]
    fn host_platform_is_linux_on_host_arch() {
        let (os, arch) = host_platform().unwrap();
        assert_eq!(os, "linux");
        assert!(arch == "amd64" || arch == "arm64", "{arch}");
    }

    /// Scripted loopback registry: 401+challenge → token → index →
    /// manifest. No external network; the full resolve() flow runs
    /// end to end against it. Served bodies hash to their advertised
    /// digests (byte-verification passes); `tamper` corrupts bodies
    /// and `omit_digest_header` drops the header to pin the
    /// fail-closed paths.
    struct MockRegistry {
        base: String,
        authed: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        basic_seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        amd64: String,
        arm64: String,
        tamper: std::sync::Arc<std::sync::atomic::AtomicBool>,
        omit_digest_header: std::sync::Arc<std::sync::atomic::AtomicBool>,
        redirect_hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        token_hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        token_always_401: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    /// Per-arch manifest body: config + two layers. The config seed
    /// keeps the two architectures' bytes (and digests) distinct.
    fn arch_manifest_body(config_seed: u8) -> String {
        serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": digest(config_seed), "size": 100},
            "layers": [
                {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                 "digest": digest(10), "size": 1000},
                {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                 "digest": digest(11), "size": 2000},
            ],
        })
        .to_string()
    }

    fn sha256_digest(bytes: &[u8]) -> String {
        use sha2::Digest;
        format!("sha256:{:x}", sha2::Sha256::digest(bytes))
    }

    async fn respond(sock: &mut tokio::net::TcpStream, status: &str, extra: &str, body: &str) {
        use tokio::io::AsyncWriteExt;
        let raw = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n{extra}\r\n{body}",
            body.len()
        );
        let _ = sock.write_all(raw.as_bytes()).await;
    }

    async fn spawn_mock_registry() -> MockRegistry {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("127.0.0.1:{port}");
        let authed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let served = authed.clone();
        let basic_seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let basic = basic_seen.clone();
        // Bodies are built once so the index advertises their real
        // digests and every response carries a verifiable header.
        let amd64_body = arch_manifest_body(21);
        let arm64_body = arch_manifest_body(22);
        let amd64 = sha256_digest(amd64_body.as_bytes());
        let arm64 = sha256_digest(arm64_body.as_bytes());
        let index_body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                 "digest": amd64, "size": 500,
                 "platform": {"os": "linux", "architecture": "amd64"}},
                {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                 "digest": arm64, "size": 500,
                 "platform": {"os": "linux", "architecture": "arm64"}},
            ],
        })
        .to_string();
        let index_digest = sha256_digest(index_body.as_bytes());
        let tamper = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let tampered = tamper.clone();
        let omit_digest_header = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let omitted = omit_digest_header.clone();
        let redirect_hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let evil = redirect_hits.clone();
        let token_hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let token_counted = token_hits.clone();
        let token_always_401 = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped = token_always_401.clone();
        let mock_amd64 = amd64.clone();
        let mock_arm64 = arm64.clone();
        let challenge_base = base.clone();
        tokio::spawn(async move {
            let base = challenge_base;
            use tokio::io::AsyncReadExt;
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                // Read the request head.
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
                let authed_request = head.to_ascii_lowercase().contains("authorization: bearer ");
                let known_repo = head.contains("/v2/library/node/manifests/");
                if head.contains("GET /token") {
                    token_counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if head.to_ascii_lowercase().contains("authorization: basic ") {
                        basic.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    if dropped.load(std::sync::atomic::Ordering::SeqCst) {
                        respond(&mut sock, "401 Unauthorized", "", "").await;
                    } else {
                        respond(&mut sock, "200 OK", "", r#"{"token":"mock-token-123"}"#).await;
                    }
                } else if head.contains("GET /bounce") {
                    // A validated realm bouncing at a second URL: the
                    // client must take the 302 as-is, never follow it.
                    let location = format!("Location: http://{base}/evil-token\r\n");
                    respond(&mut sock, "302 Found", &location, "").await;
                } else if head.contains("GET /evil-token") {
                    evil.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    respond(&mut sock, "200 OK", "", r#"{"token":"evil-token-666"}"#).await;
                } else if !known_repo {
                    respond(&mut sock, "404 Not Found", "", "").await;
                } else if !authed_request {
                    let challenge = format!(
                        "WWW-Authenticate: Bearer realm=\"http://{base}/token\",service=\"mock\",scope=\"repository:library/node:pull\"\r\n"
                    );
                    respond(&mut sock, "401 Unauthorized", &challenge, "").await;
                } else {
                    served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    // Per-arch manifest or tag index, each with the
                    // digest header the client verifies against.
                    let (body, digest) = if head.contains(&amd64) {
                        (amd64_body.as_str(), amd64.as_str())
                    } else if head.contains(&arm64) {
                        (arm64_body.as_str(), arm64.as_str())
                    } else {
                        (index_body.as_str(), index_digest.as_str())
                    };
                    let mut bytes = body.as_bytes().to_vec();
                    if tampered.load(std::sync::atomic::Ordering::SeqCst) {
                        bytes.push(b' ');
                    }
                    let extra = if omitted.load(std::sync::atomic::Ordering::SeqCst) {
                        String::new()
                    } else {
                        format!("Docker-Content-Digest: {digest}\r\n")
                    };
                    let body = String::from_utf8_lossy(&bytes);
                    respond(&mut sock, "200 OK", &extra, &body).await;
                }
            }
        });
        MockRegistry {
            base,
            authed,
            basic_seen,
            amd64: mock_amd64,
            arm64: mock_arm64,
            tamper,
            omit_digest_header,
            redirect_hits,
            token_hits,
            token_always_401,
        }
    }

    #[tokio::test]
    async fn resolve_flows_through_mock_registry() {
        let registry = spawn_mock_registry().await;
        let reference = OciReference::parse(&format!("{}/library/node:20", registry.base)).unwrap();
        let resolved = RegistryClient::new().resolve(&reference).await.unwrap();
        // Host platform won the index (verified digest, not the tag).
        let (_, arch) = host_platform().unwrap();
        let (want, config) = if arch == "amd64" {
            (registry.amd64.clone(), digest(21))
        } else {
            (registry.arm64.clone(), digest(22))
        };
        assert_eq!(resolved.manifest_digest, want);
        assert_eq!(resolved.config.digest, config);
        assert_eq!(resolved.layers.len(), 2);
        assert_eq!(resolved.layers[0].digest, digest(10));
        assert_eq!(resolved.layers[1].size, 2000);
        assert_eq!(resolved.reference, reference);
        // Both manifest fetches carried the bearer token.
        assert_eq!(registry.authed.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn resolve_missing_manifest_fails_cleanly() {
        let registry = spawn_mock_registry().await;
        let missing = OciReference::parse(&format!("{}/library/nope:20", registry.base)).unwrap();
        let err = RegistryClient::new().resolve(&missing).await.unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }

    #[test]
    fn basic_credentials_ride_https_only() {
        let authed =
            RegistryClient::new().with_basic_auth("octocat".to_string(), "gho_x".to_string());
        assert_eq!(authed.basic_for_realm("https"), Some(("octocat", "gho_x")));
        assert_eq!(authed.basic_for_realm("http"), None);
        let anon = RegistryClient::new();
        assert_eq!(anon.basic_for_realm("https"), None);
        assert_eq!(anon.basic_for_realm("http"), None);
    }

    #[test]
    fn manifest_byte_verification_pins_match_and_mismatch() {
        let bytes = br#"{"schemaVersion":2}"#;
        let digest = sha256_digest(bytes);
        assert!(verify_manifest_bytes(bytes, &digest).is_ok());
        let err = verify_manifest_bytes(br#"{"schemaVersion":3}"#, &digest).unwrap_err();
        assert!(err.contains("mismatch"), "{err}");
        assert!(verify_manifest_bytes(bytes, "md5:abc").is_err());
        // Pinned fetches also reject disagreeing headers.
        assert!(verify_pinned_manifest(bytes, &digest, Some(&digest)).is_ok());
        assert!(verify_pinned_manifest(bytes, &digest, None).is_ok());
        let other = sha256_digest(br#"{}"#);
        let err = verify_pinned_manifest(bytes, &digest, Some(&other)).unwrap_err();
        assert!(err.contains("disagrees"), "{err}");
    }

    #[tokio::test]
    async fn resolve_verifies_digest_pinned_manifest() {
        let registry = spawn_mock_registry().await;
        let pinned = registry.amd64.clone();
        let reference =
            OciReference::parse(&format!("{}/library/node@{pinned}", registry.base)).unwrap();
        let resolved = RegistryClient::new().resolve(&reference).await.unwrap();
        assert_eq!(resolved.manifest_digest, pinned);
        assert_eq!(resolved.config.digest, digest(21));
        assert_eq!(resolved.layers.len(), 2);
    }

    #[test]
    fn tag_digest_verifies_header_or_computes_fallback() {
        let bytes = br#"{"schemaVersion":2}"#;
        let digest = sha256_digest(bytes);
        // Present header verifies and wins.
        assert_eq!(tag_manifest_digest(bytes, Some(&digest)).unwrap(), digest);
        let err = tag_manifest_digest(br#"{"schemaVersion":3}"#, Some(&digest)).unwrap_err();
        assert!(err.contains("mismatch"), "{err}");
        // Absent header computes straight from the bytes.
        assert_eq!(tag_manifest_digest(bytes, None).unwrap(), digest);
    }

    #[tokio::test]
    async fn resolve_rejects_tampered_manifest_bytes() {
        let registry = spawn_mock_registry().await;
        registry
            .tamper
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let reference = OciReference::parse(&format!("{}/library/node:20", registry.base)).unwrap();
        let err = RegistryClient::new().resolve(&reference).await.unwrap_err();
        assert!(err.contains("mismatch"), "{err}");
    }

    #[tokio::test]
    async fn resolve_computes_digest_when_header_absent() {
        let registry = spawn_mock_registry().await;
        registry
            .omit_digest_header
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let reference = OciReference::parse(&format!("{}/library/node:20", registry.base)).unwrap();
        // Older registries omit the header: the pull still succeeds,
        // resolving the host platform's verified child digest.
        let resolved = RegistryClient::new().resolve(&reference).await.unwrap();
        let (_, arch) = host_platform().unwrap();
        let want = if arch == "amd64" {
            registry.amd64.clone()
        } else {
            registry.arm64.clone()
        };
        assert_eq!(resolved.manifest_digest, want);
        assert_eq!(resolved.layers.len(), 2);
    }

    #[test]
    fn anonymous_retry_triggers_only_on_rejected_credentials() {
        use reqwest::StatusCode;
        let ok = StatusCode::from_u16(200).unwrap();
        let denied = StatusCode::from_u16(401).unwrap();
        let forbidden = StatusCode::from_u16(403).unwrap();
        let missing = StatusCode::from_u16(404).unwrap();
        // Credentials sent and rejected: one anonymous retry.
        assert!(retry_anonymously(true, denied));
        assert!(retry_anonymously(true, forbidden));
        // Anything else fails loud with no retry.
        assert!(!retry_anonymously(true, ok));
        assert!(!retry_anonymously(true, missing));
        assert!(!retry_anonymously(false, ok));
        assert!(!retry_anonymously(false, denied));
        assert!(!retry_anonymously(false, forbidden));
        assert!(!retry_anonymously(false, missing));
    }

    #[tokio::test]
    async fn anonymous_token_rejection_fails_without_retry() {
        let registry = spawn_mock_registry().await;
        registry
            .token_always_401
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let challenge = BearerChallenge {
            realm: format!("http://{}/token", registry.base),
            service: None,
            scope: Some("repository:library/node:pull".to_string()),
        };
        let err = RegistryClient::new()
            .token_for(&challenge, &registry.base)
            .await
            .unwrap_err();
        assert!(err.contains("401"), "{err}");
        // Exactly one attempt: no retry without credentials, no loop.
        assert_eq!(
            registry
                .token_hits
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn token_requests_never_follow_redirects() {
        let registry = spawn_mock_registry().await;
        let challenge = BearerChallenge {
            realm: format!("http://{}/bounce", registry.base),
            service: None,
            scope: Some("repository:library/node:pull".to_string()),
        };
        // The 302 surfaces as an error; the bounce target is never
        // fetched, so no second URL escapes validation.
        let err = RegistryClient::new()
            .token_for(&challenge, &registry.base)
            .await
            .unwrap_err();
        assert!(err.contains("302"), "{err}");
        assert_eq!(
            registry
                .redirect_hits
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn loopback_token_requests_stay_anonymous() {
        let registry = spawn_mock_registry().await;
        let reference = OciReference::parse(&format!("{}/library/node:20", registry.base)).unwrap();
        // Credentials attached, yet the plaintext loopback realm
        // sees no Authorization header — and the pull still works.
        let resolved = RegistryClient::new()
            .with_basic_auth("octocat".to_string(), "gho_x".to_string())
            .resolve(&reference)
            .await
            .unwrap();
        assert_eq!(resolved.layers.len(), 2);
        assert_eq!(
            registry
                .basic_seen
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
}
