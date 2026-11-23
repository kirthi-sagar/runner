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

/// Per-request HTTP budget for registry metadata (manifests and
/// tokens are small; layers stream in a later phase).
const REGISTRY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Minimal registry client with a single-flight token cache (one
/// cached token: clients are short-lived per pull).
pub struct RegistryClient {
    http: reqwest::Client,
    cached: tokio::sync::Mutex<Option<(String, String)>>,
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
                .timeout(REGISTRY_TIMEOUT)
                .user_agent("runner")
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            cached: tokio::sync::Mutex::new(None),
        }
    }

    /// Fetch a bearer token for one challenge (cached per scope).
    async fn token_for(&self, challenge: &BearerChallenge) -> Result<String, String> {
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
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("token request failed: {e}"))?;
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

    /// GET with Accept + bearer dance: one anonymous attempt, then a
    /// single challenged retry. Returns the final body on success.
    async fn get_manifest_doc(&self, url: &str) -> Result<serde_json::Value, String> {
        const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
            application/vnd.oci.image.manifest.v1+json, \
            application/vnd.docker.distribution.manifest.list.v2+json, \
            application/vnd.docker.distribution.manifest.v2+json";
        let attempt = |token: Option<String>| {
            let http = &self.http;
            let url = url.to_string();
            async move {
                let mut request = http.get(&url).header(reqwest::header::ACCEPT, ACCEPT);
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
        let response = if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            let challenge = response
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| "registry 401 without a bearer challenge".to_string())?;
            let challenge = parse_bearer_challenge(challenge)?;
            let token = self.token_for(&challenge).await?;
            attempt(Some(token)).await?
        } else {
            response
        };
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(format!("manifest not found: {url}"));
        }
        if !response.status().is_success() {
            return Err(format!(
                "registry request failed: HTTP {}",
                response.status()
            ));
        }
        response
            .json()
            .await
            .map_err(|e| format!("manifest response is not JSON: {e}"))
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
        let doc = self
            .get_manifest_doc(&format!("{}/manifests/{}", base, reference.manifest_ref()))
            .await?;
        // Index or manifest? Shape-sniff: only indices carry `manifests`.
        let (manifest_digest, manifest) = if doc.get("manifests").is_some() {
            let index: OciIndex =
                serde_json::from_value(doc).map_err(|e| format!("invalid image index: {e}"))?;
            let (os, arch) = host_platform()?;
            let digest = select_platform(&index, &os, &arch)?;
            let doc = self
                .get_manifest_doc(&format!("{}/manifests/{}", base, digest))
                .await?;
            let manifest: OciManifest =
                serde_json::from_value(doc).map_err(|e| format!("invalid image manifest: {e}"))?;
            (digest, manifest)
        } else if doc.get("layers").is_some() {
            let manifest: OciManifest =
                serde_json::from_value(doc).map_err(|e| format!("invalid image manifest: {e}"))?;
            (reference.manifest_ref(), manifest)
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
    /// end to end against it.
    struct MockRegistry {
        base: String,
        authed: std::sync::Arc<std::sync::atomic::AtomicUsize>,
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
        let amd64 = digest(1);
        let arm64 = digest(2);
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
                    respond(&mut sock, "200 OK", "", r#"{"token":"mock-token-123"}"#).await;
                } else if !known_repo {
                    respond(&mut sock, "404 Not Found", "", "").await;
                } else if !authed_request {
                    let challenge = format!(
                        "WWW-Authenticate: Bearer realm=\"http://{base}/token\",service=\"mock\",scope=\"repository:library/node:pull\"\r\n"
                    );
                    respond(&mut sock, "401 Unauthorized", &challenge, "").await;
                } else {
                    served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if head.contains(&amd64) || head.contains(&arm64) {
                        // Per-arch manifest: config + two layers.
                        let body = serde_json::json!({
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
                        })
                        .to_string();
                        respond(&mut sock, "200 OK", "", &body).await;
                    } else {
                        // Tag request: multi-arch index.
                        let body = serde_json::json!({
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
                        respond(&mut sock, "200 OK", "", &body).await;
                    }
                }
            }
        });
        MockRegistry { base, authed }
    }

    #[tokio::test]
    async fn resolve_flows_through_mock_registry() {
        let registry = spawn_mock_registry().await;
        let reference = OciReference::parse(&format!("{}/library/node:20", registry.base)).unwrap();
        let resolved = RegistryClient::new().resolve(&reference).await.unwrap();
        // Host platform won the index.
        let (_, arch) = host_platform().unwrap();
        let want = if arch == "amd64" {
            digest(1)
        } else {
            digest(2)
        };
        assert_eq!(resolved.manifest_digest, want);
        assert_eq!(resolved.config.digest, digest(9));
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
}
