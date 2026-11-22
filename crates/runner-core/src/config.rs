//! Host configuration, RBAC policies, and spend caps.
//!
//! Super Admin controls live in `~/.config/runner/config.toml` (written
//! with `0600`: it may hold the mesh signing secret and cloud tokens).

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Super Admin cloud spend policy + provider credentials.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudPolicy {
    /// Maximum monthly cloud spend in USD (AI agents can never exceed).
    #[serde(default = "default_max_spend")]
    pub max_monthly_spend: f64,
    /// DigitalOcean personal access token (optional: enables DO bursting).
    #[serde(default)]
    pub digitalocean_token: Option<String>,
    /// Render.com API key (optional: enables Render bursting).
    #[serde(default)]
    pub render_token: Option<String>,
    /// Render workspace owner id (required alongside `render_token`).
    #[serde(default)]
    pub render_owner_id: Option<String>,
}

fn default_max_spend() -> f64 {
    0.0
}

impl Default for CloudPolicy {
    fn default() -> Self {
        Self {
            max_monthly_spend: default_max_spend(),
            digitalocean_token: None,
            render_token: None,
            render_owner_id: None,
        }
    }
}

/// Mesh identity: HMAC signing secret for invitation tokens.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Hex-encoded 32-byte secret. Generated on first `mesh invite`.
    #[serde(default)]
    pub secret: Option<String>,
    /// This node's WireGuard private key (base64). Generated on first
    /// `mesh invite` (coordinator) or `join` (peer); the 0600 config
    /// file is its only store — it is never printed after generation.
    #[serde(default)]
    pub node_key: Option<String>,
    /// UDP port for the WAN peer transport. `None` (default) disables
    /// the listener entirely; set it to federate (direct/LAN peers).
    #[serde(default)]
    pub peer_port: Option<u16>,
    /// Coordinator `host:port` for join-announce (joiner side, from
    /// `runner join --coordinator`). Unset on pure coordinators.
    #[serde(default)]
    pub coordinator: Option<String>,
    /// Coordinator WireGuard public key (joiner side, from
    /// `runner join --coordinator-pubkey`). Unset on pure coordinators.
    #[serde(default)]
    pub coordinator_pubkey: Option<String>,
    /// Invitation token (joiner side, stored at join for re-announce;
    /// 0600 file). Expires per its TTL; re-join afterwards.
    #[serde(default)]
    pub join_token: Option<String>,
    /// STUN `host:port` servers for NAT reflexive discovery. `None`
    /// (default) uses the built-in Google + Cloudflare pair; an
    /// explicit empty list disables STUN (observed-source routing
    /// still works; same-subnet dialing still works).
    #[serde(default)]
    pub stun_servers: Option<Vec<String>>,
}

/// Donor caps applied when this host serves foreign jobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DonorConfig {
    pub max_cores: u32,
    pub max_ram_mb: u64,
}

/// Persisted WAN peer record (written by `runner join`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    pub node_id: String,
    pub public_key: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    pub max_cores: u32,
    pub max_ram_mb: u64,
    #[serde(default = "default_peer_status")]
    pub status: String,
}

fn default_peer_status() -> String {
    "joining".to_string()
}

/// Coordinator queue polling + dispatch policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoordinatorConfig {
    /// Repository owner for queue polling (requires `repo_name`).
    #[serde(default)]
    pub repo_owner: Option<String>,
    /// Repository name for queue polling.
    #[serde(default)]
    pub repo_name: Option<String>,
    /// Poll cadence in seconds.
    #[serde(default = "default_poll_secs")]
    pub poll_secs: u64,
    /// Launch sandboxes for routed jobs (off = log routing only).
    #[serde(default)]
    pub auto_dispatch: bool,
    /// GitHub runner group id for JIT issuance (1 = Default).
    #[serde(default = "default_runner_group")]
    pub runner_group_id: u64,
    /// Worker package version to cache.
    #[serde(default = "default_worker_version")]
    pub worker_version: String,
    /// Maximum execution duration for a single job before supervisor kill.
    #[serde(default = "default_job_timeout_mins")]
    pub job_timeout_mins: u64,
}

fn default_poll_secs() -> u64 {
    15
}

fn default_runner_group() -> u64 {
    1
}

fn default_worker_version() -> String {
    "2.338.2".to_string()
}

fn default_job_timeout_mins() -> u64 {
    60
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            repo_owner: None,
            repo_name: None,
            poll_secs: default_poll_secs(),
            auto_dispatch: false,
            runner_group_id: default_runner_group(),
            worker_version: default_worker_version(),
            job_timeout_mins: default_job_timeout_mins(),
        }
    }
}

/// Native GitLab CI runner settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GitlabConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_gitlab_url")]
    pub url: String,
    #[serde(default)]
    pub runner_token: String,
    #[serde(default = "default_gitlab_poll_secs")]
    pub poll_secs: u64,
    #[serde(default = "default_gitlab_tags")]
    pub tags: Vec<String>,
}

fn default_false() -> bool {
    false
}

fn default_true() -> bool {
    true
}

fn default_gitlab_url() -> String {
    "https://gitlab.com".to_string()
}

fn default_gitlab_poll_secs() -> u64 {
    10
}

fn default_gitlab_tags() -> Vec<String> {
    vec![
        "zero-freeze".to_string(),
        "linux".to_string(),
        "runner".to_string(),
    ]
}

impl Default for GitlabConfig {
    fn default() -> Self {
        Self {
            enabled: default_false(),
            url: default_gitlab_url(),
            runner_token: String::new(),
            poll_secs: default_gitlab_poll_secs(),
            tags: default_gitlab_tags(),
        }
    }
}

/// Native Bitbucket Pipelines runner settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BitbucketConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub workspace: String,
    #[serde(default)]
    pub repo_slug: String,
    #[serde(default)]
    pub runner_uuid: String,
    #[serde(default)]
    pub oauth_client_id: String,
    #[serde(default)]
    pub oauth_client_secret: String,
    #[serde(default = "default_bitbucket_poll_secs")]
    pub poll_secs: u64,
    #[serde(default = "default_bitbucket_labels")]
    pub labels: Vec<String>,
}

fn default_bitbucket_poll_secs() -> u64 {
    10
}

fn default_bitbucket_labels() -> Vec<String> {
    vec![
        "zero-freeze".to_string(),
        "linux".to_string(),
        "runner".to_string(),
    ]
}

impl Default for BitbucketConfig {
    fn default() -> Self {
        Self {
            enabled: default_false(),
            workspace: String::new(),
            repo_slug: String::new(),
            runner_uuid: String::new(),
            oauth_client_id: String::new(),
            oauth_client_secret: String::new(),
            poll_secs: default_bitbucket_poll_secs(),
            labels: default_bitbucket_labels(),
        }
    }
}

/// Env var carrying the GitHub token (`administration:write` for JIT).
pub const GITHUB_TOKEN_ENV: &str = "RUNNER_GITHUB_TOKEN";
pub const GITLAB_TOKEN_ENV: &str = "RUNNER_GITLAB_TOKEN";
pub const BITBUCKET_CLIENT_ID_ENV: &str = "RUNNER_BITBUCKET_CLIENT_ID";
pub const BITBUCKET_CLIENT_SECRET_ENV: &str = "RUNNER_BITBUCKET_CLIENT_SECRET";

/// Read the GitHub token from the environment (never stored in config).
pub fn github_token_from_env() -> Option<String> {
    token_from_env(GITHUB_TOKEN_ENV)
}

/// Read the GitLab runner token from the environment.
pub fn gitlab_token_from_env() -> Option<String> {
    token_from_env(GITLAB_TOKEN_ENV)
}

/// Read the Bitbucket OAuth client id from the environment.
pub fn bitbucket_client_id_from_env() -> Option<String> {
    token_from_env(BITBUCKET_CLIENT_ID_ENV)
}

/// Read the Bitbucket OAuth client secret from the environment.
pub fn bitbucket_client_secret_from_env() -> Option<String> {
    token_from_env(BITBUCKET_CLIENT_SECRET_ENV)
}

fn token_from_env(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|t| !t.trim().is_empty())
}

/// Default environment file path (`~/.config/runner/env`,
/// `%APPDATA%\runner\env` on Windows).
pub fn default_env_path() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(|home| {
            PathBuf::from(home)
                .join(".config")
                .join("runner")
                .join("env")
        })
    }
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(|dir| PathBuf::from(dir).join("runner").join("env"))
    }
}

/// Parse shell-style `KEY=value` lines (comments, blanks, `export ` prefix,
/// and surrounding single/double quotes handled). Malformed lines are skipped.
pub fn parse_env_file(text: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for raw_line in text.lines() {
        let mut line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("export ")
            .or_else(|| line.strip_prefix("export\t"))
        {
            line = rest.trim_start();
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || key.chars().any(char::is_whitespace) {
            continue;
        }
        let mut value = value.trim().to_string();
        if value.len() >= 2 {
            let bytes = value.as_bytes();
            let (first, last) = (bytes[0], bytes[value.len() - 1]);
            if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
                value = value[1..value.len() - 1].to_string();
            }
        }
        pairs.push((key.to_string(), value));
    }
    pairs
}

/// Load variables from the given env file, never overwriting variables that
/// are already set. Missing/unreadable files load nothing. Returns the number
/// of variables newly set.
pub fn load_env_file_from(path: &std::path::Path) -> usize {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => return 0,
    };
    let mut loaded = 0;
    for (key, value) in parse_env_file(&text) {
        if std::env::var_os(&key).is_none() {
            std::env::set_var(&key, &value);
            loaded += 1;
        }
    }
    loaded
}

/// Load `~/.config/runner/env` on startup when present, without overwriting
/// existing environment variables. Returns the number newly set.
pub fn load_env_file() -> usize {
    default_env_path()
        .map(|path| load_env_file_from(&path))
        .unwrap_or(0)
}

/// Open-core edition selector for `runner.toml` profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileMode {
    /// Indie developers & agents: lightweight local execution.
    #[default]
    Local,
    /// Platform teams: hardened multi-provider mesh.
    Enterprise,
}

/// Intuitive governor knobs. `max_cpu_percent` is the CPU pressure level
/// (`some avg10`) at which throttling begins — i.e. the warn threshold.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GovernorProfile {
    #[serde(default)]
    pub max_cpu_percent: Option<f64>,
    #[serde(default)]
    pub crit_cpu_psi: Option<f64>,
}

/// Intuitive sandbox knobs (Tier-1 image paths for `microvm`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SandboxProfile {
    #[serde(default)]
    pub driver: Option<String>,
    #[serde(default)]
    pub kernel_path: Option<PathBuf>,
    #[serde(default)]
    pub rootfs_path: Option<PathBuf>,
    #[serde(default)]
    pub firecracker_bin: Option<PathBuf>,
    #[serde(default)]
    pub strict: Option<bool>,
}

/// Intuitive security knobs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecurityProfile {
    #[serde(default)]
    pub air_gapped: Option<bool>,
    #[serde(default)]
    pub network_egress_filtering: Option<bool>,
}

/// Intuitive `runner.toml` profile. Layering precedence (highest first):
/// `runner.toml` sections, then `config.toml`, then built-in defaults.
/// `mode` selects the sandbox tier default when no explicit `driver` is
/// set (`local` -> `process`, `enterprise` -> `microvm`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RunnerProfile {
    #[serde(default)]
    pub mode: ProfileMode,
    #[serde(default)]
    pub governor: Option<GovernorProfile>,
    #[serde(default)]
    pub sandbox: Option<SandboxProfile>,
    #[serde(default)]
    pub security: Option<SecurityProfile>,
}

/// Default profile path (`~/.config/runner/runner.toml`).
pub fn default_profile_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join("runner")
            .join("runner.toml")
    })
}

/// Effective open-core mode: the `runner.toml` mode when a valid profile
/// exists, otherwise [`ProfileMode::Local`]. Never fails.
pub fn effective_mode() -> ProfileMode {
    default_profile_path()
        .filter(|p| p.exists())
        .and_then(|p| load_profile_from(&p).ok())
        .map(|profile| profile.mode)
        .unwrap_or_default()
}

/// Parse a profile file. Unknown `mode` values fail the parse (validated).
pub fn load_profile_from(path: &std::path::Path) -> Result<RunnerProfile, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read profile: {e}"))?;
    toml::from_str(&text).map_err(|e| format!("parse profile: {e}"))
}

impl RunnerProfile {
    /// Apply this profile onto a config, returning human-readable warnings
    /// for rejected values (previous values are kept on rejection).
    pub fn apply_to(&self, config: &mut RunnerConfig) -> Vec<String> {
        let mut warnings = Vec::new();
        match &self.sandbox {
            Some(sandbox) => {
                if let Some(driver) = &sandbox.driver {
                    match driver.trim().to_ascii_lowercase().as_str() {
                        "process" | "microvm" => {
                            config.sandbox.driver = driver.trim().to_ascii_lowercase();
                        }
                        other => warnings.push(format!(
                            "runner.toml: ignoring unknown sandbox driver '{other}'"
                        )),
                    }
                }
                if let Some(path) = &sandbox.kernel_path {
                    config.sandbox.kernel_path = Some(path.clone());
                }
                if let Some(path) = &sandbox.rootfs_path {
                    config.sandbox.rootfs_path = Some(path.clone());
                }
                if let Some(path) = &sandbox.firecracker_bin {
                    config.sandbox.firecracker_bin = Some(path.clone());
                }
                if let Some(strict) = sandbox.strict {
                    config.sandbox.strict = strict;
                }
            }
            None => {
                config.sandbox.driver = match self.mode {
                    ProfileMode::Local => "process".to_string(),
                    ProfileMode::Enterprise => "microvm".to_string(),
                };
            }
        }
        if let Some(governor) = &self.governor {
            if let Some(max) = governor.max_cpu_percent {
                if max > 0.0 && max <= 100.0 {
                    config.governor.warn_cpu_psi = max;
                } else {
                    warnings.push(format!(
                        "runner.toml: ignoring out-of-range governor.max_cpu_percent={max}"
                    ));
                }
            }
            if let Some(crit) = governor.crit_cpu_psi {
                if crit > config.governor.warn_cpu_psi && crit <= 100.0 {
                    config.governor.crit_cpu_psi = crit;
                } else {
                    warnings.push(format!(
                        "runner.toml: ignoring crit_cpu_psi={crit} (must exceed warn {})",
                        config.governor.warn_cpu_psi
                    ));
                }
            }
        }
        if let Some(security) = &self.security {
            if let Some(air_gapped) = security.air_gapped {
                config.security.air_gapped = air_gapped;
            }
            if let Some(filtering) = security.network_egress_filtering {
                config.security.network_egress_filtering = filtering;
            }
        }
        warnings
    }
}

/// Top-level supervisor configuration.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RunnerConfig {
    #[serde(default)]
    pub org: Option<String>,
    #[serde(default)]
    pub cloud: CloudPolicy,
    #[serde(default)]
    pub mesh: MeshConfig,
    #[serde(default)]
    pub donor: Option<DonorConfig>,
    #[serde(default)]
    pub peers: Vec<PeerRecord>,
    #[serde(default)]
    pub coordinator: CoordinatorConfig,
    #[serde(default)]
    pub gitlab: GitlabConfig,
    #[serde(default)]
    pub bitbucket: BitbucketConfig,
    #[serde(default)]
    pub governor: GovernorConfig,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub power: PowerConfig,
}

/// Power management: clamshell keep-alive while AC-powered jobs run.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PowerConfig {
    /// Keep the host awake while AC power is connected and active jobs are running.
    #[serde(default)]
    pub prevent_sleep_on_ac: bool,
}

/// Transparent LAN cache proxy (`ACTIONS_CACHE_URL`) settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Listen address for the cache proxy (default 127.0.0.1:8787).
    #[serde(default = "default_cache_listen")]
    pub listen: String,
    /// Store directory override (default `~/.runner/cache/`).
    #[serde(default)]
    pub dir: String,
    /// Disk budget in GiB before LRU eviction (default 10).
    #[serde(default = "default_cache_max_size_gb")]
    pub max_size_gb: u64,
    /// Entry age in seconds before the background sweep evicts it
    /// (default 604800 = 7 days; 0 disables the sweep).
    #[serde(default = "default_cache_ttl_secs")]
    pub ttl_secs: u64,
    /// Background TTL sweep cadence in seconds (default 3600,
    /// clamped to a 60s floor).
    #[serde(default = "default_cache_sweep_secs")]
    pub sweep_secs: u64,
}

fn default_cache_listen() -> String {
    "127.0.0.1:8787".to_string()
}

fn default_cache_max_size_gb() -> u64 {
    10
}

fn default_cache_ttl_secs() -> u64 {
    604_800
}

fn default_cache_sweep_secs() -> u64 {
    3600
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            listen: default_cache_listen(),
            dir: String::new(),
            max_size_gb: default_cache_max_size_gb(),
            ttl_secs: default_cache_ttl_secs(),
            sweep_secs: default_cache_sweep_secs(),
        }
    }
}

/// Resolve the cache directory: explicit `[cache] dir` wins, else
/// `~/.runner/cache/` (`%APPDATA%\runner\cache` on Windows, current
/// dir fallback when neither home variable exists).
pub fn resolve_cache_dir(config: &CacheConfig) -> std::path::PathBuf {
    if !config.dir.trim().is_empty() {
        return std::path::PathBuf::from(config.dir.trim());
    }
    #[cfg(unix)]
    let home = std::env::var_os("HOME")
        .map(|home| std::path::PathBuf::from(home).join(".runner").join("cache"));
    #[cfg(windows)]
    let home = std::env::var_os("APPDATA")
        .map(|dir| std::path::PathBuf::from(dir).join("runner").join("cache"));
    home.unwrap_or_else(|| std::path::PathBuf::from(".runner-cache"))
}

/// Resource-governor tuning: CPU PSI `some avg10` bands for the
/// cgroups v2 weight ladder (warning = 25, critical = trickle 1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernorConfig {
    /// Pressure at/above which throttling begins (default 20.0;
    /// on Windows this is CPU busy %, default 75.0).
    #[serde(default = "default_warn_cpu_psi")]
    pub warn_cpu_psi: f64,
    /// Pressure above which the trickle throttle applies (default 40.0;
    /// on Windows this is CPU busy %, default 90.0).
    #[serde(default = "default_crit_cpu_psi")]
    pub crit_cpu_psi: f64,
    /// AFK boost mode: `auto`, `always`, or `never` (default `auto`).
    #[serde(default = "default_afk_mode")]
    pub afk_mode: String,
    /// Desktop idle seconds before AFK boost engages (default 300).
    #[serde(default = "default_afk_idle_seconds")]
    pub afk_idle_seconds: u64,
}

fn default_warn_cpu_psi() -> f64 {
    20.0
}

fn default_crit_cpu_psi() -> f64 {
    40.0
}

fn default_afk_mode() -> String {
    "auto".to_string()
}

fn default_afk_idle_seconds() -> u64 {
    300
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            warn_cpu_psi: default_warn_cpu_psi(),
            crit_cpu_psi: default_crit_cpu_psi(),
            afk_mode: default_afk_mode(),
            afk_idle_seconds: default_afk_idle_seconds(),
        }
    }
}

/// Sandbox tier selection + Tier-1 microVM images.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// `process` (community namespaces) or `microvm` (enterprise Firecracker).
    #[serde(default = "default_sandbox_driver")]
    pub driver: String,
    /// Guest kernel (`vmlinux`) for the microVM tier.
    #[serde(default)]
    pub kernel_path: Option<PathBuf>,
    /// Guest rootfs image for the microVM tier.
    #[serde(default)]
    pub rootfs_path: Option<PathBuf>,
    /// Firecracker binary (default: `firecracker` on PATH).
    #[serde(default)]
    pub firecracker_bin: Option<PathBuf>,
    /// Fail closed instead of running unsandboxed when Tier-2 is
    /// unavailable (see [`is_strict`]).
    #[serde(default)]
    pub strict: bool,
}

fn default_sandbox_driver() -> String {
    "process".to_string()
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            driver: default_sandbox_driver(),
            kernel_path: None,
            rootfs_path: None,
            firecracker_bin: None,
            strict: false,
        }
    }
}

/// Effective strict mode: the explicit CLI flag, the sandbox config,
/// or the `RUNNER_STRICT` environment override (`1`/`true`).
pub fn is_strict(explicit_flag: bool, config: &RunnerConfig) -> bool {
    explicit_flag
        || config.sandbox.strict
        || std::env::var("RUNNER_STRICT")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false)
}

/// Zero-trust security posture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Air-gapped mode: cloud bursting is refused at the pool.
    #[serde(default)]
    pub air_gapped: bool,
    /// Enforce outbound network boundary (block private/metadata, allow DNS/HTTPS).
    #[serde(default = "default_true")]
    pub network_egress_filtering: bool,
}

impl Default for SecurityConfig {
    /// Secure by default, matching the serde default: filtering is on
    /// unless explicitly disabled in either construction path.
    fn default() -> Self {
        Self {
            air_gapped: false,
            network_egress_filtering: true,
        }
    }
}

/// Embedded webhook listener for instant dispatch.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 127.0.0.1 port for the HMAC-verified webhook listener.
    /// `None` (default) disables the embedded listener; the secret always
    /// comes from `RUNNER_WEBHOOK_SECRET`, never from config files.
    #[serde(default)]
    pub listen_port: Option<u16>,
}

impl RunnerConfig {
    /// Default config file path (`%APPDATA%\runner\config.toml` on Windows).
    pub fn default_path() -> Option<PathBuf> {
        #[cfg(unix)]
        {
            std::env::var_os("HOME").map(|home| {
                PathBuf::from(home)
                    .join(".config")
                    .join("runner")
                    .join("config.toml")
            })
        }
        #[cfg(windows)]
        {
            std::env::var_os("APPDATA")
                .map(|dir| PathBuf::from(dir).join("runner").join("config.toml"))
        }
    }

    /// Load from disk, falling back to defaults when missing, then
    /// layer `runner.toml` on top when present (with warnings for
    /// rejected values). A malformed profile never blocks startup.
    pub fn load_or_default() -> Self {
        let mut config: Self = Self::default_path()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|text| toml::from_str(&text).ok())
            .unwrap_or_default();
        if let Some(path) = default_profile_path().filter(|p| p.exists()) {
            match load_profile_from(&path) {
                Ok(profile) => {
                    for warning in profile.apply_to(&mut config) {
                        eprintln!("runner: {warning}");
                    }
                }
                Err(e) => eprintln!("runner: ignoring {} ({e})", path.display()),
            }
        }
        // Secrets overlay: environment (populated from the 0600 env file
        // by the daemon, or `runner auth`) fills blank token fields.
        // File values win; `Default()` stays pure for hermetic tests.
        if config.gitlab.runner_token.trim().is_empty() {
            if let Some(token) = gitlab_token_from_env() {
                config.gitlab.runner_token = token;
            }
        }
        if config.bitbucket.oauth_client_id.trim().is_empty() {
            if let Some(id) = bitbucket_client_id_from_env() {
                config.bitbucket.oauth_client_id = id;
            }
        }
        if config.bitbucket.oauth_client_secret.trim().is_empty() {
            if let Some(secret) = bitbucket_client_secret_from_env() {
                config.bitbucket.oauth_client_secret = secret;
            }
        }
        config
    }

    /// Load from an explicit path (used by `init`; hermetic, no `$HOME`).
    pub fn load_from(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
    }

    /// Persist to an explicit path with `0600` permissions
    /// (owner-only DACL on Windows).
    pub fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(path, text)?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        #[cfg(windows)]
        crate::winacl::restrict_to_owner(path)?;
        Ok(())
    }

    /// Persist to the default path with `0600` permissions.
    pub fn save(&self) -> std::io::Result<()> {
        let path = Self::default_path().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no HOME for config path")
        })?;
        self.save_to(&path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_to_round_trip_is_private() {
        let dir = crate::test_support::TempDir::new("config-save").unwrap();
        let path = dir.path().join("sub").join("config.toml");
        let mut config = RunnerConfig {
            org: Some("acme".to_string()),
            ..RunnerConfig::default()
        };
        config.save_to(&path).unwrap();
        let loaded = RunnerConfig::load_from(&path).unwrap();
        assert_eq!(loaded.org.as_deref(), Some("acme"));
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // Windows proves the same privacy via DACL, not modes.
        #[cfg(windows)]
        {
            use crate::winacl::{read_dacl_sids, DaclTarget};
            assert_eq!(read_dacl_sids(DaclTarget::File(&path)).unwrap().len(), 2);
        }
        // Re-saving over the file keeps working (the `init` merge path).
        config.coordinator.repo_name = Some("web".to_string());
        config.save_to(&path).unwrap();
        let reloaded = RunnerConfig::load_from(&path).unwrap();
        assert_eq!(reloaded.coordinator.repo_name.as_deref(), Some("web"));
        assert_eq!(reloaded.org.as_deref(), Some("acme"));
    }

    #[test]
    fn server_listen_port_defaults_off() {
        assert_eq!(RunnerConfig::default().server.listen_port, None);
        let config: RunnerConfig = toml::from_str("[server]\nlisten_port = 9898\n").unwrap();
        assert_eq!(config.server.listen_port, Some(9898));
    }

    #[test]
    fn power_prevent_sleep_defaults_off_and_parses() {
        assert!(!RunnerConfig::default().power.prevent_sleep_on_ac);
        let config: RunnerConfig = toml::from_str("[power]\nprevent_sleep_on_ac = true\n").unwrap();
        assert!(config.power.prevent_sleep_on_ac);
    }

    #[test]
    fn job_timeout_defaults_to_sixty_minutes() {
        assert_eq!(CoordinatorConfig::default().job_timeout_mins, 60);
        // Missing field in existing configs deserializes to the default.
        let config: RunnerConfig = toml::from_str("[coordinator]\nauto_dispatch = true\n").unwrap();
        assert_eq!(config.coordinator.job_timeout_mins, 60);
        assert_eq!(config.coordinator.poll_secs, 15);
    }

    #[test]
    fn env_file_parser_handles_shell_conventions() {
        let text = "# comment\n\nexport RUNNER_GITHUB_TOKEN=\"ghp_secret==\"\nPLAIN=1\nSINGLE='a=b'\nEMPTY=\nBAD LINE\nNOEQUALS\n";
        let pairs = parse_env_file(text);
        assert_eq!(
            pairs,
            vec![
                (
                    "RUNNER_GITHUB_TOKEN".to_string(),
                    "ghp_secret==".to_string()
                ),
                ("PLAIN".to_string(), "1".to_string()),
                ("SINGLE".to_string(), "a=b".to_string()),
                ("EMPTY".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn profile_modes_select_sandbox_tier_defaults() {
        let local: RunnerProfile = toml::from_str("mode = \"local\"\n").unwrap();
        let mut config = RunnerConfig::default();
        assert!(local.apply_to(&mut config).is_empty());
        assert_eq!(config.sandbox.driver, "process");

        let enterprise: RunnerProfile = toml::from_str("mode = \"enterprise\"\n").unwrap();
        let mut config = RunnerConfig::default();
        assert!(enterprise.apply_to(&mut config).is_empty());
        assert_eq!(config.sandbox.driver, "microvm");

        // Unknown modes fail validation.
        assert!(toml::from_str::<RunnerProfile>("mode = \"turbo\"\n").is_err());
    }

    #[test]
    fn profile_sections_apply_with_rejection_warnings() {
        let profile: RunnerProfile = toml::from_str(
            "[governor]\nmax_cpu_percent = 70\ncrit_cpu_psi = 90\n\
             [sandbox]\ndriver = \"process\"\n\
             [security]\nair_gapped = true\n",
        )
        .unwrap();
        let mut config = RunnerConfig::default();
        assert!(profile.apply_to(&mut config).is_empty());
        assert_eq!(config.governor.warn_cpu_psi, 70.0);
        assert_eq!(config.governor.crit_cpu_psi, 90.0);
        assert_eq!(config.sandbox.driver, "process");
        assert!(config.security.air_gapped);

        // Invalid values warn and keep previous settings.
        let bad: RunnerProfile = toml::from_str(
            "[governor]\nmax_cpu_percent = 500\ncrit_cpu_psi = 10\n[sandbox]\ndriver = \"gvisor\"\n",
        )
        .unwrap();
        let warnings = bad.apply_to(&mut config);
        assert_eq!(warnings.len(), 3);
        assert_eq!(config.governor.warn_cpu_psi, 70.0);
        assert_eq!(config.governor.crit_cpu_psi, 90.0);
        assert_eq!(config.sandbox.driver, "process");
    }

    #[test]
    fn egress_filtering_defaults_on_until_disabled() {
        // Missing key and Rust default both enforce (secure default).
        let missing: SecurityConfig = toml::from_str("").unwrap();
        assert!(missing.network_egress_filtering);
        assert!(SecurityConfig::default().network_egress_filtering);
        // Explicit opt-out in either file layer disables.
        let off: SecurityConfig = toml::from_str("network_egress_filtering = false").unwrap();
        assert!(!off.network_egress_filtering);
        let profile: RunnerProfile =
            toml::from_str("[security]\nnetwork_egress_filtering = false\n").unwrap();
        let mut config = RunnerConfig::default();
        assert!(profile.apply_to(&mut config).is_empty());
        assert!(!config.security.network_egress_filtering);
    }

    #[test]
    fn env_file_load_never_overwrites_existing_vars() {
        let dir = crate::test_support::TempDir::new("runner-env-load").unwrap();
        let path = dir.path().join("env");
        fs::write(
            &path,
            "RUNNER_TEST_ENV_SENTINEL=from-file\nRUNNER_TEST_ENV_FRESH=from-file\n",
        )
        .unwrap();

        let sentinel_key = "RUNNER_TEST_ENV_SENTINEL";
        let fresh_key = "RUNNER_TEST_ENV_FRESH";
        let prior_sentinel = std::env::var_os(sentinel_key);
        let prior_fresh = std::env::var_os(fresh_key);
        std::env::set_var(sentinel_key, "sentinel");
        std::env::remove_var(fresh_key);

        let loaded = load_env_file_from(&path);
        assert_eq!(loaded, 1);
        assert_eq!(std::env::var(sentinel_key).unwrap(), "sentinel");
        assert_eq!(std::env::var(fresh_key).unwrap(), "from-file");

        // Missing file loads nothing and does not fail.
        assert_eq!(load_env_file_from(&dir.path().join("absent")), 0);

        match prior_sentinel {
            Some(v) => std::env::set_var(sentinel_key, v),
            None => std::env::remove_var(sentinel_key),
        }
        match prior_fresh {
            Some(v) => std::env::set_var(fresh_key, v),
            None => std::env::remove_var(fresh_key),
        }
    }

    #[test]
    fn stun_servers_default_override_and_disable() {
        use crate::mesh::stun::{stun_servers, DEFAULT_STUN_SERVERS};

        // Unset: built-in Google + Cloudflare pair.
        let unset = MeshConfig::default();
        assert_eq!(unset.stun_servers, None);
        let effective = stun_servers(&unset);
        assert_eq!(effective.len(), DEFAULT_STUN_SERVERS.len());
        assert!(effective.iter().any(|s| s.contains("google")));
        assert!(effective.iter().any(|s| s.contains("cloudflare")));

        // Explicit override wins.
        let custom: RunnerConfig =
            toml::from_str("[mesh]\nstun_servers = [\"stun.example.com:3478\"]\n").unwrap();
        assert_eq!(
            stun_servers(&custom.mesh),
            vec!["stun.example.com:3478".to_string()]
        );

        // Explicit empty list disables STUN.
        let off: RunnerConfig = toml::from_str("[mesh]\nstun_servers = []\n").unwrap();
        assert_eq!(off.mesh.stun_servers, Some(vec![]));
        assert!(stun_servers(&off.mesh).is_empty());
    }
}
