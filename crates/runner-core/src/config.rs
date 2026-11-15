//! Host configuration, RBAC policies, and spend caps.
//!
//! Super Admin controls live in `~/.config/runner/config.toml` (written
//! with `0600`: it may hold the mesh signing secret and cloud tokens).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

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

/// Read the GitHub token from the environment (never stored in config).
pub fn github_token_from_env() -> Option<String> {
    std::env::var(GITHUB_TOKEN_ENV)
        .ok()
        .filter(|t| !t.trim().is_empty())
}

/// Default environment file path (`~/.config/runner/env`).
pub fn default_env_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join("runner")
            .join("env")
    })
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
}

/// Intuitive security knobs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecurityProfile {
    #[serde(default)]
    pub air_gapped: Option<bool>,
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
}

/// Resource-governor tuning: CPU PSI `some avg10` bands for the
/// cgroups v2 weight ladder (warning = 25, critical = trickle 1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernorConfig {
    /// Pressure at/above which throttling begins (default 20.0).
    #[serde(default = "default_warn_cpu_psi")]
    pub warn_cpu_psi: f64,
    /// Pressure above which the trickle throttle applies (default 40.0).
    #[serde(default = "default_crit_cpu_psi")]
    pub crit_cpu_psi: f64,
}

fn default_warn_cpu_psi() -> f64 {
    20.0
}

fn default_crit_cpu_psi() -> f64 {
    40.0
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            warn_cpu_psi: default_warn_cpu_psi(),
            crit_cpu_psi: default_crit_cpu_psi(),
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
        }
    }
}

/// Zero-trust security posture.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Air-gapped mode: cloud bursting is refused at the pool.
    #[serde(default)]
    pub air_gapped: bool,
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
    /// Default config file path.
    pub fn default_path() -> Option<PathBuf> {
        std::env::var_os("HOME").map(|home| {
            PathBuf::from(home)
                .join(".config")
                .join("runner")
                .join("config.toml")
        })
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
        config
    }

    /// Persist to the default path with `0600` permissions.
    pub fn save(&self) -> std::io::Result<()> {
        let path = Self::default_path().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no HOME for config path")
        })?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(&path, text)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_listen_port_defaults_off() {
        assert_eq!(RunnerConfig::default().server.listen_port, None);
        let config: RunnerConfig = toml::from_str("[server]\nlisten_port = 9898\n").unwrap();
        assert_eq!(config.server.listen_port, Some(9898));
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
}
