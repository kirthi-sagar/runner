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
    vec!["zero-freeze".to_string(), "linux".to_string(), "runner".to_string()]
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
    vec!["zero-freeze".to_string(), "linux".to_string(), "runner".to_string()]
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
    std::env::var(GITHUB_TOKEN_ENV).ok().filter(|t| !t.trim().is_empty())
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

    /// Load from disk, falling back to defaults when missing.
    pub fn load_or_default() -> Self {
        Self::default_path()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|text| toml::from_str(&text).ok())
            .unwrap_or_default()
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
    fn job_timeout_defaults_to_sixty_minutes() {
        assert_eq!(CoordinatorConfig::default().job_timeout_mins, 60);
        // Missing field in existing configs deserializes to the default.
        let config: RunnerConfig = toml::from_str("[coordinator]\nauto_dispatch = true\n").unwrap();
        assert_eq!(config.coordinator.job_timeout_mins, 60);
        assert_eq!(config.coordinator.poll_secs, 15);
    }
}
