//! Universal CI provider abstraction.
//!
//! Every CI source (GitHub Actions today; GitLab, Bitbucket, local
//! tomorrow) implements [`CiProvider`]. The coordinator polls all
//! registered providers and routes each job to local, peer, or cloud
//! capacity. Provider-specific protocols live in submodules; everything
//! downstream (sandboxing, governance, fleet state) is provider-agnostic.

pub mod bitbucket;
pub mod github;
pub mod gitlab;
pub mod local;

pub use bitbucket::BitbucketProvider;
pub use gitlab::GitlabProvider;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::RwLock;

/// A queued job from any provider, awaiting capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderJob {
    /// Provider-scoped job id (opaque string).
    pub id: String,
    /// Provider name (`CiProvider::name`).
    pub provider: String,
    /// Human-readable job/workflow name.
    pub name: String,
    /// Requested labels/tags (`runs-on` equivalent).
    pub labels: Vec<String>,
}

/// Executable payload claimed from a provider.
#[derive(Debug, Clone)]
pub struct JobPayload {
    pub job_id: String,
    /// Executable steps (argv vectors rendered as strings).
    pub steps: Vec<String>,
    /// Extra environment for the execution sandbox.
    pub env: Vec<(String, String)>,
    /// Working directory override (None = provider default).
    pub work_dir: Option<PathBuf>,
    /// Supervisor kill ceiling for this job.
    pub timeout: Duration,
}

/// Universal CI source: poll → claim → execute → complete.
#[async_trait::async_trait]
pub trait CiProvider: Send + Sync {
    /// Machine-readable provider name ("github", "gitlab", "bitbucket", "local").
    fn name(&self) -> &'static str;
    /// Whether this provider is configured and enabled.
    fn is_enabled(&self) -> bool;
    /// Poll for queued jobs awaiting capacity.
    async fn poll_pending_jobs(&self) -> Result<Vec<ProviderJob>>;
    /// Claim and retrieve the execution payload for a job.
    async fn claim_job(&self, job_id: &str) -> Result<JobPayload>;
    /// Complete a job, reporting success or failure.
    async fn complete_job(&self, job_id: &str, success: bool) -> Result<()>;
}

/// Owned snapshot of a registered provider (returned instead of a
/// reference because boxed trait objects cannot hand out borrows that
/// outlive the registry lock across `.await` points).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderInfo {
    pub name: String,
    pub enabled: bool,
}

/// Registry of CI providers polled by the coordinator.
#[derive(Default)]
pub struct ProviderRegistry {
    providers: Arc<RwLock<Vec<Box<dyn CiProvider>>>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stock registry: local execution plus disabled GitHub/GitLab/
    /// Bitbucket placeholders (enabled once tokens are configured).
    pub async fn default_registry() -> Self {
        let registry = Self::new();
        registry.register(Box::new(local::LocalProvider::new())).await;
        registry.register(Box::new(github::GithubProvider::disabled())).await;
        registry.register(Box::new(GitlabProvider::disabled())).await;
        registry.register(Box::new(BitbucketProvider::disabled())).await;
        registry
    }

    /// Register a provider (replaces any provider with the same name).
    pub async fn register(&self, provider: Box<dyn CiProvider>) {
        let mut guard = self.providers.write().await;
        guard.retain(|p| p.name() != provider.name());
        guard.push(provider);
    }

    /// Names of all enabled providers, in registration order.
    pub async fn active_providers(&self) -> Vec<String> {
        self.providers
            .read()
            .await
            .iter()
            .filter(|p| p.is_enabled())
            .map(|p| p.name().to_string())
            .collect()
    }

    /// Snapshot of one registered provider, if present.
    pub async fn get_provider(&self, name: &str) -> Option<ProviderInfo> {
        self.providers.read().await.iter().find(|p| p.name() == name).map(|p| {
            ProviderInfo { name: p.name().to_string(), enabled: p.is_enabled() }
        })
    }

    /// Poll every enabled provider, concatenating queued jobs.
    /// A failing provider is skipped (error logged) so one outage never
    /// stalls the whole mesh. The read lock is shared, so concurrent polls
    /// proceed; only registration briefly waits on a slow provider.
    pub async fn poll_all(&self) -> Vec<ProviderJob> {
        let count = self.providers.read().await.len();
        let mut jobs = Vec::new();
        for index in 0..count {
            let result = {
                let guard = self.providers.read().await;
                match guard.get(index).filter(|p| p.is_enabled()) {
                    Some(provider) => Some(provider.poll_pending_jobs().await),
                    None => None,
                }
            };
            match result {
                Some(Ok(mut batch)) => jobs.append(&mut batch),
                Some(Err(e)) => eprintln!("runner: provider poll failed: {e:#}"),
                None => {}
            }
        }
        jobs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub {
        name: &'static str,
        enabled: bool,
        jobs: Vec<ProviderJob>,
    }

    #[async_trait::async_trait]
    impl CiProvider for Stub {
        fn name(&self) -> &'static str {
            self.name
        }

        fn is_enabled(&self) -> bool {
            self.enabled
        }

        async fn poll_pending_jobs(&self) -> Result<Vec<ProviderJob>> {
            Ok(self.jobs.clone())
        }

        async fn claim_job(&self, job_id: &str) -> Result<JobPayload> {
            Ok(JobPayload {
                job_id: job_id.to_string(),
                steps: Vec::new(),
                env: Vec::new(),
                work_dir: None,
                timeout: Duration::from_secs(60),
            })
        }

        async fn complete_job(&self, _job_id: &str, _success: bool) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn registry_tracks_and_polls_providers() {
        let registry = ProviderRegistry::new();
        registry
            .register(Box::new(Stub {
                name: "github",
                enabled: true,
                jobs: vec![ProviderJob {
                    id: "1".to_string(),
                    provider: "github".to_string(),
                    name: "ci".to_string(),
                    labels: vec!["runner".to_string()],
                }],
            }))
            .await;
        registry.register(Box::new(Stub { name: "local", enabled: false, jobs: vec![] })).await;

        assert_eq!(registry.active_providers().await, vec!["github".to_string()]);
        let info = registry.get_provider("github").await.unwrap();
        assert!(info.enabled);
        assert!(registry.get_provider("missing").await.is_none());

        let jobs = registry.poll_all().await;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].provider, "github");
    }
}
