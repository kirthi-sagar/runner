//! GitHub Actions provider: [`CiProvider`] adapter over the existing
//! GitHub client + coordinator queue logic.
//!
//! Thin by design — all protocol behavior (JIT issuance, queue parsing,
//! routing) stays in `src/github/` untouched, so every existing workflow
//! and test keeps passing byte-for-byte.

use anyhow::{Context, Result};

use super::{CiProvider, JobPayload, ProviderJob};
use crate::github::client::GithubClient;
use crate::github::jit::{JitRequest, generate_org_jit, generate_repo_jit};
use crate::github::webhooks::{JitScope, QueuePoller, QueuedJob};

/// Convert a coordinator job into the provider-agnostic shape.
pub fn to_provider_job(job: &QueuedJob) -> ProviderJob {
    ProviderJob {
        id: job.id.to_string(),
        provider: "github".to_string(),
        name: job.name.clone(),
        labels: job.labels.clone(),
    }
}

/// GitHub Actions provider (org or single-repo scope).
pub struct GithubProvider {
    client: Option<GithubClient>,
    poller: Option<QueuePoller>,
    scope: JitScope,
    runner_group_id: u64,
    timeout: std::time::Duration,
}

impl GithubProvider {
    /// Fully configured provider: polls `owner/repo` and issues JIT configs.
    pub fn new(
        client: GithubClient,
        owner: impl Into<String>,
        repo: impl Into<String>,
        scope: JitScope,
        runner_group_id: u64,
    ) -> Self {
        let poller = QueuePoller::new(client.clone(), owner, repo);
        Self {
            client: Some(client),
            poller: Some(poller),
            scope,
            runner_group_id,
            timeout: std::time::Duration::from_secs(3600),
        }
    }

    /// Disabled placeholder (no token configured).
    pub fn disabled() -> Self {
        Self {
            client: None,
            poller: None,
            scope: JitScope::Repo { owner: String::new(), repo: String::new() },
            runner_group_id: 1,
            timeout: std::time::Duration::from_secs(3600),
        }
    }
}

#[async_trait::async_trait]
impl CiProvider for GithubProvider {
    fn name(&self) -> &'static str {
        "github"
    }

    fn is_enabled(&self) -> bool {
        self.client.is_some() && self.poller.is_some()
    }

    async fn poll_pending_jobs(&self) -> Result<Vec<ProviderJob>> {
        let poller = self.poller.as_ref().context("github provider not configured")?;
        Ok(poller
            .poll_once()
            .await
            .map_err(|e| anyhow::anyhow!(e))?
            .iter()
            .map(to_provider_job)
            .collect())
    }

    async fn claim_job(&self, job_id: &str) -> Result<JobPayload> {
        let client = self.client.as_ref().context("github provider not configured")?;
        let req = JitRequest {
            name: format!("runner-gh-{job_id}"),
            runner_group_id: self.runner_group_id,
            labels: vec!["self-hosted".to_string(), "runner".to_string()],
            work_folder: "_work".to_string(),
        };
        let jit = match &self.scope {
            JitScope::Org { org } => generate_org_jit(client, org, &req).await,
            JitScope::Repo { owner, repo } => generate_repo_jit(client, owner, repo, &req).await,
        }
        .map_err(|e| anyhow::anyhow!(e))?;
        Ok(JobPayload {
            job_id: job_id.to_string(),
            steps: vec![format!("./run.sh --jitconfig {}", jit.encoded_jit_config)],
            env: crate::governor::topology::sandbox_env_clamps()
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            work_dir: None,
            timeout: self.timeout,
        })
    }

    async fn complete_job(&self, _job_id: &str, _success: bool) -> Result<()> {
        // GitHub completes the job when the ephemeral worker exits; the
        // JIT registration is revoked server-side. Nothing to report.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_provider_reports_off() {
        let provider = GithubProvider::disabled();
        assert_eq!(provider.name(), "github");
        assert!(!provider.is_enabled());
    }

    #[test]
    fn job_conversion_preserves_identity() {
        let job = QueuedJob {
            id: 42,
            run_id: 7,
            name: "backend".to_string(),
            labels: vec!["self-hosted".to_string(), "runner".to_string()],
        };
        let converted = to_provider_job(&job);
        assert_eq!(converted.id, "42");
        assert_eq!(converted.provider, "github");
        assert_eq!(converted.labels.len(), 2);
    }
}
