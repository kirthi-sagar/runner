//! Provider registry tests: registration, routing, multi-provider poll.

use runner::providers::{JobPayload, ProviderAdapter, ProviderJob, ProviderRegistry};
use std::time::Duration;

struct ScriptedProvider {
    name: &'static str,
    enabled: bool,
    jobs: Vec<ProviderJob>,
}

#[async_trait::async_trait]
impl ProviderAdapter for ScriptedProvider {
    fn name(&self) -> &'static str {
        self.name
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    async fn poll_pending_jobs(&self) -> anyhow::Result<Vec<ProviderJob>> {
        Ok(self.jobs.clone())
    }

    async fn claim_job(&self, job_id: &str) -> anyhow::Result<JobPayload> {
        Ok(JobPayload {
            job_id: job_id.to_string(),
            steps: vec![format!("run {job_id}")],
            env: Vec::new(),
            work_dir: None,
            timeout: Duration::from_secs(60),
        })
    }

    async fn complete_job(&self, _job_id: &str, _success: bool) -> anyhow::Result<()> {
        Ok(())
    }
}

fn job(id: &str, provider: &str) -> ProviderJob {
    ProviderJob {
        id: id.to_string(),
        provider: provider.to_string(),
        name: format!("job-{id}"),
        labels: vec!["runner".to_string()],
    }
}

#[tokio::test]
async fn registry_routes_registration_and_lookup() {
    let registry = ProviderRegistry::new();
    registry
        .register(Box::new(ScriptedProvider {
            name: "github",
            enabled: true,
            jobs: vec![job("1", "github")],
        }))
        .await;
    registry
        .register(Box::new(ScriptedProvider {
            name: "local",
            enabled: true,
            jobs: vec![],
        }))
        .await;

    assert_eq!(
        registry.active_providers().await,
        vec!["github".to_string(), "local".to_string()]
    );
    assert!(registry.get_provider("github").await.unwrap().enabled);
    assert!(registry.get_provider("nosuch").await.is_none());
}

#[tokio::test]
async fn poll_all_merges_enabled_providers_only() {
    let registry = ProviderRegistry::new();
    registry
        .register(Box::new(ScriptedProvider {
            name: "github",
            enabled: true,
            jobs: vec![job("1", "github"), job("2", "github")],
        }))
        .await;
    registry
        .register(Box::new(ScriptedProvider {
            name: "gitlab",
            enabled: false,
            jobs: vec![job("9", "gitlab")],
        }))
        .await;

    let jobs = registry.poll_all().await;
    assert_eq!(jobs.len(), 2);
    assert!(jobs.iter().all(|j| j.provider == "github"));
}

#[tokio::test]
async fn failing_provider_does_not_stall_poll() {
    struct Failing;
    #[async_trait::async_trait]
    impl ProviderAdapter for Failing {
        fn name(&self) -> &'static str {
            "broken"
        }
        fn is_enabled(&self) -> bool {
            true
        }
        async fn poll_pending_jobs(&self) -> anyhow::Result<Vec<ProviderJob>> {
            anyhow::bail!("provider down")
        }
        async fn claim_job(&self, _job_id: &str) -> anyhow::Result<JobPayload> {
            anyhow::bail!("down")
        }
        async fn complete_job(&self, _job_id: &str, _success: bool) -> anyhow::Result<()> {
            Ok(())
        }
    }

    let registry = ProviderRegistry::new();
    registry.register(Box::new(Failing)).await;
    registry
        .register(Box::new(ScriptedProvider {
            name: "local",
            enabled: true,
            jobs: vec![job("3", "local")],
        }))
        .await;
    let jobs = registry.poll_all().await;
    assert_eq!(jobs.len(), 1);
}
