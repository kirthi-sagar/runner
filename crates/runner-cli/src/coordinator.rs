//! Daemon coordinator wiring: poll queued CI jobs and dispatch them.
//!
//! Lives in the library (not `main.rs`) so integration tests can drive
//! coordinator startup inside a tokio runtime.

use runner_core::config::{github_token_from_env, RunnerConfig};
use runner_core::governor::cgroup::CgroupSlice;
use runner_core::mesh::cloud::CloudPool;
use runner_providers::github::client::GithubClient;
use runner_providers::github::webhooks::{run_coordinator, DispatchContext, JitScope, QueuePoller};

/// Spawn the coordinator poll loop when a repo + token are configured.
/// Without them the daemon runs governor-only.
///
/// Async throughout: shared-state access uses `.write().await`, never
/// `blocking_write()`, so calling this from a tokio runtime thread
/// cannot panic (regression: v0.4.1 aborted on startup whenever
/// `cloud.max_monthly_spend > 0`).
pub async fn spawn_coordinator(
    config: &RunnerConfig,
    state: runner_core::governor::supervisor::SharedState,
) {
    let coord = &config.coordinator;
    let (Some(owner), Some(repo)) = (coord.repo_owner.clone(), coord.repo_name.clone()) else {
        eprintln!("runner: no coordinator repo configured; governor-only mode");
        return;
    };
    let Some(token) = github_token_from_env() else {
        eprintln!("runner: RUNNER_GITHUB_TOKEN unset; governor-only mode");
        return;
    };
    let github = match GithubClient::new(token) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("runner: github client: {e}");
            return;
        }
    };
    let poller = QueuePoller::new(github.clone(), owner, repo)
        .with_interval(std::time::Duration::from_secs(coord.poll_secs.max(5)));
    let scope = match config.org.clone() {
        Some(org) => JitScope::Org { org },
        None => JitScope::Repo {
            owner: coord.repo_owner.clone().unwrap_or_default(),
            repo: coord.repo_name.clone().unwrap_or_default(),
        },
    };
    let dispatch = coord.auto_dispatch.then(|| DispatchContext {
        github,
        scope,
        runner_group_id: coord.runner_group_id,
        worker_version: coord.worker_version.clone(),
        sandboxed: runner_sandbox::mounts::probe_userns(),
        timeout: std::time::Duration::from_secs(coord.job_timeout_mins * 60),
    });
    if dispatch.as_ref().is_some_and(|d| !d.sandboxed) {
        eprintln!("runner: unprivileged userns blocked; dispatches run unsandboxed");
    }
    let cloud = (config.cloud.max_monthly_spend > 0.0).then(|| CloudPool::from_config(config));
    // Attach the pool to shared state so IPC-driven termination
    // (`cloud_terminate`/`cloud_purge`) can reach the provider APIs.
    if let Some(pool) = cloud.clone() {
        state
            .write()
            .await
            .set_cloud_pool(pool, config.cloud.max_monthly_spend);
    }
    tokio::spawn(run_coordinator(
        poller,
        dispatch,
        cloud,
        state,
        CgroupSlice::system_default(),
    ));
}
