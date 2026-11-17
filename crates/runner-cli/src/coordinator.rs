//! Daemon coordinator wiring: poll queued CI jobs and dispatch them.
//!
//! Lives in the library (not `main.rs`) so integration tests can drive
//! coordinator startup inside a tokio runtime.

use std::sync::Arc;
use std::time::Duration;

use runner_core::config::{
    bitbucket_client_id_from_env, bitbucket_client_secret_from_env, github_token_from_env,
    gitlab_token_from_env, RunnerConfig,
};
use runner_core::governor::cgroup::CgroupSlice;
use runner_core::mesh::cloud::CloudPool;
use runner_providers::github::client::GithubClient;
use runner_providers::github::webhooks::{run_coordinator, DispatchContext, JitScope, QueuePoller};
use runner_providers::providers::bitbucket::{run_bitbucket_loop, BitbucketProvider};
use runner_providers::providers::gitlab::{run_gitlab_loop, GitlabProvider};

/// CI forges the daemon can supervise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forge {
    Github,
    Gitlab,
    Bitbucket,
}

/// CI credentials resolved from the config file + environment.
/// File values win; blanks fall back to `RUNNER_*` variables.
#[derive(Debug, Clone, Default)]
pub struct ForgeTokens {
    pub github: Option<String>,
    pub gitlab: Option<String>,
    pub bitbucket_id: Option<String>,
    pub bitbucket_secret: Option<String>,
}

fn nonblank(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Resolve every forge credential (pure wrt config + process env).
pub fn resolve_tokens(config: &RunnerConfig) -> ForgeTokens {
    ForgeTokens {
        github: github_token_from_env(),
        gitlab: nonblank(&config.gitlab.runner_token).or_else(gitlab_token_from_env),
        bitbucket_id: nonblank(&config.bitbucket.oauth_client_id)
            .or_else(bitbucket_client_id_from_env),
        bitbucket_secret: nonblank(&config.bitbucket.oauth_client_secret)
            .or_else(bitbucket_client_secret_from_env),
    }
}

/// Which forges may supervise jobs. Pure over config + resolved tokens
/// (no env reads here) so the matrix is unit-testable.
pub fn enabled_forges(config: &RunnerConfig, tokens: &ForgeTokens) -> Vec<Forge> {
    let mut forges = Vec::new();
    let coord = &config.coordinator;
    let repo_set = coord
        .repo_owner
        .as_ref()
        .is_some_and(|s| !s.trim().is_empty())
        && coord
            .repo_name
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty());
    if repo_set && tokens.github.is_some() {
        forges.push(Forge::Github);
    }
    if config.gitlab.enabled && tokens.gitlab.is_some() {
        forges.push(Forge::Gitlab);
    }
    let bb = &config.bitbucket;
    if config.bitbucket.enabled
        && !bb.workspace.trim().is_empty()
        && !bb.runner_uuid.trim().is_empty()
        && tokens.bitbucket_id.is_some()
        && tokens.bitbucket_secret.is_some()
    {
        forges.push(Forge::Bitbucket);
    }
    forges
}

/// Spawn one coordinator task per enabled forge. Without any forge the
/// daemon runs governor-only.
///
/// Async throughout: shared-state access uses `.write().await`, never
/// `blocking_write()`, so calling this from a tokio runtime thread
/// cannot panic (regression: v0.4.1 aborted on startup whenever
/// `cloud.max_monthly_spend > 0`).
pub async fn spawn_coordinator(
    config: &RunnerConfig,
    state: runner_core::governor::supervisor::SharedState,
) {
    let tokens = resolve_tokens(config);
    let forges = enabled_forges(config, &tokens);
    if forges.is_empty() {
        eprintln!("runner: no CI providers enabled; governor-only mode");
        return;
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
    let sandboxed = runner_sandbox::mounts::probe_userns();
    if !sandboxed {
        eprintln!("runner: unprivileged userns blocked; dispatches run unsandboxed");
    }
    // One kill ceiling for every forge (GitLab/Bitbucket configs carry
    // no per-forge timeout).
    let timeout = Duration::from_secs(config.coordinator.job_timeout_mins * 60);
    if forges.contains(&Forge::Github) {
        spawn_github(config, &tokens, cloud.clone(), state.clone(), sandboxed);
    }
    if forges.contains(&Forge::Gitlab) {
        let provider = Arc::new(GitlabProvider::new(
            config.gitlab.url.clone(),
            tokens.gitlab.clone().expect("enabled_forges checked"),
            config.gitlab.tags.clone(),
        ));
        let interval = Duration::from_secs(config.gitlab.poll_secs.max(5));
        tokio::spawn(run_gitlab_loop(
            provider,
            state.clone(),
            interval,
            !sandboxed,
            timeout,
        ));
    }
    if forges.contains(&Forge::Bitbucket) {
        let provider = Arc::new(BitbucketProvider::new(
            tokens.bitbucket_id.clone().expect("enabled_forges checked"),
            tokens
                .bitbucket_secret
                .clone()
                .expect("enabled_forges checked"),
            config.bitbucket.workspace.clone(),
            config.bitbucket.repo_slug.clone(),
            config.bitbucket.runner_uuid.clone(),
            config.bitbucket.labels.clone(),
        ));
        let interval = Duration::from_secs(config.bitbucket.poll_secs.max(5));
        tokio::spawn(run_bitbucket_loop(
            provider,
            state.clone(),
            interval,
            !sandboxed,
            timeout,
        ));
    }
}

/// GitHub branch of [`spawn_coordinator`] (pre-existing behavior).
fn spawn_github(
    config: &RunnerConfig,
    tokens: &ForgeTokens,
    cloud: Option<CloudPool>,
    state: runner_core::governor::supervisor::SharedState,
    sandboxed: bool,
) {
    let coord = &config.coordinator;
    let token = tokens.github.clone().expect("enabled_forges checked");
    let github = match GithubClient::new(token) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("runner: github client: {e}");
            return;
        }
    };
    let poller = QueuePoller::new(
        github.clone(),
        coord.repo_owner.clone().unwrap_or_default(),
        coord.repo_name.clone().unwrap_or_default(),
    )
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
        sandboxed,
        timeout: std::time::Duration::from_secs(coord.job_timeout_mins * 60),
    });
    tokio::spawn(run_coordinator(
        poller,
        dispatch,
        cloud,
        state,
        CgroupSlice::system_default(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(
        github: Option<&str>,
        gitlab: Option<&str>,
        bitbucket: Option<(&str, &str)>,
    ) -> ForgeTokens {
        ForgeTokens {
            github: github.map(str::to_string),
            gitlab: gitlab.map(str::to_string),
            bitbucket_id: bitbucket.map(|(id, _)| id.to_string()),
            bitbucket_secret: bitbucket.map(|(_, secret)| secret.to_string()),
        }
    }

    #[test]
    fn enablement_matrix() {
        let mut config = RunnerConfig::default();
        let none = tokens(None, None, None);
        assert!(enabled_forges(&config, &none).is_empty());

        // GitHub needs repo coordinates + token.
        config.coordinator.repo_owner = Some("o".to_string());
        config.coordinator.repo_name = Some("r".to_string());
        assert!(enabled_forges(&config, &none).is_empty());
        let github = tokens(Some("g"), None, None);
        assert_eq!(enabled_forges(&config, &github), vec![Forge::Github]);

        // GitLab needs enabled + token.
        config.gitlab.enabled = true;
        assert_eq!(enabled_forges(&config, &github), vec![Forge::Github]);
        let both = tokens(Some("g"), Some("gl"), None);
        assert_eq!(
            enabled_forges(&config, &both),
            vec![Forge::Github, Forge::Gitlab]
        );

        // Bitbucket needs enabled + workspace + uuid + id + secret.
        config.bitbucket.enabled = true;
        assert_eq!(
            enabled_forges(&config, &both),
            vec![Forge::Github, Forge::Gitlab]
        );
        config.bitbucket.workspace = "w".to_string();
        config.bitbucket.runner_uuid = "u".to_string();
        let all = tokens(Some("g"), Some("gl"), Some(("id", "secret")));
        assert_eq!(
            enabled_forges(&config, &all),
            vec![Forge::Github, Forge::Gitlab, Forge::Bitbucket]
        );
        // Half credentials stay disabled.
        let half = ForgeTokens {
            bitbucket_id: Some("id".to_string()),
            ..ForgeTokens::default()
        };
        assert!(enabled_forges(&config, &half).is_empty());
    }
}
