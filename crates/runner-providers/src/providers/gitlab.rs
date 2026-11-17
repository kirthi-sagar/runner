//! Native GitLab CI runner adapter (REST API v4).
//!
//! Speaks the runner protocol directly: `POST /api/v4/jobs/request`
//! (204 = no work, 201 = claimed job), `PATCH .../trace` for chunked log
//! upload, `PUT ...` for completion. Claimed scripts execute through the
//! same zero-freeze sandbox as every other provider.

use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{JobPayload, ProviderAdapter, ProviderJob};

/// Runner system description sent with each job request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitlabSystemInfo {
    pub name: String,
    pub version: String,
    pub os: String,
    pub architecture: String,
    #[serde(default = "default_executor")]
    pub executor: String,
}

fn default_executor() -> String {
    "custom".to_string()
}

impl GitlabSystemInfo {
    pub fn local() -> Self {
        Self {
            name: "runner".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            os: std::env::consts::OS.to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            executor: default_executor(),
        }
    }
}

/// A claimed GitLab CI job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabJob {
    pub id: u64,
    pub token: String,
    pub script: Vec<String>,
    pub variables: Vec<(String, String)>,
    pub repo_url: Option<String>,
    pub git_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JobResponse {
    id: u64,
    token: String,
    #[serde(default)]
    steps: Vec<StepRef>,
    #[serde(default)]
    variables: Vec<VarRef>,
    #[serde(default)]
    git_info: Option<GitInfoRef>,
}

#[derive(Debug, Deserialize)]
struct StepRef {
    #[serde(default)]
    script: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VarRef {
    key: String,
    #[serde(default)]
    value: String,
}

#[derive(Debug, Deserialize)]
struct GitInfoRef {
    #[serde(default)]
    repo_url: Option<String>,
    #[serde(default)]
    #[serde(rename = "ref")]
    git_ref: Option<String>,
}

impl GitlabJob {
    /// Parse a `201 Created` job request response (pure; unit-tested).
    pub fn from_response(body: &serde_json::Value) -> Result<Self> {
        let res: JobResponse =
            serde_json::from_value(body.clone()).context("malformed gitlab job")?;
        Ok(Self {
            id: res.id,
            token: res.token,
            script: res.steps.into_iter().flat_map(|s| s.script).collect(),
            variables: res
                .variables
                .into_iter()
                .map(|v| (v.key, v.value))
                .collect(),
            repo_url: res.git_info.as_ref().and_then(|g| g.repo_url.clone()),
            git_ref: res.git_info.as_ref().and_then(|g| g.git_ref.clone()),
        })
    }
}

/// Build the `POST /api/v4/jobs/request` body (pure; unit-tested).
pub fn build_request_body(
    runner_token: &str,
    info: &GitlabSystemInfo,
    tags: &[String],
) -> serde_json::Value {
    serde_json::json!({
        "token": runner_token,
        "info": info,
        "tags": tags,
    })
}

/// Build the `Content-Range` header for a trace chunk (pure; unit-tested).
pub fn content_range(offset: usize, len: usize) -> String {
    format!("bytes {offset}-{}/*", offset + len.saturating_sub(1))
}

/// Thin REST client for the GitLab runner API.
#[derive(Debug, Clone)]
pub struct GitlabClient {
    base_url: String,
    http: reqwest::Client,
}

impl GitlabClient {
    pub fn new(gitlab_url: impl Into<String>) -> Self {
        Self {
            base_url: format!("{}/api/v4", gitlab_url.into().trim_end_matches('/')),
            http: reqwest::Client::new(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Long-poll for work: `None` on 204, `Some(job)` on 201.
    pub async fn request_job(
        &self,
        runner_token: &str,
        info: &GitlabSystemInfo,
        tags: &[String],
    ) -> Result<Option<GitlabJob>> {
        let res = self
            .http
            .post(format!("{}/jobs/request", self.base_url))
            .json(&build_request_body(runner_token, info, tags))
            .send()
            .await
            .context("gitlab jobs/request failed")?;
        match res.status() {
            s if s == reqwest::StatusCode::NO_CONTENT => Ok(None),
            s if s == reqwest::StatusCode::CREATED => {
                let body: serde_json::Value = res.json().await.context("gitlab job body")?;
                Ok(Some(GitlabJob::from_response(&body)?))
            }
            s => anyhow::bail!("gitlab jobs/request: HTTP {s}"),
        }
    }

    /// Append a log chunk. Empty chunks are a no-op (no valid range).
    pub async fn append_trace(
        &self,
        job_id: u64,
        job_token: &str,
        bytes: &[u8],
        offset: usize,
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let res = self
            .http
            .patch(format!("{}/jobs/{job_id}/trace", self.base_url))
            .header("JOB-TOKEN", job_token)
            .header("Content-Range", content_range(offset, bytes.len()))
            .body(bytes.to_vec())
            .send()
            .await
            .context("gitlab trace append failed")?;
        if !res.status().is_success() {
            anyhow::bail!("gitlab trace append: HTTP {}", res.status());
        }
        Ok(())
    }

    /// Mark the job `success` or `failed`.
    pub async fn update_job(&self, job_id: u64, job_token: &str, state: &str) -> Result<()> {
        if state != "success" && state != "failed" {
            anyhow::bail!("gitlab job state must be success|failed, got {state:?}");
        }
        let res = self
            .http
            .put(format!("{}/jobs/{job_id}", self.base_url))
            .json(&serde_json::json!({ "token": job_token, "state": state }))
            .send()
            .await
            .context("gitlab job update failed")?;
        if !res.status().is_success() {
            anyhow::bail!("gitlab job update: HTTP {}", res.status());
        }
        Ok(())
    }
}

/// Chunk size for trace uploads.
pub const TRACE_CHUNK_SIZE: usize = 64 * 1024;

/// Execute a claimed job: run the assembled script in the zero-freeze
/// sandbox, upload output in trace chunks, report completion.
/// Returns true on script success.
pub async fn execute_job(
    client: &GitlabClient,
    job: &GitlabJob,
    no_sandbox: bool,
    timeout: std::time::Duration,
) -> Result<bool> {
    let script = job.script.join("\n");
    let output = super::local::execute_captured(
        &["sh".to_string(), "-c".to_string(), script],
        &job.variables,
        no_sandbox,
        timeout,
    )
    .await?;
    let mut combined = output.stdout;
    combined.extend_from_slice(&output.stderr);
    let mut offset = 0;
    for chunk in combined.chunks(TRACE_CHUNK_SIZE) {
        client
            .append_trace(job.id, &job.token, chunk, offset)
            .await?;
        offset += chunk.len();
    }
    let success = output.code == 0;
    client
        .update_job(
            job.id,
            &job.token,
            if success { "success" } else { "failed" },
        )
        .await?;
    Ok(success)
}

/// GitLab CI provider.
pub struct GitlabProvider {
    client: Option<GitlabClient>,
    runner_token: String,
    info: GitlabSystemInfo,
    tags: Vec<String>,
    timeout: std::time::Duration,
    /// Last polled job, awaiting `claim_job` (GitLab claims at request).
    pending: tokio::sync::Mutex<Option<GitlabJob>>,
}

impl GitlabProvider {
    pub fn new(
        gitlab_url: impl Into<String>,
        runner_token: impl Into<String>,
        tags: Vec<String>,
    ) -> Self {
        Self {
            client: Some(GitlabClient::new(gitlab_url)),
            runner_token: runner_token.into(),
            info: GitlabSystemInfo::local(),
            tags,
            timeout: std::time::Duration::from_secs(3600),
            pending: tokio::sync::Mutex::new(None),
        }
    }

    pub fn disabled() -> Self {
        Self {
            client: None,
            runner_token: String::new(),
            info: GitlabSystemInfo::local(),
            tags: Vec::new(),
            timeout: std::time::Duration::from_secs(3600),
            pending: tokio::sync::Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl ProviderAdapter for GitlabProvider {
    fn name(&self) -> &'static str {
        "gitlab"
    }

    fn is_enabled(&self) -> bool {
        self.client.is_some() && !self.runner_token.trim().is_empty()
    }

    async fn poll_pending_jobs(&self) -> Result<Vec<ProviderJob>> {
        let (client, token) = match (&self.client, self.is_enabled()) {
            (Some(client), true) => (client, self.runner_token.clone()),
            _ => return Ok(Vec::new()),
        };
        match client.request_job(&token, &self.info, &self.tags).await? {
            Some(job) => {
                let id = job.id.to_string();
                let name = format!("gitlab-job-{id}");
                *self.pending.lock().await = Some(job);
                Ok(vec![ProviderJob {
                    id,
                    provider: "gitlab".to_string(),
                    name,
                    labels: self.tags.clone(),
                }])
            }
            None => Ok(Vec::new()),
        }
    }

    async fn claim_job(&self, job_id: &str) -> Result<JobPayload> {
        let pending = self.pending.lock().await;
        match pending.as_ref().filter(|job| job.id.to_string() == job_id) {
            Some(job) => Ok(JobPayload {
                job_id: job_id.to_string(),
                steps: job.script.clone(),
                env: job.variables.clone(),
                work_dir: None,
                timeout: self.timeout,
            }),
            None => anyhow::bail!("no pending gitlab claim for job {job_id}; poll again"),
        }
    }

    async fn complete_job(&self, job_id: &str, success: bool) -> Result<()> {
        let mut pending = self.pending.lock().await;
        let matches = pending
            .as_ref()
            .is_some_and(|job| job.id.to_string() == job_id);
        if !matches {
            anyhow::bail!("no pending gitlab claim for job {job_id}");
        }
        let job = pending.take().expect("checked above");
        drop(pending);
        match &self.client {
            Some(client) => {
                client
                    .update_job(
                        job.id,
                        &job.token,
                        if success { "success" } else { "failed" },
                    )
                    .await
            }
            None => anyhow::bail!("gitlab provider not configured"),
        }
    }
}

/// One daemon iteration: capacity → poll → dedup → dispatch.
/// Returns the number of jobs dispatched (0 or 1: each request hands
/// out a single claimed job).
///
/// Capacity is checked BEFORE polling: GitLab claims server-side at
/// request time, so polling while full would abandon claimed jobs.
pub async fn poll_gitlab_once(
    provider: &Arc<GitlabProvider>,
    state: &runner_core::governor::supervisor::SharedState,
    no_sandbox: bool,
    timeout: std::time::Duration,
) -> usize {
    let free = {
        let guard = state.read().await;
        guard.last_slots.saturating_sub(guard.in_flight())
    };
    if free == 0 {
        return 0;
    }
    let jobs = match provider.poll_pending_jobs().await {
        Ok(jobs) => jobs,
        Err(e) => {
            eprintln!("runner: gitlab poll failed: {e:#}");
            return 0;
        }
    };
    let Some(job) = jobs.into_iter().next() else {
        return 0;
    };
    let flying = state.read().await.in_flight_jobs();
    if crate::github::webhooks::already_in_flight(&flying, "gitlab", &job.id) {
        // Drop the duplicate server-side claim; the original execution
        // owns completion reporting.
        provider.pending.lock().await.take();
        eprintln!("runner: gitlab job {} already in flight; skipping", job.id);
        return 0;
    }
    let claimed = provider.pending.lock().await.take();
    let Some(claimed) = claimed else {
        return 0;
    };
    if claimed.id.to_string() != job.id {
        // Impossible in the sequential loop (poll sets pending just
        // above); restore and bail rather than drop a live claim.
        *provider.pending.lock().await = Some(claimed);
        return 0;
    }
    {
        let mut guard = state.write().await;
        guard.in_flight_inc();
        guard.job_started("gitlab", &job.id, &job.name);
    }
    let provider = Arc::clone(provider);
    let state = state.clone();
    let job_id = job.id.clone();
    tokio::spawn(async move {
        let Some(client) = provider.client.as_ref() else {
            eprintln!("runner: gitlab provider disabled mid-flight; dropping job {job_id}");
            let mut guard = state.write().await;
            guard.in_flight_dec();
            guard.job_finished(&job_id);
            return;
        };
        match execute_job(client, &claimed, no_sandbox, timeout).await {
            Ok(true) => eprintln!("runner: gitlab job {job_id} succeeded"),
            Ok(false) => eprintln!("runner: gitlab job {job_id} failed"),
            Err(e) => eprintln!("runner: gitlab job {job_id} error: {e:#}"),
        }
        let mut guard = state.write().await;
        guard.in_flight_dec();
        guard.job_finished(&job_id);
    });
    1
}

/// GitLab CI daemon loop: poll on `interval` (or webhook wakeup) and
/// dispatch claimed jobs until shutdown. Mirrors `run_coordinator`.
pub async fn run_gitlab_loop(
    provider: Arc<GitlabProvider>,
    state: runner_core::governor::supervisor::SharedState,
    interval: std::time::Duration,
    no_sandbox: bool,
    timeout: std::time::Duration,
) {
    let wakeup = state.read().await.wakeup();
    eprintln!("runner: gitlab coordinator polling every {interval:?} (webhook wakeups armed)");
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {},
            _ = wakeup.notified() => {
                eprintln!("runner: webhook wakeup: polling gitlab immediately");
            }
        }
        poll_gitlab_once(&provider, &state, no_sandbox, timeout).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_job_against_stub() {
        let (base, server) = crate::test_stub::serve_once(204, "No Content", &[], "");
        let client = GitlabClient::new(base);
        assert!(client
            .request_job("tok", &GitlabSystemInfo::local(), &[])
            .await
            .unwrap()
            .is_none());
        server.join().unwrap();

        let (base, server) = crate::test_stub::serve_once(401, "Unauthorized", &[], "{}");
        let client = GitlabClient::new(base);
        assert!(client
            .request_job("bad", &GitlabSystemInfo::local(), &[])
            .await
            .unwrap_err()
            .to_string()
            .contains("401"));
        server.join().unwrap();
    }

    fn info() -> GitlabSystemInfo {
        GitlabSystemInfo {
            name: "t".to_string(),
            version: "0".to_string(),
            os: "linux".to_string(),
            architecture: "x86_64".to_string(),
            executor: "custom".to_string(),
        }
    }

    #[test]
    fn request_body_carries_token_and_tags() {
        let body = build_request_body("RT", &info(), &["a".to_string()]);
        assert_eq!(body["token"], "RT");
        assert_eq!(body["tags"][0], "a");
        assert_eq!(body["info"]["os"], "linux");
    }

    #[test]
    fn trace_ranges_are_inclusive() {
        assert_eq!(content_range(0, 100), "bytes 0-99/*");
        assert_eq!(content_range(100, 50), "bytes 100-149/*");
    }

    #[test]
    fn parses_201_job_response() {
        let body = serde_json::json!({
            "id": 9, "token": "JT",
            "steps": [{ "script": ["echo hi", "make test"] }],
            "variables": [{ "key": "CI", "value": "true" }],
            "git_info": { "repo_url": "https://x/y.git", "ref": "main" },
        });
        let job = GitlabJob::from_response(&body).unwrap();
        assert_eq!(job.id, 9);
        assert_eq!(job.script, vec!["echo hi", "make test"]);
        assert_eq!(job.variables, vec![("CI".to_string(), "true".to_string())]);
        assert_eq!(job.git_ref.as_deref(), Some("main"));
    }

    #[tokio::test]
    async fn disabled_provider_polls_empty() {
        let provider = GitlabProvider::disabled();
        assert_eq!(provider.name(), "gitlab");
        assert!(!provider.is_enabled());
        assert!(provider.poll_pending_jobs().await.unwrap().is_empty());
        assert!(provider.claim_job("1").await.is_err());
    }
}
