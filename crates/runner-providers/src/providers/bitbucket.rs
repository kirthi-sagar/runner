//! Native Bitbucket Pipelines runner adapter (OAuth + API v2).
//!
//! Authenticates via OAuth 2.0 client credentials, polls the workspace
//! runner step queue, executes claimed steps in the zero-freeze sandbox,
//! and streams logs + completion status back to Bitbucket.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{JobPayload, ProviderAdapter, ProviderJob};

/// OAuth token endpoint.
pub const OAUTH_TOKEN_URL: &str = "https://bitbucket.org/site/oauth2/token";
/// API v2 base.
pub const API_BASE: &str = "https://api.bitbucket.org/2.0";
/// Refresh skew: renew tokens expiring within this window.
pub const TOKEN_REFRESH_SKEW_SECS: u64 = 60;
/// Chunk size for log uploads.
pub const LOG_CHUNK_SIZE: usize = 64 * 1024;

/// OAuth 2.0 access token response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitbucketTokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub token_type: String,
}

impl BitbucketTokenResponse {
    /// Absolute expiry from receipt time (pure; unit-tested).
    pub fn expires_at(&self, received_at: Instant) -> Instant {
        received_at + Duration::from_secs(self.expires_in)
    }
}

/// True when the token is expired or inside the refresh skew window.
pub fn token_needs_refresh(expires_at: Instant, now: Instant) -> bool {
    now + Duration::from_secs(TOKEN_REFRESH_SKEW_SECS) >= expires_at
}

/// A queued pipeline step claimed for execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitbucketStep {
    pub step_uuid: String,
    pub script: Vec<String>,
    pub env: Vec<(String, String)>,
    pub work_dir: Option<String>,
}

/// Trim + drop empty script lines (pure; unit-tested).
pub fn normalize_script(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

#[derive(Debug, Deserialize)]
struct StepsEnvelope {
    #[serde(default)]
    values: Vec<StepValue>,
}

#[derive(Debug, Deserialize)]
struct StepValue {
    uuid: String,
    #[serde(default)]
    script: Vec<String>,
    #[serde(default)]
    variables: serde_json::Value,
    #[serde(default)]
    working_directory: Option<String>,
}

fn parse_variables(value: &serde_json::Value) -> Vec<(String, String)> {
    match value {
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(k, v)| {
                let s = v
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string());
                (k.clone(), s)
            })
            .collect(),
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| {
                Some((
                    item.get("key")?.as_str()?.to_string(),
                    item.get("value")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                ))
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Parse the first queued step from a steps-list response (pure).
/// Returns `None` on an empty queue.
pub fn parse_step_response(body: &serde_json::Value) -> Result<Option<BitbucketStep>> {
    let envelope: StepsEnvelope =
        serde_json::from_value(body.clone()).context("malformed bitbucket steps")?;
    Ok(envelope
        .values
        .into_iter()
        .next()
        .map(|step| BitbucketStep {
            step_uuid: step.uuid,
            script: normalize_script(step.script),
            env: parse_variables(&step.variables),
            work_dir: step.working_directory,
        }))
}

/// Step completion payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BitbucketStepStatus {
    pub state: String,
    pub result: String,
}

impl BitbucketStepStatus {
    pub fn completed(success: bool) -> Self {
        Self {
            state: "COMPLETED".to_string(),
            result: if success {
                "SUCCESS".to_string()
            } else {
                "FAILED".to_string()
            },
        }
    }
}

/// Steps queue endpoint for one self-hosted runner.
pub fn steps_url(workspace: &str, repo_slug: &str, runner_uuid: &str) -> String {
    format!(
        "{API_BASE}/repositories/{workspace}/{repo_slug}/pipelines-config/runners/{runner_uuid}/steps"
    )
}

/// Log upload endpoint for one step.
pub fn step_log_url(workspace: &str, repo_slug: &str, step_uuid: &str) -> String {
    format!("{API_BASE}/repositories/{workspace}/{repo_slug}/pipelines/steps/{step_uuid}/log")
}

/// Status endpoint for one step.
pub fn step_status_url(workspace: &str, repo_slug: &str, step_uuid: &str) -> String {
    format!("{API_BASE}/repositories/{workspace}/{repo_slug}/pipelines/steps/{step_uuid}/status")
}

/// OAuth-authenticated API client with cached bearer token.
pub struct BitbucketClient {
    oauth_client_id: String,
    oauth_client_secret: String,
    token_url: String,
    api_base: String,
    http: reqwest::Client,
    cached: tokio::sync::Mutex<Option<(String, Instant)>>,
}

impl BitbucketClient {
    pub fn new(oauth_client_id: impl Into<String>, oauth_client_secret: impl Into<String>) -> Self {
        Self {
            oauth_client_id: oauth_client_id.into(),
            oauth_client_secret: oauth_client_secret.into(),
            token_url: OAUTH_TOKEN_URL.to_string(),
            api_base: API_BASE.to_string(),
            http: reqwest::Client::new(),
            cached: tokio::sync::Mutex::new(None),
        }
    }

    /// Point the OAuth grant at a custom token URL (tests).
    pub fn with_token_url(mut self, token_url: impl Into<String>) -> Self {
        self.token_url = token_url.into();
        self
    }

    /// Point steps/log/status calls at a custom API base (tests).
    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Self {
        self.api_base = api_base.into();
        self
    }

    fn steps_endpoint(&self, workspace: &str, repo_slug: &str, runner_uuid: &str) -> String {
        format!(
            "{}/repositories/{workspace}/{repo_slug}/pipelines-config/runners/{runner_uuid}/steps",
            self.api_base
        )
    }

    fn log_endpoint(&self, workspace: &str, repo_slug: &str, step_uuid: &str) -> String {
        format!(
            "{}/repositories/{workspace}/{repo_slug}/pipelines/steps/{step_uuid}/log",
            self.api_base
        )
    }

    fn status_endpoint(&self, workspace: &str, repo_slug: &str, step_uuid: &str) -> String {
        format!(
            "{}/repositories/{workspace}/{repo_slug}/pipelines/steps/{step_uuid}/status",
            self.api_base
        )
    }

    /// Validate credentials by performing the client-credentials grant.
    /// Returns the token expiry on success.
    pub async fn test_credentials(&self) -> Result<Instant> {
        let (_, expires_at) = self.refresh_token().await?;
        Ok(expires_at)
    }

    /// Fetch a fresh OAuth token (client credentials grant).
    async fn refresh_token(&self) -> Result<(String, Instant)> {
        let res = self
            .http
            .post(&self.token_url)
            .basic_auth(&self.oauth_client_id, Some(&self.oauth_client_secret))
            .form(&[("grant_type", "client_credentials")])
            .send()
            .await
            .context("bitbucket oauth failed")?;
        if !res.status().is_success() {
            anyhow::bail!("bitbucket oauth: HTTP {}", res.status());
        }
        let body: BitbucketTokenResponse = res.json().await.context("bitbucket oauth body")?;
        let received = Instant::now();
        Ok((body.access_token.clone(), body.expires_at(received)))
    }

    /// Bearer token, refreshing when missing or near expiry.
    async fn bearer_token(&self) -> Result<String> {
        let mut guard = self.cached.lock().await;
        let needs = guard
            .as_ref()
            .is_none_or(|(_, expires_at)| token_needs_refresh(*expires_at, Instant::now()));
        if needs {
            *guard = Some(self.refresh_token().await?);
        }
        Ok(guard.as_ref().expect("just refreshed").0.clone())
    }

    /// Poll one queued step for the runner (`None` = empty queue).
    pub async fn poll_steps(
        &self,
        workspace: &str,
        repo_slug: &str,
        runner_uuid: &str,
    ) -> Result<Option<BitbucketStep>> {
        let token = self.bearer_token().await?;
        let res = self
            .http
            .get(self.steps_endpoint(workspace, repo_slug, runner_uuid))
            .bearer_auth(token)
            .send()
            .await
            .context("bitbucket steps poll failed")?;
        if res.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        if !res.status().is_success() {
            anyhow::bail!("bitbucket steps poll: HTTP {}", res.status());
        }
        let body: serde_json::Value = res.json().await.context("bitbucket steps body")?;
        parse_step_response(&body)
    }

    /// Append one log chunk (empty chunks are a no-op).
    pub async fn append_log(
        &self,
        workspace: &str,
        repo_slug: &str,
        step_uuid: &str,
        log_chunk: &[u8],
    ) -> Result<()> {
        if log_chunk.is_empty() {
            return Ok(());
        }
        let token = self.bearer_token().await?;
        let res = self
            .http
            .post(self.log_endpoint(workspace, repo_slug, step_uuid))
            .bearer_auth(token)
            .body(log_chunk.to_vec())
            .send()
            .await
            .context("bitbucket log append failed")?;
        if !res.status().is_success() {
            anyhow::bail!("bitbucket log append: HTTP {}", res.status());
        }
        Ok(())
    }

    /// Mark the step `SUCCESS` or `FAILED`.
    pub async fn complete_step(
        &self,
        workspace: &str,
        repo_slug: &str,
        step_uuid: &str,
        success: bool,
    ) -> Result<()> {
        let token = self.bearer_token().await?;
        let res = self
            .http
            .put(self.status_endpoint(workspace, repo_slug, step_uuid))
            .bearer_auth(token)
            .json(&BitbucketStepStatus::completed(success))
            .send()
            .await
            .context("bitbucket step update failed")?;
        if !res.status().is_success() {
            anyhow::bail!("bitbucket step update: HTTP {}", res.status());
        }
        Ok(())
    }
}

/// Execute a claimed step: check out the repo, sandboxed `sh -c` run,
/// chunked log upload, status report. Returns true on script success.
pub async fn execute_step(
    client: &BitbucketClient,
    workspace: &str,
    repo_slug: &str,
    step: &BitbucketStep,
    no_sandbox: bool,
    timeout: Duration,
) -> Result<bool> {
    // Steps carry no repo/ref: clone the default branch from the
    // workspace coordinates with the OAuth bearer token.
    let mut script = String::new();
    if !workspace.trim().is_empty() && !repo_slug.trim().is_empty() {
        let repo_url = format!("https://bitbucket.org/{workspace}/{repo_slug}.git");
        let token = client.bearer_token().await?;
        if let Some(prefix) = super::checkout_prefix(&repo_url, None, "x-token-auth", &token) {
            script.push_str(&prefix);
        }
    }
    script.push_str(&step.script.join("\n"));
    let output = super::local::execute_captured(
        &["sh".to_string(), "-c".to_string(), script],
        &step.env,
        no_sandbox,
        timeout,
    )
    .await?;
    let mut combined = output.stdout;
    combined.extend_from_slice(&output.stderr);
    for chunk in combined.chunks(LOG_CHUNK_SIZE) {
        client
            .append_log(workspace, repo_slug, &step.step_uuid, chunk)
            .await?;
    }
    let success = output.code == 0;
    client
        .complete_step(workspace, repo_slug, &step.step_uuid, success)
        .await?;
    Ok(success)
}

/// Bitbucket Pipelines provider.
pub struct BitbucketProvider {
    client: Option<BitbucketClient>,
    workspace: String,
    repo_slug: String,
    runner_uuid: String,
    labels: Vec<String>,
    timeout: Duration,
    pending: tokio::sync::Mutex<Option<BitbucketStep>>,
}

impl BitbucketProvider {
    pub fn new(
        oauth_client_id: impl Into<String>,
        oauth_client_secret: impl Into<String>,
        workspace: impl Into<String>,
        repo_slug: impl Into<String>,
        runner_uuid: impl Into<String>,
        labels: Vec<String>,
    ) -> Self {
        Self {
            client: Some(BitbucketClient::new(oauth_client_id, oauth_client_secret)),
            workspace: workspace.into(),
            repo_slug: repo_slug.into(),
            runner_uuid: runner_uuid.into(),
            labels,
            timeout: Duration::from_secs(3600),
            pending: tokio::sync::Mutex::new(None),
        }
    }

    pub fn disabled() -> Self {
        Self {
            client: None,
            workspace: String::new(),
            repo_slug: String::new(),
            runner_uuid: String::new(),
            labels: Vec::new(),
            timeout: Duration::from_secs(3600),
            pending: tokio::sync::Mutex::new(None),
        }
    }

    /// Point OAuth + API at one loopback stub (tests): the token grant
    /// goes to `{base}/site/oauth2/token`, API calls to `{base}/2.0`.
    pub fn with_base_url(mut self, base_url: &str) -> Self {
        if let Some(client) = self.client.take() {
            let base = base_url.trim_end_matches('/');
            self.client = Some(
                client
                    .with_token_url(format!("{base}/site/oauth2/token"))
                    .with_api_base(format!("{base}/2.0")),
            );
        }
        self
    }
}

#[async_trait::async_trait]
impl ProviderAdapter for BitbucketProvider {
    fn name(&self) -> &'static str {
        "bitbucket"
    }

    fn is_enabled(&self) -> bool {
        self.client.is_some() && !self.workspace.is_empty() && !self.runner_uuid.is_empty()
    }

    async fn poll_pending_jobs(&self) -> Result<Vec<ProviderJob>> {
        let client = match (&self.client, self.is_enabled()) {
            (Some(client), true) => client,
            _ => return Ok(Vec::new()),
        };
        match client
            .poll_steps(&self.workspace, &self.repo_slug, &self.runner_uuid)
            .await?
        {
            Some(step) => {
                let id = step.step_uuid.clone();
                *self.pending.lock().await = Some(step);
                Ok(vec![ProviderJob {
                    id: id.clone(),
                    provider: "bitbucket".to_string(),
                    name: format!("bitbucket-step-{id}"),
                    labels: self.labels.clone(),
                }])
            }
            None => Ok(Vec::new()),
        }
    }

    async fn claim_job(&self, job_id: &str) -> Result<JobPayload> {
        let pending = self.pending.lock().await;
        match pending.as_ref().filter(|step| step.step_uuid == job_id) {
            Some(step) => Ok(JobPayload {
                job_id: job_id.to_string(),
                steps: step.script.clone(),
                env: step.env.clone(),
                work_dir: step.work_dir.clone().map(std::path::PathBuf::from),
                timeout: self.timeout,
            }),
            None => anyhow::bail!("no pending bitbucket claim for job {job_id}; poll again"),
        }
    }

    async fn complete_job(&self, job_id: &str, success: bool) -> Result<()> {
        let mut pending = self.pending.lock().await;
        let matches = pending
            .as_ref()
            .is_some_and(|step| step.step_uuid == job_id);
        if !matches {
            anyhow::bail!("no pending bitbucket claim for job {job_id}");
        }
        let step = pending.take().expect("checked above");
        drop(pending);
        match &self.client {
            Some(client) => {
                client
                    .complete_step(&self.workspace, &self.repo_slug, &step.step_uuid, success)
                    .await
            }
            None => anyhow::bail!("bitbucket provider not configured"),
        }
    }
}

/// One daemon iteration: reserve → poll → dedup → dispatch.
/// Returns the number of steps dispatched (0 or 1: each poll hands
/// out a single queued step).
///
/// The slot is reserved BEFORE polling so a claimed step is never
/// abandoned for lack of a local slot, and concurrent forge loops
/// cannot over-dispatch a constrained host.
pub async fn poll_bitbucket_once(
    provider: &Arc<BitbucketProvider>,
    state: &runner_core::governor::supervisor::SharedState,
    no_sandbox: bool,
    timeout: std::time::Duration,
) -> usize {
    if !state.write().await.try_reserve_slot() {
        return 0;
    }
    let jobs = match provider.poll_pending_jobs().await {
        Ok(jobs) => jobs,
        Err(e) => {
            eprintln!("runner: bitbucket poll failed: {e:#}");
            let mut guard = state.write().await;
            guard.record_forge_poll("bitbucket", 0, Some(format!("{e:#}")));
            guard.release_slot_reservation();
            return 0;
        }
    };
    let Some(job) = jobs.into_iter().next() else {
        let mut guard = state.write().await;
        guard.record_forge_poll("bitbucket", 0, None);
        guard.release_slot_reservation();
        return 0;
    };
    state.write().await.record_forge_poll("bitbucket", 1, None);
    let flying = state.read().await.in_flight_jobs();
    if crate::github::webhooks::already_in_flight(&flying, "bitbucket", &job.id) {
        // Drop the duplicate claim; the original execution owns
        // completion reporting.
        provider.pending.lock().await.take();
        eprintln!(
            "runner: bitbucket step {} already in flight; skipping",
            job.id
        );
        state.write().await.release_slot_reservation();
        return 0;
    }
    let claimed = provider.pending.lock().await.take();
    let Some(claimed) = claimed else {
        state.write().await.release_slot_reservation();
        return 0;
    };
    if claimed.step_uuid != job.id {
        // Impossible in the sequential loop (poll sets pending just
        // above); restore and bail rather than drop a live claim.
        *provider.pending.lock().await = Some(claimed);
        state.write().await.release_slot_reservation();
        return 0;
    }
    // The reservation converts into this step's slot (no second inc).
    state
        .write()
        .await
        .job_started("bitbucket", &job.id, &job.name);
    let provider = Arc::clone(provider);
    let state = state.clone();
    let job_id = job.id.clone();
    tokio::spawn(async move {
        let workspace = provider.workspace.clone();
        let repo_slug = provider.repo_slug.clone();
        let Some(client) = provider.client.as_ref() else {
            eprintln!("runner: bitbucket provider disabled mid-flight; dropping step {job_id}");
            let mut guard = state.write().await;
            guard.in_flight_dec();
            guard.job_finished("bitbucket", &job_id);
            return;
        };
        match execute_step(
            client, &workspace, &repo_slug, &claimed, no_sandbox, timeout,
        )
        .await
        {
            Ok(true) => eprintln!("runner: bitbucket step {job_id} succeeded"),
            Ok(false) => eprintln!("runner: bitbucket step {job_id} failed"),
            Err(e) => eprintln!("runner: bitbucket step {job_id} error: {e:#}"),
        }
        let mut guard = state.write().await;
        guard.in_flight_dec();
        guard.job_finished("bitbucket", &job_id);
    });
    1
}

/// Bitbucket Pipelines daemon loop: poll on `interval` (or webhook
/// wakeup) and dispatch claimed steps until shutdown.
pub async fn run_bitbucket_loop(
    provider: Arc<BitbucketProvider>,
    state: runner_core::governor::supervisor::SharedState,
    interval: std::time::Duration,
    no_sandbox: bool,
    timeout: std::time::Duration,
) {
    let wakeup = state.read().await.wakeup();
    eprintln!("runner: bitbucket coordinator polling every {interval:?} (webhook wakeups armed)");
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {},
            _ = wakeup.notified() => {
                eprintln!("runner: webhook wakeup: polling bitbucket immediately");
            }
        }
        poll_bitbucket_once(&provider, &state, no_sandbox, timeout).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn credentials_grant_against_stub() {
        let (base, server) = crate::test_stub::serve_once(
            200,
            "OK",
            &[],
            r#"{"access_token":"tok","expires_in":3600,"token_type":"Bearer"}"#,
        );
        let client = BitbucketClient::new("id", "secret").with_token_url(base);
        let expiry = client.test_credentials().await.unwrap();
        assert!(expiry > Instant::now());
        server.join().unwrap();

        let (base, server) = crate::test_stub::serve_once(401, "Unauthorized", &[], "{}");
        let client = BitbucketClient::new("id", "bad").with_token_url(base);
        assert!(client.test_credentials().await.is_err());
        server.join().unwrap();
    }

    #[test]
    fn token_expiry_and_refresh_window() {
        let token = BitbucketTokenResponse {
            access_token: "abc".to_string(),
            expires_in: 3600,
            token_type: "Bearer".to_string(),
        };
        let received = Instant::now();
        let expires_at = token.expires_at(received);
        assert!(!token_needs_refresh(expires_at, received));
        assert!(token_needs_refresh(
            expires_at,
            received + Duration::from_secs(3600)
        ));
        assert!(token_needs_refresh(
            expires_at,
            received + Duration::from_secs(3600 - TOKEN_REFRESH_SKEW_SECS + 1)
        ));
    }

    #[test]
    fn script_normalization_trims_and_drops_empties() {
        assert_eq!(
            normalize_script(vec![
                "  echo hi  ".to_string(),
                String::new(),
                "  ".to_string()
            ]),
            vec!["echo hi".to_string()]
        );
    }

    #[test]
    fn parses_queued_step_and_empty_queue() {
        let body = serde_json::json!({
            "values": [{
                "uuid": "step-1",
                "script": ["npm test", ""],
                "variables": { "NODE_ENV": "ci" },
                "working_directory": "/opt/build",
            }],
        });
        let step = parse_step_response(&body).unwrap().expect("step");
        assert_eq!(step.step_uuid, "step-1");
        assert_eq!(step.script, vec!["npm test".to_string()]);
        assert_eq!(step.env, vec![("NODE_ENV".to_string(), "ci".to_string())]);
        assert_eq!(step.work_dir.as_deref(), Some("/opt/build"));

        let empty = serde_json::json!({ "values": [] });
        assert!(parse_step_response(&empty).unwrap().is_none());
    }

    #[test]
    fn completion_payload_states() {
        assert_eq!(
            BitbucketStepStatus::completed(true),
            BitbucketStepStatus {
                state: "COMPLETED".to_string(),
                result: "SUCCESS".to_string()
            }
        );
        assert_eq!(BitbucketStepStatus::completed(false).result, "FAILED");
    }

    #[tokio::test]
    async fn disabled_provider_polls_empty() {
        let provider = BitbucketProvider::disabled();
        assert_eq!(provider.name(), "bitbucket");
        assert!(!provider.is_enabled());
        assert!(provider.poll_pending_jobs().await.unwrap().is_empty());
        assert!(provider.claim_job("x").await.is_err());
    }
}
