//! Native Bitbucket Pipelines runner adapter (OAuth + API v2).
//!
//! Authenticates via OAuth 2.0 client credentials, polls the workspace
//! runner step queue, executes claimed steps in the zero-freeze sandbox,
//! and streams logs + completion status back to Bitbucket.

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
    http: reqwest::Client,
    cached: tokio::sync::Mutex<Option<(String, Instant)>>,
}

impl BitbucketClient {
    pub fn new(oauth_client_id: impl Into<String>, oauth_client_secret: impl Into<String>) -> Self {
        Self {
            oauth_client_id: oauth_client_id.into(),
            oauth_client_secret: oauth_client_secret.into(),
            http: reqwest::Client::new(),
            cached: tokio::sync::Mutex::new(None),
        }
    }

    /// Fetch a fresh OAuth token (client credentials grant).
    async fn refresh_token(&self) -> Result<(String, Instant)> {
        let res = self
            .http
            .post(OAUTH_TOKEN_URL)
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
            .get(steps_url(workspace, repo_slug, runner_uuid))
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
            .post(step_log_url(workspace, repo_slug, step_uuid))
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
            .put(step_status_url(workspace, repo_slug, step_uuid))
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

/// Execute a claimed step: sandboxed `sh -c` run, chunked log upload,
/// status report. Returns true on script success.
pub async fn execute_step(
    client: &BitbucketClient,
    workspace: &str,
    repo_slug: &str,
    step: &BitbucketStep,
    no_sandbox: bool,
    timeout: Duration,
) -> Result<bool> {
    let script = step.script.join("\n");
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

#[cfg(test)]
mod tests {
    use super::*;

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
