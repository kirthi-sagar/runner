//! Just-in-time runner configuration (`generate-jitconfig`).
//!
//! Generating a JIT config requires `administration:write`. The returned
//! `encoded_jit_config` is single-use and pre-scoped: no reusable
//! registration token ever touches the worker host.

use serde::{Deserialize, Serialize};

/// Required token scope for JIT issuance.
pub const REQUIRED_SCOPE: &str = "administration:write";

/// `POST /orgs/{org}/actions/runners/generate-jitconfig` path.
pub fn org_jit_path(org: &str) -> String {
    format!("/orgs/{org}/actions/runners/generate-jitconfig")
}

/// `POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig` path.
pub fn repo_jit_path(owner: &str, repo: &str) -> String {
    format!("/repos/{owner}/{repo}/actions/runners/generate-jitconfig")
}

/// JIT config request body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JitRequest {
    pub name: String,
    pub runner_group_id: u64,
    pub labels: Vec<String>,
    #[serde(default = "default_work_folder")]
    pub work_folder: String,
}

fn default_work_folder() -> String {
    "_work".to_string()
}

/// JIT config response (`encoded_jit_config` passed to `run.sh`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JitResponse {
    pub runner: JitRunner,
    pub encoded_jit_config: String,
}

/// Runner identity embedded in the JIT response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JitRunner {
    pub id: u64,
    pub name: String,
}

/// Generate a JIT config for an org runner.
pub async fn generate_org_jit(
    client: &super::client::GithubClient,
    org: &str,
    req: &JitRequest,
) -> Result<JitResponse, String> {
    post_jit(&client.org_jit_url(org), client, req).await
}

/// Generate a JIT config for a single-repo runner.
pub async fn generate_repo_jit(
    client: &super::client::GithubClient,
    owner: &str,
    repo: &str,
    req: &JitRequest,
) -> Result<JitResponse, String> {
    post_jit(&client.repo_jit_url(owner, repo), client, req).await
}

async fn post_jit(
    url: &str,
    client: &super::client::GithubClient,
    req: &JitRequest,
) -> Result<JitResponse, String> {
    let res = client
        .authed(client.http().post(url))
        .json(req)
        .send()
        .await
        .map_err(|e| format!("generate-jitconfig failed: {e}"))?;
    let status = res.status();
    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::NOT_FOUND {
        return Err(format!(
            "generate-jitconfig rejected (HTTP {status}): token needs {REQUIRED_SCOPE}"
        ));
    }
    if !status.is_success() {
        return Err(format!("generate-jitconfig: HTTP {status}"));
    }
    res.json::<JitResponse>()
        .await
        .map_err(|e| format!("generate-jitconfig body: {e}"))
}

/// Base64-decode the single-use `encoded_jit_config` blob, verifying it is
/// well-formed before handing it to the worker.
pub fn decode_jit_config(encoded: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    if encoded.trim().is_empty() {
        return Err("empty encoded_jit_config".to_string());
    }
    base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|e| format!("malformed encoded_jit_config: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_match_github_api() {
        assert_eq!(
            org_jit_path("acme"),
            "/orgs/acme/actions/runners/generate-jitconfig"
        );
        assert_eq!(
            repo_jit_path("acme", "web"),
            "/repos/acme/web/actions/runners/generate-jitconfig"
        );
    }

    #[test]
    fn request_serializes_required_fields() {
        let req = JitRequest {
            name: "runner-1".to_string(),
            runner_group_id: 2,
            labels: vec!["self-hosted".to_string(), "runner".to_string()],
            work_folder: "_work".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["name"], "runner-1");
        assert_eq!(json["runner_group_id"], 2);
        assert_eq!(json["labels"][1], "runner");
        assert_eq!(json["work_folder"], "_work");
    }
}
