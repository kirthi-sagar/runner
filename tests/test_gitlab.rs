//! GitLab adapter tests: protocol payloads, trace ranges, and
//! `ProviderAdapter` routing (no network; pure constructors + parsing).

use runner::providers::gitlab::{
    build_request_body, content_range, GitlabClient, GitlabJob, GitlabProvider, GitlabSystemInfo,
};
use runner::providers::{ProviderAdapter, ProviderRegistry};

fn info() -> GitlabSystemInfo {
    GitlabSystemInfo {
        name: "runner".to_string(),
        version: "0.1.0".to_string(),
        os: "linux".to_string(),
        architecture: "x86_64".to_string(),
        executor: "custom".to_string(),
    }
}

#[test]
fn request_payload_carries_token_tags_and_info() {
    let body = build_request_body(
        "RUNNER-TOKEN",
        &info(),
        &["zero-freeze".to_string(), "linux".to_string()],
    );
    assert_eq!(body["token"], "RUNNER-TOKEN");
    assert_eq!(body["tags"].as_array().unwrap().len(), 2);
    assert_eq!(body["info"]["executor"], "custom");
    assert_eq!(body["info"]["os"], "linux");
}

#[test]
fn job_response_deserializes_script_and_variables() {
    let body = serde_json::json!({
        "id": 123,
        "token": "JOB-TOKEN",
        "steps": [
            { "name": "build", "script": ["cargo build", "cargo test"] },
            { "name": "lint", "script": ["cargo clippy"] },
        ],
        "variables": [
            { "key": "CI_COMMIT_SHA", "value": "abc123" },
            { "key": "EMPTY", "value": "" },
        ],
        "git_info": { "repo_url": "https://gitlab.com/a/b.git", "ref": "main" },
    });
    let job = GitlabJob::from_response(&body).unwrap();
    assert_eq!(job.id, 123);
    assert_eq!(
        job.script,
        vec!["cargo build", "cargo test", "cargo clippy"]
    );
    assert_eq!(job.variables.len(), 2);
    assert_eq!(job.repo_url.as_deref(), Some("https://gitlab.com/a/b.git"));
}

#[test]
fn trace_content_ranges_are_byte_inclusive() {
    assert_eq!(content_range(0, 1024), "bytes 0-1023/*");
    assert_eq!(content_range(1024, 64 * 1024), "bytes 1024-66559/*");
}

#[test]
fn client_targets_api_v4() {
    let client = GitlabClient::new("https://gitlab.example.com/");
    assert_eq!(client.base_url(), "https://gitlab.example.com/api/v4");
}

#[tokio::test]
async fn gitlab_provider_routes_through_trait() {
    let provider = GitlabProvider::new(
        "https://gitlab.com",
        "RUNNER-TOKEN",
        vec!["runner".to_string()],
    );
    assert_eq!(provider.name(), "gitlab");
    assert!(provider.is_enabled());

    let registry = ProviderRegistry::new();
    registry.register(Box::new(provider)).await;
    assert_eq!(
        registry.active_providers().await,
        vec!["gitlab".to_string()]
    );
    assert!(registry.get_provider("gitlab").await.unwrap().enabled);
}

#[tokio::test]
async fn default_registry_includes_gitlab_placeholder() {
    let registry = ProviderRegistry::default_registry().await;
    let info = registry
        .get_provider("gitlab")
        .await
        .expect("gitlab registered");
    assert!(!info.enabled);
    // Only the local provider is active out of the box.
    assert_eq!(registry.active_providers().await, vec!["local".to_string()]);
}
