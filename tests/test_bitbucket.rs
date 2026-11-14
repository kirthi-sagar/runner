//! Bitbucket adapter tests: OAuth payloads, step extraction, and
//! `CiProvider` routing (no network; pure constructors + parsing).

use runner::providers::bitbucket::{
    BitbucketProvider, BitbucketStepStatus, BitbucketTokenResponse, normalize_script,
    parse_step_response, steps_url, token_needs_refresh,
};
use runner::providers::{CiProvider, ProviderRegistry};
use std::time::{Duration, Instant};

#[test]
fn oauth_response_deserializes_with_expiry() {
    let body = serde_json::json!({
        "access_token": "tok-123",
        "expires_in": 3600,
        "token_type": "Bearer",
    });
    let token: BitbucketTokenResponse = serde_json::from_value(body).unwrap();
    assert_eq!(token.access_token, "tok-123");
    let received = Instant::now();
    let expires_at = token.expires_at(received);
    assert!(!token_needs_refresh(expires_at, received));
    assert!(token_needs_refresh(expires_at, received + Duration::from_secs(7200)));
}

#[test]
fn step_extraction_normalizes_script_and_env() {
    let body = serde_json::json!({
        "values": [{
            "uuid": "step-uuid-1",
            "script": ["  npm ci  ", "", "npm test"],
            "variables": [
                { "key": "NODE_ENV", "value": "production" },
                { "key": "EMPTY" },
            ],
            "working_directory": "/opt/atlassian/pipelines/agent/build",
        }],
    });
    let step = parse_step_response(&body).unwrap().expect("step");
    assert_eq!(step.step_uuid, "step-uuid-1");
    assert_eq!(step.script, vec!["npm ci", "npm test"]);
    assert_eq!(
        step.env,
        vec![
            ("NODE_ENV".to_string(), "production".to_string()),
            ("EMPTY".to_string(), String::new()),
        ]
    );
    assert!(step.work_dir.is_some());

    let empty = serde_json::json!({ "values": [] });
    assert!(parse_step_response(&empty).unwrap().is_none());
    assert_eq!(normalize_script(vec![]), Vec::<String>::new());
}

#[test]
fn step_status_and_queue_urls() {
    let ok = BitbucketStepStatus::completed(true);
    assert_eq!(serde_json::to_value(&ok).unwrap()["result"], "SUCCESS");
    let failed = BitbucketStepStatus::completed(false);
    assert_eq!(serde_json::to_value(&failed).unwrap()["state"], "COMPLETED");
    assert_eq!(
        steps_url("acme", "web", "runner-1"),
        "https://api.bitbucket.org/2.0/repositories/acme/web/\
         pipelines-config/runners/runner-1/steps"
    );
}

#[tokio::test]
async fn bitbucket_provider_routes_through_trait() {
    let provider = BitbucketProvider::new("id", "secret", "acme", "web", "runner-1", vec!["runner".to_string()]);
    assert_eq!(provider.name(), "bitbucket");
    assert!(provider.is_enabled());

    let registry = ProviderRegistry::new();
    registry.register(Box::new(provider)).await;
    assert_eq!(registry.active_providers().await, vec!["bitbucket".to_string()]);
    assert!(registry.get_provider("bitbucket").await.unwrap().enabled);
}

#[tokio::test]
async fn default_registry_includes_bitbucket_placeholder() {
    let registry = ProviderRegistry::default_registry().await;
    let info = registry.get_provider("bitbucket").await.expect("bitbucket registered");
    assert!(!info.enabled);
}
