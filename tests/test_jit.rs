//! JIT tests: response parsing, blob decode, launch argv, and queue
//! parsing for mesh jobs.

use runner::github::client::GithubClient;
use runner::github::jit::{JitRequest, JitResponse, decode_jit_config};
use runner::github::webhooks::parse_queued_jobs;
use runner::sandbox::worker::WorkerLaunch;

#[test]
fn jit_response_parses_and_blob_decodes() {
    let body = serde_json::json!({
        "runner": { "id": 77, "name": "runner-1-2" },
        "encoded_jit_config": "aGVsbG8td29ybGQ=",
    });
    let res: JitResponse = serde_json::from_value(body).unwrap();
    assert_eq!(res.runner.id, 77);
    assert_eq!(decode_jit_config(&res.encoded_jit_config).unwrap(), b"hello-world");
    assert!(decode_jit_config("").is_err());
    assert!(decode_jit_config("!!!not-base64!!!").is_err());
}

#[test]
fn jit_request_serializes_and_targets_org_and_repo() {
    let client = GithubClient::new("ghp_test").unwrap();
    let req = JitRequest {
        name: "runner-1".to_string(),
        runner_group_id: 1,
        labels: vec!["self-hosted".to_string(), "runner".to_string()],
        work_folder: "_work".to_string(),
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["runner_group_id"], 1);
    assert_eq!(
        client.org_jit_url("acme"),
        "https://api.github.com/orgs/acme/actions/runners/generate-jitconfig"
    );
    assert_eq!(
        client.repo_jit_url("acme", "web"),
        "https://api.github.com/repos/acme/web/actions/runners/generate-jitconfig"
    );
}

#[test]
fn worker_launches_with_jitconfig_argv() {
    let launch = WorkerLaunch::new("/cache/worker-2.338.2".into(), "BLOB123");
    let argv = launch.argv();
    assert_eq!(argv[0], "./run.sh");
    assert_eq!(argv[1], "--jitconfig");
    assert_eq!(argv[2], "BLOB123");
    assert_eq!(argv.len(), 3);
}

#[test]
fn queue_parsing_selects_mesh_jobs() {
    let body = serde_json::json!({
        "total_count": 2,
        "jobs": [
            { "id": 11, "run_id": 5, "name": "backend (postgres)",
              "labels": ["self-hosted", "runner"], "status": "queued" },
            { "id": 12, "run_id": 5, "name": "cloud",
              "labels": ["ubuntu-latest"], "status": "queued" },
        ],
    });
    let jobs = parse_queued_jobs(&body).unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].name, "backend (postgres)");
}
