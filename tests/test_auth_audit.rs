//! Auth/audit/policy tests: the exact lib operations behind
//! `runner auth`, `runner audit verify`, and `runner policy inspect`,
//! exercised against isolated temp directories (never the real HOME).

use runner::audit::{verify_file, AuditLog, VerifyOutcome};
use runner::auth::{ProviderSlot, TokenStore};
use runner::policy::{describe, load_or_permissive};
use runner::telemetry::LogLevel;

#[test]
fn auth_token_store_round_trip_in_isolation() {
    let dir = runner::test_support::TempDir::new("auth-it").unwrap();
    let store = TokenStore::new(dir.path().join("env"));
    assert!(!store.has_token(ProviderSlot::Github));

    // Pre-existing content (comments, other vars) survives rotation.
    std::fs::write(store.path(), "# secrets\nOTHER=1\n").unwrap();
    let path = store.set_token(ProviderSlot::Github, "ghp_first").unwrap();
    assert!(store.has_token(ProviderSlot::Github));
    store.set_token(ProviderSlot::Github, "ghp_second").unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("# secrets\nOTHER=1\n"));
    assert_eq!(text.matches("RUNNER_GITHUB_TOKEN=").count(), 1);
    assert!(text.contains("ghp_second"));
    assert!(!text.contains("ghp_first"));
}

#[test]
fn audit_verify_detects_intact_tampered_and_absent_trails() {
    let dir = runner::test_support::TempDir::new("audit-it").unwrap();
    let missing = dir.path().join("nope.jsonl");
    let outcome = verify_file(&missing);
    assert!(outcome.ok());
    assert_eq!(outcome, VerifyOutcome::Absent { path: missing });

    let path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&path).unwrap();
    log.append(LogLevel::Info, "fleet", "runner-1 registered");
    log.append(LogLevel::Error, "worker", "job-9 failed");
    let outcome = verify_file(&path);
    assert!(outcome.ok());
    assert_eq!(
        outcome,
        VerifyOutcome::Intact {
            path: path.clone(),
            entries: 2
        }
    );
    assert!(outcome.report().contains("intact"));

    // Flip one byte in the first entry: must detect, must name the file.
    let mut text = std::fs::read_to_string(&path).unwrap();
    text = text.replacen("runner-1", "runner-2", 1);
    std::fs::write(&path, text).unwrap();
    let outcome = verify_file(&path);
    assert!(!outcome.ok());
    assert!(matches!(outcome, VerifyOutcome::Tampered { .. }));
    assert!(outcome.report().contains("TAMPER"));

    // Garbage line is tamper, not a crash.
    std::fs::write(&path, "not json\n").unwrap();
    assert!(!verify_file(&path).ok());
}

#[test]
fn policy_load_and_describe_cover_all_sources() {
    let dir = runner::test_support::TempDir::new("policy-it").unwrap();
    let missing = dir.path().join("fleet-policy.toml");
    let (policy, note) = load_or_permissive(&missing);
    assert_eq!(policy, runner::policy::FleetPolicy::permissive());
    assert!(note.contains("no policy file"));
    assert!(describe(&policy).contains("none configured"));

    let text = r#"
default_max_cores = 8
default_max_ram_mb = 16384

[[tenants]]
tenant = "acme"
max_cores = 2
max_ram_mb = 4096
providers = ["github"]
allow_cloud_burst = false
"#;
    std::fs::write(&missing, text).unwrap();
    let (policy, note) = load_or_permissive(&missing);
    assert!(note.contains("loaded fleet policy"));
    let rendered = describe(&policy);
    assert!(rendered.contains("tenant 'acme'"));
    assert!(rendered.contains("2 cores"));
    assert!(rendered.contains("providers [github]"));
    assert!(rendered.contains("cloud burst: denied"));

    std::fs::write(&missing, "[[tenants\n").unwrap();
    let (policy, note) = load_or_permissive(&missing);
    assert_eq!(policy, runner::policy::FleetPolicy::permissive());
    assert!(note.contains("rejecting"));
}
