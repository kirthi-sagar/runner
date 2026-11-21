//! Strict sandbox mode: fail closed instead of running unsandboxed.
//!
//! `execute_local_sandboxed` with `strict` refuses when Tier-2 is
//! disabled; `RUNNER_STRICT=1` flips strict on without a CLI flag.

use runner::config::{is_strict, RunnerConfig};
use runner::providers::local::execute_local_sandboxed;
use std::time::Duration;

#[tokio::test]
async fn test_strict_refuses_no_sandbox() {
    // Never spawned (strict bails first), so any argv works on every OS.
    let argv = vec!["echo".to_string(), "hello".to_string()];
    let err = execute_local_sandboxed(&argv, true, Duration::from_secs(30), true)
        .await
        .expect_err("strict + no_sandbox must fail closed");
    assert!(
        err.to_string()
            .contains("--strict refuses unsandboxed execution"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn test_strict_env_override() {
    let config = RunnerConfig::default();
    assert!(!is_strict(false, &config));
    std::env::set_var("RUNNER_STRICT", "1");
    assert!(is_strict(false, &config));
    std::env::set_var("RUNNER_STRICT", "true");
    assert!(is_strict(false, &config));
    std::env::set_var("RUNNER_STRICT", "0");
    assert!(!is_strict(false, &config));
    std::env::remove_var("RUNNER_STRICT");
    assert!(!is_strict(false, &config));
    // Config file strict sticks without any flag or env.
    let mut strict_config = RunnerConfig::default();
    strict_config.sandbox.strict = true;
    assert!(is_strict(false, &strict_config));
    // Explicit flag wins on its own.
    assert!(is_strict(true, &config));
}
