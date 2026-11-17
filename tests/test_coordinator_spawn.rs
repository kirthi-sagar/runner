//! Coordinator startup regression: with cloud bursting enabled
//! (`max_monthly_spend > 0`), spawning the coordinator inside a tokio
//! runtime must not panic (v0.4.1 aborted via `blocking_write` under
//! `panic = "abort"`), and the pool must attach to shared state.
//!
//! A second test simulates consecutive queue polls returning identical
//! job IDs against `SharedState` and proves the dedup decision lets
//! exactly one dispatch through per unique job.

use runner::config::RunnerConfig;
use runner::governor::supervisor::new_shared_state;
use runner_cli::coordinator::spawn_coordinator;
use runner_providers::github::webhooks::already_in_flight;

fn coordinator_config() -> RunnerConfig {
    let mut config = RunnerConfig::default();
    config.coordinator.repo_owner = Some("owner".to_string());
    config.coordinator.repo_name = Some("repo".to_string());
    config.coordinator.auto_dispatch = false;
    config.cloud.max_monthly_spend = 50.0;
    config
}

#[tokio::test]
async fn spawn_with_cloud_cap_attaches_pool_without_panic() {
    // SAFETY: this test binary owns its process; no other test here
    // depends on the token value.
    std::env::set_var("RUNNER_GITHUB_TOKEN", "test-token");
    let config = coordinator_config();
    let state = new_shared_state();

    // Would panic (blocking_write inside the runtime) before the fix.
    spawn_coordinator(&config, state.clone()).await;

    let guard = state.read().await;
    assert!(
        guard.cloud_pool().is_some(),
        "cloud pool must attach when max_monthly_spend > 0"
    );
    assert_eq!(guard.cloud_spend_cap(), 50.0);
    // The spawned coordinator task outlives this assertion; it polls no
    // sooner than its 5s floor, so the test binary exits first.
}

#[tokio::test]
async fn consecutive_polls_dispatch_each_job_once() {
    let state = new_shared_state();
    // Poll 1 observes jobs 7 and 8; both dispatch and get recorded.
    for (id, name) in [(7u64, "a"), (8u64, "b")] {
        let flying = state.read().await.in_flight_jobs();
        assert!(!already_in_flight(&flying, "github", &id.to_string()));
        state
            .write()
            .await
            .job_started("github", &id.to_string(), name);
    }
    // Poll 2 observes the same queued ids: all skip, zero re-dispatch.
    let flying = state.read().await.in_flight_jobs();
    assert!(already_in_flight(&flying, "github", "7"));
    assert!(already_in_flight(&flying, "github", "8"));
    assert_eq!(flying.len(), 2);
    // Same ids from another forge are different jobs.
    assert!(!already_in_flight(&flying, "gitlab", "7"));
    // Completion releases the id for future runs.
    state.write().await.job_finished("7");
    let flying = state.read().await.in_flight_jobs();
    assert!(!already_in_flight(&flying, "github", "7"));
    assert!(already_in_flight(&flying, "github", "8"));
}
