//! Egress-guard lifecycle: disabled bypasses, enabled acquires and
//! holds across worker/engine execution, broken programs fail closed
//! with a descriptive error. (Windows live-session coverage lives in
//! the `RUNNER_LIVE_WFP`-gated unit test; execution fixtures here are
//! Unix-gated like the worker module's own tests.)

#[cfg(not(windows))]
use runner::sandbox::ebpf::EgressFilterProgram;
use runner::sandbox::egress::EgressGuard;
#[cfg(unix)]
use std::time::Duration;

#[test]
fn disabled_bypasses_guard() {
    assert!(EgressGuard::acquire(false).unwrap().is_none());
}

#[cfg(not(windows))]
#[test]
fn enabled_acquires_guard_matching_probe() {
    let guard = EgressGuard::acquire(true).unwrap().expect("guard");
    assert_eq!(
        guard.is_live(),
        runner::sandbox::ebpf::nft::probe_nft_egress()
    );
}

#[cfg(not(windows))]
#[test]
fn broken_program_fails_closed_with_descriptive_error() {
    let unblocked = EgressFilterProgram {
        blocked_v4: Vec::new(),
        allowed_ports: vec![(17, 53), (6, 443)],
    };
    let err = EgressGuard::acquire_from(&unblocked).unwrap_err();
    assert!(err.contains("network egress filtering"), "{err}");
    assert!(err.contains("rfc1918"), "{err}");
}

/// Fake worker package: a `run.sh` honoring `--jitconfig`, exiting 0.
#[cfg(unix)]
fn fake_worker_package(tag: &str) -> (runner::test_support::TempDir, std::path::PathBuf) {
    use std::io::Write;
    let dir = runner::test_support::TempDir::new(tag).unwrap();
    let pkg = dir.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    let script = pkg.join("run.sh");
    let mut file = std::fs::File::create(&script).unwrap();
    file.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
    file.sync_all().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    // TempDir must outlive the package path: return it alongside.
    (dir, pkg)
}

#[cfg(unix)]
#[tokio::test]
async fn worker_runs_bypassed_when_disabled() {
    use runner::sandbox::worker::{run_supervised, WorkerLaunch};
    use std::sync::Arc;
    let (_dir, pkg) = fake_worker_package("egress-bypassed");
    let launch = WorkerLaunch::new(pkg, "BLOB");
    assert!(!launch.network_egress_filtering);
    let outcome = run_supervised(
        &launch,
        None,
        Duration::from_secs(10),
        Arc::new(runner::governor::darwin::DarwinQos),
    )
    .await
    .unwrap();
    assert_eq!(outcome.exit_code, Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn worker_runs_guarded_when_enabled() {
    use runner::sandbox::worker::{run_supervised, WorkerLaunch};
    use std::sync::Arc;
    let (_dir, pkg) = fake_worker_package("egress-guarded");
    let mut launch = WorkerLaunch::new(pkg, "BLOB");
    launch.network_egress_filtering = true;
    let outcome = run_supervised(
        &launch,
        None,
        Duration::from_secs(10),
        Arc::new(runner::governor::darwin::DarwinQos),
    )
    .await
    .unwrap();
    assert_eq!(outcome.exit_code, Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn engine_process_tier_runs_guarded_when_enabled() {
    use runner::sandbox::driver::{SandboxDriver, SandboxEngine};
    let engine = SandboxEngine::new(SandboxDriver::Process).with_network_egress_filtering(true);
    let code = engine
        .execute(&["true".to_string()], Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(code, 0);
}
