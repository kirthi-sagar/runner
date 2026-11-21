//! Service tests: env loading semantics and systemd unit rendering.
//!
//! Live `systemctl` calls are exercised by manual smoke only; these tests
//! cover the pure helpers and file-loading path end to end.

use std::fs;

use runner::config::{load_env_file_from, parse_env_file};
use runner::service::{current_binary_path, unit_file_contents, user_unit_path};

#[test]
fn env_round_trip_sets_only_missing_vars() {
    let dir = runner::test_support::TempDir::new("service-env-it").unwrap();
    let path = dir.path().join("env");
    fs::write(
        &path,
        "# runner env\nRUNNER_TEST_SVC_KEEP=from-file\nRUNNER_TEST_SVC_NEW=from-file\n",
    )
    .unwrap();

    let keep = "RUNNER_TEST_SVC_KEEP";
    let new = "RUNNER_TEST_SVC_NEW";
    let prior_keep = std::env::var_os(keep);
    let prior_new = std::env::var_os(new);
    std::env::set_var(keep, "preset");
    std::env::remove_var(new);

    assert_eq!(load_env_file_from(&path), 1);
    assert_eq!(std::env::var(keep).unwrap(), "preset");
    assert_eq!(std::env::var(new).unwrap(), "from-file");
    // Idempotent: second load sets nothing new.
    assert_eq!(load_env_file_from(&path), 0);

    match prior_keep {
        Some(v) => std::env::set_var(keep, v),
        None => std::env::remove_var(keep),
    }
    match prior_new {
        Some(v) => std::env::set_var(new, v),
        None => std::env::remove_var(new),
    }
}

#[test]
fn parser_skips_malformed_lines() {
    let pairs = parse_env_file("A=1\nnot a pair\n=novalue\nB = 2 \n");
    assert_eq!(
        pairs,
        vec![
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "2".to_string()),
        ]
    );
}

#[test]
fn unit_file_matches_installer_contract() {
    let text = unit_file_contents("/opt/runner/bin/runner start");
    assert!(text.starts_with("[Unit]\n"));
    assert!(text.contains("ExecStart=/opt/runner/bin/runner start\n"));
    assert!(text.contains("EnvironmentFile=-%h/.config/runner/env\n"));
    assert!(text.contains(
        "Environment=\"PATH=%h/.cargo/bin:%h/.local/bin:/usr/local/bin:/usr/bin:/bin\"\n"
    ));
    assert!(text.contains("WantedBy=default.target\n"));
    assert!(text.ends_with('\n'));
}

#[test]
fn unit_path_and_binary_resolve() {
    // HOME is set under Unix cargo test; Windows CI leaves it
    // unset, and the path must be absent exactly then.
    match user_unit_path() {
        Some(unit) => assert!(unit.ends_with(".config/systemd/user/runner.service")),
        None => assert!(
            std::env::var_os("HOME").is_none(),
            "unit path missing while HOME is set"
        ),
    }

    // The integration test binary itself must resolve to a real file.
    let exe = current_binary_path().unwrap();
    assert!(std::path::Path::new(&exe).is_file());
}
