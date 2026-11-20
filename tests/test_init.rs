//! `runner init` onboarding: config merge, secret storage, idempotency.
//!
//! The core takes explicit paths so these tests never touch the real HOME.

use std::fs;

use runner::init::{run_init, InitOptions, InitReport};
use runner::test_support::TempDir;

fn options(tag: &str) -> (TempDir, InitOptions) {
    let dir = TempDir::new(tag).unwrap();
    let opts = InitOptions {
        org: None,
        repo: None,
        token: None,
        config_path: dir.path().join("runner").join("config.toml"),
        env_path: dir.path().join("runner").join("env"),
        cache_dir: dir.path().join("cache"),
    };
    (dir, opts)
}

fn read_config(report: &InitReport) -> String {
    fs::read_to_string(&report.config_path).unwrap()
}

#[cfg(unix)]
fn mode_of(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn fresh_init_writes_config_and_next_steps() {
    let (_dir, mut opts) = options("init-fresh-it");
    opts.org = Some("acme".to_string());
    opts.repo = Some("acme/web".to_string());

    let report = run_init(&opts).unwrap();
    assert!(report.created_config);
    assert!(!report.changes.is_empty());

    let text = read_config(&report);
    assert!(text.contains("org = \"acme\""), "config text: {text}");
    assert!(
        text.contains("repo_owner = \"acme\""),
        "config text: {text}"
    );
    assert!(text.contains("repo_name = \"web\""), "config text: {text}");
    #[cfg(unix)]
    assert_eq!(mode_of(&report.config_path), 0o600);

    let rendered = runner::init::render_report(&report);
    for step in [
        "runner auth github",
        "runner service install",
        "runner doctor",
    ] {
        assert!(
            rendered.contains(step),
            "missing next step {step}: {rendered}"
        );
    }
}

#[test]
fn token_is_stored_once_and_never_printed() {
    let (_dir, mut opts) = options("init-token-it");
    opts.org = Some("acme".to_string());
    opts.token = Some("ghp_s3cretvalue".to_string());

    let report = run_init(&opts).unwrap();
    let env = fs::read_to_string(&opts.env_path).unwrap();
    assert_eq!(env.matches("RUNNER_GITHUB_TOKEN=").count(), 1);
    assert!(env.contains("RUNNER_GITHUB_TOKEN=ghp_s3cretvalue"));
    #[cfg(unix)]
    assert_eq!(mode_of(&opts.env_path), 0o600);

    // Re-running with the same token rotates in place (no duplicates).
    let report2 = run_init(&opts).unwrap();
    assert!(!report2.created_config);
    let env2 = fs::read_to_string(&opts.env_path).unwrap();
    assert_eq!(env2.matches("RUNNER_GITHUB_TOKEN=").count(), 1);

    // The secret (or any recognizable fragment) never reaches the report.
    let rendered = runner::init::render_report(&report);
    assert!(!rendered.contains("ghp_s3cretvalue"), "{rendered}");
    assert!(!rendered.contains("ghp_s3cr"), "{rendered}");
}

#[test]
fn rerun_merges_and_preserves_foreign_sections() {
    let (_dir, mut opts) = options("init-merge-it");
    fs::create_dir_all(opts.config_path.parent().unwrap()).unwrap();
    fs::write(
        &opts.config_path,
        "[cloud]\nmax_monthly_spend = 42.0\n[coordinator]\nauto_dispatch = true\n",
    )
    .unwrap();

    opts.org = Some("acme".to_string());
    let report = run_init(&opts).unwrap();
    assert!(!report.created_config);
    let text = read_config(&report);
    assert!(text.contains("org = \"acme\""), "config text: {text}");
    assert!(
        text.contains("max_monthly_spend = 42.0"),
        "config text: {text}"
    );
    assert!(text.contains("auto_dispatch = true"), "config text: {text}");

    // An identical re-run changes nothing but still reports next steps.
    let report2 = run_init(&opts).unwrap();
    assert!(report2.changes.is_empty());
    let rendered = runner::init::render_report(&report2);
    assert!(rendered.contains("already up to date"), "{rendered}");
    assert!(rendered.contains("runner doctor"), "{rendered}");
}

#[test]
fn malformed_config_fails_closed_without_write() {
    let (_dir, mut opts) = options("init-malformed-it");
    fs::create_dir_all(opts.config_path.parent().unwrap()).unwrap();
    fs::write(&opts.config_path, "[[[ not toml\n").unwrap();
    opts.org = Some("acme".to_string());

    let err = run_init(&opts).unwrap_err();
    assert!(err.contains("parse"), "error: {err}");
    assert_eq!(
        fs::read_to_string(&opts.config_path).unwrap(),
        "[[[ not toml\n"
    );
    assert!(!opts.env_path.exists());
}

#[test]
fn invalid_repo_slugs_are_rejected_without_write() {
    for (i, bad) in ["noslash", "a/b/c", "/name", "owner/"].iter().enumerate() {
        let (_dir, mut opts) = options(&format!("init-badrepo-{i}-it"));
        opts.repo = Some((*bad).to_string());
        let err = run_init(&opts).unwrap_err();
        assert!(err.contains("owner/name"), "slug {bad:?}: {err}");
        assert!(
            !opts.config_path.exists(),
            "slug {bad:?} must not write config"
        );
    }
}

#[test]
fn empty_options_still_seeds_layout() {
    let (_dir, opts) = options("init-empty-it");
    let report = run_init(&opts).unwrap();
    assert!(report.created_config);
    assert!(report.changes.is_empty());
    let text = read_config(&report);
    assert!(!text.contains("org = "), "config text: {text}");
    assert!(opts.cache_dir.is_dir());

    // Explicit empty strings are treated as absent, not malformed.
    let (_dir2, mut opts2) = options("init-empty-str-it");
    opts2.org = Some("   ".to_string());
    opts2.repo = Some(String::new());
    let report2 = run_init(&opts2).unwrap();
    let text2 = read_config(&report2);
    assert!(!text2.contains("org = "), "config text: {text2}");
    assert!(!text2.contains("repo_owner = "), "config text: {text2}");
}
