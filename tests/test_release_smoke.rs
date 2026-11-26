//! Release-asset smoke tests: pin the installer ↔ release-workflow
//! contract hermetically (pure file parsing, no network, no builds).
//!
//! Guards the `curl | sh` path: asset names the installer fetches must
//! match the names `release.yml` publishes, checksums must verify
//! before extraction, and every version literal must agree.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// `VERSION="2.16.1"` from install.sh.
fn installer_version(sh: &str) -> String {
    sh.lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("VERSION=\"")
                .and_then(|rest| rest.strip_suffix('"'))
        })
        .expect("install.sh must pin VERSION")
        .to_string()
}

/// `[workspace.package] version = "2.16.1"` from the root manifest.
fn workspace_version(toml: &str) -> String {
    let mut in_workspace_package = false;
    for line in toml.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_workspace_package = line == "[workspace.package]";
            continue;
        }
        if in_workspace_package && line.starts_with("version") {
            return line
                .split('=')
                .nth(1)
                .expect("version line has =")
                .trim()
                .trim_matches('"')
                .to_string();
        }
    }
    panic!("root Cargo.toml must declare [workspace.package] version");
}

#[test]
fn installer_version_matches_workspace() {
    let sh = read("install.sh");
    let toml = read("Cargo.toml");
    assert_eq!(installer_version(&sh), workspace_version(&toml));
}

#[test]
fn asset_pattern_matches_release_matrix() {
    let sh = read("install.sh");
    let workflow = read(".github/workflows/release.yml");
    // Installer fetches versioned per-target tarballs from this repo's
    // release downloads.
    assert!(
        sh.contains("TARBALL=\"runner-v$VERSION-$TARGET.tar.gz\""),
        "installer tarball pattern drifted"
    );
    assert!(
        sh.contains("https://github.com/runnerhq/runner/releases/download/v$VERSION"),
        "installer base URL drifted"
    );
    // Every target the workflow builds must be installable.
    for target in [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "aarch64-apple-darwin",
    ] {
        assert!(
            sh.contains(target),
            "installer missing TARGET mapping for {target}"
        );
        assert!(
            workflow.contains(target),
            "release workflow missing matrix target {target}"
        );
    }
    // Workflow publishes the tarball + detached checksum the
    // installer consumes.
    assert!(workflow.contains("runner-*.tar.gz"));
    assert!(workflow.contains("runner-*.tar.gz.sha256"));
    // The Darwin asset name is a deliberate special case (not the
    // `runner-<version>-<triple>` convention); both sides must agree.
    // The workflow composes it via STAGE, the installer names it fully.
    assert!(workflow.contains("STAGE=\"runner-darwin-arm64\""));
    assert!(workflow.contains("\"$STAGE.tar.gz\""));
    assert!(sh.contains("runner-darwin-arm64.tar.gz"));
}

#[test]
fn windows_installer_pins_runnerhq_repo() {
    let ps1 = read("install.ps1");
    // The native installer must fetch releases from this repo.
    assert!(
        ps1.contains("$repo = 'runnerhq/runner'"),
        "install.ps1 repo pin drifted"
    );
    assert!(
        ps1.contains("https://raw.githubusercontent.com/runnerhq/runner/main/install.ps1"),
        "install.ps1 bootstrap URL drifted"
    );
}

#[test]
fn checksum_verifies_before_extract() {
    let sh = read("install.sh");
    let fetch_sum = sh
        .find("$BASE_URL/$TARBALL.sha256")
        .expect("installer must fetch the .sha256 sidecar");
    let verify = sh
        .find("sha256sum -c")
        .expect("installer must verify with sha256sum -c");
    let extract = sh.find("tar -xzf").expect("installer must extract");
    assert!(
        fetch_sum < verify && verify < extract,
        "checksum must verify after fetch and before extract"
    );
    assert!(
        sh.contains("checksum mismatch"),
        "checksum failure must abort loudly"
    );
    // Fail closed: no verifier means no install, never a skip.
    assert!(
        sh.contains("error: sha256sum required for secure release verification"),
        "missing verifier must be fatal"
    );
    assert!(
        !sh.contains("skipping checksum"),
        "unverified extraction must not exist"
    );
}

#[test]
fn installer_supports_uninstall_and_rejects_macos() {
    let sh = read("install.sh");
    // Uninstall removes service, binary, and unit; config survives.
    assert!(sh.contains("--uninstall|uninstall)"), "uninstall flag");
    assert!(sh.contains("config and data are kept"), "data preserved");
    let uninstall = sh.find("--uninstall|uninstall)").unwrap();
    let preflight = sh.find("Pre-flight checks").unwrap();
    assert!(
        uninstall < preflight,
        "uninstall must run before pre-flight gates"
    );
    // macOS installs via launchd (no hard error); Intel macs refuse cleanly.
    assert!(sh.contains("Darwin-arm64"), "darwin target mapping");
    assert!(
        sh.contains("Library/LaunchAgents/com.runner.coordinator.plist"),
        "launchd agent path"
    );
    assert!(sh.contains("launchctl load"), "launchd enablement");
    assert!(sh.contains("launchctl unload"), "launchd uninstall");
    assert!(sh.contains("Intel macs are not supported"), "intel refusal");
    assert!(
        !sh.contains("macOS support is planned post-v1.0"),
        "stale planned-post-v1.0 marker"
    );
}

#[test]
fn installer_fails_closed_on_wsl2_misconfiguration() {
    let sh = read("install.sh");
    // WSL2 detected via distro env or kernel version string.
    assert!(sh.contains("WSL_DISTRO_NAME"), "wsl env detection");
    assert!(sh.contains("microsoft"), "wsl kernel detection");
    // No-systemd WSL fails with the exact remediation.
    assert!(
        sh.contains("WSL2 without systemd"),
        "systemd preflight error"
    );
    assert!(sh.contains("systemd=true"), "systemd remediation");
    // /mnt checkouts refused (9P + CRLF break Linux tooling).
    assert!(sh.contains("/mnt/*"), "/mnt checkout refusal");
}

#[test]
fn sha256_sidecar_format_parses() {
    // Format produced by `sha256sum file > file.sha256` in release.yml:
    // "<64 hex>  <filename>". Parse it the way a verifier would.
    let line = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  runner-v2.16.1-x86_64-unknown-linux-gnu.tar.gz\n";
    let (hex, file) = line.split_once("  ").expect("two-space separator");
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(file.trim_start().starts_with("runner-v"));
    assert!(file.trim_end().ends_with(".tar.gz"));
}

#[test]
fn manifest_versions_agree() {
    let toml = read("Cargo.toml");
    let version = workspace_version(&toml);
    // Every intra-workspace path dependency pins the same version.
    for line in toml.lines().filter(|l| l.contains("path = \"crates/")) {
        assert!(
            line.contains(&format!("version = \"{version}\"")),
            "path dep drifted from workspace version: {line}"
        );
    }
    // Every crate manifest inherits (never pins) the version.
    for krate in [
        "runner-cli",
        "runner-core",
        "runner-enterprise",
        "runner-providers",
        "runner-sandbox",
        "runner-telemetry",
    ] {
        let manifest = read(&format!("crates/{krate}/Cargo.toml"));
        assert!(
            manifest.contains("version.workspace = true"),
            "{krate} must inherit the workspace version"
        );
    }
    // Installer agrees with the manifests.
    assert_eq!(installer_version(&read("install.sh")), version);
}
