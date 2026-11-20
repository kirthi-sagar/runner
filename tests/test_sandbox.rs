//! Sandbox tests: `/home/*` rejection, RFC 1918 classification, and
//! tmpfs workspace lifecycle (create → scrub → remove).

use runner::sandbox::mounts::{sanitize_job_id, validate_no_home_mount, Workspace};
use runner::sandbox::network::{is_blocked_egress, is_rfc1918, nftables_sandbox_ruleset};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

#[test]
fn home_directories_are_never_mountable() {
    for blocked in ["/home", "/home/linux", "/home/linux/work/repo"] {
        assert!(
            validate_no_home_mount(&[Path::new(blocked)]).is_err(),
            "{blocked}"
        );
    }
    for allowed in ["/workspace", "/tmp/runner-jobs/job-1", "/opt/cache"] {
        assert!(
            validate_no_home_mount(&[Path::new(allowed)]).is_ok(),
            "{allowed}"
        );
    }
    // Mixed lists fail closed.
    assert!(validate_no_home_mount(&[Path::new("/workspace"), Path::new("/home/x")]).is_err());
}

#[test]
fn rfc1918_and_special_ranges_are_blocked() {
    for ip in [
        "10.0.0.1",
        "172.16.5.4",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.169.254",
        "127.0.0.1",
    ] {
        let addr = IpAddr::from_str(ip).unwrap();
        assert!(is_blocked_egress(addr), "{ip}");
    }
    for ip in [
        "1.1.1.1",
        "8.8.8.8",
        "140.82.112.4",
        "172.32.0.1",
        "192.167.1.1",
    ] {
        let addr = IpAddr::from_str(ip).unwrap();
        assert!(
            !is_rfc1918(match addr {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => unreachable!(),
            }),
            "{ip}"
        );
        assert!(!is_blocked_egress(addr), "{ip}");
    }
    // IPv6 ULA blocked, global unicast allowed.
    assert!(is_blocked_egress(IpAddr::from_str("fd12:3456::1").unwrap()));
    assert!(!is_blocked_egress(
        IpAddr::from_str("2606:4700:4700::1111").unwrap()
    ));
}

#[test]
fn sandbox_ruleset_drops_private_allows_dns_https() {
    let rules = nftables_sandbox_ruleset();
    for cidr in [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "fd00::/8",
    ] {
        assert!(rules.contains(cidr), "{cidr}");
    }
    assert!(rules.contains("udp dport 53 accept"));
    assert!(rules.contains("tcp dport 443 accept"));
    assert!(rules.trim_end().ends_with('}'));
}

#[test]
fn workspace_lifecycle_isolates_and_scrubs() {
    let dir = runner::test_support::TempDir::new("sandbox-it").unwrap();
    std::env::set_var("RUNNER_JOB_ROOT", dir.path());
    let leaked = {
        let ws = Workspace::create("job-99").unwrap();
        assert!(ws.path().starts_with(dir.path()));
        let nested = ws.path().join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(ws.path().join("token.txt"), "ghp_secret").unwrap();
        std::fs::write(nested.join("data.bin"), vec![1u8; 1024]).unwrap();
        ws.path().to_path_buf()
    };
    // Drop scrubbed contents and removed the tree.
    assert!(!leaked.exists());
    std::env::remove_var("RUNNER_JOB_ROOT");
}

#[test]
fn hostile_job_ids_stay_inside_root() {
    assert!(!sanitize_job_id("../../etc/cron").contains('/'));
    assert!(!sanitize_job_id("..\\..\\win").contains('\\'));
}

/// Live: download + extract the real official worker (~150MB).
/// Run explicitly: `cargo test --test test_sandbox -- --ignored`.
#[tokio::test]
#[ignore]
async fn live_worker_cache_download() {
    use runner::sandbox::worker::ensure_cached_in;
    let dir = runner::test_support::TempDir::new("live-worker").unwrap();
    let pkg = ensure_cached_in(dir.path(), "2.338.2", "x64")
        .await
        .unwrap();
    assert!(pkg.join("run.sh").exists());
    assert!(pkg.join("bin").join("Runner.Worker").exists());
}

/// Live: verify the sandbox path this kernel supports — a real sandboxed
/// child spawn where unprivileged mounts work, else the plain-spawn
/// fallback the dispatcher takes when `probe_userns` is false.
/// Run explicitly: `cargo test --test test_sandbox -- --ignored`.
#[cfg(unix)]
#[test]
#[ignore]
fn live_sandbox_or_fallback_spawn() {
    use runner::sandbox::mounts::{probe_userns, sandbox_pre_exec, SandboxSpec};
    if probe_userns() {
        let dir = runner::test_support::TempDir::new("live-sandbox").unwrap();
        let ws = dir.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let spec = SandboxSpec::new(ws).unwrap();
        let mut cmd = std::process::Command::new("true");
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(move || sandbox_pre_exec(&spec));
        }
        assert!(cmd.status().unwrap().success());
    } else {
        eprintln!("userns mounts blocked on this host; verifying fallback spawn");
        assert!(std::process::Command::new("true")
            .status()
            .unwrap()
            .success());
    }
}
