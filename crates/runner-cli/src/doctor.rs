//! System diagnostics (`runner doctor`): kernel, cgroups, sandboxes,
//! daemon, MCP registration, and (with `--enterprise`) fleet policy and
//! audit continuity. Checks are pure over gathered facts and unit-tested;
//! only [`run_all`] touches the live system.

use std::os::unix::fs::PermissionsExt;

/// Check severity: exit code is 0 unless a [`Status::Fail`] exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    fn glyph(&self) -> &'static str {
        match self {
            Self::Pass => "[✓]",
            Self::Warn => "[!]",
            Self::Fail => "[✗]",
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// One diagnostic result.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
}

impl Check {
    fn pass(name: &str, detail: String) -> Self {
        Self {
            name: name.to_string(),
            status: Status::Pass,
            detail,
        }
    }

    fn warn(name: &str, detail: String) -> Self {
        Self {
            name: name.to_string(),
            status: Status::Warn,
            detail,
        }
    }

    fn fail(name: &str, detail: String) -> Self {
        Self {
            name: name.to_string(),
            status: Status::Fail,
            detail,
        }
    }
}

/// Parse `(major, minor)` from a kernel release like `5.15.0-91-generic`.
pub fn parse_kernel_release(text: &str) -> Option<(u32, u32)> {
    let mut parts = text.trim().split(|c: char| !c.is_ascii_digit());
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next().filter(|s| !s.is_empty())?.parse().ok()?;
    Some((major, minor))
}

fn check_kernel() -> Check {
    let release =
        std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_else(|_| "?".to_string());
    let release = release.trim().to_string();
    let mut missing = Vec::new();
    for file in ["cpu", "memory", "io"] {
        if !std::path::Path::new(&format!("/proc/pressure/{file}")).exists() {
            missing.push(file);
        }
    }
    match parse_kernel_release(&release) {
        Some((major, minor)) if (major, minor) >= (5, 8) && missing.is_empty() => {
            Check::pass("kernel", format!("{release} with PSI (cpu/memory/io)"))
        }
        Some(_) if !missing.is_empty() => Check::fail(
            "kernel",
            format!(
                "{release} but /proc/pressure missing: {}",
                missing.join(",")
            ),
        ),
        _ => Check::fail(
            "kernel",
            format!("{release}: need Linux >= 5.8 with PSI support"),
        ),
    }
}

fn check_cgroup() -> Check {
    match std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers") {
        Ok(text) => {
            let controllers: Vec<&str> = text.split_whitespace().collect();
            if controllers.is_empty() {
                Check::warn(
                    "cgroupsv2",
                    "mounted but no controllers enabled".to_string(),
                )
            } else {
                Check::pass(
                    "cgroupsv2",
                    format!("controllers: {}", controllers.join(" ")),
                )
            }
        }
        Err(_) => Check::fail(
            "cgroupsv2",
            "/sys/fs/cgroup/cgroup.controllers unreadable (need cgroups v2)".to_string(),
        ),
    }
}

fn check_userns() -> Check {
    if runner_sandbox::mounts::probe_userns() {
        Check::pass(
            "userns",
            "unprivileged user+mount namespaces work (Tier-2)".to_string(),
        )
    } else {
        Check::warn(
            "userns",
            "user namespaces unavailable; jobs run governed-direct (Tier-2 degraded)".to_string(),
        )
    }
}

fn check_kvm() -> Check {
    if runner_sandbox::microvm::probe_kvm() {
        Check::pass("kvm", "/dev/kvm ready (Tier-1 microVM)".to_string())
    } else {
        Check::warn(
            "kvm",
            "/dev/kvm missing; Tier-1 microVMs unavailable".to_string(),
        )
    }
}

fn check_ebpf() -> Check {
    if runner_sandbox::ebpf::probe_ebpf() {
        Check::pass(
            "ebpf",
            "unprivileged socket-filter attach works".to_string(),
        )
    } else {
        Check::warn(
            "ebpf",
            "socket-filter attach unavailable; network policy degraded".to_string(),
        )
    }
}

async fn check_daemon() -> Check {
    let path = runner_core::ipc::resolve_sock_path();
    if !path.exists() {
        return Check::warn(
            "daemon",
            format!("socket {} absent; daemon not running?", path.display()),
        );
    }
    let mode_ok = std::fs::metadata(&path)
        .map(|m| m.permissions().mode() & 0o777 == 0o600)
        .unwrap_or(false);
    match runner_core::ipc::ipc_call(&path, "ping").await {
        Ok(_) if mode_ok => {
            Check::pass("daemon", format!("IPC alive at {} (0600)", path.display()))
        }
        Ok(_) => Check::warn(
            "daemon",
            format!(
                "IPC alive at {} but permissions are not 0600",
                path.display()
            ),
        ),
        Err(e) => Check::warn("daemon", format!("socket present but ping failed: {e}")),
    }
}

fn mcp_entry_present(path: &std::path::Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|doc| doc.get("mcpServers")?.get("runner").cloned())
        .is_some()
}

fn check_mcp() -> Check {
    use runner_core::mcp::install::{default_target_path, McpTarget};

    let mut registered = Vec::new();
    for target in [McpTarget::Cursor, McpTarget::Claude] {
        if let Some(path) = default_target_path(target) {
            if mcp_entry_present(&path) {
                registered.push(target.name());
            }
        }
    }
    if registered.is_empty() {
        Check::warn(
            "mcp",
            "no agent registration found; run `runner mcp install --target cursor|claude`"
                .to_string(),
        )
    } else {
        Check::pass("mcp", format!("registered for: {}", registered.join(", ")))
    }
}

fn check_policy() -> Check {
    use runner_enterprise::policy::{default_policy_path, load_or_permissive};

    match default_policy_path() {
        Some(path) => {
            let (policy, note) = load_or_permissive(&path);
            if note.starts_with("loaded") {
                Check::pass(
                    "policy",
                    format!("{} tenants active ({})", policy.tenants.len(), note),
                )
            } else if note.starts_with("rejecting") || note.starts_with("unreadable") {
                Check::warn("policy", note)
            } else {
                Check::warn(
                    "policy",
                    format!("{note} (enterprise dormant until configured)"),
                )
            }
        }
        None => Check::warn("policy", "no HOME; cannot locate fleet policy".to_string()),
    }
}

fn check_audit() -> Check {
    use runner_enterprise::audit::{default_audit_path, verify_file, VerifyOutcome};

    match default_audit_path() {
        Some(path) => match verify_file(&path) {
            VerifyOutcome::Intact { entries, .. } => {
                Check::pass("audit", format!("SHA-256 chain intact ({entries} entries)"))
            }
            VerifyOutcome::Absent { .. } => Check::warn(
                "audit",
                "no audit trail yet; chain starts on first entry".to_string(),
            ),
            VerifyOutcome::Tampered { reason, .. } => Check::fail("audit", reason),
        },
        None => Check::warn("audit", "no HOME; cannot locate audit trail".to_string()),
    }
}

/// Gather every check; `enterprise` adds policy + audit continuity.
pub async fn run_all(enterprise: bool) -> Vec<Check> {
    let mut checks = vec![
        check_kernel(),
        check_cgroup(),
        check_userns(),
        check_kvm(),
        check_ebpf(),
        check_daemon().await,
        check_mcp(),
    ];
    if enterprise {
        checks.push(check_policy());
        checks.push(check_audit());
    }
    checks
}

/// True when no check failed (warnings allowed).
pub fn overall_ok(checks: &[Check]) -> bool {
    !checks.iter().any(|c| c.status == Status::Fail)
}

/// Human-readable checklist.
pub fn render_text(checks: &[Check]) -> String {
    let mut out = String::from("runner doctor\n");
    for check in checks {
        out.push_str(&format!(
            "{} {:<10} {}\n",
            check.status.glyph(),
            check.name,
            check.detail
        ));
    }
    out.push_str(if overall_ok(checks) {
        "result: healthy\n"
    } else {
        "result: FAILURES PRESENT\n"
    });
    out
}

/// Machine-readable report.
pub fn render_json(checks: &[Check]) -> String {
    let items: Vec<serde_json::Value> = checks
        .iter()
        .map(|c| {
            serde_json::json!({ "name": c.name, "status": c.status.name(), "detail": c.detail })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({ "checks": items, "ok": overall_ok(checks) }))
        .unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_releases_parse() {
        assert_eq!(parse_kernel_release("5.15.0-91-generic\n"), Some((5, 15)));
        assert_eq!(parse_kernel_release("6.8.0"), Some((6, 8)));
        assert_eq!(parse_kernel_release("5.8"), Some((5, 8)));
        assert!(parse_kernel_release("not-a-kernel").is_none());
        assert!(parse_kernel_release("").is_none());
        assert!((5, 15) >= (5, 8));
        assert!((5, 4) < (5, 8));
    }

    #[test]
    fn renderers_cover_all_statuses() {
        let checks = vec![
            Check::pass("a", "fine".to_string()),
            Check::warn("b", "degraded".to_string()),
            Check::fail("c", "broken".to_string()),
        ];
        let text = render_text(&checks);
        assert!(text.contains("[✓]"));
        assert!(text.contains("[!]"));
        assert!(text.contains("[✗]"));
        assert!(text.contains("FAILURES PRESENT"));
        assert!(!overall_ok(&checks));
        let json: serde_json::Value = serde_json::from_str(&render_json(&checks)).unwrap();
        assert_eq!(json["ok"], false);
        assert_eq!(json["checks"][2]["status"], "fail");

        let healthy = vec![Check::pass("a", "fine".to_string())];
        assert!(overall_ok(&healthy));
        assert!(render_text(&healthy).contains("result: healthy"));
    }

    #[test]
    fn mcp_detection_reads_runner_entry() {
        let dir = runner_core::test_support::TempDir::new("doctor-mcp").unwrap();
        let path = dir.path().join("mcp.json");
        assert!(!mcp_entry_present(&path));
        std::fs::write(&path, r#"{"mcpServers": {"other": {}}}"#).unwrap();
        assert!(!mcp_entry_present(&path));
        std::fs::write(&path, r#"{"mcpServers": {"runner": {"command": "x"}}}"#).unwrap();
        assert!(mcp_entry_present(&path));
        std::fs::write(&path, "{invalid").unwrap();
        assert!(!mcp_entry_present(&path));
    }
}
