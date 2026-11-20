//! System diagnostics (`runner doctor`): kernel, cgroups, sandboxes,
//! daemon, MCP registration, and (with `--enterprise`) fleet policy and
//! audit continuity. Checks are pure over gathered facts and unit-tested;
//! only [`run_all`] touches the live system.

#[cfg(unix)]
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

/// Windows has no `/proc` telemetry; the check names the gap instead
/// of probing paths that can never exist.
#[cfg(windows)]
fn check_kernel() -> Check {
    Check::fail(
        "kernel",
        "feature unavailable on Windows: kernel PSI telemetry (/proc)".to_string(),
    )
}

#[cfg(unix)]
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

/// Windows has no cgroups; the check names the gap explicitly.
#[cfg(windows)]
fn check_cgroup() -> Check {
    Check::fail(
        "cgroupsv2",
        "feature unavailable on Windows: cgroup pressure control".to_string(),
    )
}

#[cfg(unix)]
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
    #[cfg(unix)]
    let mode_ok = std::fs::metadata(&path)
        .map(|m| m.permissions().mode() & 0o777 == 0o600)
        .unwrap_or(false);
    // No POSIX modes on Windows; the socket is absent there anyway
    // (IPC is unsupported), so the warn path below always applies.
    #[cfg(windows)]
    let mode_ok = false;
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

/// Per-probe TCP connect timeout: the egress check must stay fast
/// even when the network silently drops packets (no RST).
const EGRESS_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// One egress expectation: `target` should be reachable iff `allow`.
struct EgressProbe {
    name: &'static str,
    target: std::net::SocketAddr,
    allow: bool,
}

/// Egress compliance probes. Report-only by design: cloud CI runners
/// legitimately reach instance metadata, and offline hosts cannot
/// reach public HTTPS — so unexpected outcomes are `Warn`, never
/// `Fail`, and can never flip [`overall_ok`].
fn egress_probes() -> Vec<EgressProbe> {
    use std::net::{IpAddr, Ipv4Addr};
    vec![
        EgressProbe {
            name: "egress:metadata",
            target: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80),
            allow: false,
        },
        EgressProbe {
            name: "egress:rfc1918",
            target: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1)), 443),
            allow: false,
        },
        EgressProbe {
            name: "egress:https",
            target: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
            allow: true,
        },
    ]
}

/// Map a probe outcome to a [`Check`]: matches expectation → `Pass`,
/// anything else → `Warn` (report-only; see [`egress_probes`]).
fn egress_verdict(probe: &EgressProbe, reachable: bool) -> Check {
    let expected = if probe.allow { "allowed" } else { "blocked" };
    let observed = if reachable { "reachable" } else { "blocked" };
    let detail = format!("{}: expected {expected}, observed {observed}", probe.target);
    if reachable == probe.allow {
        Check::pass(probe.name, detail)
    } else {
        Check::warn(probe.name, detail)
    }
}

/// Attempt a TCP connect with a short timeout. `false` covers refused,
/// timed-out, and administratively filtered targets alike.
fn tcp_reachable(target: std::net::SocketAddr) -> bool {
    std::net::TcpStream::connect_timeout(&target, EGRESS_PROBE_TIMEOUT).is_ok()
}

/// Run the egress compliance probes (blocking; each is timeout-bounded).
fn check_egress() -> Vec<Check> {
    egress_probes()
        .iter()
        .map(|probe| egress_verdict(probe, tcp_reachable(probe.target)))
        .collect()
}

/// Compact duration rendering for TTL details (`7d`, `12h`, `90s`).
fn format_ttl(ttl_secs: u64) -> String {
    if ttl_secs == 0 {
        return "disabled".to_string();
    }
    if ttl_secs.is_multiple_of(86_400) {
        return format!("{}d", ttl_secs / 86_400);
    }
    if ttl_secs.is_multiple_of(3600) {
        return format!("{}h", ttl_secs / 3600);
    }
    format!("{ttl_secs}s")
}

/// Gathered cache facts; verdict logic lives in [`cache_verdict`].
struct CacheFacts {
    listen: String,
    writable: bool,
    reachable: bool,
    reachable_known: bool,
    ttl_secs: u64,
}

/// Cache verdict: Pass only when the store is writable, the proxy
/// answers on loopback, and TTL is enabled. Anything else is Warn —
/// a stopped daemon or a fresh host must never fail `doctor`.
fn cache_verdict(facts: &CacheFacts) -> Check {
    let ttl = format_ttl(facts.ttl_secs);
    if !facts.writable {
        return Check::warn(
            "cache",
            format!("store not writable; proxy on {}", facts.listen),
        );
    }
    if !facts.reachable_known {
        return Check::warn(
            "cache",
            format!(
                "store writable, but listen {:?} is unparseable",
                facts.listen
            ),
        );
    }
    if !facts.reachable {
        return Check::warn(
            "cache",
            format!(
                "proxy on {} unreachable (daemon down?), store writable, TTL {ttl}",
                facts.listen
            ),
        );
    }
    if facts.ttl_secs == 0 {
        return Check::warn(
            "cache",
            format!("proxy on {}, store writable, TTL disabled", facts.listen),
        );
    }
    Check::pass(
        "cache",
        format!(
            "proxy on {}, store writable, TTL {ttl} active",
            facts.listen
        ),
    )
}

/// Real writability proof: permission bits lie under ACLs and
/// overlays, so create the directory and round-trip a probe file.
fn store_writable(dir: &std::path::Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".doctor-write-probe");
    if std::fs::write(&probe, b"ok").is_err() {
        return false;
    }
    std::fs::remove_file(&probe).is_ok()
}

fn check_cache(config: &runner_core::config::RunnerConfig) -> Check {
    use runner_core::config::resolve_cache_dir;
    use std::str::FromStr;

    let dir = resolve_cache_dir(&config.cache);
    let writable = store_writable(&dir);
    let listen = config.cache.listen.clone();
    let (reachable, reachable_known) = match std::net::SocketAddr::from_str(&listen) {
        Ok(addr) => (tcp_reachable(addr), true),
        Err(_) => (false, false),
    };
    cache_verdict(&CacheFacts {
        listen,
        writable,
        reachable,
        reachable_known,
        ttl_secs: config.cache.ttl_secs,
    })
}

/// Gathered workstation-guard facts; verdict in [`guards_verdict`].
struct GuardFacts {
    temp_c: Option<f64>,
    discharging: bool,
}

/// Guard verdict: always Pass except on battery (Warn: the governor
/// halts intake while discharging, which operators should know).
/// Missing sensors read as no-temp / AC, never as failure.
fn guards_verdict(facts: &GuardFacts) -> Check {
    let temp = facts
        .temp_c
        .map(|t| format!("{t:.1}°C"))
        .unwrap_or_else(|| "n/a (no sensor)".to_string());
    let power = if facts.discharging { "battery" } else { "AC" };
    let detail = format!("temp {temp}, power {power} (85°C latch armed)");
    if facts.discharging {
        Check::warn("guards", detail)
    } else {
        Check::pass("guards", detail)
    }
}

fn check_workstation_guards() -> Check {
    use runner_core::governor::thermal::{package_temp_c, power_state, PowerState};

    guards_verdict(&GuardFacts {
        temp_c: package_temp_c(),
        discharging: power_state() == PowerState::Discharging,
    })
}

/// Gathered AFK facts; verdict in [`afk_verdict`].
struct AfkFacts {
    mode: String,
    detector: bool,
}

/// AFK verdict: the configured mode (canonicalized) plus detector
/// presence. A missing detector is Warn, never Fail: headless hosts
/// without logind govern safely via fail-safe Active.
fn afk_verdict(facts: &AfkFacts) -> Check {
    if facts.detector {
        Check::pass("afk", format!("mode {}, idle detector ready", facts.mode))
    } else {
        Check::warn(
            "afk",
            format!(
                "mode {}, no loginctl detector (headless-safe: reads Active)",
                facts.mode
            ),
        )
    }
}

/// No-op pump handler: the doctor only needs the transport socket
/// for STUN, never for mesh traffic.
struct NoopHandler;

impl runner_core::mesh::transport::PeerHandler for NoopHandler {
    fn on_announce<'a>(
        &'a self,
        _tx: &'a runner_core::mesh::transport::PeerTransport,
        _announce: runner_core::mesh::proto::JoinAnnounce,
        _src: std::net::SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {})
    }

    fn on_established<'a>(
        &'a self,
        _tx: &'a runner_core::mesh::transport::PeerTransport,
        _node_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {})
    }

    fn on_message<'a>(
        &'a self,
        _tx: &'a runner_core::mesh::transport::PeerTransport,
        _node_id: &'a str,
        _msg: runner_core::mesh::proto::PeerMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {})
    }
}

struct NatFacts {
    reflexive: Option<std::net::SocketAddr>,
    /// `direct` (no NAT), `cone`, `symmetric`, or `unknown` (one server).
    class: Option<String>,
    error: Option<String>,
}

/// NAT class name: reflexive == source IP toward the server means no
/// NAT in the path (`direct`); otherwise the two-server comparison
/// decides, or `unknown` when only one server answered.
fn nat_class_name(nat: Option<runner_core::mesh::stun::NatClass>, direct: bool) -> String {
    if direct {
        return "direct".to_string();
    }
    match nat {
        Some(runner_core::mesh::stun::NatClass::Cone) => "cone".to_string(),
        Some(runner_core::mesh::stun::NatClass::Symmetric) => "symmetric".to_string(),
        None => "unknown".to_string(),
    }
}

fn nat_verdict(facts: &NatFacts) -> Check {
    match (&facts.reflexive, &facts.class) {
        (Some(addr), Some(class)) if class == "symmetric" => Check::warn(
            "nat",
            format!(
                "reflexive {addr}, symmetric NAT — unreachable peers fall back to cloud burst same-tick"
            ),
        ),
        (Some(addr), Some(class)) => {
            Check::pass("nat", format!("reflexive {addr}, NAT class: {class}"))
        }
        (Some(addr), None) => Check::pass("nat", format!("reflexive {addr}")),
        (None, _) => match &facts.error {
            Some(error) => Check::warn(
                "nat",
                format!("STUN silent ({error}); WAN peers route via observed source only"),
            ),
            None => Check::warn(
                "nat",
                "STUN disabled or unresolvable; WAN peers route via observed source only".to_string(),
            ),
        },
    }
}

/// WAN NAT readiness: reflexive address + class via the configured
/// STUN servers. Warns (never fails) when offline, disabled, or
/// symmetric — the mesh degrades gracefully in all three cases.
async fn check_nat(config: &runner_core::config::RunnerConfig) -> Check {
    use runner_core::mesh::stun::{
        discover_via_transport, local_addr_for, resolve_stun_servers, stun_servers,
    };
    use runner_core::mesh::transport::{PeerTransport, TransportConfig};

    let servers = resolve_stun_servers(&stun_servers(&config.mesh)).await;
    if servers.is_empty() {
        return nat_verdict(&NatFacts {
            reflexive: None,
            class: None,
            error: None,
        });
    }
    let tx = match PeerTransport::spawn(
        TransportConfig {
            listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            keys: runner_core::mesh::peer::generate_keypair(),
        },
        std::sync::Arc::new(NoopHandler),
    )
    .await
    {
        Ok(tx) => tx,
        Err(e) => {
            return nat_verdict(&NatFacts {
                reflexive: None,
                class: None,
                error: Some(e),
            });
        }
    };
    let source_ip = servers.first().and_then(|s| local_addr_for(*s));
    match discover_via_transport(&tx, &servers).await {
        Ok(found) => {
            let direct = source_ip.is_some_and(|ip| ip == found.reflexive.ip());
            let class = nat_class_name(found.nat, direct);
            nat_verdict(&NatFacts {
                reflexive: Some(found.reflexive),
                class: Some(class),
                error: None,
            })
        }
        Err(e) => nat_verdict(&NatFacts {
            reflexive: None,
            class: None,
            error: Some(e),
        }),
    }
}

struct WslFacts {
    proc_version: String,
    distro: Option<String>,
    systemd_active: bool,
}

fn wsl_verdict(facts: &WslFacts) -> Check {
    let lowered = facts.proc_version.to_ascii_lowercase();
    if !lowered.contains("microsoft") && facts.distro.is_none() {
        return Check::pass("wsl", "not running under WSL".to_string());
    }
    let generation = if lowered.contains("wsl2") {
        "WSL2"
    } else {
        "WSL"
    };
    let distro = facts
        .distro
        .clone()
        .unwrap_or_else(|| "unknown distro".to_string());
    if facts.systemd_active {
        Check::pass("wsl", format!("{generation} ({distro}), systemd active"))
    } else {
        Check::warn(
            "wsl",
            format!(
                "{generation} ({distro}) without systemd; set [boot] systemd=true in /etc/wsl.conf and run: wsl --shutdown"
            ),
        )
    }
}

/// Windows Subsystem for Linux identity + systemd readiness. Never
/// fails: native Linux passes trivially, WSL without systemd warns
/// with the exact remediation (see docs/windows.md).
fn check_wsl() -> Check {
    wsl_verdict(&WslFacts {
        proc_version: std::fs::read_to_string("/proc/version").unwrap_or_default(),
        distro: std::env::var("WSL_DISTRO_NAME")
            .ok()
            .filter(|s| !s.is_empty()),
        systemd_active: std::path::Path::new("/run/systemd/system").is_dir(),
    })
}

fn check_afk_boost(config: &runner_core::config::RunnerConfig) -> Check {
    use runner_core::governor::afk::{detector_available, AfkMode};

    afk_verdict(&AfkFacts {
        mode: AfkMode::parse(&config.governor.afk_mode).name().to_string(),
        detector: detector_available(),
    })
}

/// Gather every check; `enterprise` adds policy + audit continuity,
/// `egress` adds the report-only network compliance probes.
pub async fn run_all(
    config: &runner_core::config::RunnerConfig,
    enterprise: bool,
    egress: bool,
) -> Vec<Check> {
    let mut checks = vec![
        check_kernel(),
        check_cgroup(),
        check_userns(),
        check_kvm(),
        check_ebpf(),
        check_daemon().await,
        check_mcp(),
        check_cache(config),
        check_workstation_guards(),
        check_afk_boost(config),
        check_nat(config).await,
        check_wsl(),
    ];
    if enterprise {
        checks.push(check_policy());
        checks.push(check_audit());
    }
    if egress {
        checks.extend(check_egress());
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
    fn nat_class_names_cover_all_paths() {
        use runner_core::mesh::stun::NatClass;
        assert_eq!(nat_class_name(None, true), "direct");
        assert_eq!(nat_class_name(Some(NatClass::Cone), false), "cone");
        assert_eq!(
            nat_class_name(Some(NatClass::Symmetric), false),
            "symmetric"
        );
        assert_eq!(nat_class_name(None, false), "unknown");
    }

    #[test]
    fn nat_verdict_passes_warns_but_never_fails() {
        let addr: std::net::SocketAddr = "198.51.100.7:45001".parse().unwrap();
        // Direct/cone pass with reflexive + class in the detail (the
        // frozen JSON schema carries it via `detail`).
        for class in ["direct", "cone", "unknown"] {
            let check = nat_verdict(&NatFacts {
                reflexive: Some(addr),
                class: Some(class.to_string()),
                error: None,
            });
            assert_eq!(check.name, "nat");
            assert!(matches!(check.status, Status::Pass));
            assert!(
                check.detail.contains("198.51.100.7:45001"),
                "{}",
                check.detail
            );
            assert!(check.detail.contains(class), "{}", check.detail);
        }
        // Symmetric warns with cloud-burst advice.
        let check = nat_verdict(&NatFacts {
            reflexive: Some(addr),
            class: Some("symmetric".to_string()),
            error: None,
        });
        assert!(matches!(check.status, Status::Warn));
        assert!(check.detail.contains("cloud burst"), "{}", check.detail);
        // Silence and disabled STUN warn, keeping overall_ok green.
        for facts in [
            NatFacts {
                reflexive: None,
                class: None,
                error: Some("all STUN servers silent".to_string()),
            },
            NatFacts {
                reflexive: None,
                class: None,
                error: None,
            },
        ] {
            let check = nat_verdict(&facts);
            assert!(matches!(check.status, Status::Warn));
        }
        assert!(overall_ok(&[nat_verdict(&NatFacts {
            reflexive: None,
            class: None,
            error: None,
        })]));
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

    #[test]
    fn egress_verdicts_match_expectation_and_never_fail() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let blocked = EgressProbe {
            name: "egress:test-block",
            target: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            allow: false,
        };
        assert_eq!(egress_verdict(&blocked, false).status, Status::Pass);
        // Unexpectedly reachable is a warning, never a failure.
        assert_eq!(egress_verdict(&blocked, true).status, Status::Warn);
        let allowed = EgressProbe {
            name: "egress:test-allow",
            target: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2),
            allow: true,
        };
        assert_eq!(egress_verdict(&allowed, true).status, Status::Pass);
        assert_eq!(egress_verdict(&allowed, false).status, Status::Warn);
    }

    #[test]
    fn tcp_prober_observes_reachable_and_refused() {
        use std::str::FromStr;
        // Positive control: a bound localhost listener reads reachable.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(tcp_reachable(addr));
        drop(listener);
        // The closed port now refuses (fast, no timeout burn). Retry
        // briefly: a parallel test binary can reuse the ephemeral port
        // within microseconds of the drop.
        let mut refused = false;
        for _ in 0..20 {
            if !tcp_reachable(addr) {
                refused = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(refused, "closed port stayed reachable: {addr}");
        // Documentation prefix is unroutable; must report unreachable,
        // not hang past the timeout (generous upper bound for CI).
        let dark = std::net::SocketAddr::from_str("192.0.2.1:443").unwrap();
        let start = std::time::Instant::now();
        assert!(!tcp_reachable(dark));
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
    }

    #[test]
    fn ttl_renders_compact_units() {
        assert_eq!(format_ttl(0), "disabled");
        assert_eq!(format_ttl(604_800), "7d");
        assert_eq!(format_ttl(43_200), "12h");
        assert_eq!(format_ttl(90), "90s");
    }

    fn cache_facts() -> CacheFacts {
        CacheFacts {
            listen: "127.0.0.1:8787".to_string(),
            writable: true,
            reachable: true,
            reachable_known: true,
            ttl_secs: 604_800,
        }
    }

    #[test]
    fn cache_verdict_passes_only_when_fully_healthy() {
        let pass = cache_verdict(&cache_facts());
        assert_eq!(pass.status, Status::Pass);
        assert_eq!(pass.name, "cache");
        assert!(pass.detail.contains("TTL 7d active"));

        // Every degraded shape warns; none fails.
        let mut down = cache_facts();
        down.reachable = false;
        let warn = cache_verdict(&down);
        assert_eq!(warn.status, Status::Warn);
        assert!(warn.detail.contains("unreachable"));

        let mut ro = cache_facts();
        ro.writable = false;
        assert_eq!(cache_verdict(&ro).status, Status::Warn);

        let mut no_ttl = cache_facts();
        no_ttl.ttl_secs = 0;
        let warn = cache_verdict(&no_ttl);
        assert_eq!(warn.status, Status::Warn);
        assert!(warn.detail.contains("TTL disabled"));

        let mut bad_listen = cache_facts();
        bad_listen.reachable_known = false;
        assert_eq!(cache_verdict(&bad_listen).status, Status::Warn);
    }

    #[test]
    fn store_probe_creates_dir_and_cleans_up() {
        let dir = runner_core::test_support::TempDir::new("doctor-writable").unwrap();
        let nested = dir.path().join("a").join("b");
        assert!(store_writable(&nested));
        assert!(nested.is_dir());
        assert!(!nested.join(".doctor-write-probe").exists());
        // A path blocked by a regular file is not writable.
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, b"x").unwrap();
        assert!(!store_writable(&blocker.join("sub")));
    }

    #[test]
    fn guards_verdict_reports_temp_power_and_battery_warn() {
        let ac = guards_verdict(&GuardFacts {
            temp_c: Some(51.25),
            discharging: false,
        });
        assert_eq!(ac.status, Status::Pass);
        assert!(ac.detail.contains("51.2°C"));
        assert!(ac.detail.contains("power AC"));

        let batt = guards_verdict(&GuardFacts {
            temp_c: None,
            discharging: true,
        });
        assert_eq!(batt.status, Status::Warn);
        assert!(batt.detail.contains("n/a (no sensor)"));
        assert!(batt.detail.contains("power battery"));
    }

    #[test]
    fn afk_verdict_names_mode_and_detector_state() {
        let ready = afk_verdict(&AfkFacts {
            mode: "auto".to_string(),
            detector: true,
        });
        assert_eq!(ready.status, Status::Pass);
        assert!(ready.detail.contains("mode auto"));
        assert!(ready.detail.contains("idle detector ready"));

        let missing = afk_verdict(&AfkFacts {
            mode: "never".to_string(),
            detector: false,
        });
        assert_eq!(missing.status, Status::Warn);
        assert!(missing.detail.contains("mode never"));
    }

    #[test]
    fn renderers_include_new_checks() {
        let checks = vec![
            cache_verdict(&cache_facts()),
            guards_verdict(&GuardFacts {
                temp_c: Some(60.0),
                discharging: false,
            }),
            afk_verdict(&AfkFacts {
                mode: "always".to_string(),
                detector: true,
            }),
        ];
        let text = render_text(&checks);
        assert!(text.contains("cache"));
        assert!(text.contains("guards"));
        assert!(text.contains("afk"));
        let json: serde_json::Value = serde_json::from_str(&render_json(&checks)).unwrap();
        assert_eq!(json["ok"], true);
        let names: Vec<&str> = json["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["cache", "guards", "afk"]);
    }

    #[test]
    fn wsl_verdict_covers_native_ready_and_unready() {
        // Native Linux (or macOS): trivial pass, never noise.
        let native = wsl_verdict(&WslFacts {
            proc_version: "Linux version 6.8.0-91-generic".to_string(),
            distro: None,
            systemd_active: true,
        });
        assert_eq!(native.name, "wsl");
        assert!(matches!(native.status, Status::Pass));

        // WSL2 + systemd: pass naming distro and readiness.
        let ready = wsl_verdict(&WslFacts {
            proc_version: "Linux version 5.15.153.1-microsoft-standard-WSL2".to_string(),
            distro: Some("Ubuntu".to_string()),
            systemd_active: true,
        });
        assert!(matches!(ready.status, Status::Pass));
        assert!(ready.detail.contains("WSL2"), "{}", ready.detail);
        assert!(ready.detail.contains("Ubuntu"), "{}", ready.detail);

        // WSL without systemd: warn with the exact remediation.
        let unready = wsl_verdict(&WslFacts {
            proc_version: "Linux version 5.15.153.1-microsoft-standard-WSL2".to_string(),
            distro: None,
            systemd_active: false,
        });
        assert!(matches!(unready.status, Status::Warn));
        assert!(
            unready.detail.contains("systemd=true"),
            "{}",
            unready.detail
        );

        // Distro env alone (unreadable /proc/version) still detects WSL.
        let env_only = wsl_verdict(&WslFacts {
            proc_version: String::new(),
            distro: Some("Debian".to_string()),
            systemd_active: true,
        });
        assert!(matches!(env_only.status, Status::Pass));
        assert!(env_only.detail.contains("Debian"), "{}", env_only.detail);
    }
}
