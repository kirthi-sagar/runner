//! Job-scoped network egress guard (v2.6.0 Phase 4).
//!
//! [`EgressGuard::acquire`] runs before a job spawns and the guard is
//! held across the job's duration, so enforcement covers the whole
//! child process tree and drops on completion. Any acquisition
//! failure aborts the job with a descriptive error — never executes
//! unfiltered.
//!
//! Platform legs:
//!
//! * Windows: opens a dynamic WFP engine session and installs the 11
//!   sandbox filters — live kernel enforcement — scoped to the
//!   worker image when resolvable, unscoped otherwise (both bounded
//!   in time by the dynamic session).
//! * Linux, privileged: validates the filter program, runs the
//!   canary packets, then attaches the rendered ruleset as a unique
//!   nftables table (RAII-torn-down). A failed attach after a
//!   successful probe aborts the job — capable yet broken never runs
//!   unfiltered.
//! * Linux, unprivileged, and macOS: builds the filter program,
//!   validates its assembly, and runs canary packets through the
//!   executed bytecode before the job runs (no kernel attachment).
//!   [`EgressGuard::is_live`] reports true exactly when kernel
//!   enforcement backs the guard.

#[cfg(not(windows))]
use crate::ebpf::{evaluate_packet, BpfVerdict, EgressFilterProgram};

/// Job-scoped egress enforcement handle.
#[derive(Debug)]
pub struct EgressGuard {
    /// Live WFP session (Windows only; dynamic teardown on drop).
    #[cfg(windows)]
    _session: crate::wfp::WfpEngineSession,
    /// Scoping identity when filters attach per-app (Windows only).
    #[cfg(windows)]
    scoped_app: Option<crate::wfp::WfpAppId>,
    /// Validated filter program, held live across the job.
    #[cfg(not(windows))]
    _program: EgressFilterProgram,
    /// Live nftables attachment when the kernel accepted our table
    /// (Linux privileged path; `None` in canary mode).
    #[cfg(not(windows))]
    _attachment: Option<crate::ebpf::nft::NftEgressAttachment>,
}

impl EgressGuard {
    /// Acquire enforcement for one job. Returns `None` when disabled
    /// (bypassed); otherwise engages the platform leg and fails
    /// closed with a descriptive error on any failure.
    pub fn acquire(enabled: bool) -> Result<Option<Self>, String> {
        Self::acquire_scoped(enabled, None)
    }

    /// Acquire enforcement scoped to one application image. With no
    /// path, installs the unscoped session rules (clean fallback).
    /// On Windows a resolvable path scopes all 11 filters to that
    /// image; when resolution fails the guard falls back to unscoped
    /// filters with a loud log — filtering (the invariant) is
    /// preserved while precision degrades, never the reverse. Off
    /// Windows the path validates non-empty and is otherwise ignored
    /// (app scoping is a Windows-kernel concept).
    pub fn acquire_scoped(enabled: bool, app_path: Option<&str>) -> Result<Option<Self>, String> {
        if !enabled {
            return Ok(None);
        }
        let app = app_path
            .map(|path| crate::wfp::WfpAppId::new(path.to_string()))
            .transpose()?;
        #[cfg(windows)]
        {
            let session = crate::wfp::WfpEngineSession::open().map_err(|e| {
                format!("network egress filtering: failed to open WFP engine session: {e}")
            })?;
            match app {
                Some(app) => match session.install_sandbox_rules_scoped(&app) {
                    Ok(_) => Ok(Some(EgressGuard {
                        _session: session,
                        scoped_app: Some(app),
                    })),
                    Err(e) => {
                        // Partial scoped filters may already be
                        // installed; they share weights/actions with
                        // the unscoped set, so verdicts stay identical
                        // and everything dies with the session.
                        eprintln!(
                            "wfp: app-id resolution failed for '{}': {e}; \
                             falling back to unscoped session filters",
                            app.path
                        );
                        session.install_sandbox_rules().map_err(|e| {
                            format!(
                                "network egress filtering: failed to install sandbox filters: {e}"
                            )
                        })?;
                        Ok(Some(EgressGuard {
                            _session: session,
                            scoped_app: None,
                        }))
                    }
                },
                None => {
                    session.install_sandbox_rules().map_err(|e| {
                        format!("network egress filtering: failed to install sandbox filters: {e}")
                    })?;
                    Ok(Some(EgressGuard {
                        _session: session,
                        scoped_app: None,
                    }))
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = app;
            let mut guard = Self::acquire_from(&EgressFilterProgram::new())?;
            // Privileged Linux attaches live kernel enforcement; the
            // probe failing means incapable (unprivileged, no nft),
            // which degrades to canary mode — but a failed attach
            // AFTER a successful probe aborts (capable yet broken
            // must never run unfiltered).
            if crate::ebpf::nft::probe_nft_egress() {
                guard._attachment = Some(crate::ebpf::nft::NftEgressAttachment::attach().map_err(
                    |e| format!("network egress filtering: nftables attach failed: {e}"),
                )?);
            }
            Ok(Some(guard))
        }
    }

    /// Validated-leg acquisition over an explicit program (the seam
    /// fail-closed tests use to prove broken programs abort). Always
    /// canary mode: callers that want kernel enforcement attach
    /// separately (see [`EgressGuard::acquire`]).
    #[cfg(not(windows))]
    pub fn acquire_from(program: &EgressFilterProgram) -> Result<Self, String> {
        program
            .to_instructions()
            .map_err(|e| format!("network egress filtering: filter program invalid: {e}"))?;
        check_canaries(program)?;
        Ok(EgressGuard {
            _program: program.clone(),
            _attachment: None,
        })
    }

    /// True when live kernel enforcement (not just a validated
    /// program) backs this guard: a WFP session on Windows, an
    /// attached nftables table on Linux, never in canary mode.
    pub fn is_live(&self) -> bool {
        #[cfg(windows)]
        {
            true
        }
        #[cfg(not(windows))]
        {
            self._attachment.is_some()
        }
    }

    /// True when the installed filters carry an app-identity
    /// condition (Windows scoped installs only).
    pub fn is_scoped(&self) -> bool {
        #[cfg(windows)]
        {
            self.scoped_app.is_some()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}

/// Prove the program enforces before any job runs: each canary must
/// produce its contract verdict, or acquisition fails closed.
#[cfg(not(windows))]
fn check_canaries(program: &EgressFilterProgram) -> Result<(), String> {
    let canaries = [
        (
            canary_v4([10, 0, 0, 1], 6, 443),
            BpfVerdict::Drop,
            "rfc1918",
        ),
        (
            canary_v4([169, 254, 169, 254], 6, 80),
            BpfVerdict::Drop,
            "metadata",
        ),
        (canary_v4([8, 8, 8, 8], 6, 443), BpfVerdict::Pass, "https"),
        (canary_v4([8, 8, 8, 8], 17, 53), BpfVerdict::Pass, "dns"),
        (canary_v6(0xfd, 6, 443), BpfVerdict::Drop, "ula"),
        (canary_v6(0x20, 6, 443), BpfVerdict::Pass, "public-v6"),
    ];
    for (packet, expected, name) in canaries {
        let verdict = evaluate_packet(program, &packet);
        if verdict != expected {
            return Err(format!(
                "network egress filtering: filter self-check failed (canary {name} \
                 evaluated to {verdict:?}, want {expected:?}); refusing to run unfiltered"
            ));
        }
    }
    Ok(())
}

/// Minimal IPv4 packet for canaries (20-byte header + 4 transport bytes).
#[cfg(not(windows))]
fn canary_v4(dst: [u8; 4], proto: u8, dport: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 24];
    packet[0] = 0x45;
    packet[9] = proto;
    packet[16..20].copy_from_slice(&dst);
    packet[22..24].copy_from_slice(&dport.to_be_bytes());
    packet
}

/// Minimal IPv6 packet for canaries (40-byte header + 4 transport bytes).
#[cfg(not(windows))]
fn canary_v6(first_dst_byte: u8, proto: u8, dport: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 44];
    packet[0] = 0x60;
    packet[6] = proto;
    packet[24] = first_dst_byte;
    packet[42..44].copy_from_slice(&dport.to_be_bytes());
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_disabled_bypasses() {
        assert!(EgressGuard::acquire(false).unwrap().is_none());
        assert!(
            EgressGuard::acquire_scoped(false, Some("C:\\w\\Worker.exe"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn acquire_scoped_rejects_empty_path() {
        let err = EgressGuard::acquire_scoped(true, Some("  ")).unwrap_err();
        assert!(err.contains("must not be empty"), "{err}");
    }

    #[cfg(not(windows))]
    #[test]
    fn acquire_scoped_validates_then_behaves_validated() {
        // App scoping is a Windows-kernel concept: elsewhere the path
        // validates and the guard holds the validated program.
        let guard = EgressGuard::acquire_scoped(true, Some("C:\\w\\Worker.exe"))
            .unwrap()
            .expect("guard");
        assert_eq!(guard.is_live(), crate::ebpf::nft::probe_nft_egress());
        assert!(!guard.is_scoped());
    }

    #[cfg(not(windows))]
    #[test]
    fn acquire_enabled_matches_probe() {
        // Unprivileged boxes hold the validated program (canary
        // mode); privileged Linux attaches live. Either way,
        // `is_live` tracks the probe exactly.
        let guard = EgressGuard::acquire(true).unwrap().expect("guard");
        assert_eq!(guard.is_live(), crate::ebpf::nft::probe_nft_egress());
    }

    #[cfg(not(windows))]
    #[test]
    fn acquire_from_rejects_broken_program() {
        // No blocked ranges: the rfc1918 canary passes instead of
        // dropping, so acquisition fails with a descriptive error.
        let unblocked = EgressFilterProgram {
            blocked_v4: Vec::new(),
            allowed_ports: vec![(17, 53), (6, 443)],
        };
        let err = EgressGuard::acquire_from(&unblocked).unwrap_err();
        assert!(err.contains("network egress filtering"), "{err}");
        assert!(err.contains("rfc1918"), "{err}");
        // No allowlist: the https canary drops instead of passing.
        let unallowed = EgressFilterProgram {
            blocked_v4: EgressFilterProgram::new().blocked_v4,
            allowed_ports: Vec::new(),
        };
        let err = EgressGuard::acquire_from(&unallowed).unwrap_err();
        assert!(err.contains("network egress filtering"), "{err}");
        assert!(err.contains("https"), "{err}");
    }

    /// Live acquisition: dynamic session plus 11 installed filters.
    /// Requires elevated Windows plus `RUNNER_LIVE_WFP=1` (the CI
    /// windows-native job sets it).
    #[cfg(windows)]
    #[test]
    fn live_acquire_installs_session() {
        if std::env::var("RUNNER_LIVE_WFP").is_err() {
            eprintln!("live egress-guard harness skipped (needs RUNNER_LIVE_WFP=1)");
            return;
        }
        let guard = EgressGuard::acquire(true)
            .expect("acquire live guard")
            .expect("guard");
        assert!(guard.is_live());
    }

    /// Live scoped acquisition: filters attach with the app-id
    /// condition resolved from this test binary's own image. Same
    /// elevation + `RUNNER_LIVE_WFP=1` gate as the unscoped test.
    #[cfg(windows)]
    #[test]
    fn live_acquire_scoped_installs() {
        if std::env::var("RUNNER_LIVE_WFP").is_err() {
            eprintln!("live egress-guard harness skipped (needs RUNNER_LIVE_WFP=1)");
            return;
        }
        let exe = std::env::current_exe().expect("own exe path");
        let guard = EgressGuard::acquire_scoped(true, exe.to_str())
            .expect("acquire live scoped guard")
            .expect("guard");
        assert!(guard.is_live());
        assert!(guard.is_scoped());
    }
}
