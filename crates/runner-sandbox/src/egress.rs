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
//!   sandbox filters — live kernel enforcement. The filters are
//!   unscoped ALE connect rules, so they cover every host process
//!   while the job runs (bounded in time by the dynamic session);
//!   per-job app scoping is a follow-up.
//! * Elsewhere (Linux, macOS): builds the filter program, validates
//!   its assembly, and runs canary packets through the executed
//!   bytecode (private destinations must drop, public DNS/HTTPS must
//!   pass) before the job runs. Privileged kernel attachment
//!   (`bpf()`/`nft`) is a follow-up; the guard guarantees a live,
//!   self-verified enforcement descriptor, reported as such by
//!   [`EgressGuard::is_live`].

#[cfg(not(windows))]
use crate::ebpf::{evaluate_packet, BpfVerdict, EgressFilterProgram};

/// Job-scoped egress enforcement handle.
#[derive(Debug)]
pub struct EgressGuard {
    /// Live WFP session (Windows only; dynamic teardown on drop).
    #[cfg(windows)]
    _session: crate::wfp::WfpEngineSession,
    /// Validated filter program, held live across the job.
    #[cfg(not(windows))]
    _program: EgressFilterProgram,
}

impl EgressGuard {
    /// Acquire enforcement for one job. Returns `None` when disabled
    /// (bypassed); otherwise engages the platform leg and fails
    /// closed with a descriptive error on any failure.
    pub fn acquire(enabled: bool) -> Result<Option<Self>, String> {
        if !enabled {
            return Ok(None);
        }
        #[cfg(windows)]
        {
            let session = crate::wfp::WfpEngineSession::open().map_err(|e| {
                format!("network egress filtering: failed to open WFP engine session: {e}")
            })?;
            session.install_sandbox_rules().map_err(|e| {
                format!("network egress filtering: failed to install sandbox filters: {e}")
            })?;
            Ok(Some(EgressGuard { _session: session }))
        }
        #[cfg(not(windows))]
        {
            Self::acquire_from(&EgressFilterProgram::new()).map(Some)
        }
    }

    /// Validated-leg acquisition over an explicit program (the seam
    /// fail-closed tests use to prove broken programs abort).
    #[cfg(not(windows))]
    pub fn acquire_from(program: &EgressFilterProgram) -> Result<Self, String> {
        program
            .to_instructions()
            .map_err(|e| format!("network egress filtering: filter program invalid: {e}"))?;
        check_canaries(program)?;
        Ok(EgressGuard {
            _program: program.clone(),
        })
    }

    /// True when live kernel enforcement (not just a validated
    /// program) backs this guard.
    pub fn is_live(&self) -> bool {
        cfg!(windows)
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
    }

    #[cfg(not(windows))]
    #[test]
    fn acquire_enabled_holds_validated_program() {
        let guard = EgressGuard::acquire(true).unwrap().expect("guard");
        assert!(!guard.is_live());
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
}
