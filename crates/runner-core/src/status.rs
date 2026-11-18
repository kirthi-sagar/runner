//! Machine-readable host telemetry (spec section 4.2).
//!
//! Shared by `runner status`, the MCP `get_ci_status` tool, and the IPC
//! `status` method so all three report identical shapes.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::governor::cgroup::CgroupSlice;
use crate::governor::psi::{read_snapshot, PressureLevel};
use crate::governor::supervisor::{ForgeHealth, SupervisorState};
use crate::governor::topology::{default_reserved_cores, detect_slots, CpuTopology};

#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub status: &'static str,
    pub version: &'static str,
    pub host: HostStatus,
    pub concurrency: ConcurrencyStatus,
    pub active_jobs: Vec<serde_json::Value>,
    pub mesh_nodes: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governor_error: Option<String>,
    /// Per-forge poll health; present only when built with daemon state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forges: Option<BTreeMap<String, ForgeHealth>>,
}

#[derive(Debug, Serialize)]
pub struct HostStatus {
    pub total_cores: u32,
    pub physical_cores: u32,
    pub available_cores_for_ci: f64,
    pub total_memory_bytes: u64,
    pub available_memory_bytes: u64,
    pub psi_pressure: PsiStatus,
    pub cgroup_weight: Option<u32>,
    pub temperature_c: Option<f64>,
    pub discharging: bool,
}

#[derive(Debug, Serialize)]
pub struct PsiStatus {
    pub cpu_some_avg10: f64,
    pub memory_some_avg10: f64,
    pub io_full_avg10: f64,
    pub cpu_level: PressureLevel,
}

#[derive(Debug, Serialize)]
pub struct ConcurrencyStatus {
    pub max_slots: u32,
    pub active_slots: u32,
    pub queued_github_jobs: u32,
    pub afk_boost: bool,
}

/// Build a live status report from kernel interfaces, enriched with
/// daemon state (per-forge health). Never fails: read errors are
/// captured in `governor_error` with safe fallbacks.
pub fn status_report_with_state(state: &SupervisorState) -> StatusReport {
    let mut report = status_report();
    report.forges = Some(state.forge_health());
    report
}

/// Build a live status report from kernel interfaces. Never fails: read
/// errors are captured in `governor_error` with safe fallbacks.
pub fn status_report() -> StatusReport {
    let mut governor_error = None;
    let snapshot = read_snapshot().unwrap_or_default();
    let (topology, mem_total_mb, mem_avail_mb, max_slots) = match detect_slots(false) {
        Ok(report) => (
            report.topology,
            report.mem_total_mb,
            report.mem_avail_mb,
            report.slots,
        ),
        Err(e) => {
            governor_error = Some(format!("topology: {e}"));
            (
                CpuTopology {
                    logical: 0,
                    physical: 0,
                },
                0,
                0,
                1,
            )
        }
    };
    let cgroup_weight = CgroupSlice::system_default().weight().ok();
    let reserved = default_reserved_cores(topology.logical);
    let temperature_c = crate::governor::thermal::package_temp_c();
    let discharging = crate::governor::thermal::power_state()
        == crate::governor::thermal::PowerState::Discharging;

    StatusReport {
        status: "healthy",
        version: env!("CARGO_PKG_VERSION"),
        host: HostStatus {
            total_cores: topology.logical,
            physical_cores: topology.physical,
            available_cores_for_ci: (topology.logical as f64 - reserved).max(0.0),
            total_memory_bytes: mem_total_mb * 1024 * 1024,
            available_memory_bytes: mem_avail_mb * 1024 * 1024,
            psi_pressure: PsiStatus {
                cpu_some_avg10: snapshot.cpu_some_avg10(),
                memory_some_avg10: snapshot.memory.some.avg10,
                io_full_avg10: snapshot.io.full.avg10,
                cpu_level: snapshot.cpu_pressure(),
            },
            cgroup_weight,
            temperature_c,
            discharging,
        },
        concurrency: ConcurrencyStatus {
            max_slots,
            active_slots: 0,
            queued_github_jobs: 0,
            afk_boost: false,
        },
        active_jobs: Vec::new(),
        mesh_nodes: Vec::new(),
        governor_error,
        forges: None,
    }
}
