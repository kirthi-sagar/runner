//! Slot calculations across CPU configs (spec section 3.6 matrix).

use runner::governor::topology::{
    calculate_slots, default_reserved_cores, default_reserved_mem_mb, SlotInputs, JOB_MIN_CORES,
    JOB_MIN_MEM_MB,
};

#[test]
fn spec_matrix_interactive_slots() {
    // 4c/4t interactive -> 1 slot.
    assert_eq!(
        calculate_slots(SlotInputs {
            c_total: 4.0,
            c_reserved: default_reserved_cores(4),
            c_job_min: JOB_MIN_CORES,
            m_avail_mb: 12_288,
            m_reserved_mb: default_reserved_mem_mb(16_384),
            m_job_min_mb: JOB_MIN_MEM_MB,
        }),
        1
    );
    // 4c/8t interactive -> 4 slots (RAM permitting).
    assert_eq!(
        calculate_slots(SlotInputs {
            c_total: 8.0,
            c_reserved: default_reserved_cores(8),
            c_job_min: JOB_MIN_CORES,
            m_avail_mb: 12_288,
            m_reserved_mb: default_reserved_mem_mb(16_384),
            m_job_min_mb: JOB_MIN_MEM_MB,
        }),
        4
    );
}

#[cfg(windows)]
#[test]
fn windows_detects_real_topology_and_memory() {
    let report = runner::governor::topology::detect_slots(false).expect("detect slots");
    assert!(
        report.topology.logical >= report.topology.physical,
        "logical {} < physical {}",
        report.topology.logical,
        report.topology.physical
    );
    assert!(report.topology.physical >= 1, "no cores detected");
    assert!(report.mem_total_mb > 0, "no memory reported");
    assert!(
        report.mem_avail_mb <= report.mem_total_mb,
        "avail exceeds total"
    );
    assert!(report.slots >= 1, "zero slots");
}

#[test]
fn afk_boost_expands_slots() {
    let interactive = calculate_slots(SlotInputs {
        c_total: 8.0,
        c_reserved: default_reserved_cores(8),
        c_job_min: JOB_MIN_CORES,
        m_avail_mb: 12_288,
        m_reserved_mb: default_reserved_mem_mb(16_384),
        m_job_min_mb: JOB_MIN_MEM_MB,
    });
    let boosted = calculate_slots(SlotInputs {
        c_total: 8.0,
        c_reserved: 0.5,
        c_job_min: JOB_MIN_CORES,
        m_avail_mb: 12_288,
        m_reserved_mb: 512,
        m_job_min_mb: JOB_MIN_MEM_MB,
    });
    assert!(boosted > interactive);
}
