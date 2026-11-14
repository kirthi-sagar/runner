//! Slot calculations across CPU configs (spec section 3.6 matrix).

use runner::governor::topology::{
    JOB_MIN_CORES, JOB_MIN_MEM_MB, SlotInputs, calculate_slots, default_reserved_cores,
    default_reserved_mem_mb,
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
