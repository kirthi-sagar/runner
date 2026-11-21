//! CPU core/thread topology and parallel-slot calculation.
//!
//! Slot formula (spec section 3.4):
//!
//! ```text
//! S = max(1, min(floor((C_total - C_reserved) / C_job_min),
//!                floor((M_avail - M_reserved) / M_job_min)))
//! ```
//!
//! SMT siblings are detected via
//! `/sys/devices/system/cpu/cpu*/topology/thread_siblings_list`: CPUs
//! sharing a list entry are threads of one physical core.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;

/// Minimum cores per CI job slot (spec default).
pub const JOB_MIN_CORES: f64 = 1.5;
/// Minimum RAM per CI job slot in MiB (spec default 2.0 GiB).
pub const JOB_MIN_MEM_MB: u64 = 2048;
/// Minimum interactive RAM headroom in MiB (spec default 4 GiB).
pub const MIN_RESERVED_MEM_MB: u64 = 4096;
/// Minimum interactive core headroom.
pub const MIN_RESERVED_CORES: f64 = 2.0;

/// Detected CPU topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuTopology {
    /// Logical CPUs visible to the kernel (`C_total`).
    pub logical: u32,
    /// Physical cores (distinct `thread_siblings_list` sets).
    pub physical: u32,
}

impl CpuTopology {
    pub fn smt_enabled(&self) -> bool {
        self.logical > self.physical
    }

    /// Threads per physical core (1 without SMT).
    pub fn threads_per_core(&self) -> u32 {
        self.logical.checked_div(self.physical).unwrap_or(0)
    }
}

/// Parse one `thread_siblings_list` entry (`0`, `0,8`, `0-1`) into a
/// canonical sorted CPU id list.
pub fn parse_sibling_list(text: &str) -> Result<Vec<u32>, String> {
    let mut ids = Vec::new();
    for part in text.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: u32 = lo.parse().map_err(|_| format!("bad range: {part}"))?;
            let hi: u32 = hi.parse().map_err(|_| format!("bad range: {part}"))?;
            if hi < lo {
                return Err(format!("bad range: {part}"));
            }
            ids.extend(lo..=hi);
        } else {
            ids.push(part.parse().map_err(|_| format!("bad cpu id: {part}"))?);
        }
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

/// Detect topology from a `/sys/devices/system/cpu`-shaped directory.
pub fn detect_topology_from(sysfs_cpu: &Path) -> io::Result<CpuTopology> {
    let mut logical = 0u32;
    let mut physical_sets: HashSet<Vec<u32>> = HashSet::new();
    let mut index = 0u32;
    loop {
        let siblings = sysfs_cpu
            .join(format!("cpu{index}"))
            .join("topology/thread_siblings_list");
        if !siblings.exists() {
            break;
        }
        let text = fs::read_to_string(&siblings)?;
        let set =
            parse_sibling_list(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        physical_sets.insert(set);
        logical += 1;
        index += 1;
    }
    if logical == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no cpuN entries under {}", sysfs_cpu.display()),
        ));
    }
    Ok(CpuTopology {
        logical,
        physical: physical_sets.len() as u32,
    })
}

/// Detect live host CPU topology.
pub fn detect_topology() -> io::Result<CpuTopology> {
    detect_topology_from(Path::new("/sys/devices/system/cpu"))
}

/// Default interactive core headroom: `max(2, 0.25 * C_total)`.
pub fn default_reserved_cores(c_total: u32) -> f64 {
    MIN_RESERVED_CORES.max(0.25 * c_total as f64)
}

/// Default interactive RAM headroom in MiB: `max(4GiB, 0.20 * M_total)`.
pub fn default_reserved_mem_mb(m_total_mb: u64) -> u64 {
    MIN_RESERVED_MEM_MB.max((0.20 * m_total_mb as f64) as u64)
}

/// Inputs to the slot formula.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlotInputs {
    pub c_total: f64,
    pub c_reserved: f64,
    pub c_job_min: f64,
    pub m_avail_mb: u64,
    pub m_reserved_mb: u64,
    pub m_job_min_mb: u64,
}

/// Safe parallel runner slots `S` (always >= 1).
pub fn calculate_slots(inputs: SlotInputs) -> u32 {
    let cpu_slots = ((inputs.c_total - inputs.c_reserved) / inputs.c_job_min).floor() as i64;
    let mem_slots = inputs
        .m_avail_mb
        .saturating_sub(inputs.m_reserved_mb)
        .checked_div(inputs.m_job_min_mb.max(1))
        .unwrap_or(0) as i64;
    cpu_slots.min(mem_slots).max(1) as u32
}

/// Read `(MemTotal, MemAvailable)` from `/proc/meminfo` in MiB.
pub fn read_meminfo_mb() -> io::Result<(u64, u64)> {
    read_meminfo_mb_from(Path::new("/proc/meminfo"))
}

fn read_meminfo_mb_from(path: &Path) -> io::Result<(u64, u64)> {
    let text = fs::read_to_string(path)?;
    let mut total_kb = None;
    let mut avail_kb = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_kb = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok());
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail_kb = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok());
        }
    }
    match (total_kb, avail_kb) {
        (Some(total), Some(avail)) => Ok((total / 1024, avail / 1024)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing MemTotal/MemAvailable",
        )),
    }
}

/// Full slot report for the live host.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlotReport {
    pub topology: CpuTopology,
    pub mem_total_mb: u64,
    pub mem_avail_mb: u64,
    pub slots: u32,
    pub afk_boost: bool,
}

/// Detect live slots. Under `afk_boost`, reserved headroom collapses to
/// near-zero (spec section 3.4).
pub fn detect_slots(afk_boost: bool) -> io::Result<SlotReport> {
    #[cfg(target_os = "macos")]
    {
        mac_slots(afk_boost)
    }
    #[cfg(windows)]
    {
        windows_slots(afk_boost)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let topology = detect_topology()?;
        let (mem_total_mb, mem_avail_mb) = read_meminfo_mb()?;
        Ok(slots_from_counts(
            topology,
            mem_total_mb,
            mem_avail_mb,
            afk_boost,
        ))
    }
}

/// Windows has no sysfs/NUMA topology wired; report a static
/// single-core topology so slot math still resolves. (The governor
/// loop sizes from `available_parallelism` instead.)
#[cfg(windows)]
fn windows_slots(afk_boost: bool) -> io::Result<SlotReport> {
    eprintln!("NUMA topology unavailable on Windows");
    Ok(slots_from_counts(
        CpuTopology {
            logical: 1,
            physical: 1,
        },
        4096,
        4096,
        afk_boost,
    ))
}

/// Assemble a slot report from explicit counts (shared by the Linux
/// sysfs path and the macOS sysconf path).
fn slots_from_counts(
    topology: CpuTopology,
    mem_total_mb: u64,
    mem_avail_mb: u64,
    afk_boost: bool,
) -> SlotReport {
    let (c_reserved, m_reserved_mb) = if afk_boost {
        (0.5, 512)
    } else {
        (
            default_reserved_cores(topology.logical),
            default_reserved_mem_mb(mem_total_mb),
        )
    };
    let slots = calculate_slots(SlotInputs {
        c_total: topology.logical as f64,
        c_reserved,
        c_job_min: JOB_MIN_CORES,
        m_avail_mb: mem_avail_mb,
        m_reserved_mb,
        m_job_min_mb: JOB_MIN_MEM_MB,
    });
    SlotReport {
        topology,
        mem_total_mb,
        mem_avail_mb,
        slots,
        afk_boost,
    }
}

/// macOS slot detection: logical CPUs from the stdlib, total RAM from
/// sysconf. Available memory approximates as total (no pressure
/// feedback on macOS v1); the static reserve headroom still applies.
#[cfg(target_os = "macos")]
fn mac_slots(afk_boost: bool) -> io::Result<SlotReport> {
    let logical = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4)
        .max(1);
    // SAFETY: sysconf with valid names is pure.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
    let mem_total_mb = if pages > 0 && page_size > 0 {
        ((pages as u64) * (page_size as u64)) / (1024 * 1024)
    } else {
        8192
    };
    Ok(slots_from_counts(
        CpuTopology {
            logical,
            physical: logical,
        },
        mem_total_mb,
        mem_total_mb,
        afk_boost,
    ))
}

/// `nproc`-trap clamps injected into every job sandbox (spec section 3.6).
pub fn sandbox_env_clamps() -> [(&'static str, &'static str); 4] {
    [
        ("CMAKE_BUILD_PARALLEL_LEVEL", "2"),
        ("UV_CONCURRENT_DOWNLOADS", "4"),
        ("MKL_NUM_THREADS", "2"),
        ("OPENBLAS_NUM_THREADS", "2"),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn slots_from_counts_matches_detect_contract() {
        // 8 logical CPUs, 16 GiB: sane multi-slot report, AFK boosts.
        let plain = slots_from_counts(
            CpuTopology {
                logical: 8,
                physical: 8,
            },
            16384,
            16384,
            false,
        );
        assert!(plain.slots >= 2, "slots: {}", plain.slots);
        assert_eq!(plain.mem_total_mb, 16384);
        assert!(!plain.afk_boost);
        let boosted = slots_from_counts(
            CpuTopology {
                logical: 8,
                physical: 8,
            },
            16384,
            16384,
            true,
        );
        assert!(boosted.slots >= plain.slots);
        // Degenerate inputs still yield a usable report (never zero slots).
        let tiny = slots_from_counts(
            CpuTopology {
                logical: 1,
                physical: 1,
            },
            512,
            512,
            false,
        );
        assert!(tiny.slots >= 1);
    }

    use super::*;

    #[test]
    fn parses_sibling_lists() {
        assert_eq!(parse_sibling_list("0\n").unwrap(), vec![0]);
        assert_eq!(parse_sibling_list("0,8\n").unwrap(), vec![0, 8]);
        assert_eq!(parse_sibling_list("0-3\n").unwrap(), vec![0, 1, 2, 3]);
        assert!(parse_sibling_list("3-0").is_err());
    }

    #[test]
    fn four_cores_no_smt_yields_one_slot() {
        // 4c/4t interactive: (4 - 2) / 1.5 = 1 slot.
        let slots = calculate_slots(SlotInputs {
            c_total: 4.0,
            c_reserved: 2.0,
            c_job_min: JOB_MIN_CORES,
            m_avail_mb: 12_288,
            m_reserved_mb: 4096,
            m_job_min_mb: JOB_MIN_MEM_MB,
        });
        assert_eq!(slots, 1);
    }

    #[test]
    fn four_cores_smt_yields_four_slots() {
        // 4c/8t interactive: (8 - 2) / 1.5 = 4 slots (RAM permitting).
        let slots = calculate_slots(SlotInputs {
            c_total: 8.0,
            c_reserved: 2.0,
            c_job_min: JOB_MIN_CORES,
            m_avail_mb: 12_288,
            m_reserved_mb: 4096,
            m_job_min_mb: JOB_MIN_MEM_MB,
        });
        assert_eq!(slots, 4);
    }

    #[test]
    fn memory_can_bound_slots() {
        let slots = calculate_slots(SlotInputs {
            c_total: 16.0,
            c_reserved: 4.0,
            c_job_min: JOB_MIN_CORES,
            m_avail_mb: 8192,
            m_reserved_mb: 4096,
            m_job_min_mb: JOB_MIN_MEM_MB,
        });
        assert_eq!(slots, 2);
    }

    #[test]
    fn slots_never_drop_below_one() {
        let slots = calculate_slots(SlotInputs {
            c_total: 2.0,
            c_reserved: 4.0,
            c_job_min: JOB_MIN_CORES,
            m_avail_mb: 1024,
            m_reserved_mb: 4096,
            m_job_min_mb: JOB_MIN_MEM_MB,
        });
        assert_eq!(slots, 1);
    }

    #[test]
    fn detects_topology_from_fixture() {
        let dir = crate::test_support::TempDir::new("topo").unwrap();
        // Simulate 2c/4t: cpu0+cpu1 share core 0, cpu2+cpu3 share core 1.
        for (cpu, siblings) in [(0, "0-1"), (1, "0-1"), (2, "2-3"), (3, "2-3")] {
            let path = dir.path().join(format!("cpu{cpu}/topology"));
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("thread_siblings_list"), siblings).unwrap();
        }
        let topo = detect_topology_from(dir.path()).unwrap();
        assert_eq!(
            topo,
            CpuTopology {
                logical: 4,
                physical: 2
            }
        );
        assert!(topo.smt_enabled());
        assert_eq!(topo.threads_per_core(), 2);
    }
}
