//! Zero-freeze kernel governor: cgroups v2 slices, PSI monitoring,
//! CPU topology slots, and AFK boost.

pub mod afk;
pub mod cgroup;
pub mod psi;
pub mod supervisor;
pub mod topology;
