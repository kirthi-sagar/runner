//! Zero-freeze kernel governor: cgroups v2 slices, PSI monitoring,
//! CPU topology slots, AFK boost, and macOS QoS pinning.

pub mod afk;
pub mod cgroup;
pub mod darwin;
pub mod psi;
pub mod supervisor;
pub mod thermal;
pub mod topology;
