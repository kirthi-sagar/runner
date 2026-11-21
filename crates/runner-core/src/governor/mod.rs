//! Zero-freeze kernel governor: cgroups v2 slices, PSI monitoring,
//! CPU topology slots, AFK boost, macOS QoS pinning, and Windows
//! Job Objects.

pub mod afk;
pub mod cgroup;
pub mod darwin;
pub mod psi;
pub mod supervisor;
pub mod thermal;
pub mod topology;
#[cfg(windows)]
pub mod windows;
