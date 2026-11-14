//! `runner`: host supervisor, federated mesh coordinator, and sandbox
//! hypervisor for GitHub Actions runners.
//!
//! Binding design authority: `README.md` and
//! `AI_AGENT_RUNNER_SPECIFICATION.md` in the repository root.
//!
//! # Non-negotiable invariants
//!
//! * Never `cgroup.freeze` active tests; trickle-throttle with `cpu.weight = 1`.
//! * Wrap the official `actions/runner` worker via single-use JIT configs.
//! * Never mount `/home/*` into job sandboxes; block RFC 1918 egress.

pub mod config;
pub mod control_plane;
pub mod github;
pub mod governor;
pub mod ipc;
pub mod mcp;
pub mod mesh;
pub mod pidfile;
pub mod providers;
pub mod sandbox;
pub mod status;

/// Std-only unique temp dir guard for tests (no external crates).
#[doc(hidden)]
pub mod test_support {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        pub fn new(tag: &str) -> std::io::Result<Self> {
            let id = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "runner-test-{}-{}-{tag}",
                std::process::id(),
                id
            ));
            std::fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
