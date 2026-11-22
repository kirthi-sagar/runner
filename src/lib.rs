//! `runner` open-core facade: stable `runner::*` API over the workspace.
//!
//! The implementation lives in focused crates; this crate only re-exports
//! so existing binaries, tests, and agents keep working unchanged:
//!
//! * [`runner_core`] — engine: config, governor, mesh, IPC, MCP, status.
//! * [`runner_sandbox`] — dual-tier isolation (process namespaces / microVM).
//! * [`runner_providers`] — universal CI adapters (GitHub/GitLab/Bitbucket/local).
//! * [`runner_telemetry`] — ring-buffer capture and structured JSON logs.
//! * [`runner_enterprise`] — governance: control plane, audit, fleet policy, SSO.
//! * [`runner_cli`] — unified binary entrypoint (`service` helpers).
//! * [`runner_guest_agent`] — Tier-1 in-guest exec agent over vsock.
//!
//! Binding design authority: `README.md` and
//! `AI_AGENT_RUNNER_SPECIFICATION.md` in the repository root.
//!
//! # Non-negotiable invariants
//!
//! * Never `cgroup.freeze` active tests; trickle-throttle with `cpu.weight = 1`.
//! * Wrap the official `actions/runner` worker via single-use JIT configs.
//! * Never mount `/home/*` into job sandboxes; block RFC 1918 egress.

pub use runner_cli::{init, service};
pub use runner_core::{
    auth, cache, config, governor, ipc, mcp, mesh, pidfile, status, test_support,
};
pub use runner_enterprise::{audit, control_plane, policy, spend, sso, webhook};
pub use runner_guest_agent as guest_agent;
pub use runner_providers::{github, providers};
pub use runner_sandbox as sandbox;
pub use runner_telemetry as telemetry;
