//! Windows Filtering Platform egress boundary (v2.6.0).
//!
//! Native Windows enforcement of the shared [`crate::network`] egress
//! contract — drop RFC 1918, link-local, and ULA destinations, allow
//! only DNS (UDP 53) and public HTTPS (TCP 443), drop everything
//! else — bringing Windows to parity with the Linux eBPF boundary.
//!
//! Design (ratified for v2.6.0):
//!
//! * Filters attach at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` / `_V6`, the
//!   outbound-connect authorize layers. No callout driver: plain
//!   allow/block filters via user-mode `fwpuclnt` APIs only.
//! * The session is dynamic (`FWPM_SESSION_FLAG_DYNAMIC`): if the
//!   runner process dies, the kernel tears the session and every
//!   filter down, so rules can never leak past the job.
//! * Deny-before-allow ordering is weight-enforced (see
//!   [`WEIGHT_BLOCK_PRIVATE`]), never position-dependent.
//! * Supply-chain purity holds: only a `windows-sys` feature flag,
//!   zero new crates.
//!
//! Gating split (same convention as [`crate::seatbelt`]): the rule
//! builder, condition matchers, and arbitration in [`types`] compile
//! everywhere and are unit-tested on Linux CI, while the mappings to
//! real WFP constants live in the `#[cfg(windows)]`-gated `api`
//! module.
//!
//! Phase 1 delivered the core contract plus the pure-logic rule
//! engine ([`types`]). Phase 2 adds the live engine half ([`engine`]):
//! a dynamic session (`FwpmEngineOpen0`) with RAII close plus ALE
//! filter installation (`FwpmFilterAdd0`). Per-app scoping
//! (`FWPM_CONDITION_ALE_APP_ID`, resolved in the Windows-only `api`
//! module) narrows filters to one image; true process-tree
//! confinement needs token/package isolation (follow-up).

pub mod engine;
pub mod types;

pub use engine::{plan_conditions, WfpConditionPlan, WfpEngineSession};

pub use types::{
    arbitrate, parse_v4_cidr, parse_v6_cidr, sandbox_egress_rules, sandbox_egress_rules_scoped,
    v4_prefix_mask, v6_prefix_mask, WfpAction, WfpAddressCondition, WfpAppId, WfpFilterRule,
    WfpLayer, WfpPortCondition, WfpProtocol, WfpSession, SESSION_DESCRIPTION, SESSION_NAME,
    WEIGHT_BLOCK_PRIVATE, WEIGHT_DEFAULT_DROP, WEIGHT_PERMIT_ALLOWLIST,
};

/// `#[cfg(windows)]` mappings from the portable contract to real WFP
/// constants, plus the app-id resolver.
#[cfg(windows)]
pub mod api;
