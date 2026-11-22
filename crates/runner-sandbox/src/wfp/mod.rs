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
//! filter installation (`FwpmFilterAdd0`). Job-scoped
//! install/remove wiring lands in a later phase.

pub mod engine;
pub mod types;

pub use engine::{plan_conditions, WfpConditionPlan, WfpEngineSession};

pub use types::{
    arbitrate, parse_v4_cidr, parse_v6_cidr, sandbox_egress_rules, v4_prefix_mask, v6_prefix_mask,
    WfpAction, WfpAddressCondition, WfpFilterRule, WfpLayer, WfpPortCondition, WfpProtocol,
    WfpSession, SESSION_DESCRIPTION, SESSION_NAME, WEIGHT_BLOCK_PRIVATE, WEIGHT_DEFAULT_DROP,
    WEIGHT_PERMIT_ALLOWLIST,
};

/// `#[cfg(windows)]` mappings from the portable contract to real WFP
/// constants. Pure value mappings only — engine calls arrive in
/// Phase 2.
#[cfg(windows)]
pub mod api {
    use windows_sys::core::GUID;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;

    use super::types::{WfpAction, WfpLayer};

    /// ALE authorize layer GUID for a portable [`WfpLayer`].
    pub fn layer_guid(layer: WfpLayer) -> GUID {
        match layer {
            WfpLayer::AleAuthConnectV4 => wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            WfpLayer::AleAuthConnectV6 => wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        }
    }

    /// Session flags for the sandbox egress session: dynamic only,
    /// so the kernel reaps every filter if the runner dies.
    pub fn session_flags() -> u32 {
        wfp::FWPM_SESSION_FLAG_DYNAMIC
    }

    /// WFP action code for a portable [`WfpAction`].
    pub fn action_type(action: WfpAction) -> wfp::FWP_ACTION_TYPE {
        match action {
            WfpAction::Block => wfp::FWP_ACTION_BLOCK,
            WfpAction::Permit => wfp::FWP_ACTION_PERMIT,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn mappings_cover_both_layers_and_actions() {
            // GUID has no PartialEq; compare the leading fields.
            let v4 = layer_guid(WfpLayer::AleAuthConnectV4);
            let v6 = layer_guid(WfpLayer::AleAuthConnectV6);
            assert_ne!(v4.data1, 0);
            assert_ne!(v6.data1, 0);
            assert_ne!(v4.data1, v6.data1);
            assert_eq!(session_flags(), wfp::FWPM_SESSION_FLAG_DYNAMIC);
            assert_eq!(action_type(WfpAction::Block), wfp::FWP_ACTION_BLOCK);
            assert_eq!(action_type(WfpAction::Permit), wfp::FWP_ACTION_PERMIT);
        }
    }
}
