//! WFP dynamic engine session + sandbox filter installation (Phase 2).
//!
//! Windows half: [`WfpEngineSession`] opens a dynamic engine session
//! (`FwpmEngineOpen0` with `FWPM_SESSION_FLAG_DYNAMIC`) and installs
//! the portable sandbox egress ruleset as native ALE connect filters
//! (`FwpmFilterAdd0`). The session is RAII: `Drop` closes the engine
//! handle on the clean path, and dynamic teardown reaps the session
//! and every installed filter even if the process dies.
//!
//! Portable half: [`plan_conditions`] lowers each rule to native
//! condition plans, so the rule-to-condition mapping is unit-tested
//! on every platform. Lowering notes:
//!
//! * IPv4 remote address → `FWPM_CONDITION_IP_REMOTE_ADDRESS` with an
//!   `FWP_V4_ADDR_AND_MASK` (address + mask, as stored).
//! * IPv6 remote address → the same condition with an
//!   `FWP_V6_ADDR_AND_MASK` (address + prefix length; the portable
//!   mask lowers through a leading-one count, exact for the
//!   CIDR-contiguous masks the contract builds).
//! * Port rules → `FWPM_CONDITION_IP_PROTOCOL` (`FWP_UINT8`) plus
//!   `FWPM_CONDITION_IP_REMOTE_PORT` (`FWP_UINT16`).
//! * App rules → `FWPM_CONDITION_ALE_APP_ID` with a resolved
//!   `FWP_BYTE_BLOB` (one resolution shared across the install).
//! * Filter weight → `FWP_UINT64` value; block/permit → `FWPM_ACTION0`.
//!
//! Non-Windows builds get a disabled stub exposing the same method
//! surface so downstream call sites compile unconditionally. Every
//! stub method logs the WFP feature name and fails — never silently
//! succeeds.

use super::types::{WfpAddressCondition, WfpFilterRule, WfpProtocol};

/// Planned native WFP condition (portable; lowered to
/// `FWPM_FILTER_CONDITION0` on Windows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpConditionPlan {
    /// `FWPM_CONDITION_IP_REMOTE_ADDRESS` as IPv4 addr + mask.
    RemoteAddressV4 {
        /// Big-endian network address.
        addr: u32,
        /// Big-endian prefix mask.
        mask: u32,
    },
    /// `FWPM_CONDITION_IP_REMOTE_ADDRESS` as IPv6 addr + prefix len.
    RemoteAddressV6 {
        /// 16-byte network address.
        addr: [u8; 16],
        /// Prefix length (WFP takes a length, not a mask, for v6).
        prefix_len: u8,
    },
    /// `FWPM_CONDITION_IP_PROTOCOL` (`FWP_UINT8`).
    IpProtocol {
        /// Transport protocol.
        protocol: WfpProtocol,
    },
    /// `FWPM_CONDITION_IP_REMOTE_PORT` (`FWP_UINT16`).
    RemotePort {
        /// Destination port.
        port: u16,
    },
}

/// Lower a portable rule to native condition plans, in filter order:
/// remote address first, then protocol, then port. Default rules
/// lower to zero plans (unconditional filters).
pub fn plan_conditions(rule: &WfpFilterRule) -> Vec<WfpConditionPlan> {
    let mut plans = Vec::new();
    match rule.address {
        Some(WfpAddressCondition::V4 { addr, mask }) => {
            plans.push(WfpConditionPlan::RemoteAddressV4 { addr, mask });
        }
        Some(WfpAddressCondition::V6 { addr, mask }) => {
            plans.push(WfpConditionPlan::RemoteAddressV6 {
                addr,
                prefix_len: v6_prefix_len(mask),
            });
        }
        None => {}
    }
    if let Some(port) = rule.port {
        plans.push(WfpConditionPlan::IpProtocol {
            protocol: port.protocol,
        });
        plans.push(WfpConditionPlan::RemotePort { port: port.port });
    }
    plans
}

/// Derive an IPv6 prefix length from a 16-byte mask by counting
/// leading one bits. Masks built by `parse_v6_cidr` are always
/// CIDR-contiguous, so the count is exact; a non-contiguous mask
/// lowers to its leading run, which for a block rule drops a
/// superset (fail-closed).
fn v6_prefix_len(mask: [u8; 16]) -> u8 {
    let mut len: u8 = 0;
    for byte in mask {
        if byte == 0xff {
            len += 8;
        } else {
            len += byte.leading_ones() as u8;
            break;
        }
    }
    len.min(128)
}

#[cfg(windows)]
mod imp {
    use std::io;
    use std::ptr;

    use windows_sys::core::{GUID, PWSTR};
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

    use super::{plan_conditions, WfpConditionPlan};
    use crate::wfp::api;
    use crate::wfp::types::{
        sandbox_egress_rules, sandbox_egress_rules_scoped, WfpAppId, WfpFilterRule,
        SESSION_DESCRIPTION, SESSION_NAME,
    };

    /// RAII handle to a dynamic WFP engine session (Windows only).
    ///
    /// The session opens with `FWPM_SESSION_FLAG_DYNAMIC`: if the
    /// runner process dies without closing, the kernel reaps the
    /// session and every filter installed through it. `Drop` closes
    /// the engine handle explicitly on the clean path.
    #[derive(Debug)]
    pub struct WfpEngineSession {
        handle: HANDLE,
        // Session display strings; kept alive for the session lifetime.
        _name: Vec<u16>,
        _description: Vec<u16>,
    }

    // SAFETY: the engine HANDLE is an owned kernel object reference —
    // opened here, closed exactly once in Drop, with no thread
    // affinity — so moving ownership across threads is safe. `Sync`
    // is deliberately not implemented: concurrent shared use is not
    // needed and gets no safety claim.
    unsafe impl Send for WfpEngineSession {}

    impl WfpEngineSession {
        /// Open a dynamic engine session on the local host with
        /// default authentication.
        pub fn open() -> io::Result<Self> {
            let name = api::wide_string(SESSION_NAME);
            let description = api::wide_string(SESSION_DESCRIPTION);
            let session = wfp::FWPM_SESSION0 {
                sessionKey: random_guid(),
                displayData: wfp::FWPM_DISPLAY_DATA0 {
                    name: name.as_ptr() as PWSTR,
                    description: description.as_ptr() as PWSTR,
                },
                flags: api::session_flags(),
                ..Default::default()
            };
            let mut handle: HANDLE = ptr::null_mut();
            // SAFETY: null server/identity select the local host with
            // default auth; `session` and `handle` are valid for the call.
            let code = unsafe {
                wfp::FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_DEFAULT as u32,
                    ptr::null(),
                    &session,
                    &mut handle,
                )
            };
            if code != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            Ok(WfpEngineSession {
                handle,
                _name: name,
                _description: description,
            })
        }

        /// Install the sandbox egress filters; returns their filter IDs.
        ///
        /// Fails closed: the first failing filter aborts the install
        /// with the engine's error. Filters installed before the
        /// failure stay owned by this dynamic session and die with it.
        pub fn install_sandbox_rules(&self) -> io::Result<Vec<u64>> {
            let mut ids = Vec::new();
            for rule in sandbox_egress_rules() {
                ids.push(self.install_rule(&rule, None)?);
            }
            Ok(ids)
        }

        /// Install the 11 sandbox egress filters scoped to one
        /// application image; returns their filter IDs. The app id is
        /// resolved once and shared across the install. See
        /// [`WfpAppId`] for the scoping boundary (one image, not a
        /// process tree).
        pub fn install_sandbox_rules_scoped(&self, app: &WfpAppId) -> io::Result<Vec<u64>> {
            let mut blob = api::AppIdBlob::resolve(&app.path)?;
            let mut ids = Vec::new();
            for rule in sandbox_egress_rules_scoped(app) {
                ids.push(self.install_rule(&rule, Some(&mut blob))?);
            }
            Ok(ids)
        }

        /// Install one portable rule as a native ALE connect filter,
        /// attaching the app-identity condition when the rule carries
        /// one (the resolved blob must accompany it).
        fn install_rule(
            &self,
            rule: &WfpFilterRule,
            app: Option<&mut api::AppIdBlob>,
        ) -> io::Result<u64> {
            // Scratch storage: everything the filter points at must
            // outlive the FwpmFilterAdd0 call (the engine copies on
            // add). Each slot is written in the arm that stores its
            // pointer, so uninitialized memory is never observed.
            let mut v4_slot = std::mem::MaybeUninit::<wfp::FWP_V4_ADDR_AND_MASK>::uninit();
            let mut v6_slot = std::mem::MaybeUninit::<wfp::FWP_V6_ADDR_AND_MASK>::uninit();
            let plans = plan_conditions(rule);
            let mut conditions = Vec::with_capacity(plans.len());
            for plan in &plans {
                conditions.push(match *plan {
                    WfpConditionPlan::RemoteAddressV4 { addr, mask } => {
                        v4_slot.write(wfp::FWP_V4_ADDR_AND_MASK { addr, mask });
                        wfp::FWPM_FILTER_CONDITION0 {
                            fieldKey: wfp::FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            matchType: wfp::FWP_MATCH_EQUAL,
                            conditionValue: wfp::FWP_CONDITION_VALUE0 {
                                r#type: wfp::FWP_V4_ADDR_MASK,
                                Anonymous: wfp::FWP_CONDITION_VALUE0_0 {
                                    v4AddrMask: v4_slot.as_mut_ptr(),
                                },
                            },
                        }
                    }
                    WfpConditionPlan::RemoteAddressV6 { addr, prefix_len } => {
                        v6_slot.write(wfp::FWP_V6_ADDR_AND_MASK {
                            addr,
                            prefixLength: prefix_len,
                        });
                        wfp::FWPM_FILTER_CONDITION0 {
                            fieldKey: wfp::FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            matchType: wfp::FWP_MATCH_EQUAL,
                            conditionValue: wfp::FWP_CONDITION_VALUE0 {
                                r#type: wfp::FWP_V6_ADDR_MASK,
                                Anonymous: wfp::FWP_CONDITION_VALUE0_0 {
                                    v6AddrMask: v6_slot.as_mut_ptr(),
                                },
                            },
                        }
                    }
                    WfpConditionPlan::IpProtocol { protocol } => wfp::FWPM_FILTER_CONDITION0 {
                        fieldKey: wfp::FWPM_CONDITION_IP_PROTOCOL,
                        matchType: wfp::FWP_MATCH_EQUAL,
                        conditionValue: wfp::FWP_CONDITION_VALUE0 {
                            r#type: wfp::FWP_UINT8,
                            Anonymous: wfp::FWP_CONDITION_VALUE0_0 {
                                uint8: protocol.number(),
                            },
                        },
                    },
                    WfpConditionPlan::RemotePort { port } => wfp::FWPM_FILTER_CONDITION0 {
                        fieldKey: wfp::FWPM_CONDITION_IP_REMOTE_PORT,
                        matchType: wfp::FWP_MATCH_EQUAL,
                        conditionValue: wfp::FWP_CONDITION_VALUE0 {
                            r#type: wfp::FWP_UINT16,
                            Anonymous: wfp::FWP_CONDITION_VALUE0_0 { uint16: port },
                        },
                    },
                });
            }
            if rule.app.is_some() {
                let Some(blob) = app else {
                    return Err(io::Error::other(
                        "wfp: app-scoped rule without resolved application id",
                    ));
                };
                conditions.push(wfp::FWPM_FILTER_CONDITION0 {
                    fieldKey: api::app_id_condition(),
                    matchType: wfp::FWP_MATCH_EQUAL,
                    conditionValue: wfp::FWP_CONDITION_VALUE0 {
                        r#type: wfp::FWP_BYTE_BLOB_TYPE,
                        Anonymous: wfp::FWP_CONDITION_VALUE0_0 {
                            byteBlob: blob.as_mut_ptr(),
                        },
                    },
                });
            }
            let mut weight_value = rule.weight;
            let weight = wfp::FWP_VALUE0 {
                r#type: wfp::FWP_UINT64,
                Anonymous: wfp::FWP_VALUE0_0 {
                    uint64: &mut weight_value as *mut u64,
                },
            };
            let name = api::wide_string(rule.name);
            let filter = wfp::FWPM_FILTER0 {
                filterKey: random_guid(),
                displayData: wfp::FWPM_DISPLAY_DATA0 {
                    name: name.as_ptr() as PWSTR,
                    description: ptr::null_mut(),
                },
                flags: wfp::FWPM_FILTER_FLAG_NONE,
                layerKey: api::layer_guid(rule.layer),
                subLayerKey: wfp::FWPM_SUBLAYER_UNIVERSAL,
                weight,
                numFilterConditions: conditions.len() as u32,
                filterCondition: if conditions.is_empty() {
                    ptr::null_mut()
                } else {
                    conditions.as_mut_ptr()
                },
                action: wfp::FWPM_ACTION0 {
                    r#type: api::action_type(rule.action),
                    Anonymous: wfp::FWPM_ACTION0_0 {
                        filterType: GUID::default(),
                    },
                },
                ..Default::default()
            };
            let mut id: u64 = 0;
            // SAFETY: live session handle; `filter` and every value it
            // points at are owned locals alive for the call (address
            // slots are written before their pointers are stored, and
            // the app blob outlives the install loop); null SD selects
            // the default security descriptor.
            let code =
                unsafe { wfp::FwpmFilterAdd0(self.handle, &filter, ptr::null_mut(), &mut id) };
            if code != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            Ok(id)
        }
    }

    impl Drop for WfpEngineSession {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful FwpmEngineOpen0
            // and is closed exactly once. The close status is
            // unrecoverable in Drop by design; dynamic teardown still
            // reaps the session on failure.
            unsafe {
                wfp::FwpmEngineClose0(self.handle);
            }
        }
    }

    /// Fresh random GUID for session/filter keys.
    fn random_guid() -> GUID {
        GUID::from_u128(rand::random::<u128>())
    }
}

#[cfg(not(windows))]
mod imp {
    use std::io;

    /// Disabled stand-in: same method surface so downstream call sites
    /// compile unconditionally. Every method logs the WFP feature name
    /// and fails — never silently succeeds.
    #[derive(Debug)]
    pub struct WfpEngineSession {
        _sealed: (),
    }

    impl WfpEngineSession {
        /// Always fails: WFP engine sessions exist only on Windows.
        pub fn open() -> io::Result<Self> {
            eprintln!(
                "wfp: engine sessions require Windows; \
                 WFP filtering is disabled on this platform"
            );
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WFP engine sessions require Windows",
            ))
        }

        /// Unreachable via `open`, but fails loudly all the same.
        pub fn install_sandbox_rules(&self) -> io::Result<Vec<u64>> {
            eprintln!(
                "wfp: engine sessions require Windows; \
                 cannot install filters on this platform"
            );
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WFP engine sessions require Windows",
            ))
        }

        /// Unreachable via `open`, but fails loudly all the same.
        pub fn install_sandbox_rules_scoped(
            &self,
            _app: &crate::wfp::types::WfpAppId,
        ) -> io::Result<Vec<u64>> {
            eprintln!(
                "wfp: engine sessions require Windows; \
                 cannot install scoped filters on this platform"
            );
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WFP engine sessions require Windows",
            ))
        }
    }
}

pub use imp::WfpEngineSession;

#[cfg(test)]
mod tests {
    use super::{plan_conditions, v6_prefix_len, WfpConditionPlan, WfpEngineSession};
    use crate::network;
    use crate::wfp::types::{
        parse_v4_cidr, sandbox_egress_rules, WfpAction, WfpAddressCondition, WfpLayer, WfpProtocol,
    };

    #[test]
    fn condition_plans_cover_ruleset() {
        let rules = sandbox_egress_rules();
        assert_eq!(rules.len(), 11);
        let mut total = 0;
        for rule in &rules {
            let plans = plan_conditions(rule);
            total += plans.len();
            match (rule.action, rule.address, rule.port) {
                (WfpAction::Block, Some(_), None) => assert_eq!(plans.len(), 1),
                (WfpAction::Permit, None, Some(_)) => assert_eq!(plans.len(), 2),
                (WfpAction::Block, None, None) => assert!(plans.is_empty()),
                shape => panic!("unexpected rule shape: {shape:?}"),
            }
        }
        // 4 v4 blocks + 2 v4 permits(x2) + v4 default + 1 v6 block +
        // 2 v6 permits(x2) + v6 default.
        assert_eq!(total, 13);
    }

    #[test]
    fn v4_address_plans_match_contract_cidrs() {
        let mut planned: Vec<(u32, u32)> = sandbox_egress_rules()
            .iter()
            .flat_map(plan_conditions)
            .filter_map(|plan| match plan {
                WfpConditionPlan::RemoteAddressV4 { addr, mask } => Some((addr, mask)),
                _ => None,
            })
            .collect();
        planned.sort_unstable();
        let mut expected: Vec<(u32, u32)> = network::RFC1918_CIDRS
            .iter()
            .chain(std::iter::once(&network::LINK_LOCAL_CIDR))
            .map(|cidr| parse_v4_cidr(cidr).unwrap())
            .collect();
        expected.sort_unstable();
        assert_eq!(planned, expected);
    }

    #[test]
    fn v6_address_plan_carries_prefix_len() {
        let v6_block = sandbox_egress_rules()
            .into_iter()
            .find(|rule| {
                rule.layer == WfpLayer::AleAuthConnectV6
                    && rule.action == WfpAction::Block
                    && rule.address.is_some()
            })
            .expect("v6 ULA block rule");
        assert_eq!(
            plan_conditions(&v6_block),
            vec![WfpConditionPlan::RemoteAddressV6 {
                addr: [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                prefix_len: 7,
            }]
        );
    }

    #[test]
    fn port_plans_carry_protocol_and_port() {
        for rule in sandbox_egress_rules() {
            if rule.action != WfpAction::Permit {
                continue;
            }
            let port = rule.port.expect("permit rules carry a port");
            assert_eq!(
                plan_conditions(&rule),
                vec![
                    WfpConditionPlan::IpProtocol {
                        protocol: port.protocol,
                    },
                    WfpConditionPlan::RemotePort { port: port.port },
                ]
            );
            assert!(matches!(
                (port.protocol, port.port),
                (WfpProtocol::Udp, 53) | (WfpProtocol::Tcp, 443)
            ));
        }
    }

    #[test]
    fn address_plan_mirrors_rule_condition() {
        for rule in sandbox_egress_rules() {
            let Some(condition) = rule.address else {
                continue;
            };
            let plans = plan_conditions(&rule);
            assert_eq!(plans.len(), 1);
            match (condition, plans[0]) {
                (
                    WfpAddressCondition::V4 { addr, mask },
                    WfpConditionPlan::RemoteAddressV4 {
                        addr: planned_addr,
                        mask: planned_mask,
                    },
                ) => {
                    assert_eq!((planned_addr, planned_mask), (addr, mask));
                }
                (
                    WfpAddressCondition::V6 { addr, mask },
                    WfpConditionPlan::RemoteAddressV6 {
                        addr: planned_addr,
                        prefix_len,
                    },
                ) => {
                    assert_eq!(planned_addr, addr);
                    assert_eq!(prefix_len, v6_prefix_len(mask));
                }
                (condition, plan) => panic!("plan mismatch: {condition:?} -> {plan:?}"),
            }
        }
    }

    #[test]
    fn v6_prefix_len_derives_from_mask() {
        assert_eq!(v6_prefix_len([0xff; 16]), 128);
        assert_eq!(
            v6_prefix_len([0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            7
        );
        assert_eq!(
            v6_prefix_len([0xff, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            9
        );
        assert_eq!(v6_prefix_len([0; 16]), 0);
        // Non-contiguous masks lower to the leading run (fail-closed).
        assert_eq!(
            v6_prefix_len([0xff, 0x00, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            8
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn stub_open_reports_unsupported() {
        let err = WfpEngineSession::open().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    /// The session crosses `.await` points inside the supervised
    /// worker future (`tokio::spawn` requires `Send`); this pins the
    /// bound at compile time on every Windows CI job.
    #[cfg(windows)]
    #[test]
    fn session_is_send_for_async_supervision() {
        fn assert_send<T: Send>() {}
        assert_send::<WfpEngineSession>();
    }

    /// Live engine lifecycle: open a dynamic session, install the 11
    /// sandbox filters, drop. Requires elevated Windows plus
    /// `RUNNER_LIVE_WFP=1` (mirrors the `RUNNER_LIVE_KVM` gate); the
    /// CI windows-native job sets it.
    #[cfg(windows)]
    #[test]
    fn live_engine_lifecycle_installs_rules() {
        if std::env::var("RUNNER_LIVE_WFP").is_err() {
            eprintln!("live WFP harness skipped (needs RUNNER_LIVE_WFP=1 on elevated Windows)");
            return;
        }
        let session = WfpEngineSession::open().expect("open dynamic WFP session");
        let ids = session
            .install_sandbox_rules()
            .expect("install 11 sandbox filters");
        assert_eq!(ids.len(), 11);
        assert!(ids.iter().all(|id| *id != 0));
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 11, "filter IDs are unique");
        // `session` drops here: explicit engine close, and dynamic
        // teardown reaps the 11 filters either way.
    }

    /// Live scoped install: all 11 filters attach with the app-id
    /// condition resolved from this test binary's own image. Same
    /// elevation + `RUNNER_LIVE_WFP=1` gate as the unscoped test.
    #[cfg(windows)]
    #[test]
    fn live_engine_scoped_install() {
        if std::env::var("RUNNER_LIVE_WFP").is_err() {
            eprintln!("live WFP harness skipped (needs RUNNER_LIVE_WFP=1 on elevated Windows)");
            return;
        }
        let exe = std::env::current_exe().expect("own exe path");
        let app =
            crate::wfp::types::WfpAppId::new(exe.to_str().expect("utf-8 exe path").to_string())
                .expect("non-empty app path");
        let session = WfpEngineSession::open().expect("open dynamic WFP session");
        let ids = session
            .install_sandbox_rules_scoped(&app)
            .expect("install 11 scoped sandbox filters");
        assert_eq!(ids.len(), 11);
        assert!(ids.iter().all(|id| *id != 0));
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 11, "filter IDs are unique");
    }
}
