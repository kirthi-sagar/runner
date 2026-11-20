//! WAN peer dispatch: coordinator offers + peer worker execution.
//!
//! Forge-agnostic glue between coordinator loops (GitHub today) and the
//! mesh transport: offers carry pre-minted JIT blobs so peers execute
//! without provider credentials.

use std::pin::Pin;
use std::time::Duration;

use runner_core::governor::cgroup::CgroupSlice;
use runner_core::governor::supervisor::SharedState;
use runner_core::mesh::proto::{JobAccept, JobOffer, JobResult, PROTO_TAG};
use runner_core::mesh::roles::PeerExecutor;
use runner_core::mesh::transport::PeerTransport;

use super::github::webhooks::{run_worker_with_jit, WorkerRunConfig};

/// Accept wait per offer: a silent peer fails back fast.
pub const OFFER_TIMEOUT_SECS: u64 = 5;

/// Dispatch one job to a peer: send the offer, await accept, record the
/// in-flight entry + lease. Any failure returns Err with nothing
/// recorded, so the caller falls back same-tick (no wedge possible).
pub async fn dispatch_to_peer(
    tx: &PeerTransport,
    state: &SharedState,
    offer: JobOffer,
    lease: Duration,
    node_id: &str,
) -> Result<(), String> {
    let accept: JobAccept = tx
        .offer(
            node_id,
            offer.clone(),
            Duration::from_secs(OFFER_TIMEOUT_SECS),
        )
        .await
        .map_err(|e| format!("peer {node_id} offer failed: {e}"))?;
    if !accept.accepted {
        return Err(format!(
            "peer {node_id} declined job {}: {}",
            offer.job_id, accept.reason
        ));
    }
    let mut guard = state.write().await;
    guard.job_started(&offer.provider, &offer.job_id.to_string(), &offer.name);
    guard.add_peer_lease(
        &offer.provider,
        &offer.job_id.to_string(),
        node_id.to_string(),
        std::time::Instant::now() + lease,
    );
    Ok(())
}

/// Peer-side executor: runs received JIT blobs through the standard
/// worker path (cache, sandbox, supervision), capped by donor timeout
/// and sliced into the donor cgroup.
pub struct WorkerExecutor {
    worker_version: String,
    sandboxed: bool,
    timeout_cap: Duration,
    slice: CgroupSlice,
    state: SharedState,
}

impl WorkerExecutor {
    pub fn new(
        worker_version: String,
        sandboxed: bool,
        timeout_cap: Duration,
        slice: CgroupSlice,
        state: SharedState,
    ) -> Self {
        Self {
            worker_version,
            sandboxed,
            timeout_cap,
            slice,
            state,
        }
    }
}

impl PeerExecutor for WorkerExecutor {
    fn execute<'a>(
        &'a self,
        offer: &'a JobOffer,
    ) -> Pin<Box<dyn std::future::Future<Output = JobResult> + Send + 'a>> {
        Box::pin(async move {
            let timeout = Duration::from_secs(offer.timeout_secs.max(1)).min(self.timeout_cap);
            // The peer's OWN loopback proxy (never the coordinator's LAN
            // endpoint: unreachable over WAN, and its bearer must not
            // cross the mesh), namespaced to the offered repo.
            let cache = {
                let guard = self.state.read().await;
                match (guard.cache_base_url(), guard.cache_token()) {
                    (Some(url), Some(token)) => {
                        let url = match offer.repo.clone() {
                            Some(slug) => runner_core::cache::server::scoped_base_url(&url, &slug),
                            None => url,
                        };
                        Some((url, token))
                    }
                    _ => None,
                }
            };
            let cfg = WorkerRunConfig {
                worker_version: self.worker_version.clone(),
                jit_blob: offer.jit_blob.clone(),
                job_tag: format!("peer-{}", offer.job_id),
                job_name: offer.name.clone(),
                sandboxed: self.sandboxed,
                cache,
                timeout,
            };
            match run_worker_with_jit(&cfg, Some(&self.slice)).await {
                Ok(outcome) => JobResult {
                    proto: PROTO_TAG.to_string(),
                    provider: offer.provider.clone(),
                    job_id: offer.job_id,
                    exit_code: outcome.exit_code,
                    killed: outcome.killed,
                },
                // Spawn/setup failure completes abnormally: the record
                // finishes (natural retry next tick mints a fresh JIT
                // elsewhere) instead of wedging until lease expiry.
                Err(e) => {
                    eprintln!("runner: peer execution failed: {e}");
                    JobResult {
                        proto: PROTO_TAG.to_string(),
                        provider: offer.provider.clone(),
                        job_id: offer.job_id,
                        exit_code: None,
                        killed: true,
                    }
                }
            }
        })
    }
}
