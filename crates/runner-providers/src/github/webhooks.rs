//! Queue signals: `workflow_job` webhooks + coordinator poll loop.
//!
//! The coordinator polls queued workflow runs, filters jobs matching
//! `runs-on: [self-hosted, runner]`, routes each job (local slot → WAN
//! trusted peer → cloud burst), then mints a single-use JIT config and
//! launches the sandboxed worker for local dispatches.

use std::time::Duration;

use serde::Deserialize;

use super::client::GithubClient;
use super::jit::{generate_org_jit, generate_repo_jit, JitRequest};

/// A queued job demanding capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedJob {
    pub id: u64,
    pub run_id: u64,
    pub name: String,
    pub labels: Vec<String>,
}

/// `queued` action = request for capacity; anything else releases/ignores.
pub fn is_capacity_request(action: &str) -> bool {
    action == "queued"
}

/// True when job labels select this mesh (`self-hosted` + `runner`).
pub fn job_matches_runner(labels: &[String]) -> bool {
    labels.iter().any(|l| l == "self-hosted") && labels.iter().any(|l| l == "runner")
}

#[derive(Debug, Deserialize)]
struct RunsEnvelope {
    #[serde(default)]
    workflow_runs: Vec<RunRef>,
}

#[derive(Debug, Deserialize)]
struct RunRef {
    id: u64,
}

#[derive(Debug, Deserialize)]
struct JobsEnvelope {
    #[serde(default)]
    jobs: Vec<JobRef>,
}

#[derive(Debug, Deserialize)]
struct JobRef {
    id: u64,
    run_id: u64,
    name: String,
    #[serde(default)]
    labels: Vec<String>,
    status: String,
}

/// Parse queued mesh jobs from a jobs-list response body (pure).
pub fn parse_queued_jobs(body: &serde_json::Value) -> Result<Vec<QueuedJob>, String> {
    let envelope: JobsEnvelope =
        serde_json::from_value(body.clone()).map_err(|e| format!("jobs body: {e}"))?;
    Ok(envelope
        .jobs
        .into_iter()
        .filter(|job| job.status == "queued" && job_matches_runner(&job.labels))
        .map(|job| QueuedJob {
            id: job.id,
            run_id: job.run_id,
            name: job.name,
            labels: job.labels,
        })
        .collect())
}

/// Fast queue poller over the workflow runs/jobs REST API.
pub struct QueuePoller {
    client: GithubClient,
    owner: String,
    repo: String,
    interval: Duration,
}

impl QueuePoller {
    pub fn new(client: GithubClient, owner: impl Into<String>, repo: impl Into<String>) -> Self {
        Self {
            client,
            owner: owner.into(),
            repo: repo.into(),
            interval: Duration::from_secs(15),
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// One poll: queued runs → queued mesh jobs.
    pub async fn poll_once(&self) -> Result<Vec<QueuedJob>, String> {
        let runs_url = format!(
            "{}/repos/{}/{}/actions/runs?status=queued&per_page=20",
            self.client.base_url(),
            self.owner,
            self.repo
        );
        let res = self
            .client
            .authed(self.client.http().get(&runs_url))
            .send()
            .await
            .map_err(|e| format!("runs poll failed: {e}"))?;
        if !res.status().is_success() {
            return Err(format!("runs poll: HTTP {}", res.status()));
        }
        let body: serde_json::Value = res.json().await.map_err(|e| format!("runs body: {e}"))?;
        let runs: RunsEnvelope =
            serde_json::from_value(body).map_err(|e| format!("runs body: {e}"))?;

        let mut jobs = Vec::new();
        for run in runs.workflow_runs {
            let jobs_url = format!(
                "{}/repos/{}/{}/actions/runs/{}/jobs",
                self.client.base_url(),
                self.owner,
                self.repo,
                run.id
            );
            let res = self
                .client
                .authed(self.client.http().get(&jobs_url))
                .send()
                .await
                .map_err(|e| format!("jobs poll failed: {e}"))?;
            if !res.status().is_success() {
                continue;
            }
            let body: serde_json::Value =
                res.json().await.map_err(|e| format!("jobs body: {e}"))?;
            jobs.extend(parse_queued_jobs(&body)?);
        }
        Ok(jobs)
    }
}

/// Where one job should execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    /// Local workstation slot.
    Local,
    /// Trusted peer node (friends & family WAN peer).
    WanPeer { node_id: String },
    /// Ephemeral cloud burst (provider).
    Cloud { provider: String },
    /// No capacity anywhere: leave queued for the next poll.
    Wait,
}

/// Route one job: local slot → non-drained WAN peer → cloud burst → wait.
pub fn route_job(
    local_slots_free: u32,
    peers: &[runner_core::config::PeerRecord],
    drained: &std::collections::HashMap<String, String>,
    cloud_available: bool,
) -> RouteDecision {
    if local_slots_free > 0 {
        return RouteDecision::Local;
    }
    if let Some(peer) = peers.iter().find(|p| !drained.contains_key(&p.node_id)) {
        return RouteDecision::WanPeer {
            node_id: peer.node_id.clone(),
        };
    }
    if cloud_available {
        return RouteDecision::Cloud {
            provider: "digitalocean".to_string(),
        };
    }
    RouteDecision::Wait
}

/// JIT issuance scope for local dispatches.
#[derive(Debug, Clone)]
pub enum JitScope {
    Org { org: String },
    Repo { owner: String, repo: String },
}

/// Local dispatch context: JIT issuance + worker supervision inputs.
#[derive(Debug, Clone)]
pub struct DispatchContext {
    pub github: GithubClient,
    pub scope: JitScope,
    pub runner_group_id: u64,
    pub worker_version: String,
    pub sandboxed: bool,
    pub timeout: Duration,
}

/// Dispatch one job locally: mint JIT → cache worker → sandbox → supervise.
pub async fn dispatch_local(
    job: &QueuedJob,
    ctx: &DispatchContext,
    slice: Option<&runner_core::governor::cgroup::CgroupSlice>,
) -> Result<runner_sandbox::worker::WorkerOutcome, String> {
    use runner_sandbox::mounts::Workspace;
    use runner_sandbox::worker::{ensure_cached, run_supervised, WorkerLaunch};

    let req = JitRequest {
        name: format!("runner-{}-{}", job.run_id, job.id),
        runner_group_id: ctx.runner_group_id,
        labels: vec!["self-hosted".to_string(), "runner".to_string()],
        work_folder: "_work".to_string(),
    };
    let jit = match &ctx.scope {
        JitScope::Org { org } => generate_org_jit(&ctx.github, org, &req).await?,
        JitScope::Repo { owner, repo } => generate_repo_jit(&ctx.github, owner, repo, &req).await?,
    };
    super::jit::decode_jit_config(&jit.encoded_jit_config)?;

    let work_dir = ensure_cached(&ctx.worker_version).await?;
    let workspace =
        Workspace::create(&format!("job-{}", job.id)).map_err(|e| format!("workspace: {e}"))?;
    let mut launch = WorkerLaunch::new(work_dir, jit.encoded_jit_config);
    if ctx.sandboxed {
        let spec = workspace.sandbox_spec()?;
        launch = launch.sandboxed(spec);
    }
    eprintln!(
        "runner: dispatching job {} ({}) sandboxed={}",
        job.id, job.name, ctx.sandboxed
    );
    let outcome = run_supervised(&launch, slice, ctx.timeout)
        .await
        .map_err(|e| format!("worker spawn: {e}"))?;
    eprintln!("runner: job {} finished: {:?}", job.id, outcome);
    Ok(outcome)
}

/// Coordinator poll loop: poll queued jobs, route each one, and execute
/// local/cloud dispatches when `dispatch` is `Some` (auto-dispatch).
/// Runs until the process shuts down.
pub async fn run_coordinator(
    poller: QueuePoller,
    dispatch: Option<DispatchContext>,
    cloud: Option<runner_core::mesh::cloud::CloudPool>,
    state: runner_core::governor::supervisor::SharedState,
    slice: runner_core::governor::cgroup::CgroupSlice,
) {
    let auto = dispatch.is_some();
    eprintln!(
        "runner: coordinator polling every {:?} (auto_dispatch={auto})",
        poller.interval()
    );
    loop {
        tokio::time::sleep(poller.interval()).await;
        let jobs = match poller.poll_once().await {
            Ok(jobs) => jobs,
            Err(e) => {
                eprintln!("runner: queue poll failed: {e}");
                continue;
            }
        };
        for job in jobs {
            let (free, peers, drained) = {
                let guard = state.read().await;
                (
                    guard.last_slots.saturating_sub(guard.in_flight()),
                    guard.peers(),
                    guard.drained_nodes(),
                )
            };
            let cloud_available = cloud.as_ref().is_some_and(|pool| {
                pool.has_provider("digitalocean") || pool.has_provider("render")
            });
            match route_job(free, &peers, &drained, cloud_available) {
                RouteDecision::Local => {
                    eprintln!("runner: job {} ({}) routed local", job.id, job.name);
                    if let Some(ctx) = dispatch.clone() {
                        let state = state.clone();
                        let slice = slice.clone();
                        let job = job.clone();
                        state.write().await.in_flight_inc();
                        tokio::spawn(async move {
                            let result = dispatch_local(&job, &ctx, Some(&slice)).await;
                            if let Err(e) = result {
                                eprintln!("runner: local dispatch failed: {e}");
                            }
                            state.write().await.in_flight_dec();
                        });
                    }
                }
                RouteDecision::WanPeer { node_id } => {
                    eprintln!(
                        "runner: job {} ({}) routed to WAN peer {node_id} \
                         (remote execution transport lands in hardening)",
                        job.id, job.name
                    );
                }
                RouteDecision::Cloud { provider } => {
                    eprintln!(
                        "runner: job {} ({}) routed to cloud {provider}",
                        job.id, job.name
                    );
                    if let (Some(pool), true) = (cloud.clone(), auto) {
                        let state = state.clone();
                        let pool = pool.clone();
                        tokio::spawn(async move {
                            let name = format!("runner-ci-{}-{}", job.run_id, job.id);
                            match pool.provision(&provider, &name).await {
                                Ok(node) => {
                                    eprintln!(
                                        "runner: cloud node {} up for job {}",
                                        node.id, job.id
                                    );
                                    state.write().await.add_cloud_node(node);
                                }
                                Err(e) => eprintln!("runner: cloud burst failed: {e}"),
                            }
                        });
                    }
                }
                RouteDecision::Wait => {
                    eprintln!("runner: job {} ({}) waiting for capacity", job.id, job.name);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_requests_capacity() {
        assert!(is_capacity_request("queued"));
        assert!(!is_capacity_request("completed"));
        assert!(!is_capacity_request("in_progress"));
    }

    #[test]
    fn label_matching_selects_mesh_jobs() {
        let mesh = vec!["self-hosted".to_string(), "runner".to_string()];
        let cloud = vec!["ubuntu-latest".to_string()];
        assert!(job_matches_runner(&mesh));
        assert!(!job_matches_runner(&cloud));
    }

    #[test]
    fn parses_queued_mesh_jobs_only() {
        let body = serde_json::json!({
            "total_count": 3,
            "jobs": [
                { "id": 1, "run_id": 10, "name": "backend",
                  "labels": ["self-hosted", "runner"], "status": "queued" },
                { "id": 2, "run_id": 10, "name": "cloud",
                  "labels": ["ubuntu-latest"], "status": "queued" },
                { "id": 3, "run_id": 10, "name": "done",
                  "labels": ["self-hosted", "runner"], "status": "completed" },
            ],
        });
        let jobs = parse_queued_jobs(&body).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, 1);
    }

    #[test]
    fn routing_prefers_local_then_peer_then_cloud() {
        use std::collections::HashMap;
        let peer = runner_core::config::PeerRecord {
            node_id: "n1".to_string(),
            public_key: "k".to_string(),
            endpoint: None,
            max_cores: 4,
            max_ram_mb: 8192,
            status: "online".to_string(),
        };
        assert_eq!(
            route_job(1, &[], &HashMap::new(), false),
            RouteDecision::Local
        );
        assert_eq!(
            route_job(0, std::slice::from_ref(&peer), &HashMap::new(), false),
            RouteDecision::WanPeer {
                node_id: "n1".to_string()
            }
        );
        assert_eq!(
            route_job(0, &[], &HashMap::new(), true),
            RouteDecision::Cloud {
                provider: "digitalocean".to_string()
            }
        );
        assert_eq!(
            route_job(0, &[], &HashMap::new(), false),
            RouteDecision::Wait
        );
        let mut drained = HashMap::new();
        drained.insert("n1".to_string(), "t".to_string());
        assert_eq!(
            route_job(0, std::slice::from_ref(&peer), &drained, false),
            RouteDecision::Wait
        );
    }
}
