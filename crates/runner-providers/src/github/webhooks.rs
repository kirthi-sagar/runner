//! Queue signals: `workflow_job` webhooks + coordinator poll loop.
//!
//! The coordinator polls queued workflow runs, filters jobs matching
//! `runs-on: [self-hosted, runner]`, routes each job (local slot → WAN
//! trusted peer → cloud burst), then mints a single-use JIT config and
//! launches the sandboxed worker for local dispatches.

use std::collections::HashMap;
use std::time::{Duration, Instant};

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
/// `cloud_provider` is the resolved burst target (`None` when no cloud
/// provider is configured); routing never hardcodes a provider name.
pub fn route_job(
    local_slots_free: u32,
    peers: &[runner_core::config::PeerRecord],
    drained: &std::collections::HashMap<String, String>,
    cloud_provider: Option<&str>,
) -> RouteDecision {
    if local_slots_free > 0 {
        return RouteDecision::Local;
    }
    if let Some(peer) = peers.iter().find(|p| !drained.contains_key(&p.node_id)) {
        return RouteDecision::WanPeer {
            node_id: peer.node_id.clone(),
        };
    }
    if let Some(provider) = cloud_provider {
        return RouteDecision::Cloud {
            provider: provider.to_string(),
        };
    }
    RouteDecision::Wait
}

/// True when the queued job is already tracked as in flight (a prior
/// poll dispatched it locally or provisioned a cloud node for it).
/// Namespaced by provider so identical job IDs from different forges
/// (GitHub `42` vs GitLab `42`) never collide. The coordinator skips
/// such jobs so each unique job dispatches exactly once no matter how
/// many polls observe it queued.
pub fn already_in_flight(
    in_flight: &[runner_core::governor::supervisor::InFlightJob],
    provider: &str,
    job_id: &str,
) -> bool {
    in_flight
        .iter()
        .any(|j| j.provider == provider && j.id == job_id)
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
    /// LAN cache proxy base URL (None when the proxy failed to bind).
    pub cache_url: Option<String>,
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
    // Transparent LAN cache: no cache_url means the proxy failed to
    // bind at boot, and the worker falls back to upstream caching.
    if let Some(url) = ctx.cache_url.as_deref() {
        for (key, value) in runner_core::cache::server::worker_env(url) {
            launch = launch.env(key, value);
        }
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
/// True when new cloud spend is allowed: a positive cap the ledgered
/// month total has not yet reached. A zero cap means bursting was
/// never enabled, so nothing is allowed.
pub fn budget_allows(month_spend_usd: f64, cap_usd: f64) -> bool {
    cap_usd > 0.0 && month_spend_usd < cap_usd
}

/// Fail-closed budget gate over a ledger read: provision only when the
/// read succeeds and the spend is under cap. A ledger error refuses.
pub fn spend_within_cap(spend: Result<f64, String>, cap_usd: f64) -> bool {
    spend.is_ok_and(|usd| budget_allows(usd, cap_usd))
}

/// Sync termination hook for the scale-to-zero watchdog: a deliberate
/// no-op. Production teardown is async (`CloudPool::terminate`), so the
/// coordinator acts on [`ScaleAction::Terminate`](runner_core::mesh::cloud::autoscale::ScaleAction)
/// instead of this hook.
#[derive(Debug, Default)]
pub struct DeferredTerminator;

impl runner_core::mesh::cloud::autoscale::Terminator for DeferredTerminator {
    fn terminate(&mut self, _instance_id: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Per-node idle controllers, keyed by cloud instance id.
pub type WatchdogMap =
    HashMap<String, runner_core::mesh::cloud::autoscale::AutoscaleController<DeferredTerminator>>;

/// Sync controllers with tracked nodes and poll once (pure decision
/// step; termination itself happens in [`run_watchdog_cycle`]).
pub fn poll_watchdogs(
    controllers: &mut WatchdogMap,
    nodes: &[runner_core::mesh::cloud::CloudNode],
    now: Instant,
    queue_depth: u32,
) -> Vec<runner_core::mesh::cloud::autoscale::ScaleAction> {
    use runner_core::mesh::cloud::autoscale::AutoscaleController;
    for node in nodes {
        controllers
            .entry(node.id.clone())
            .or_insert_with(|| AutoscaleController::new(node.id.clone(), now, DeferredTerminator));
    }
    controllers.retain(|id, _| nodes.iter().any(|n| &n.id == id));
    let mut actions = Vec::new();
    for controller in controllers.values_mut() {
        match controller.poll(now, queue_depth) {
            Ok(action) => actions.push(action),
            Err(e) => eprintln!("runner: watchdog poll failed: {e}"),
        }
    }
    actions
}

/// One scale-to-zero cycle: terminate nodes the watchdog flags and
/// drop them from state. Provider failures keep the node (and its
/// expired clock) so the next cycle retries.
pub async fn run_watchdog_cycle(
    pool: &runner_core::mesh::cloud::CloudPool,
    state: &runner_core::governor::supervisor::SharedState,
    controllers: &mut WatchdogMap,
    now: Instant,
    queue_depth: u32,
) {
    use runner_core::mesh::cloud::autoscale::ScaleAction;
    let nodes = state.read().await.cloud_nodes();
    for action in poll_watchdogs(controllers, &nodes, now, queue_depth) {
        if let ScaleAction::Terminate { instance_id } = action {
            let Some(node) = nodes.iter().find(|n| n.id == instance_id) else {
                continue;
            };
            match pool.terminate(node).await {
                Ok(_) => {
                    eprintln!("runner: scale-to-zero terminated idle cloud node {instance_id}");
                    let mut guard = state.write().await;
                    guard.remove_cloud_node(&instance_id);
                    // Release the job record the provision left behind
                    // (ours carry runner-ci-{run}-{job} names).
                    if let Some(job_id) =
                        runner_core::mesh::cloud::cloud_job_id_from_node_name(&node.name)
                    {
                        guard.job_finished("github", &job_id);
                    }
                    controllers.remove(&instance_id);
                }
                Err(e) => {
                    eprintln!("runner: cloud terminate {instance_id} failed ({e}); retrying");
                }
            }
        }
    }
}

pub async fn run_coordinator(
    poller: QueuePoller,
    dispatch: Option<DispatchContext>,
    cloud: Option<runner_core::mesh::cloud::CloudPool>,
    state: runner_core::governor::supervisor::SharedState,
    slice: runner_core::governor::cgroup::CgroupSlice,
) {
    let auto = dispatch.is_some();
    let wakeup = state.read().await.wakeup();
    eprintln!(
        "runner: coordinator polling every {:?} (auto_dispatch={auto}, webhook wakeups armed)",
        poller.interval()
    );
    loop {
        tokio::select! {
            _ = tokio::time::sleep(poller.interval()) => {},
            _ = wakeup.notified() => {
                eprintln!("runner: webhook wakeup: polling immediately");
            }
        }
        let jobs = match poller.poll_once().await {
            Ok(jobs) => jobs,
            Err(e) => {
                eprintln!("runner: queue poll failed: {e}");
                state.write().await.record_forge_poll("github", 0, Some(e));
                continue;
            }
        };
        {
            let mut guard = state.write().await;
            guard.set_queue_depth(jobs.len() as u32);
            guard.record_forge_poll("github", jobs.len() as u32, None);
        }
        for job in jobs {
            let (free, peers, drained, flying) = {
                let guard = state.read().await;
                (
                    guard.last_slots.saturating_sub(guard.in_flight()),
                    guard.peers(),
                    guard.drained_nodes(),
                    guard.in_flight_jobs(),
                )
            };
            if already_in_flight(&flying, "github", &job.id.to_string()) {
                eprintln!(
                    "runner: job {} ({}) already in flight; skipping re-dispatch",
                    job.id, job.name
                );
                continue;
            }
            let cloud_provider = cloud.as_ref().and_then(|pool| pool.preferred_provider());
            match route_job(free, &peers, &drained, cloud_provider.as_deref()) {
                RouteDecision::Local => {
                    eprintln!("runner: job {} ({}) routed local", job.id, job.name);
                    if let Some(ctx) = dispatch.clone() {
                        // Atomic reserve at dispatch: another forge may
                        // have taken the last slot since routing read it.
                        // Losing the race degrades to Wait (next poll).
                        if !state.write().await.try_reserve_slot() {
                            eprintln!(
                                "runner: job {} ({}) lost slot race; waiting for capacity",
                                job.id, job.name
                            );
                            continue;
                        }
                        let state = state.clone();
                        let slice = slice.clone();
                        let job = job.clone();
                        let job_id = job.id.to_string();
                        // The reservation is this job's slot (no second inc).
                        state
                            .write()
                            .await
                            .job_started("github", &job_id, &job.name);
                        tokio::spawn(async move {
                            let result = dispatch_local(&job, &ctx, Some(&slice)).await;
                            if let Err(e) = result {
                                eprintln!("runner: local dispatch failed: {e}");
                            }
                            let mut guard = state.write().await;
                            guard.in_flight_dec();
                            guard.job_finished("github", &job_id);
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
                        // Hard budget stop: refuse new spend once the
                        // ledgered month total reaches the cap. A ledger
                        // read failure also refuses (fail closed).
                        let spend = pool.month_spend();
                        let cap = state.read().await.cloud_spend_cap();
                        if !spend_within_cap(spend.clone(), cap) {
                            match spend {
                                Ok(usd) => eprintln!(
                                    "runner: budget stop: month spend ${usd:.2} reached cap ${cap:.2}; job {} waits",
                                    job.id
                                ),
                                Err(e) => eprintln!(
                                    "runner: budget stop: spend ledger unreadable ({e}); refusing cloud burst for job {} until fixed",
                                    job.id
                                ),
                            }
                            continue;
                        }
                        // Track the cloud dispatch so later polls dedup
                        // against it. Cloud entries persist (remote jobs
                        // report no completion signal) and roll off via
                        // the tracked-jobs cap.
                        state
                            .write()
                            .await
                            .job_started("github", &job.id.to_string(), &job.name);
                        let state = state.clone();
                        let pool = pool.clone();
                        let job_id = job.id.to_string();
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
                                Err(e) => {
                                    // Release the dedup record so the next
                                    // tick retries instead of deadlocking.
                                    eprintln!("runner: cloud burst failed: {e}");
                                    state.write().await.job_finished("github", &job_id);
                                }
                            }
                        });
                    }
                }
                RouteDecision::Wait => {
                    eprintln!("runner: job {} ({}) waiting for capacity", job.id, job.name);
                }
            }
        }
        // Scale-to-zero runs in the standalone watchdog task
        // (`spawn_cloud_watchdog`), independent of this loop.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use runner_core::governor::supervisor::new_shared_state;
    use runner_core::mesh::cloud::autoscale::ScaleAction;
    use runner_core::mesh::cloud::{CloudNode, CloudPool};

    fn node(id: &str) -> CloudNode {
        CloudNode {
            id: id.to_string(),
            provider: "digitalocean".to_string(),
            status: "active".to_string(),
            launched_at: 0,
            name: String::new(),
        }
    }

    #[test]
    fn watchdog_flags_idle_node_at_five_minutes() {
        let start = Instant::now();
        let mut controllers: WatchdogMap = HashMap::new();
        let nodes = vec![node("i-1")];
        let actions = poll_watchdogs(&mut controllers, &nodes, start, 0);
        assert_eq!(actions, vec![ScaleAction::Keep]);
        let actions = poll_watchdogs(
            &mut controllers,
            &nodes,
            start + Duration::from_secs(299),
            0,
        );
        assert_eq!(actions, vec![ScaleAction::Keep]);
        let actions = poll_watchdogs(
            &mut controllers,
            &nodes,
            start + Duration::from_secs(300),
            0,
        );
        assert_eq!(
            actions,
            vec![ScaleAction::Terminate {
                instance_id: "i-1".to_string()
            }]
        );
    }

    #[test]
    fn watchdog_resets_on_queue_depth_and_wakeup() {
        let start = Instant::now();
        let mut controllers: WatchdogMap = HashMap::new();
        let nodes = vec![node("i-1")];
        poll_watchdogs(&mut controllers, &nodes, start, 0);
        // Queued work resets the clock: 299 more seconds still keeps.
        poll_watchdogs(
            &mut controllers,
            &nodes,
            start + Duration::from_secs(299),
            2,
        );
        let actions = poll_watchdogs(
            &mut controllers,
            &nodes,
            start + Duration::from_secs(598),
            0,
        );
        assert_eq!(actions, vec![ScaleAction::Keep]);
        // Webhook wakeup (mark_active) resets without a queue poll.
        controllers
            .get_mut("i-1")
            .unwrap()
            .mark_active(start + Duration::from_secs(598));
        let actions = poll_watchdogs(
            &mut controllers,
            &nodes,
            start + Duration::from_secs(897),
            0,
        );
        assert_eq!(actions, vec![ScaleAction::Keep]);
    }

    #[test]
    fn budget_stop_triggers_at_cap() {
        assert!(budget_allows(0.0, 25.0));
        assert!(budget_allows(24.99, 25.0));
        assert!(!budget_allows(25.0, 25.0));
        assert!(!budget_allows(30.0, 25.0));
        // Fail-closed gate: ledger errors refuse like an exceeded cap.
        assert!(spend_within_cap(Ok(0.0), 25.0));
        assert!(!spend_within_cap(Ok(25.0), 25.0));
        assert!(!spend_within_cap(Err("corrupt".to_string()), 25.0));
        // Zero cap means bursting was never enabled.
        assert!(!budget_allows(0.0, 0.0));
    }

    #[test]
    fn watchdog_map_tracks_node_membership() {
        let start = Instant::now();
        let mut controllers: WatchdogMap = HashMap::new();
        poll_watchdogs(&mut controllers, &[node("a"), node("b")], start, 0);
        assert_eq!(controllers.len(), 2);
        // Removed nodes lose their controllers; survivors keep clocks.
        poll_watchdogs(&mut controllers, &[node("b")], start, 0);
        assert!(controllers.contains_key("b"));
        assert!(!controllers.contains_key("a"));
    }

    #[tokio::test]
    async fn watchdog_cycle_keeps_node_when_provider_fails() {
        // Pool without tokens: terminate errors, node stays for retry.
        let pool = CloudPool::from_config(&runner_core::config::RunnerConfig::default());
        let state = new_shared_state();
        state.write().await.add_cloud_node(node("i-9"));
        let mut controllers: WatchdogMap = HashMap::new();
        let start = Instant::now();
        run_watchdog_cycle(&pool, &state, &mut controllers, start, 0).await;
        run_watchdog_cycle(
            &pool,
            &state,
            &mut controllers,
            start + Duration::from_secs(300),
            0,
        )
        .await;
        assert_eq!(state.read().await.cloud_nodes().len(), 1);
        assert!(controllers.contains_key("i-9"));
    }

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
            route_job(1, &[], &HashMap::new(), None),
            RouteDecision::Local
        );
        assert_eq!(
            route_job(0, std::slice::from_ref(&peer), &HashMap::new(), None),
            RouteDecision::WanPeer {
                node_id: "n1".to_string()
            }
        );
        assert_eq!(
            route_job(0, &[], &HashMap::new(), Some("digitalocean")),
            RouteDecision::Cloud {
                provider: "digitalocean".to_string()
            }
        );
        assert_eq!(
            route_job(0, &[], &HashMap::new(), None),
            RouteDecision::Wait
        );
        let mut drained = HashMap::new();
        drained.insert("n1".to_string(), "t".to_string());
        assert_eq!(
            route_job(0, std::slice::from_ref(&peer), &drained, None),
            RouteDecision::Wait
        );
    }

    #[test]
    fn routing_selects_render_fallback_provider() {
        use std::collections::HashMap;
        // Render-only pool: the resolved provider flows through
        // instead of a hardcoded DigitalOcean selection.
        assert_eq!(
            route_job(0, &[], &HashMap::new(), Some("render")),
            RouteDecision::Cloud {
                provider: "render".to_string()
            }
        );
    }

    #[test]
    fn consecutive_polls_dispatch_once() {
        use runner_core::governor::supervisor::SupervisorState;
        // Poll 1 observes the job, dispatches, and records it.
        let mut state = SupervisorState::default();
        assert!(!already_in_flight(&state.in_flight_jobs(), "github", "42"));
        state.job_started("github", "42", "ci");
        // Poll 2 observes the same queued job id: skip, no re-dispatch.
        assert!(already_in_flight(&state.in_flight_jobs(), "github", "42"));
        // A different job still dispatches.
        assert!(!already_in_flight(&state.in_flight_jobs(), "github", "43"));
        // Same numeric id from another forge is a different job.
        assert!(!already_in_flight(&state.in_flight_jobs(), "gitlab", "42"));
        // Completion releases the id for future runs.
        state.job_finished("github", "42");
        assert!(!already_in_flight(&state.in_flight_jobs(), "github", "42"));
    }
}
