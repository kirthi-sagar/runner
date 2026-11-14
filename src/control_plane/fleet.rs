//! Fleet inventory: runner registration, heartbeats, stale eviction.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Node enrollment record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerRegistration {
    pub runner_id: String,
    pub hostname: String,
    pub capacity: u32,
    #[serde(default)]
    pub supported_providers: Vec<String>,
}

/// Periodic node telemetry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    pub runner_id: String,
    pub cpu_usage: f64,
    pub psi_pressure: f64,
    pub active_jobs: u32,
}

/// Live view of one fleet member.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RunnerSnapshot {
    #[serde(flatten)]
    pub registration: RunnerRegistration,
    pub cpu_usage: f64,
    pub psi_pressure: f64,
    pub active_jobs: u32,
    pub last_heartbeat_secs_ago: u64,
}

#[derive(Debug)]
struct RunnerRecord {
    registration: RunnerRegistration,
    token: String,
    last_heartbeat: Instant,
    cpu_usage: f64,
    psi_pressure: f64,
    active_jobs: u32,
}

/// Thread-safe fleet registry with heartbeat TTL eviction.
#[derive(Debug)]
pub struct FleetRegistry {
    ttl: Duration,
    runners: tokio::sync::RwLock<HashMap<String, RunnerRecord>>,
}

impl FleetRegistry {
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(60))
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self { ttl, runners: tokio::sync::RwLock::new(HashMap::new()) }
    }

    /// Register (or re-register) a node; returns its bearer token.
    pub async fn register(&self, registration: RunnerRegistration) -> String {
        let token = crate::control_plane::auth::random_hex(32);
        self.runners.write().await.insert(
            registration.runner_id.clone(),
            RunnerRecord {
                registration,
                token: token.clone(),
                last_heartbeat: Instant::now(),
                cpu_usage: 0.0,
                psi_pressure: 0.0,
                active_jobs: 0,
            },
        );
        token
    }

    /// True when the bearer token matches the registered node.
    pub async fn authenticate(&self, runner_id: &str, token: &str) -> bool {
        self.runners
            .read()
            .await
            .get(runner_id)
            .is_some_and(|record| record.token == token)
    }

    /// Record a heartbeat; unknown ids are rejected.
    pub async fn heartbeat(&self, payload: &HeartbeatPayload) -> Result<(), String> {
        let mut guard = self.runners.write().await;
        match guard.get_mut(&payload.runner_id) {
            Some(record) => {
                record.last_heartbeat = Instant::now();
                record.cpu_usage = payload.cpu_usage;
                record.psi_pressure = payload.psi_pressure;
                record.active_jobs = payload.active_jobs;
                Ok(())
            }
            None => Err(format!("unknown runner_id: {}", payload.runner_id)),
        }
    }

    /// Snapshot of non-stale runners.
    pub async fn active_runners(&self) -> Vec<RunnerSnapshot> {
        let now = Instant::now();
        self.runners
            .read()
            .await
            .values()
            .filter(|record| now.duration_since(record.last_heartbeat) < self.ttl)
            .map(|record| RunnerSnapshot {
                registration: record.registration.clone(),
                cpu_usage: record.cpu_usage,
                psi_pressure: record.psi_pressure,
                active_jobs: record.active_jobs,
                last_heartbeat_secs_ago: now.duration_since(record.last_heartbeat).as_secs(),
            })
            .collect()
    }

    /// Drop stale nodes; returns the evicted count.
    pub async fn evict_stale(&self) -> usize {
        let now = Instant::now();
        let mut guard = self.runners.write().await;
        let before = guard.len();
        guard.retain(|_, record| now.duration_since(record.last_heartbeat) < self.ttl);
        before - guard.len()
    }
}

impl Default for FleetRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(id: &str) -> RunnerRegistration {
        RunnerRegistration {
            runner_id: id.to_string(),
            hostname: "host".to_string(),
            capacity: 4,
            supported_providers: vec!["github".to_string()],
        }
    }

    #[tokio::test]
    async fn register_heartbeat_and_evict() {
        let fleet = FleetRegistry::with_ttl(Duration::from_millis(60));
        let token = fleet.register(registration("r1")).await;
        assert!(!token.is_empty());
        fleet
            .heartbeat(&HeartbeatPayload {
                runner_id: "r1".to_string(),
                cpu_usage: 0.5,
                psi_pressure: 12.0,
                active_jobs: 2,
            })
            .await
            .unwrap();
        assert!(fleet.heartbeat(&HeartbeatPayload {
            runner_id: "ghost".to_string(),
            cpu_usage: 0.0,
            psi_pressure: 0.0,
            active_jobs: 0,
        }).await.is_err());
        assert_eq!(fleet.active_runners().await.len(), 1);
        tokio::time::sleep(Duration::from_millis(90)).await;
        assert_eq!(fleet.evict_stale().await, 1);
        assert!(fleet.active_runners().await.is_empty());
    }
}
