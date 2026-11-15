//! Multi-tenant fleet policy: per-tenant resource ceilings, provider
//! allow-lists, and cloud-burst gates evaluated before dispatch.

use serde::{Deserialize, Serialize};

/// Resource + provider envelope for one tenant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantPolicy {
    pub tenant: String,
    pub max_cores: f64,
    pub max_ram_mb: u64,
    /// Provider names this tenant may consume (`github`, `local`, ...).
    /// Empty means all providers allowed.
    #[serde(default)]
    pub providers: Vec<String>,
    /// Whether cloud bursting is allowed for this tenant.
    #[serde(default = "default_true")]
    pub allow_cloud_burst: bool,
}

fn default_true() -> bool {
    true
}

/// Fleet-wide policy with per-tenant overrides.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FleetPolicy {
    #[serde(default)]
    pub default_max_cores: f64,
    #[serde(default)]
    pub default_max_ram_mb: u64,
    #[serde(default)]
    pub tenants: Vec<TenantPolicy>,
}

impl FleetPolicy {
    /// Permissive default: 0 cores/RAM means "no ceiling".
    pub fn permissive() -> Self {
        Self::default()
    }
}

/// A dispatch request awaiting a policy decision.
#[derive(Debug, Clone)]
pub struct JobRequest {
    pub tenant: String,
    pub cores: f64,
    pub ram_mb: u64,
    pub provider: String,
    pub cloud: bool,
}

/// Policy verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny(String),
}

impl PolicyDecision {
    pub fn allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
}

impl FleetPolicy {
    fn tenant_policy(&self, tenant: &str) -> Option<&TenantPolicy> {
        self.tenants.iter().find(|t| t.tenant == tenant)
    }

    /// Evaluate a dispatch request against fleet + tenant ceilings.
    /// Unknown tenants fall back to the fleet defaults.
    pub fn evaluate(&self, req: &JobRequest) -> PolicyDecision {
        let (max_cores, max_ram_mb, providers, allow_cloud) = match self.tenant_policy(&req.tenant)
        {
            Some(t) => (
                t.max_cores,
                t.max_ram_mb,
                t.providers.clone(),
                t.allow_cloud_burst,
            ),
            None => (
                self.default_max_cores,
                self.default_max_ram_mb,
                Vec::new(),
                true,
            ),
        };
        if max_cores > 0.0 && req.cores > max_cores {
            return PolicyDecision::Deny(format!(
                "tenant '{}' requests {cores} cores, ceiling is {max_cores}",
                req.tenant,
                cores = req.cores,
            ));
        }
        if max_ram_mb > 0 && req.ram_mb > max_ram_mb {
            return PolicyDecision::Deny(format!(
                "tenant '{}' requests {}MB RAM, ceiling is {max_ram_mb}MB",
                req.tenant, req.ram_mb,
            ));
        }
        if !providers.is_empty() && !providers.iter().any(|p| p == &req.provider) {
            return PolicyDecision::Deny(format!(
                "tenant '{}' may not use provider '{}'",
                req.tenant, req.provider,
            ));
        }
        if req.cloud && !allow_cloud {
            return PolicyDecision::Deny(
                format!("tenant '{}' may not burst to cloud", req.tenant,),
            );
        }
        PolicyDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> FleetPolicy {
        FleetPolicy {
            default_max_cores: 8.0,
            default_max_ram_mb: 16384,
            tenants: vec![TenantPolicy {
                tenant: "acme".to_string(),
                max_cores: 2.0,
                max_ram_mb: 4096,
                providers: vec!["github".to_string()],
                allow_cloud_burst: false,
            }],
        }
    }

    fn req(tenant: &str, cores: f64, ram_mb: u64, provider: &str, cloud: bool) -> JobRequest {
        JobRequest {
            tenant: tenant.to_string(),
            cores,
            ram_mb,
            provider: provider.to_string(),
            cloud,
        }
    }

    #[test]
    fn tenant_ceilings_provider_and_burst_gates() {
        let policy = policy();
        assert!(policy
            .evaluate(&req("acme", 2.0, 2048, "github", false))
            .allowed());
        assert!(!policy
            .evaluate(&req("acme", 4.0, 2048, "github", false))
            .allowed());
        assert!(!policy
            .evaluate(&req("acme", 2.0, 8192, "github", false))
            .allowed());
        assert!(!policy
            .evaluate(&req("acme", 2.0, 2048, "gitlab", false))
            .allowed());
        assert!(!policy
            .evaluate(&req("acme", 2.0, 2048, "github", true))
            .allowed());
    }

    #[test]
    fn unknown_tenants_fall_back_to_fleet_defaults() {
        let policy = policy();
        assert!(policy
            .evaluate(&req("newco", 8.0, 16384, "bitbucket", true))
            .allowed());
        assert!(!policy
            .evaluate(&req("newco", 16.0, 1024, "github", false))
            .allowed());
    }
}
