//! Ephemeral cloud credit bursting with scale-to-zero.

pub mod autoscale;
pub mod digitalocean;
pub mod render;

use serde::{Deserialize, Serialize};

/// A live cloud worker node tracked by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudNode {
    pub id: String,
    pub provider: String,
    pub status: String,
    /// Launch time as Unix epoch seconds (0 = unknown, pre-upgrade node).
    #[serde(default)]
    pub launched_at: u64,
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl CloudNode {
    /// Seconds since launch (saturating; 0 when unknown).
    pub fn uptime_secs(&self, now_secs: u64) -> u64 {
        now_secs.saturating_sub(self.launched_at)
    }
}

/// Compact human duration: `45s`, `3m`, `2h12m`, `4d`.
pub fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        return format!("{secs}s");
    }
    if secs < 3_600 {
        return format!("{}m", secs / 60);
    }
    if secs < 86_400 {
        return format!("{}h{:02}m", secs / 3_600, (secs % 3_600) / 60);
    }
    format!("{}d", secs / 86_400)
}

/// Provider clients built from Super Admin config. A missing token means
/// that provider is unavailable (no silent fallback, no crash).
#[derive(Debug, Clone, Default)]
pub struct CloudPool {
    digitalocean: Option<digitalocean::DoClient>,
    render: Option<(render::RenderClient, String)>,
    air_gapped: bool,
}

impl CloudPool {
    pub fn from_config(config: &crate::config::RunnerConfig) -> Self {
        let digitalocean = config
            .cloud
            .digitalocean_token
            .as_deref()
            .and_then(|token| digitalocean::DoClient::new(token).ok());
        let render = config
            .cloud
            .render_token
            .as_deref()
            .zip(config.cloud.render_owner_id.as_deref())
            .and_then(|(token, owner)| {
                render::RenderClient::new(token)
                    .ok()
                    .map(|client| (client, owner.to_string()))
            });
        Self {
            digitalocean,
            render,
            air_gapped: config.security.air_gapped,
        }
    }

    pub fn has_provider(&self, provider: &str) -> bool {
        match provider {
            "digitalocean" => self.digitalocean.is_some(),
            "render" => self.render.is_some(),
            _ => false,
        }
    }

    /// Provision one ephemeral worker on the named provider.
    /// Refused outright when the security profile is air-gapped.
    pub async fn provision(&self, provider: &str, name: &str) -> Result<CloudNode, String> {
        if self.air_gapped {
            return Err("air-gapped mode: cloud bursting is disabled".to_string());
        }
        match provider {
            "digitalocean" => {
                let client = self
                    .digitalocean
                    .as_ref()
                    .ok_or_else(|| "digitalocean token not configured".to_string())?;
                let id = client
                    .create_droplet(&digitalocean::CreateDroplet::ci_worker(name))
                    .await?;
                Ok(CloudNode {
                    id: id.to_string(),
                    provider: provider.to_string(),
                    status: "provisioning".to_string(),
                    launched_at: now_epoch_secs(),
                })
            }
            "render" => {
                let (client, owner) = self
                    .render
                    .as_ref()
                    .ok_or_else(|| "render token/owner not configured".to_string())?;
                let id = client
                    .create_worker(&render::CreateWorker::ci_worker(name, owner))
                    .await?;
                Ok(CloudNode {
                    id,
                    provider: provider.to_string(),
                    status: "provisioning".to_string(),
                    launched_at: now_epoch_secs(),
                })
            }
            _ => Err(format!("unknown provider: {provider}")),
        }
    }

    /// Terminate one worker (full cleanup on DigitalOcean).
    pub async fn terminate(&self, node: &CloudNode) -> Result<Vec<String>, String> {
        match node.provider.as_str() {
            "digitalocean" => {
                let client = self
                    .digitalocean
                    .as_ref()
                    .ok_or_else(|| "digitalocean token not configured".to_string())?;
                let id: u64 = node
                    .id
                    .parse()
                    .map_err(|_| format!("bad droplet id: {}", node.id))?;
                client.destroy_droplet_full(id).await
            }
            "render" => {
                let (client, _) = self
                    .render
                    .as_ref()
                    .ok_or_else(|| "render token not configured".to_string())?;
                client.delete(&node.id).await?;
                Ok(Vec::new())
            }
            _ => Err(format!("unknown provider: {}", node.provider)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn air_gapped_pool_refuses_provisioning() {
        let mut config = crate::config::RunnerConfig::default();
        config.security.air_gapped = true;
        let pool = CloudPool::from_config(&config);
        let err = pool.provision("digitalocean", "ci-1").await.unwrap_err();
        assert!(err.contains("air-gapped"), "unexpected: {err}");

        // Non-gapped pool without tokens fails on credentials instead.
        let open = CloudPool::from_config(&crate::config::RunnerConfig::default());
        let err = open.provision("digitalocean", "ci-1").await.unwrap_err();
        assert!(err.contains("not configured"), "unexpected: {err}");
    }

    #[test]
    fn uptime_formats_compactly_and_saturates() {
        assert_eq!(format_uptime(45), "45s");
        assert_eq!(format_uptime(125), "2m");
        assert_eq!(format_uptime(7_500), "2h05m");
        assert_eq!(format_uptime(200_000), "2d");
        let node = CloudNode {
            id: "i".to_string(),
            provider: "render".to_string(),
            status: "active".to_string(),
            launched_at: 1_000,
        };
        assert_eq!(node.uptime_secs(1_100), 100);
        assert_eq!(node.uptime_secs(999), 0);
        // Old payloads without the field still parse (launched_at = 0).
        let legacy: CloudNode = serde_json::from_value(serde_json::json!({
            "id": "i", "provider": "render", "status": "active",
        }))
        .unwrap();
        assert_eq!(legacy.launched_at, 0);
    }
}
