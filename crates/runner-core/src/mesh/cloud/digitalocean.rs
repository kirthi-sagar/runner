//! DigitalOcean droplet provisioner.
//!
//! Create: `POST /v2/droplets` → `202 Accepted`, poll `links.actions`.
//! Destroy: `DELETE /v2/droplets/{id}` → `204`, irreversible. Volumes,
//! snapshots, and reserved IPs are NOT deleted automatically, so full
//! teardown cleans them explicitly to preserve credits.

use serde::{Deserialize, Serialize};

/// API base for droplet operations.
pub const API_BASE: &str = "https://api.digitalocean.com";
/// Droplet create endpoint.
pub const DROPLETS_PATH: &str = "/v2/droplets";

/// Droplet destroy endpoint for one id.
pub fn droplet_path(id: u64) -> String {
    format!("/v2/droplets/{id}")
}

/// Droplet creation request (pure builder; unit-tested).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CreateDroplet {
    pub name: String,
    pub region: String,
    pub size: String,
    pub image: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ssh_keys: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tags: Vec<String>,
}

impl CreateDroplet {
    /// Ephemeral CI worker droplet tagged for the mesh.
    pub fn ci_worker(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            region: "nyc3".to_string(),
            size: "s-2vcpu-4gb".to_string(),
            image: "ubuntu-24-04-x64".to_string(),
            ssh_keys: Vec::new(),
            tags: vec!["runner".to_string(), "ephemeral".to_string()],
        }
    }

    pub fn body(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DropletEnvelope {
    droplet: DropletRef,
}

#[derive(Debug, Clone, Deserialize)]
struct DropletRef {
    id: u64,
}

/// Extract the droplet id from a create response body (pure).
pub fn parse_created_id(body: &serde_json::Value) -> Result<u64, String> {
    serde_json::from_value::<DropletEnvelope>(body.clone())
        .map(|env| env.droplet.id)
        .map_err(|e| format!("unexpected droplet response: {e}"))
}

/// One droplet row from the list endpoint (reconciliation input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropletSummary {
    pub id: u64,
    pub name: String,
    pub status: String,
    pub created_at: String,
}

/// Parse `GET /v2/droplets` (pure; malformed rows are skipped, never
/// fatal — one odd droplet must not block orphan discovery).
pub fn parse_droplets_list(body: &serde_json::Value) -> Vec<DropletSummary> {
    body.get("droplets")
        .and_then(|v| v.as_array())
        .map(|droplets| {
            droplets
                .iter()
                .filter_map(|d| {
                    Some(DropletSummary {
                        id: d.get("id")?.as_u64()?,
                        name: d.get("name")?.as_str()?.to_string(),
                        status: d
                            .get("status")
                            .and_then(|s| s.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        created_at: d
                            .get("created_at")
                            .and_then(|s| s.as_str())
                            .unwrap_or("")
                            .to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Live API client (Bearer token).
#[derive(Debug, Clone)]
pub struct DoClient {
    token: String,
    http: reqwest::Client,
    base_url: String,
}

impl DoClient {
    pub fn new(token: impl Into<String>) -> Result<Self, String> {
        let token = token.into();
        if token.trim().is_empty() {
            return Err("digitalocean token must not be empty".to_string());
        }
        Ok(Self {
            token,
            http: reqwest::Client::new(),
            base_url: API_BASE.to_string(),
        })
    }

    /// Override the API base (mock harness, private mirrors).
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.bearer_auth(&self.token)
    }

    /// Create a droplet; returns its id on `202 Accepted`.
    pub async fn create_droplet(&self, spec: &CreateDroplet) -> Result<u64, String> {
        let base = self.base_url.as_str();
        let res = self
            .auth(self.http.post(format!("{base}{DROPLETS_PATH}")))
            .json(&spec.body())
            .send()
            .await
            .map_err(|e| format!("droplet create failed: {e}"))?;
        if res.status() != reqwest::StatusCode::ACCEPTED {
            return Err(format!("droplet create: HTTP {}", res.status()));
        }
        let body: serde_json::Value = res
            .json()
            .await
            .map_err(|e| format!("droplet create body: {e}"))?;
        parse_created_id(&body)
    }

    /// List droplets (first page, 200 max) for orphan reconciliation.
    pub async fn list_droplets(&self) -> Result<Vec<DropletSummary>, String> {
        let base = self.base_url.as_str();
        let res = self
            .auth(self.http.get(format!("{base}{DROPLETS_PATH}?per_page=200")))
            .send()
            .await
            .map_err(|e| format!("droplets list failed: {e}"))?;
        if !res.status().is_success() {
            return Err(format!("droplets list: HTTP {}", res.status()));
        }
        let body: serde_json::Value = res
            .json()
            .await
            .map_err(|e| format!("droplets list body: {e}"))?;
        Ok(parse_droplets_list(&body))
    }

    /// Destroy a droplet (`204`, irreversible).
    pub async fn destroy_droplet(&self, id: u64) -> Result<(), String> {
        let base = self.base_url.as_str();
        let res = self
            .auth(self.http.delete(format!("{base}{}", droplet_path(id))))
            .send()
            .await
            .map_err(|e| format!("droplet destroy failed: {e}"))?;
        if res.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(format!("droplet destroy: HTTP {}", res.status()));
        }
        Ok(())
    }

    /// Full teardown: droplet + its snapshots + volumes that were attached.
    /// Snapshot/volume cleanup is best-effort; failures are returned as
    /// warnings without failing the destroy.
    pub async fn destroy_droplet_full(&self, id: u64) -> Result<Vec<String>, String> {
        let mut warnings = Vec::new();
        // Snapshots must be listed BEFORE the droplet is gone.
        let snapshot_ids = self.list_droplet_snapshots(id).await.unwrap_or_else(|e| {
            warnings.push(format!("snapshots list: {e}"));
            Vec::new()
        });
        let volume_ids = self.attached_volumes(id).await.unwrap_or_else(|e| {
            warnings.push(format!("volumes list: {e}"));
            Vec::new()
        });
        self.destroy_droplet(id).await?;
        for snap_id in snapshot_ids {
            if let Err(e) = self.delete_snapshot(&snap_id).await {
                warnings.push(format!("snapshot {snap_id}: {e}"));
            }
        }
        for vol_id in volume_ids {
            if let Err(e) = self.delete_volume(&vol_id).await {
                warnings.push(format!("volume {vol_id}: {e}"));
            }
        }
        Ok(warnings)
    }

    async fn list_droplet_snapshots(&self, id: u64) -> Result<Vec<String>, String> {
        #[derive(Deserialize)]
        struct Snaps {
            #[serde(default)]
            snapshots: Vec<IdRef>,
        }
        #[derive(Deserialize)]
        struct IdRef {
            id: serde_json::Value,
        }
        let base = self.base_url.as_str();
        let res = self
            .auth(self.http.get(format!("{base}/v2/droplets/{id}/snapshots")))
            .send()
            .await
            .map_err(|e| format!("snapshots: {e}"))?;
        if !res.status().is_success() {
            return Err(format!("snapshots: HTTP {}", res.status()));
        }
        let body: Snaps = res
            .json()
            .await
            .map_err(|e| format!("snapshots body: {e}"))?;
        Ok(body
            .snapshots
            .iter()
            .map(|s| s.id.to_string().trim_matches('"').to_string())
            .collect())
    }

    async fn attached_volumes(&self, droplet_id: u64) -> Result<Vec<String>, String> {
        #[derive(Deserialize)]
        struct Vols {
            #[serde(default)]
            volumes: Vec<Vol>,
        }
        #[derive(Deserialize)]
        struct Vol {
            id: String,
            #[serde(default)]
            droplet_ids: Vec<u64>,
        }
        let base = self.base_url.as_str();
        let res = self
            .auth(self.http.get(format!("{base}/v2/volumes?per_page=200")))
            .send()
            .await
            .map_err(|e| format!("volumes: {e}"))?;
        if !res.status().is_success() {
            return Err(format!("volumes: HTTP {}", res.status()));
        }
        let body: Vols = res.json().await.map_err(|e| format!("volumes body: {e}"))?;
        Ok(body
            .volumes
            .iter()
            .filter(|v| v.droplet_ids.contains(&droplet_id))
            .map(|v| v.id.clone())
            .collect())
    }

    async fn delete_snapshot(&self, snapshot_id: &str) -> Result<(), String> {
        let res = self
            .auth(self.http.delete({
                let base = self.base_url.as_str();
                format!("{base}/v2/snapshots/{snapshot_id}")
            }))
            .send()
            .await
            .map_err(|e| format!("snapshot delete: {e}"))?;
        if res.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(format!("snapshot delete: HTTP {}", res.status()));
        }
        Ok(())
    }

    async fn delete_volume(&self, volume_id: &str) -> Result<(), String> {
        let res = self
            .auth(self.http.delete({
                let base = self.base_url.as_str();
                format!("{base}/v2/volumes/{volume_id}")
            }))
            .send()
            .await
            .map_err(|e| format!("volume delete: {e}"))?;
        if res.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(format!("volume delete: HTTP {}", res.status()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destroy_path_matches_api() {
        assert_eq!(droplet_path(42), "/v2/droplets/42");
    }

    #[test]
    fn droplets_list_parses_and_skips_malformed_rows() {
        let body = serde_json::json!({
            "droplets": [
                {"id": 7, "name": "runner-ci-1-2", "status": "active",
                 "created_at": "2026-11-17T10:00:00Z"},
                {"id": "nan", "name": "broken"},
                {"name": "no-id"},
            ],
        });
        let rows = parse_droplets_list(&body);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, 7);
        assert_eq!(rows[0].name, "runner-ci-1-2");
        assert_eq!(rows[0].created_at, "2026-11-17T10:00:00Z");
        assert!(parse_droplets_list(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn worker_body_has_required_fields() {
        let body = CreateDroplet::ci_worker("runner-ci-1").body();
        assert_eq!(body["name"], "runner-ci-1");
        assert_eq!(body["size"], "s-2vcpu-4gb");
        assert!(body["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "runner"));
    }

    #[test]
    fn parses_created_droplet_id() {
        let body = serde_json::json!({
            "droplet": { "id": 12345, "name": "x" },
            "links": { "actions": [{ "id": 1 }] },
        });
        assert_eq!(parse_created_id(&body).unwrap(), 12345);
        assert!(parse_created_id(&serde_json::json!({})).is_err());
    }
}
