//! Render.com background worker provisioner.
//!
//! Create: `POST https://api.render.com/v1/services` with Bearer auth and
//! `type: "background_worker"`. Teardown via suspend + delete. Paid
//! compute is prorated per second, so prompt supervisor-driven teardown
//! preserves credits.

use serde::Serialize;

/// Services collection endpoint.
pub const SERVICES_URL: &str = "https://api.render.com/v1/services";
/// Service type for queue-consuming CI workers.
pub const BACKGROUND_WORKER_TYPE: &str = "background_worker";

/// Service teardown endpoint.
pub fn service_path(id: &str) -> String {
    format!("{SERVICES_URL}/{id}")
}

/// Service suspend endpoint.
pub fn suspend_path(id: &str) -> String {
    format!("{}/suspend", service_path(id))
}

/// Background worker creation request (pure builder; unit-tested).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CreateWorker {
    #[serde(rename = "type")]
    pub service_type: String,
    pub name: String,
    #[serde(rename = "ownerId")]
    pub owner_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub env_vars: Vec<EnvVar>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

impl CreateWorker {
    pub fn ci_worker(name: impl Into<String>, owner_id: impl Into<String>) -> Self {
        Self {
            service_type: BACKGROUND_WORKER_TYPE.to_string(),
            name: name.into(),
            owner_id: owner_id.into(),
            image_url: None,
            env_vars: Vec::new(),
        }
    }

    pub fn body(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Live API client (Bearer key).
#[derive(Debug, Clone)]
pub struct RenderClient {
    token: String,
    http: reqwest::Client,
}

impl RenderClient {
    pub fn new(token: impl Into<String>) -> Result<Self, String> {
        let token = token.into();
        if token.trim().is_empty() {
            return Err("render token must not be empty".to_string());
        }
        Ok(Self {
            token,
            http: reqwest::Client::new(),
        })
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.bearer_auth(&self.token)
    }

    /// Create a background worker; returns the service id.
    pub async fn create_worker(&self, spec: &CreateWorker) -> Result<String, String> {
        let res = self
            .auth(self.http.post(SERVICES_URL))
            .json(&spec.body())
            .send()
            .await
            .map_err(|e| format!("worker create failed: {e}"))?;
        if !(res.status().is_success()) {
            return Err(format!("worker create: HTTP {}", res.status()));
        }
        let body: serde_json::Value = res
            .json()
            .await
            .map_err(|e| format!("worker create body: {e}"))?;
        body.get("id")
            .and_then(|id| id.as_str().map(str::to_string))
            .ok_or_else(|| "worker create: missing service id".to_string())
    }

    /// Suspend a service (stops billing accrual on paid instances).
    pub async fn suspend(&self, id: &str) -> Result<(), String> {
        let res = self
            .auth(self.http.post(suspend_path(id)))
            .send()
            .await
            .map_err(|e| format!("worker suspend failed: {e}"))?;
        if !res.status().is_success() {
            return Err(format!("worker suspend: HTTP {}", res.status()));
        }
        Ok(())
    }

    /// Delete a service permanently.
    pub async fn delete(&self, id: &str) -> Result<(), String> {
        let res = self
            .auth(self.http.delete(service_path(id)))
            .send()
            .await
            .map_err(|e| format!("worker delete failed: {e}"))?;
        if !(res.status().is_success() || res.status() == reqwest::StatusCode::NO_CONTENT) {
            return Err(format!("worker delete: HTTP {}", res.status()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_body_has_required_fields() {
        let body = CreateWorker::ci_worker("runner-ci-1", "owner-1").body();
        assert_eq!(body["type"], "background_worker");
        assert_eq!(body["name"], "runner-ci-1");
        assert_eq!(body["ownerId"], "owner-1");
    }

    #[test]
    fn teardown_paths_match_api() {
        assert_eq!(
            service_path("srv-1"),
            "https://api.render.com/v1/services/srv-1"
        );
        assert_eq!(
            suspend_path("srv-1"),
            "https://api.render.com/v1/services/srv-1/suspend"
        );
    }
}
