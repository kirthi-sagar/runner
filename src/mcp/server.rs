//! JSON-RPC 2.0 stdio transport for the MCP server.
//!
//! Implements the MCP lifecycle over newline-delimited stdin/stdout:
//! `initialize`, `notifications/initialized`, `tools/list`, `tools/call`,
//! and `ping`. Compatible with async MCP clients such as Goose.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::tools::{ALL_TOOLS, ToolContext, execute_tool, tool_description, tool_schema};

/// Fallback protocol version when the client sends none. When the client
/// offers one, the server echoes it back (single-version interop).
pub const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest<T = Value> {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<T>,
}

/// JSON-RPC 2.0 success response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse<T = Value> {
    pub jsonrpc: String,
    pub id: Value,
    pub result: T,
}

/// JSON-RPC 2.0 error response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcErrorResponse {
    pub jsonrpc: String,
    pub id: Value,
    pub error: JsonRpcError,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl<T> JsonRpcRequest<T> {
    pub fn new(id: u64, method: impl Into<String>, params: Option<T>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: Some(Value::from(id)),
            method: method.into(),
            params,
        }
    }
}

fn ok(id: Value, result: Value) -> Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: Value, code: i64, message: String) -> Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id,
        "error": { "code": code, "message": message } })
}

/// MCP server bound to a tool context.
pub struct McpServer {
    ctx: ToolContext,
}

impl McpServer {
    pub fn new(ctx: ToolContext) -> Self {
        Self { ctx }
    }

    /// Handle one parsed JSON-RPC value. Returns `None` for notifications
    /// (no `id`), which require no response.
    pub async fn handle_value(&self, value: Value) -> Option<Value> {
        let req: JsonRpcRequest = match serde_json::from_value(value) {
            Ok(req) => req,
            Err(e) => {
                return Some(err(Value::Null, -32600, format!("invalid request: {e}")));
            }
        };
        if req.jsonrpc != "2.0" {
            return Some(err(Value::Null, -32600, "jsonrpc must be \"2.0\"".into()));
        }
        let id = match req.id {
            Some(id) => id,
            None => return None, // Notification: no response.
            };
        Some(self.dispatch(&id, &req.method, req.params.as_ref()).await)
    }

    async fn dispatch(&self, id: &Value, method: &str, params: Option<&Value>) -> Value {
        match method {
            "initialize" => ok(id.clone(), self.initialize(params)),
            "tools/list" => ok(id.clone(), self.tools_list()),
            "tools/call" => match self.tools_call(params).await {
                Ok(result) => ok(id.clone(), result),
                Err(e) => err(id.clone(), e.code, e.message),
            },
            "ping" => ok(id.clone(), Value::Object(Default::default())),
            _ => err(id.clone(), -32601, format!("method not found: {method}")),
        }
    }

    fn initialize(&self, params: Option<&Value>) -> Value {
        let version = params
            .and_then(|p| p.get("protocolVersion"))
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_PROTOCOL_VERSION);
        serde_json::json!({
            "protocolVersion": version,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "runner", "version": env!("CARGO_PKG_VERSION") },
        })
    }

    fn tools_list(&self) -> Value {
        let tools: Vec<Value> = ALL_TOOLS
            .iter()
            .map(|name| {
                serde_json::json!({
                    "name": name,
                    "description": tool_description(name),
                    "inputSchema": tool_schema(name),
                })
            })
            .collect();
        serde_json::json!({ "tools": tools })
    }

    async fn tools_call(&self, params: Option<&Value>) -> Result<Value, super::tools::ToolError> {
        use super::tools::ToolError;
        let params = params.ok_or_else(|| ToolError::invalid_params("missing params"))?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::invalid_params("missing tools/call name"))?;
        let args = params.get("arguments");
        let value = execute_tool(name, args, &self.ctx).await?;
        Ok(serde_json::json!({
            "content": [{ "type": "text",
                "text": serde_json::to_string_pretty(&value).unwrap_or_default() }],
        }))
    }

    /// Serve newline-delimited JSON-RPC on async reader/writer (stdio).
    pub async fn serve<R, W>(&self, reader: R, mut writer: W) -> anyhow::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut lines = BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await? {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Value>(line) {
                Ok(value) => self.handle_value(value).await,
                Err(e) => Some(err(Value::Null, -32700, format!("parse error: {e}"))),
            };
            if let Some(response) = response {
                writer.write_all(serde_json::to_string(&response)?.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
            }
        }
        Ok(())
    }

    /// Serve on process stdin/stdout.
    pub async fn serve_stdio(&self) -> anyhow::Result<()> {
        self.serve(tokio::io::stdin(), tokio::io::stdout()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RunnerConfig;
    use crate::governor::supervisor::new_shared_state;

    fn server() -> McpServer {
        McpServer::new(ToolContext::new(new_shared_state(), RunnerConfig::default()))
    }

    #[test]
    fn tools_call_envelope_serializes() {
        let req = JsonRpcRequest::new(
            1,
            "tools/call",
            Some(serde_json::json!({"name": "get_fleet_topology"})),
        );
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["method"], "tools/call");
        assert_eq!(json["params"]["name"], "get_fleet_topology");
    }

    #[tokio::test]
    async fn initialize_echoes_protocol_version() {
        let res = server()
            .handle_value(serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocolVersion": "2024-11-05",
                    "capabilities": {}, "clientInfo": {"name": "t", "version": "0"} },
            }))
            .await
            .unwrap();
        assert_eq!(res["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(res["result"]["serverInfo"]["name"], "runner");
    }

    #[tokio::test]
    async fn notifications_get_no_response() {
        let res = server()
            .handle_value(serde_json::json!({
                "jsonrpc": "2.0", "method": "notifications/initialized",
            }))
            .await;
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn unknown_method_is_not_found() {
        let res = server()
            .handle_value(serde_json::json!(
                {"jsonrpc": "2.0", "id": 2, "method": "bogus"}))
            .await
            .unwrap();
        assert_eq!(res["error"]["code"], -32601);
    }
}
