//! Core execution engine: configuration, resource governor, federated
//! mesh, local IPC, agent MCP server, and host status.

pub mod auth;
pub mod config;
pub mod governor;
pub mod ipc;
pub mod mcp;
pub mod mesh;
pub mod pidfile;
pub mod status;
pub mod test_support;
