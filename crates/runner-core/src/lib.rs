//! Core execution engine: configuration, resource governor, federated
//! mesh, local IPC, agent MCP server, and host status.

pub mod auth;
pub mod cache;
pub mod config;
pub mod governor;
pub mod ipc;
pub mod mcp;
pub mod mesh;
pub mod pidfile;
pub mod power;
pub mod status;
pub mod test_support;
#[cfg(windows)]
pub(crate) mod winacl;
