//! Shared library surface of the `runner` binary: service management
//! helpers and the live terminal monitor (the CLI entrypoint itself
//! lives in `main.rs`).

pub mod agent;
pub mod cache;
pub mod cloud;
pub mod commands;
pub mod coordinator;
pub mod doctor;
pub mod hook;
pub mod init;
pub mod provider;
pub mod service;
pub mod top;
