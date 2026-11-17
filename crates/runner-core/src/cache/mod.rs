//! Transparent LAN cache proxy (`ACTIONS_CACHE_URL`).
//!
//! A daemon-embedded GitHub Actions Cache service: workers on this host
//! (and LAN peers, in a later milestone) resolve `actions/cache` hits
//! over loopback instead of the internet, with zero workflow edits.

pub mod server;
pub mod store;

pub use store::{CacheStatsSnapshot, CacheStore};
