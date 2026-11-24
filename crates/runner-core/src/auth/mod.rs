//! Forge authentication: provider token slots, device-flow login,
//! and file-backed credential stores.

pub mod device_flow;
pub mod store;

pub use store::{ProviderSlot, TokenStore};
