//! Universal provider layer: the [`providers::ProviderAdapter`] trait
//! normalizes every CI source (GitHub, GitLab, Bitbucket, local CLI)
//! into provider-agnostic job contracts for the engine.

pub mod github;
pub mod providers;
