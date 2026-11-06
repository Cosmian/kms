pub mod config;
pub mod error;
pub mod service;

#[cfg(all(test, unix))]
pub mod integration_tests;

pub use cosmian_kms_k8s_plugin_proto::kmsv2;
