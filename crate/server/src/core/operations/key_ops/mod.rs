//! Key operations: lifecycle, authorization, resolution, crypto dispatch, and usage limits.
//!
//! This module is the hub for all key-related operation logic.  Each concern
//! lives in its own submodule; this file re-exports the public API so that
//! external consumers can continue importing from `key_ops::`.

pub(crate) mod authorization;
pub(crate) mod crypto_op;
pub(crate) mod key_resolution;
pub(crate) mod lifecycle;
pub(crate) mod usage_limits;

// ─── Re-exports (stable external API) ───────────────────────────────────────

pub(crate) use authorization::{enforce_create_permission, reject_protection_storage_masks};
pub(crate) use crypto_op::{CryptoOpSpec, perform_crypto_operation};
pub(crate) use key_resolution::KeysetMode;
pub(crate) use lifecycle::{record_cascading_metrics, setup_object_lifecycle};
