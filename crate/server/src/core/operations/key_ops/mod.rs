//! Key operations: lifecycle, authorization, resolution, crypto dispatch, and usage limits.
//!
//! Crypto dispatch and key selection are now methods on [`KMS`](crate::core::KMS).
//! This module re-exports the traits, enums, and lifecycle utility.

pub(crate) mod crypto_op;

// ─── Re-exports (stable external API) ───────────────────────────────────────

pub(crate) use crypto_op::{CryptoOpSpec, KeySelectionSpec, KeysetMode, ObjectLifecycleExt};
