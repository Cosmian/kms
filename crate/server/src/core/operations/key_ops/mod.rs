//! Key operations: lifecycle, authorization, resolution, crypto dispatch, and usage limits.
//!
//! All logic lives in [`crypto_op`]; this file simply re-exports the public API
//! so that external consumers can continue importing from `key_ops::`.

pub(crate) mod crypto_op;

// ─── Re-exports (stable external API) ───────────────────────────────────────

pub(crate) use crypto_op::{
    CryptoOpSpec, KeySelectionSpec, KeysetMode, perform_crypto_operation, select_unique_key,
    setup_object_lifecycle,
};
