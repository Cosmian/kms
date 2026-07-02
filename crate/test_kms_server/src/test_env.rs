//! Safe in-process environment-variable overrides for test vectors.
//!
//! `std::env::set_var` is `unsafe` in Rust 1.87+ and is forbidden by this
//! crate's `deny(unsafe_code)` policy.  This module provides a thread-safe
//! alternative that the vector runner consults **before** falling back to the
//! real process environment.
//!
//! Usage (server init):
//! ```rust,ignore
//! crate::test_env::set("HSM_BOOTSTRAP_KEK_ID", &kek_id);
//! ```
//!
//! Usage (vector runner placeholder resolution):
//! ```rust,ignore
//! let value = crate::test_env::get("HSM_BOOTSTRAP_KEK_ID")
//!     .or_else(|| std::env::var("HSM_BOOTSTRAP_KEK_ID").ok());
//! ```

use std::{
    collections::HashMap,
    sync::{OnceLock, PoisonError, RwLock},
};

static OVERRIDES: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

fn map() -> &'static RwLock<HashMap<String, String>> {
    OVERRIDES.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Store an in-process env override under `key`.
///
/// # Panics
/// Panics if the internal `RwLock` has been poisoned (should never happen in
/// a normal test run).
pub fn set(key: &str, value: &str) {
    map()
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key.to_owned(), value.to_owned());
}

/// Look up an in-process env override.  Returns `None` if not set.
#[must_use]
pub fn get(key: &str) -> Option<String> {
    map()
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .get(key)
        .cloned()
}
