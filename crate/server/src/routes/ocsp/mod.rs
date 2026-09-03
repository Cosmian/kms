//! OCSP route scope registration.
//!
//! Exposes `GET /ocsp/{encoded}` and `POST /ocsp/` as public (no-auth) routes.

pub(crate) mod handler;

pub(crate) use handler::{evict_ocsp_cache_entry, get_ocsp, post_ocsp};
