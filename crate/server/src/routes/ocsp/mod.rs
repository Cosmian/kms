//! OCSP route scope registration.
//!
//! Exposes `GET /ocsp/{encoded}` and `POST /ocsp/` as public (no-auth) routes.
//!
//! # Rate limiting
//! These endpoints are covered only by the server-wide, per-peer-IP
//! `RateLimiterMiddleware` (see `start_kms_server.rs`) — there is no
//! OCSP-specific request limiter. Because the responder's in-memory cache
//! (`handler::OCSP_CACHE`) is keyed per-serial and is bypassed whenever a
//! request carries a nonce or the CA is compromised, a distributed
//! low-and-slow query flood (many distinct serials, or many source IPs, each
//! under the generic per-IP threshold) can still force repeated signing
//! operations — which are comparatively expensive, especially when backed by
//! an HSM. This is a known, accepted residual capacity risk rather than an
//! oversight; a dedicated OCSP-specific limiter was intentionally deferred.

pub(crate) mod handler;

pub(crate) use handler::{evict_ocsp_cache_entry, get_ocsp, post_ocsp};
