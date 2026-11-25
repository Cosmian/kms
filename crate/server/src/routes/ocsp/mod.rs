//! OCSP route scope registration.
//!
//! Exposes `GET /ocsp/{encoded}` and `POST /ocsp/` as public (no-auth) routes.
//!
//! # Rate limiting
//! These endpoints are covered by the server-wide, per-peer-IP `RateLimiterMiddleware` (see
//! `start_kms_server.rs`). The responder's in-memory cache (`handler::OCSP_CACHE`) is keyed
//! per-serial and is bypassed whenever a request carries a nonce, asks for several `CertID`s
//! or the CA is compromised. Every cache miss therefore resolves all its `CertID`s with one
//! certificate scan and waits for one of the `handler::OCSP_LOOKUP_PERMITS` (one per available
//! CPU) before scanning and signing, so a flood queues instead of multiplying concurrent
//! scans and signatures (which are expensive, especially when backed by an HSM). There is no
//! OCSP-specific per-client limiter: a distributed low-and-slow flood can still keep the
//! lookup budget busy, which is an accepted residual capacity risk.

pub(crate) mod handler;

pub(crate) use handler::{evict_ocsp_cache_entry, get_ocsp, post_ocsp};
