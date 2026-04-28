#![allow(clippy::doc_markdown, clippy::needless_borrows_for_generic_args)]
//! Integration tests for the REST Native Crypto API (`/v1/crypto/*`).
//!
//! Uses the same in-process `actix_web::test` infrastructure as the CSE and
//! health-endpoint tests — no TCP server, no external HTTP client.
//!
//! Module layout:
//!   common          — shared helpers used across test modules
//!   encrypt_decrypt — AES-GCM round-trips (128 / 256-bit), AAD binding
//!   sign_verify     — RS256 / ES256 round-trips; tamper rejection
//!   mac             — HS256 compute + correct/wrong MAC verify
//!   error_cases     — unknown alg (422), bad key id (4xx), wrong key type
//!   rfc_vectors     — RFC 7515 known-answer and known-key tests

mod common;
mod encrypt_decrypt;
mod error_cases;
mod mac;
mod rfc_vectors;
mod sign_verify;
