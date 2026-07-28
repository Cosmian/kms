//! SPIRE-compatible API routes.
//!
//! Implements a subset of the auth protocol used by SPIRE/SPIFFE plugins:
//! - Transit engine (`/v1/{transit_mount}/`) — key creation, signing
//! - PKI engine (`/v1/{pki_mount}/`) — sign-intermediate (CSR signing)
//!
//! Authentication is handled by [`crate::middlewares::spire_token_middleware`]
//! which validates `X-Vault-Token` headers against the auth-verifier instance.

pub(crate) mod auth_proxy;
pub(crate) mod error;
pub(crate) mod pki;
pub(crate) mod transit;
