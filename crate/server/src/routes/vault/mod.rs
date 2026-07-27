//! Vault-compatible API routes.
//!
//! Implements a subset of the `HashiCorp` Vault HTTP API used by SPIRE/SPIFFE:
//! - Transit engine (`/v1/{transit_mount}/`) — key creation, signing
//! - PKI engine (`/v1/{pki_mount}/`) — sign-intermediate (CSR signing)
//!
//! Authentication is handled by [`crate::middlewares::vault_token_middleware`]
//! which validates `X-Vault-Token` headers against the auth-verifier instance.

pub(crate) mod error;
pub(crate) mod pki;
pub(crate) mod transit;
