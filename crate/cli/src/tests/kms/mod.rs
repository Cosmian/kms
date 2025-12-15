#![cfg(feature = "non-fips")]
mod access;
mod attributes;
#[cfg(feature = "non-fips")]
mod auth_tests;
mod certificates;
#[cfg(feature = "non-fips")]
mod cover_crypt;
mod derive_key;
pub(crate) mod digested;
mod discover_versions;
mod elliptic_curve;
mod error_messages;
mod google_cmd;
mod hash;
mod hsm;
mod mac;
mod mac_verify;
mod metrics;
mod opaque_object;
mod query;
mod rng;
mod rsa;
mod secret_data;
mod shared;
mod symmetric;
#[cfg(feature = "non-fips")] // Since KMIP test vectors use non-FIPS algorithms such as ChaCha20
mod xml;
