//! KMIP key rotation operations: `ReKey` (KMIP 1.4 §4.4 / KMIP 2.1 §6.1.46),
//! `ReKeyKeyPair` (KMIP 1.4 §4.5 / KMIP 2.1 §6.1.47), `ReCertify` (KMIP 1.4 §4.8 / KMIP 2.1 §6.1.45).
//!
//! Submodules:
//! - [`common`] — Shared helpers for date computation, attribute preparation,
//!   rotation metadata, and privileged-user enforcement.
//! - [`symmetric`] — `ReKey` for symmetric keys (plain, wrapped, wrapping keys).
//! - [`keypair`] — `ReKeyKeyPair` for asymmetric key pairs (RSA, EC, PQC, Covercrypt).

mod common;
mod keypair;
mod symmetric;

pub(crate) use common::{
    RekeyOperation, ReplacementObject, RotationCandidate, compute_rotation_uid,
    enforce_privileged_user, execute_rekey, prepare_replacement_attributes,
    set_rotation_metadata_on_new_key, update_old_key_after_rekey,
};
pub(crate) use keypair::rekey_keypair;
pub(crate) use symmetric::rekey;
