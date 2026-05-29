//! KMIP key rotation operations: `ReKey` (§4.4), `ReKeyKeyPair` (§4.5).
//!
//! Submodules:
//! - [`common`] — Shared helpers for date arithmetic, attribute preparation,
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
