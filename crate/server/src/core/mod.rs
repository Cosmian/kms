pub(crate) mod certbot;
pub(crate) mod cover_crypt;
pub mod crud;
pub(crate) mod implementation;

use std::sync::{Arc, Mutex};

use cosmian_crypto_core::CsRng;

use crate::database::Database;

#[allow(clippy::upper_case_acronyms)]

/// A Simple Key Management System that partially implements KMIP 2.1:
/// https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip
pub struct KMS {
    rng: Arc<Mutex<CsRng>>,
    db: Box<dyn Database + Sync + Send>,
}
