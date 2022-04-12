pub(crate) mod abe;
pub(crate) mod implementation;
pub mod kmip_server;

use super::database::Database;

/// A Simple Key Management System that partially implements KMIP 2.1:
/// https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip
pub struct KMS {
    db: Box<dyn Database + Sync + Send>,
}
