use tracing::trace;
use version_compare::{compare, Cmp};

use crate::{error::KmsError, result::KResult};

pub(crate) fn do_migration(
    last_kms_version_run: &str,
    current_kms_version: &str,
    state: &str,
) -> KResult<bool> {
    if let Ok(cmp) = compare(last_kms_version_run, current_kms_version) {
        match (cmp, state) {
            (Cmp::Eq | Cmp::Ge | Cmp::Gt, "ready") => {
                trace!("No migration needed");
                Ok(false)
            }
            (Cmp::Eq | Cmp::Ge | Cmp::Gt | Cmp::Ne | Cmp::Lt | Cmp::Le, _) => Ok(true),
        }
    } else {
        Err(KmsError::DatabaseError(
            "Error comparing versions".to_owned(),
        ))
    }
}
