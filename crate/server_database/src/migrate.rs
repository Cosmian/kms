use tracing::trace;
use version_compare::{compare, Cmp};

use crate::error::{DbError, DbResult};

pub(crate) fn do_migration(
    last_kms_version_run: &str,
    current_kms_version: &str,
    state: &str,
) -> DbResult<bool> {
    compare(last_kms_version_run, current_kms_version).map_or_else(
        |()| {
            Err(DbError::DatabaseError(
                "Error comparing versions".to_owned(),
            ))
        },
        |cmp| match (cmp, state) {
            (Cmp::Eq | Cmp::Ge | Cmp::Gt, "ready") => {
                trace!("No migration needed");
                Ok(false)
            }
            (Cmp::Eq | Cmp::Ge | Cmp::Gt | Cmp::Ne | Cmp::Lt | Cmp::Le, _) => Ok(true),
        },
    )
}
