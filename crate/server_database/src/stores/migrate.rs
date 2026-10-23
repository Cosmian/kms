use async_trait::async_trait;
use cosmian_kmip::kmip_2_1::{
    extra::tagging::SYSTEM_TAG_CERTIFICATE_SERIAL_PREFIX, kmip_objects::Object,
};
use serde::{Deserialize, Serialize};

use crate::{core::extract_serial_hex_from_object, error::DbResult};

/// Name of the `parameters` row that records whether the one-time
/// `wrapping_key_id` backfill has completed for this database.
///
/// The backfill scans and deserializes every object whose `wrapping_key_id`
/// column is `NULL`. Without this marker the scan would re-run on every server
/// startup (unwrapped objects legitimately keep a `NULL` value forever), so the
/// marker gates it to run at most once per database.
pub(crate) const WRAPPING_KEY_BACKFILL_PARAM: &str = "wrapping_key_id_backfilled";

/// Name of the `parameters` row that records whether the one-time `_serial=<HEX>` tag
/// backfill for certificates stored before that tag existed has completed.
pub(crate) const CERTIFICATE_SERIAL_TAG_BACKFILL_PARAM: &str = "certificate_serial_tag_backfilled";

/// `_serial=<HEX>` tag for a certificate object (same value as `set_certificate_serial_tag`),
/// `None` for any other object or an unparsable certificate.
pub(crate) fn certificate_serial_tag(object: &Object) -> Option<String> {
    extract_serial_hex_from_object(object)
        .map(|hex| format!("{SYSTEM_TAG_CERTIFICATE_SERIAL_PREFIX}{hex}"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The state of the database
pub(crate) enum DbState {
    Ready,
    Upgrading,
}

/// Base trait for database migration functionality
#[async_trait(?Send)]
pub(crate) trait Migrate {
    /// Set the state of the database ("ready" or "upgrading").
    async fn set_db_state(&self, state: DbState) -> DbResult<()>;

    /// Set the current version of the database.
    /// Recorded when a database is first initialized so that later startups can recognize it.
    async fn set_current_db_version(&self, version: &str) -> DbResult<()>;
}

#[cfg(test)]
mod tests {
    use super::DbState;

    /// The serialized form is persisted in the database `parameters` table / Redis;
    /// it must stay stable (`"ready"`, `"upgrading"`) across versions.
    #[test]
    fn test_db_state_serialization_is_stable() {
        assert_eq!(
            serde_json::to_string(&DbState::Ready).ok().as_deref(),
            Some("\"ready\"")
        );
        assert_eq!(
            serde_json::to_string(&DbState::Upgrading).ok().as_deref(),
            Some("\"upgrading\"")
        );
        assert_eq!(
            serde_json::from_str::<DbState>("\"upgrading\"").ok(),
            Some(DbState::Upgrading)
        );
        assert_eq!(serde_json::from_str::<DbState>("\"bogus\"").ok(), None);
    }
}
