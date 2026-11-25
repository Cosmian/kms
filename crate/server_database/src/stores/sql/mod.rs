use std::collections::{HashMap, HashSet, hash_map::Entry};

use cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::KmipOperation};
use cosmian_kms_interfaces::KeyInventoryBucket;
use cosmian_logger::debug;
use time::OffsetDateTime;

pub(crate) mod locate_query;
mod mysql;
pub(crate) use mysql::MySqlPool;
mod pgsql;
pub(crate) use pgsql::{
    PG_MAX_RETRIES, PgPool, is_pg_retryable_error, pg_retry_backoff_ms,
    pg_url_verifies_server_cert, prepare_pg_connection,
};
mod sqlite;
pub(crate) use sqlite::SqlitePool;

mod database;

/// Add one `(id, owner, state, operations)` row to the per-object map of
/// granted operations.
///
/// The same object may be returned twice: once for the direct grant and once
/// for the wildcard `*` grant. The permission sets are united instead of
/// overwriting the entry; the first row's owner and state are kept.
fn merge_granted_operations(
    map: &mut HashMap<String, (String, State, HashSet<KmipOperation>)>,
    id: String,
    owner: String,
    state: State,
    operations: HashSet<KmipOperation>,
) {
    match map.entry(id) {
        Entry::Occupied(mut entry) => entry.get_mut().2.extend(operations),
        Entry::Vacant(entry) => {
            entry.insert((owner, state, operations));
        }
    }
}

/// Convert a CRL number to the signed SQL `BIGINT`/`INTEGER` column value,
/// saturating at `i64::MAX`.
fn crl_number_to_sql(crl_number: u64) -> i64 {
    i64::try_from(crl_number).unwrap_or(i64::MAX)
}

/// Convert a stored SQL `crl_number` back to a CRL number; a negative value
/// maps to `0`.
fn crl_number_from_sql(stored: i64) -> u64 {
    u64::try_from(stored).unwrap_or(0)
}

/// Build a key-inventory entry from one row of the `key-inventory` query.
///
/// The row's object type is never NULL (the query filters on it); `count` is
/// clamped to 0 should a backend ever return a negative value.
fn key_inventory_row(
    object_type: String,
    algorithm: Option<String>,
    key_length: Option<i64>,
    state: Option<String>,
    count: i64,
) -> (KeyInventoryBucket, u64) {
    (
        KeyInventoryBucket {
            object_type,
            algorithm,
            key_length: key_length.and_then(|l| i32::try_from(l).ok()),
            state,
        },
        u64::try_from(count).unwrap_or(0),
    )
}

/// Parse the raw JSON value of a stored `DeactivationDate` attribute.
///
/// Older rows store dates as a `[year, ordinal, h, m, s, ns, oh, om, os]` array,
/// newer ones as a human-readable string: both go through the `time` serde
/// implementation. Unparsable values are logged and skipped so a single bad row
/// cannot blank the whole metric.
fn parse_deactivation_dates(raw: impl IntoIterator<Item = String>) -> Vec<OffsetDateTime> {
    raw.into_iter()
        .filter_map(|json| match serde_json::from_str::<OffsetDateTime>(&json) {
            Ok(date) => Some(date),
            Err(e) => {
                debug!("[metrics] skipping unparsable DeactivationDate {json}: {e}");
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::KmipOperation};
    use time::macros::datetime;

    use super::{
        crl_number_from_sql, crl_number_to_sql, key_inventory_row, merge_granted_operations,
        parse_deactivation_dates,
    };

    #[test]
    fn merge_granted_operations_unions_direct_and_wildcard_rows() {
        let mut map = HashMap::new();
        merge_granted_operations(
            &mut map,
            "id".to_owned(),
            "alice".to_owned(),
            State::Active,
            HashSet::from([KmipOperation::Get]),
        );
        merge_granted_operations(
            &mut map,
            "id".to_owned(),
            "bob".to_owned(),
            State::PreActive,
            HashSet::from([KmipOperation::Encrypt]),
        );
        assert_eq!(
            map.get("id"),
            Some(&(
                "alice".to_owned(),
                State::Active,
                HashSet::from([KmipOperation::Get, KmipOperation::Encrypt])
            ))
        );
    }

    #[test]
    fn crl_number_sql_conversions_clamp() {
        assert_eq!(crl_number_to_sql(42), 42);
        assert_eq!(crl_number_to_sql(u64::MAX), i64::MAX);
        assert_eq!(crl_number_from_sql(42), 42);
        assert_eq!(crl_number_from_sql(-1), 0);
    }

    #[test]
    fn parse_deactivation_dates_accepts_both_stored_formats_and_skips_garbage() {
        let dates = parse_deactivation_dates([
            r#""2026-10-02 20:10:46.0 +00:00:00""#.to_owned(),
            "[2026,148,14,16,26,0,0,0,0]".to_owned(),
            "\"not a date\"".to_owned(),
        ]);
        assert_eq!(
            dates,
            vec![
                datetime!(2026-10-02 20:10:46 UTC),
                datetime!(2026-05-28 14:16:26 UTC),
            ]
        );
    }

    #[test]
    fn key_inventory_row_clamps_out_of_range_values() {
        let (bucket, count) = key_inventory_row(
            "SymmetricKey".to_owned(),
            Some("AES".to_owned()),
            Some(i64::MAX),
            Some("Active".to_owned()),
            -3,
        );
        assert_eq!(bucket.key_length, None);
        assert_eq!(count, 0);
    }
}
