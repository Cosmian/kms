use std::collections::{HashMap, HashSet, hash_map::Entry};

use cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::KmipOperation};

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

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::KmipOperation};

    use super::{crl_number_from_sql, crl_number_to_sql, merge_granted_operations};

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
}
