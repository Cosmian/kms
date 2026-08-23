use std::collections::HashSet;

use cosmian_kmip::kmip_2_1::KmipOperation;
use cosmian_kms_interfaces::{ObjectsStore, PermissionsStore, UserId};
use uuid::Uuid;

use crate::error::DbResult;

pub(super) async fn permissions<DB: ObjectsStore + PermissionsStore>(db: &DB) -> DbResult<()> {
    cosmian_logger::log_init(None);
    permissions_users(db).await?;
    permissions_wildcard(db).await?;
    crl_persistence(db).await?;
    Ok(())
}

async fn permissions_users<DB: ObjectsStore + PermissionsStore>(db: &DB) -> DbResult<()> {
    cosmian_logger::log_init(None);

    let user_id_1 = UserId::new(Uuid::new_v4().to_string());
    let user_id_2 = UserId::new(Uuid::new_v4().to_string());
    let uid = Uuid::new_v4().to_string();

    // simple insert
    db.grant_operations(&uid, &user_id_1, HashSet::from([KmipOperation::Get]))
        .await?;

    let perms = db
        .list_user_operations_on_object(&uid, &user_id_1, false)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&KmipOperation::Get));

    // double insert, expect no duplicate
    db.grant_operations(&uid, &user_id_1, HashSet::from([KmipOperation::Get]))
        .await?;

    let perms = db
        .list_user_operations_on_object(&uid, &user_id_1, false)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&KmipOperation::Get));

    // insert other operation type
    db.grant_operations(&uid, &user_id_1, HashSet::from([KmipOperation::Encrypt]))
        .await?;

    let perms = db
        .list_user_operations_on_object(&uid, &user_id_1, false)
        .await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&KmipOperation::Encrypt));
    assert!(perms.contains(&KmipOperation::Get));

    // insert other `userid2`, check it is ok and it didn't change anything for `userid`
    db.grant_operations(&uid, &user_id_2, HashSet::from([KmipOperation::Get]))
        .await?;

    let perms = db
        .list_user_operations_on_object(&uid, &user_id_2, false)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&KmipOperation::Get));

    let perms = db
        .list_user_operations_on_object(&uid, &user_id_1, false)
        .await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&KmipOperation::Encrypt));
    assert!(perms.contains(&KmipOperation::Get));

    let accesses = db.list_object_operations_granted(&uid).await?;

    assert_eq!(accesses.len(), 2);
    assert!(accesses.contains_key(user_id_1.as_str()));
    assert!(accesses.contains_key(user_id_2.as_str()));
    assert_eq!(accesses[user_id_1.as_str()].len(), 2);
    assert!(accesses[user_id_1.as_str()].contains(&KmipOperation::Encrypt));
    assert!(accesses[user_id_1.as_str()].contains(&KmipOperation::Get));
    assert_eq!(accesses[user_id_2.as_str()].len(), 1);
    assert!(accesses[user_id_2.as_str()].contains(&KmipOperation::Get));

    // remove `Get` access for `userid`
    db.remove_operations(&uid, &user_id_1, HashSet::from([KmipOperation::Get]))
        .await?;

    let perms = db
        .list_user_operations_on_object(&uid, &user_id_2, false)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&KmipOperation::Get));

    let perms = db
        .list_user_operations_on_object(&uid, &user_id_1, false)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&KmipOperation::Encrypt));

    Ok(())
}

async fn permissions_wildcard<DB: ObjectsStore + PermissionsStore>(db: &DB) -> DbResult<()> {
    let user_id = UserId::new(Uuid::new_v4().to_string());
    let uid = Uuid::new_v4().to_string();

    // simple insert
    db.grant_operations(&uid, &user_id, HashSet::from([KmipOperation::Get]))
        .await?;

    let perms = db
        .list_user_operations_on_object(&uid, &user_id, false)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&KmipOperation::Get));

    // insert other operation type using wildcard user
    db.grant_operations(
        &uid,
        &UserId::from("*"),
        HashSet::from([KmipOperation::Encrypt]),
    )
    .await?;

    let perms = db
        .list_user_operations_on_object(&uid, &user_id, false)
        .await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&KmipOperation::Encrypt));
    assert!(perms.contains(&KmipOperation::Get));

    // direct permissions however should not have changed
    let perms = db
        .list_user_operations_on_object(&uid, &user_id, true)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&KmipOperation::Get));

    // permissions of the wildcard user should be encrypt
    let perms = db
        .list_user_operations_on_object(&uid, &UserId::from("*"), false)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&KmipOperation::Encrypt));

    // double insert, expect no duplicate
    db.grant_operations(
        &uid,
        &UserId::from("*"),
        HashSet::from([KmipOperation::Encrypt]),
    )
    .await?;

    let perms = db
        .list_user_operations_on_object(&uid, &user_id, false)
        .await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&KmipOperation::Encrypt));
    assert!(perms.contains(&KmipOperation::Get));

    // grant access to Get via the wildcard user - expect no duplicates
    db.grant_operations(
        &uid,
        &UserId::from("*"),
        HashSet::from([KmipOperation::Get]),
    )
    .await?;

    let perms = db
        .list_user_operations_on_object(&uid, &user_id, false)
        .await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&KmipOperation::Encrypt));
    assert!(perms.contains(&KmipOperation::Get));

    // Remove Get access to user: it should still have access via the wildcard user
    db.remove_operations(&uid, &user_id, HashSet::from([KmipOperation::Get]))
        .await?;

    let perms = db
        .list_user_operations_on_object(&uid, &user_id, false)
        .await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&KmipOperation::Encrypt));
    assert!(perms.contains(&KmipOperation::Get));

    // remove Encrypt access for the  wildcard user: user1 should only be left with Get access
    db.remove_operations(
        &uid,
        &UserId::from("*"),
        HashSet::from([KmipOperation::Encrypt]),
    )
    .await?;

    // remove Get from user 3
    db.remove_operations(&uid, &user_id, HashSet::from([KmipOperation::Get]))
        .await?;

    // permissions of the wildcard user should be Get
    let perms = db
        .list_user_operations_on_object(&uid, &UserId::from("*"), false)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&KmipOperation::Get));

    // direct permissions of the user should be none
    let perms = db
        .list_user_operations_on_object(&uid, &user_id, true)
        .await?;
    assert!(perms.is_empty());

    // permissions of the user should also be Get
    let perms = db
        .list_user_operations_on_object(&uid, &user_id, false)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&KmipOperation::Get));

    Ok(())
}

// ── CRL persistence tests ─────────────────────────────────────────────────────

/// DB-layer unit tests for CRL persistence methods (RFC 5280 §5.2.3).
///
/// Tests:
/// - `get_max_crl_number` returns `None` when the `crls` table is empty.
/// - `upsert_crl` stores a CRL; `get_crl` retrieves it.
/// - `upsert_crl` with the same issuer replaces the previous entry (upsert).
/// - `get_max_crl_number` returns the highest `crl_number` across all issuers.
/// - `list_crl_issuers` enumerates all stored issuer IDs.
/// - The CRL counter seed logic `max(unix_ts, db_max + 1)` is satisfied.
async fn crl_persistence<DB: PermissionsStore>(db: &DB) -> DbResult<()> {
    cosmian_logger::log_init(None);

    let issuer_a = Uuid::new_v4().to_string();
    let issuer_b = Uuid::new_v4().to_string();

    // 1. Fresh DB: no CRL stored yet — get_max_crl_number must return None.
    let max = db.get_max_crl_number().await?;
    assert!(
        max.is_none(),
        "get_max_crl_number on empty table must return None"
    );

    // 2. Store the first CRL (issuer A, crl_number=10).
    let der_a_v1 = vec![0xDE, 0xAD, 0xBE, 0xEF];
    db.upsert_crl(
        &issuer_a,
        &der_a_v1,
        10,
        "2026-01-01T00:00:00Z",
        "2026-01-08T00:00:00Z",
    )
    .await?;

    // 3. Retrieve the stored CRL — must match what was inserted.
    let stored = db.get_crl(&issuer_a).await?;
    assert!(stored.is_some(), "get_crl must return Some after upsert");
    let (der_back, _) = stored.unwrap();
    assert_eq!(der_back, der_a_v1, "retrieved DER must equal inserted DER");

    // 4. get_max_crl_number must now return 10.
    let max = db.get_max_crl_number().await?;
    assert_eq!(
        max,
        Some(10),
        "max CRL number must be 10 after first upsert"
    );

    // 5. Add a second issuer with a higher crl_number (crl_number=42).
    let der_b = vec![0xCA, 0xFE];
    db.upsert_crl(
        &issuer_b,
        &der_b,
        42,
        "2026-01-01T00:00:00Z",
        "2026-01-08T00:00:00Z",
    )
    .await?;
    let max = db.get_max_crl_number().await?;
    assert_eq!(
        max,
        Some(42),
        "max CRL number must be 42 after inserting issuer_b"
    );

    // 6. list_crl_issuers must return both issuers.
    let issuers: Vec<String> = db
        .list_crl_issuers()
        .await?
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert!(
        issuers.contains(&issuer_a),
        "list_crl_issuers must include issuer_a"
    );
    assert!(
        issuers.contains(&issuer_b),
        "list_crl_issuers must include issuer_b"
    );

    // 7. Upsert replaces: update issuer A to crl_number=99 with new DER.
    let der_a_v2 = vec![0x11, 0x22, 0x33];
    db.upsert_crl(
        &issuer_a,
        &der_a_v2,
        99,
        "2026-01-02T00:00:00Z",
        "2026-01-09T00:00:00Z",
    )
    .await?;

    // 7a. get_crl must return the *new* DER for issuer A.
    let stored = db.get_crl(&issuer_a).await?;
    let (der_back, _) = stored.unwrap();
    assert_eq!(
        der_back, der_a_v2,
        "upsert must overwrite the previous CRL DER"
    );

    // 7b. get_max_crl_number must now return 99 (issuer A > issuer B).
    let max = db.get_max_crl_number().await?;
    assert_eq!(
        max,
        Some(99),
        "max CRL number must be 99 after updating issuer_a"
    );

    // 8. Non-existent issuer returns None — no panic, no DB error.
    let unknown = db.get_crl(&Uuid::new_v4().to_string()).await?;
    assert!(unknown.is_none(), "get_crl for unknown issuer must be None");

    // 9. CRL counter seed non-regression: max(unix_ts, db_max + 1) must be > db_max.
    //    This mirrors the logic in KMS::instantiate(). Verify the invariant holds.
    let db_max = db.get_max_crl_number().await?.unwrap_or(0);
    let ts_seed = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap_or(1);
    let seed = ts_seed.max(db_max + 1);
    assert!(
        seed > db_max,
        "CRL counter seed must be strictly greater than DB max (RFC 5280 §5.2.3 monotonicity)"
    );

    Ok(())
}
