use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use uuid::Uuid;

use super::{get_sql_cipher, get_sqlite};
use crate::{database::Database, log_utils::log_init, result::KResult};

#[actix_rt::test]
pub async fn test_permissions() -> KResult<()> {
    permissions(get_sql_cipher().await?).await?;
    permissions(get_sqlite().await?).await?;
    Ok(())
}

async fn permissions<DB: Database>(
    db_and_params: (DB, Option<ExtraDatabaseParams>),
) -> KResult<()> {
    log_init("debug");
    let db = db_and_params.0;
    let db_params = db_and_params.1.as_ref();

    let userid = "foo@example.org";
    let userid2 = "bar@example.org";
    let uid = Uuid::new_v4().to_string();

    // simple insert
    db.grant_access(&uid, userid, ObjectOperationType::Get, db_params)
        .await?;

    let perms = db.perms(&uid, userid, db_params).await?;
    assert_eq!(perms, vec![ObjectOperationType::Get]);

    // double insert, expect no duplicate
    db.grant_access(&uid, userid, ObjectOperationType::Get, db_params)
        .await?;

    let perms = db.perms(&uid, userid, db_params).await?;
    assert_eq!(perms, vec![ObjectOperationType::Get]);

    // insert other operation type
    db.grant_access(&uid, userid, ObjectOperationType::Encrypt, db_params)
        .await?;

    let perms = db.perms(&uid, userid, db_params).await?;
    assert_eq!(
        perms,
        vec![ObjectOperationType::Get, ObjectOperationType::Encrypt]
    );

    // insert other `userid2`, check it is ok and it didn't change anything for `userid`
    db.grant_access(&uid, userid2, ObjectOperationType::Get, db_params)
        .await?;

    let perms = db.perms(&uid, userid2, db_params).await?;
    assert_eq!(perms, vec![ObjectOperationType::Get]);

    let perms = db.perms(&uid, userid, db_params).await?;
    assert_eq!(
        perms,
        vec![ObjectOperationType::Get, ObjectOperationType::Encrypt]
    );

    let accesses = db.list_accesses(&uid, db_params).await?;
    assert_eq!(
        accesses,
        vec![
            (
                String::from("bar@example.org"),
                vec![ObjectOperationType::Get]
            ),
            (
                String::from("foo@example.org"),
                vec![ObjectOperationType::Get, ObjectOperationType::Encrypt]
            )
        ]
    );

    // remove `Get` access for `userid`
    db.remove_access(&uid, userid, ObjectOperationType::Get, db_params)
        .await?;

    let perms = db.perms(&uid, userid2, db_params).await?;
    assert_eq!(perms, vec![ObjectOperationType::Get]);

    let perms = db.perms(&uid, userid, db_params).await?;
    assert_eq!(perms, vec![ObjectOperationType::Encrypt]);

    Ok(())
}
