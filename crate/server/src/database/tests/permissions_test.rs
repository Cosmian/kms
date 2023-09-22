use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use cosmian_logger::log_utils::log_init;
use uuid::Uuid;

use crate::{database::Database, result::KResult};

pub async fn permissions<DB: Database>(
    db_and_params: &(DB, Option<ExtraDatabaseParams>),
) -> KResult<()> {
    log_init("debug");
    let db = &db_and_params.0;
    let db_params = db_and_params.1.as_ref();

    let user_id_1 = "user_id_1@example.org";
    let user_id_2 = "user_id_2@example.org";
    let uid = Uuid::new_v4().to_string();

    // simple insert
    db.grant_access(&uid, user_id_1, ObjectOperationType::Get, db_params)
        .await?;

    let perms = db.perms(&uid, user_id_1, db_params).await?;
    assert_eq!(perms, vec![ObjectOperationType::Get]);

    // double insert, expect no duplicate
    db.grant_access(&uid, user_id_1, ObjectOperationType::Get, db_params)
        .await?;

    let perms = db.perms(&uid, user_id_1, db_params).await?;
    assert_eq!(perms, vec![ObjectOperationType::Get]);

    // insert other operation type
    db.grant_access(&uid, user_id_1, ObjectOperationType::Encrypt, db_params)
        .await?;

    let perms = db.perms(&uid, user_id_1, db_params).await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&ObjectOperationType::Encrypt));
    assert!(perms.contains(&ObjectOperationType::Get));

    // insert other `userid2`, check it is ok and it didn't change anything for `userid`
    db.grant_access(&uid, user_id_2, ObjectOperationType::Get, db_params)
        .await?;

    let perms = db.perms(&uid, user_id_2, db_params).await?;
    assert_eq!(perms, vec![ObjectOperationType::Get]);

    let perms = db.perms(&uid, user_id_1, db_params).await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&ObjectOperationType::Encrypt));
    assert!(perms.contains(&ObjectOperationType::Get));

    let accesses = db.list_accesses(&uid, db_params).await?;

    assert_eq!(accesses.len(), 2);
    assert!(accesses.contains_key(user_id_1));
    assert!(accesses.contains_key(user_id_2));
    assert_eq!(accesses[user_id_1].len(), 2);
    assert!(accesses[user_id_1].contains(&ObjectOperationType::Encrypt));
    assert!(accesses[user_id_1].contains(&ObjectOperationType::Get));
    assert_eq!(accesses[user_id_2].len(), 1);
    assert!(accesses[user_id_2].contains(&ObjectOperationType::Get));

    // remove `Get` access for `userid`
    db.remove_access(&uid, user_id_1, ObjectOperationType::Get, db_params)
        .await?;

    let perms = db.perms(&uid, user_id_2, db_params).await?;
    assert_eq!(perms, vec![ObjectOperationType::Get]);

    let perms = db.perms(&uid, user_id_1, db_params).await?;
    assert_eq!(perms, vec![ObjectOperationType::Encrypt]);

    Ok(())
}
