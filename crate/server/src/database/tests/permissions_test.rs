use std::collections::HashSet;

use cosmian_kms_client::access::ObjectOperationType;
use uuid::Uuid;

use crate::{
    core::extra_database_params::ExtraDatabaseParams, database::Database, result::KResult,
};

pub(crate) async fn permissions<DB: Database>(
    db_and_params: &(DB, Option<ExtraDatabaseParams>),
) -> KResult<()> {
    cosmian_logger::log_utils::log_init(None);
    permissions_users(db_and_params).await?;
    permissions_wildcard(db_and_params).await?;
    Ok(())
}

async fn permissions_users<DB: Database>(
    db_and_params: &(DB, Option<ExtraDatabaseParams>),
) -> KResult<()> {
    cosmian_logger::log_utils::log_init(None);
    let db = &db_and_params.0;
    let db_params = db_and_params.1.as_ref();

    let user_id_1 = Uuid::new_v4().to_string();
    let user_id_2 = Uuid::new_v4().to_string();
    let uid = Uuid::new_v4().to_string();

    // simple insert
    db.grant_access(
        &uid,
        &user_id_1,
        HashSet::from([ObjectOperationType::Get]),
        db_params,
    )
    .await?;

    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id_1, false, db_params)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&ObjectOperationType::Get));

    // double insert, expect no duplicate
    db.grant_access(
        &uid,
        &user_id_1,
        HashSet::from([ObjectOperationType::Get]),
        db_params,
    )
    .await?;

    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id_1, false, db_params)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&ObjectOperationType::Get));

    // insert other operation type
    db.grant_access(
        &uid,
        &user_id_1,
        HashSet::from([ObjectOperationType::Encrypt]),
        db_params,
    )
    .await?;

    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id_1, false, db_params)
        .await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&ObjectOperationType::Encrypt));
    assert!(perms.contains(&ObjectOperationType::Get));

    // insert other `userid2`, check it is ok and it didn't change anything for `userid`
    db.grant_access(
        &uid,
        &user_id_2,
        HashSet::from([ObjectOperationType::Get]),
        db_params,
    )
    .await?;

    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id_2, false, db_params)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&ObjectOperationType::Get));

    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id_1, false, db_params)
        .await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&ObjectOperationType::Encrypt));
    assert!(perms.contains(&ObjectOperationType::Get));

    let accesses = db.list_object_accesses_granted(&uid, db_params).await?;

    assert_eq!(accesses.len(), 2);
    assert!(accesses.contains_key(&user_id_1));
    assert!(accesses.contains_key(&user_id_2));
    assert_eq!(accesses[&user_id_1].len(), 2);
    assert!(accesses[&user_id_1].contains(&ObjectOperationType::Encrypt));
    assert!(accesses[&user_id_1].contains(&ObjectOperationType::Get));
    assert_eq!(accesses[&user_id_2].len(), 1);
    assert!(accesses[&user_id_2].contains(&ObjectOperationType::Get));

    // remove `Get` access for `userid`
    db.remove_access(
        &uid,
        &user_id_1,
        HashSet::from([ObjectOperationType::Get]),
        db_params,
    )
    .await?;

    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id_2, false, db_params)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&ObjectOperationType::Get));

    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id_1, false, db_params)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&ObjectOperationType::Encrypt));

    Ok(())
}

async fn permissions_wildcard<DB: Database>(
    db_and_params: &(DB, Option<ExtraDatabaseParams>),
) -> KResult<()> {
    let db = &db_and_params.0;
    let db_params = db_and_params.1.as_ref();

    let user_id = Uuid::new_v4().to_string();
    let uid = Uuid::new_v4().to_string();

    // simple insert
    db.grant_access(
        &uid,
        &user_id,
        HashSet::from([ObjectOperationType::Get]),
        db_params,
    )
    .await?;

    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id, false, db_params)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&ObjectOperationType::Get));

    // insert other operation type using wildcard user
    db.grant_access(
        &uid,
        "*",
        HashSet::from([ObjectOperationType::Encrypt]),
        db_params,
    )
    .await?;

    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id, false, db_params)
        .await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&ObjectOperationType::Encrypt));
    assert!(perms.contains(&ObjectOperationType::Get));

    // direct permissions however should not have changed
    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id, true, db_params)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&ObjectOperationType::Get));

    // permissions of the wildcard user should be encrypt
    let perms = db
        .list_user_access_rights_on_object(&uid, "*", false, db_params)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&ObjectOperationType::Encrypt));

    // double insert, expect no duplicate
    db.grant_access(
        &uid,
        "*",
        HashSet::from([ObjectOperationType::Encrypt]),
        db_params,
    )
    .await?;

    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id, false, db_params)
        .await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&ObjectOperationType::Encrypt));
    assert!(perms.contains(&ObjectOperationType::Get));

    // grant access to Get via the wildcard user - expect no duplicates
    db.grant_access(
        &uid,
        "*",
        HashSet::from([ObjectOperationType::Get]),
        db_params,
    )
    .await?;

    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id, false, db_params)
        .await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&ObjectOperationType::Encrypt));
    assert!(perms.contains(&ObjectOperationType::Get));

    // Remove Get access to user: it should still have access via the wildcard user
    db.remove_access(
        &uid,
        &user_id,
        HashSet::from([ObjectOperationType::Get]),
        db_params,
    )
    .await?;

    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id, false, db_params)
        .await?;
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&ObjectOperationType::Encrypt));
    assert!(perms.contains(&ObjectOperationType::Get));

    // remove Encrypt access for the  wildcard user: user1 should only be left with Get access
    db.remove_access(
        &uid,
        "*",
        HashSet::from([ObjectOperationType::Encrypt]),
        db_params,
    )
    .await?;

    // remove Get from user 3
    db.remove_access(
        &uid,
        &user_id,
        HashSet::from([ObjectOperationType::Get]),
        db_params,
    )
    .await?;

    // permissions of the wildcard user should be Get
    let perms = db
        .list_user_access_rights_on_object(&uid, "*", false, db_params)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&ObjectOperationType::Get));

    // direct permissions of the user should be none
    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id, true, db_params)
        .await?;
    assert!(perms.is_empty());

    // permissions of the user should also be Get
    let perms = db
        .list_user_access_rights_on_object(&uid, &user_id, false, db_params)
        .await?;
    assert_eq!(perms.len(), 1);
    assert!(perms.contains(&ObjectOperationType::Get));

    Ok(())
}
