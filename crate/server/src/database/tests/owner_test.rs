use std::collections::HashSet;

use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
use cosmian_kmip::kmip::kmip_types::{CryptographicAlgorithm, StateEnumeration};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, ObjectOperationType},
    crypto::symmetric::create_symmetric_key,
};
use uuid::Uuid;

use super::{get_pgsql, get_sql_cipher, get_sqlite};
use crate::{database::Database, kms_bail, log_utils::log_init, result::KResult};

#[actix_rt::test]
pub async fn test_owner() -> KResult<()> {
    owner(get_sql_cipher().await?).await?;
    owner(get_sqlite().await?).await?;
    owner(get_pgsql().await?).await?;
    Ok(())
}

async fn owner<DB: Database>(db_and_params: (DB, Option<ExtraDatabaseParams>)) -> KResult<()> {
    log_init("debug");
    let db = db_and_params.0;
    let db_params = db_and_params.1.as_ref();

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";
    let userid = "foo@example.org";
    let userid2 = "bar@example.org";
    let invalid_owner = "invalid_owner";
    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    let symmetric_key = create_symmetric_key(&symmetric_key_bytes, CryptographicAlgorithm::AES);
    let uid = Uuid::new_v4().to_string();

    db.upsert(
        &uid,
        owner,
        &symmetric_key,
        &HashSet::new(),
        StateEnumeration::Active,
        db_params,
    )
    .await?;

    assert!(db.is_object_owned_by(&uid, owner, db_params).await?);

    // Retrieve object with valid owner with `Get` operation type - OK

    let objs_ = db
        .retrieve(&uid, owner, ObjectOperationType::Get, db_params)
        .await?;
    match objs_.len() {
        0 => kms_bail!("There should be an object"),
        1 => {
            assert_eq!(StateEnumeration::Active, objs_[0].state);
            assert_eq!(&symmetric_key, &objs_[0].object);
        }
        _ => kms_bail!("There should be only one object"),
    }

    // Retrieve object with invalid owner with `Get` operation type - ko
    if !db
        .retrieve(&uid, invalid_owner, ObjectOperationType::Get, db_params)
        .await?
        .is_empty()
    {
        kms_bail!("It should not be possible to get this object")
    }

    // Add authorized `userid` to `read_access` table

    db.grant_access(&uid, userid, ObjectOperationType::Get, db_params)
        .await?;

    // Retrieve object with authorized `userid` with `Create` operation type - ko

    if !db
        .retrieve(&uid, userid, ObjectOperationType::Create, db_params)
        .await?
        .is_empty()
    {
        kms_bail!("It should not be possible to get this object with `Create` request")
    }

    // Retrieve object with authorized `userid` with `Get` operation type - OK
    let objs_ = db
        .retrieve(&uid, userid, ObjectOperationType::Get, db_params)
        .await?;
    match objs_.len() {
        0 => kms_bail!("There should be an object"),
        1 => {
            assert_eq!(StateEnumeration::Active, objs_[0].state);
            assert_eq!(&symmetric_key, &objs_[0].object);
        }
        _ => kms_bail!("There should be only one object"),
    }

    // Add authorized `userid2` to `read_access` table
    db.grant_access(&uid, userid2, ObjectOperationType::Get, db_params)
        .await?;

    // Try to add same access again - OK
    db.grant_access(&uid, userid2, ObjectOperationType::Get, db_params)
        .await?;

    let objects = db.find(None, None, owner, db_params).await?;
    assert_eq!(objects.len(), 1);
    let (o_uid, o_state, _, _) = &objects[0];
    assert_eq!(o_uid, &uid);
    assert_eq!(o_state, &StateEnumeration::Active);

    let objects = db.find(None, None, userid2, db_params).await?;
    assert!(objects.is_empty());

    let objects = db.list_access_rights_obtained(userid2, db_params).await?;
    assert_eq!(
        objects,
        vec![(
            uid.clone(),
            String::from(owner),
            StateEnumeration::Active,
            vec![ObjectOperationType::Get],
            false
        )]
    );

    // Retrieve object with authorized `userid2` with `Create` operation type - ko
    if !db
        .retrieve(&uid, userid2, ObjectOperationType::Create, db_params)
        .await?
        .is_empty()
    {
        kms_bail!("It should not be possible to get this object with `Create` request")
    }

    // Retrieve object with authorized `userid` with `Get` operation type - OK
    let objs_ = db
        .retrieve(&uid, userid2, ObjectOperationType::Get, db_params)
        .await?;
    match objs_.len() {
        0 => kms_bail!("There should be an object"),
        1 => {
            assert_eq!(StateEnumeration::Active, objs_[0].state);
            assert_eq!(&symmetric_key, &objs_[0].object);
        }
        _ => kms_bail!("There should be only one object"),
    }

    // Be sure we can still retrieve object with authorized `userid` with `Get` operation type - OK
    let objs_ = db
        .retrieve(&uid, userid, ObjectOperationType::Get, db_params)
        .await?;
    match objs_.len() {
        0 => kms_bail!("There should be an object"),
        1 => {
            assert_eq!(StateEnumeration::Active, objs_[0].state);
            assert_eq!(&symmetric_key, &objs_[0].object);
        }
        _ => kms_bail!("There should be only one object"),
    }

    // Remove `userid2` authorization
    db.remove_access(&uid, userid2, ObjectOperationType::Get, db_params)
        .await?;

    // Retrieve object with `userid2` with `Get` operation type - ko
    if !db
        .retrieve(&uid, userid2, ObjectOperationType::Get, db_params)
        .await?
        .is_empty()
    {
        kms_bail!("It should not be possible to get this object with `Get` request")
    }

    Ok(())
}
