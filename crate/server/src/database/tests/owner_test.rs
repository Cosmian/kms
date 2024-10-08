use std::collections::HashSet;

use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
use cosmian_kmip::{
    crypto::symmetric::create_symmetric_key_kmip_object,
    kmip::kmip_types::{CryptographicAlgorithm, StateEnumeration},
};
use cosmian_kms_client::access::ObjectOperationType;
use uuid::Uuid;

use crate::{
    core::extra_database_params::ExtraDatabaseParams,
    database::{object_with_metadata::ObjectWithMetadata, Database},
    kms_bail,
    result::KResult,
};

pub(crate) async fn owner<DB: Database>(
    db_and_params: &(DB, Option<ExtraDatabaseParams>),
) -> KResult<()> {
    cosmian_logger::log_utils::log_init(None);
    let db = &db_and_params.0;
    let db_params = db_and_params.1.as_ref();

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";
    let user_id_1 = "user_id_1@example.org";
    let user_id_2 = "user_id_2@example.org";
    let invalid_owner = "invalid_owner";
    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    let symmetric_key =
        create_symmetric_key_kmip_object(&symmetric_key_bytes, CryptographicAlgorithm::AES)?;
    let uid = Uuid::new_v4().to_string();

    db.upsert(
        &uid,
        owner,
        &symmetric_key,
        symmetric_key.attributes()?,
        Some(&HashSet::new()),
        StateEnumeration::Active,
        db_params,
    )
    .await?;

    assert!(db.is_object_owned_by(&uid, owner, db_params).await?);

    // Retrieve object with valid owner with `Get` operation type - OK

    let objs_ = db
        .retrieve(&uid, owner, ObjectOperationType::Get, db_params)
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();

    match objs_.len() {
        0 => kms_bail!("There should be an object"),
        1 => {
            assert_eq!(StateEnumeration::Active, objs_[0].state);
            assert!(symmetric_key == objs_[0].object);
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

    db.grant_access(
        &uid,
        user_id_1,
        HashSet::from([ObjectOperationType::Get]),
        db_params,
    )
    .await?;

    // Retrieve object with authorized `user_id_1` with `Create` operation type - ko

    if !db
        .retrieve(&uid, user_id_1, ObjectOperationType::Create, db_params)
        .await?
        .is_empty()
    {
        kms_bail!("It should not be possible to get this object with `Create` request")
    }

    // Retrieve object with authorized `user_id_1` with `Get` operation type - OK
    let objs_ = db
        .retrieve(&uid, user_id_1, ObjectOperationType::Get, db_params)
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();

    match objs_.len() {
        0 => kms_bail!("There should be an object"),
        1 => {
            assert_eq!(StateEnumeration::Active, objs_[0].state);
            assert!(symmetric_key == objs_[0].object);
        }
        _ => kms_bail!("There should be only one object"),
    }

    // Add authorized `userid2` to `read_access` table
    db.grant_access(
        &uid,
        user_id_2,
        HashSet::from([ObjectOperationType::Get]),
        db_params,
    )
    .await?;

    // Try to add same access again - OK
    db.grant_access(
        &uid,
        user_id_2,
        HashSet::from([ObjectOperationType::Get]),
        db_params,
    )
    .await?;

    // We should still be able to find the object by its owner
    let objects = db.find(None, None, owner, true, db_params).await?;
    assert_eq!(objects.len(), 1);
    let (o_uid, o_state, _, _) = &objects[0];
    assert_eq!(o_uid, &uid);
    assert_eq!(o_state, &StateEnumeration::Active);

    // We should not be able to find the object by specifying  that user_id_2 is the owner
    let objects = db.find(None, None, user_id_2, true, db_params).await?;
    assert!(objects.is_empty());

    let objects = db
        .list_user_granted_access_rights(user_id_2, db_params)
        .await?;
    assert_eq!(
        objects[&uid],
        (
            String::from(owner),
            StateEnumeration::Active,
            vec![ObjectOperationType::Get].into_iter().collect(),
        )
    );

    // Retrieve object with authorized `userid2` with `Create` operation type - ko
    if !db
        .retrieve(&uid, user_id_2, ObjectOperationType::Create, db_params)
        .await?
        .is_empty()
    {
        kms_bail!("It should not be possible to get this object with `Create` request")
    }

    // Retrieve object with authorized `userid` with `Get` operation type - OK
    let objs_ = db
        .retrieve(&uid, user_id_2, ObjectOperationType::Get, db_params)
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();

    match objs_.len() {
        0 => kms_bail!("There should be an object"),
        1 => {
            assert_eq!(StateEnumeration::Active, objs_[0].state);
            assert!(symmetric_key == objs_[0].object);
        }
        _ => kms_bail!("There should be only one object"),
    }

    // Be sure we can still retrieve object with authorized `userid` with `Get` operation type - OK
    let objs_ = db
        .retrieve(&uid, user_id_1, ObjectOperationType::Get, db_params)
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();

    match objs_.len() {
        0 => kms_bail!("There should be an object"),
        1 => {
            assert_eq!(StateEnumeration::Active, objs_[0].state);
            assert!(symmetric_key == objs_[0].object);
        }
        _ => kms_bail!("There should be only one object"),
    }

    // Remove `userid2` authorization
    db.remove_access(
        &uid,
        user_id_2,
        HashSet::from([ObjectOperationType::Get]),
        db_params,
    )
    .await?;

    // Retrieve object with `userid2` with `Get` operation type - ko
    if !db
        .retrieve(&uid, user_id_2, ObjectOperationType::Get, db_params)
        .await?
        .is_empty()
    {
        kms_bail!("It should not be possible to get this object with `Get` request")
    }

    Ok(())
}
