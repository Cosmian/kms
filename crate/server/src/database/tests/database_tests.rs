use std::collections::HashSet;

use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
use cosmian_kmip::{
    crypto::symmetric::create_symmetric_key_kmip_object,
    kmip::kmip_types::{
        CryptographicAlgorithm, Link, LinkType, LinkedObjectIdentifier, StateEnumeration,
    },
};
use cosmian_kms_client::access::ObjectOperationType;
use cosmian_logger::log_utils::log_init;
use uuid::Uuid;

use crate::{
    core::extra_database_params::ExtraDatabaseParams,
    database::{
        database_trait::AtomicOperation, object_with_metadata::ObjectWithMetadata, Database,
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub(crate) async fn tx_and_list<DB: Database>(
    db_and_params: &(DB, Option<ExtraDatabaseParams>),
) -> KResult<()> {
    log_init(None);
    let db = &db_and_params.0;
    let db_params = db_and_params.1.as_ref();

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";

    // Create key
    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let symmetric_key_1 =
        create_symmetric_key_kmip_object(symmetric_key.as_slice(), CryptographicAlgorithm::AES)?;

    let uid_1 = Uuid::new_v4().to_string();

    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let symmetric_key_2 =
        create_symmetric_key_kmip_object(symmetric_key.as_slice(), CryptographicAlgorithm::AES)?;

    let uid_2 = Uuid::new_v4().to_string();

    let operations = vec![
        AtomicOperation::Create((
            uid_1.clone(),
            symmetric_key_1.clone(),
            symmetric_key_1.attributes()?.clone(),
            HashSet::new(),
        )),
        AtomicOperation::Create((
            uid_2.clone(),
            symmetric_key_2.clone(),
            symmetric_key_2.attributes()?.clone(),
            HashSet::new(),
        )),
    ];
    db.atomic(owner, &operations, db_params).await?;

    let list = db.find(None, None, owner, true, db_params).await?;
    match list
        .iter()
        .find(|(id, _state, _attrs, _is_wrapped)| id == &uid_1)
    {
        Some((uid_, state_, _attrs, is_wrapped)) => {
            assert_eq!(&uid_1, uid_);
            assert_eq!(&StateEnumeration::Active, state_);
            assert!(!*is_wrapped);
        }
        None => kms_bail!("The object 1, uid_1 should be in the list"),
    }
    match list
        .iter()
        .find(|(id, _state, _attrs, _is_wrapped)| id == &uid_2)
    {
        Some((uid_, state_, _attrs, is_wrapped)) => {
            assert_eq!(&uid_2, uid_);
            assert_eq!(&StateEnumeration::Active, state_);
            assert!(!*is_wrapped);
        }
        None => kms_bail!("The object 2, uid_2 should be in the list"),
    }

    db.delete(&uid_1, owner, db_params).await?;
    db.delete(&uid_2, owner, db_params).await?;

    if !db
        .retrieve(&uid_1, owner, ObjectOperationType::Get, db_params)
        .await?
        .is_empty()
    {
        kms_bail!("The object 1 should have been deleted");
    }
    if !db
        .retrieve(&uid_2, owner, ObjectOperationType::Get, db_params)
        .await?
        .is_empty()
    {
        kms_bail!("The object 2 should have been deleted");
    }

    Ok(())
}

pub(crate) async fn atomic<DB: Database>(
    db_and_params: &(DB, Option<ExtraDatabaseParams>),
) -> KResult<()> {
    log_init(None);
    let db = &db_and_params.0;
    let db_params = db_and_params.1.as_ref();

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";

    // Create key

    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let symmetric_key_1 =
        create_symmetric_key_kmip_object(symmetric_key.as_slice(), CryptographicAlgorithm::AES)?;

    let uid_1 = Uuid::new_v4().to_string();

    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let symmetric_key_2 =
        create_symmetric_key_kmip_object(symmetric_key.as_slice(), CryptographicAlgorithm::AES)?;

    let uid_2 = Uuid::new_v4().to_string();

    db.atomic(
        owner,
        &[
            AtomicOperation::Create((
                uid_1.clone(),
                symmetric_key_1.clone(),
                symmetric_key_1.attributes()?.clone(),
                HashSet::new(),
            )),
            AtomicOperation::Create((
                uid_2.clone(),
                symmetric_key_2.clone(),
                symmetric_key_2.attributes()?.clone(),
                HashSet::new(),
            )),
        ],
        db_params,
    )
    .await?;
    assert!(
        !db.retrieve(&uid_1, owner, ObjectOperationType::Get, db_params)
            .await?
            .is_empty()
    );
    assert!(
        !db.retrieve(&uid_2, owner, ObjectOperationType::Get, db_params)
            .await?
            .is_empty()
    );

    // create the uid 1 twice. This should fail
    let atomic = db
        .atomic(
            owner,
            &[
                AtomicOperation::Create((
                    uid_1.clone(),
                    symmetric_key_1.clone(),
                    symmetric_key_1.attributes()?.clone(),
                    HashSet::new(),
                )),
                AtomicOperation::Create((
                    uid_2.clone(),
                    symmetric_key_2.clone(),
                    symmetric_key_2.attributes()?.clone(),
                    HashSet::new(),
                )),
            ],
            db_params,
        )
        .await;
    assert!(atomic.is_err());

    // this however should work
    db.atomic(
        owner,
        &[
            AtomicOperation::Upsert((
                uid_1.clone(),
                symmetric_key_1.clone(),
                symmetric_key_1.attributes()?.clone(),
                Some(HashSet::new()),
                StateEnumeration::Deactivated,
            )),
            AtomicOperation::Upsert((
                uid_2.clone(),
                symmetric_key_2.clone(),
                symmetric_key_2.attributes()?.clone(),
                Some(HashSet::new()),
                StateEnumeration::Deactivated,
            )),
        ],
        db_params,
    )
    .await?;

    assert_eq!(
        db.retrieve(&uid_1, owner, ObjectOperationType::Get, db_params)
            .await?
            .get(&uid_1)
            .expect("uid_1 should be in the db")
            .state,
        StateEnumeration::Deactivated
    );
    assert_eq!(
        db.retrieve(&uid_2, owner, ObjectOperationType::Get, db_params)
            .await?
            .get(&uid_2)
            .expect("uid_1 should be in the db")
            .state,
        StateEnumeration::Deactivated
    );
    Ok(())
}

pub(crate) async fn upsert<DB: Database>(
    db_and_params: &(DB, Option<ExtraDatabaseParams>),
) -> KResult<()> {
    log_init(None);
    let db = &db_and_params.0;
    let db_params = db_and_params.1.as_ref();

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";

    // Create key

    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let mut symmetric_key =
        create_symmetric_key_kmip_object(symmetric_key.as_slice(), CryptographicAlgorithm::AES)?;

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

    let objs_ = db
        .retrieve(&uid, owner, ObjectOperationType::Get, db_params)
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();
    match objs_.len() {
        1 => {
            assert_eq!(StateEnumeration::Active, objs_[0].state);
            assert!(symmetric_key == objs_[0].object);
        }
        _ => kms_bail!("There should be only one object"),
    }

    let attributes = symmetric_key.attributes_mut()?;
    attributes.link = Some(vec![Link {
        link_type: LinkType::PreviousLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString("foo".to_owned()),
    }]);

    db.upsert(
        &uid,
        owner,
        &symmetric_key,
        symmetric_key.attributes()?,
        Some(&HashSet::new()),
        StateEnumeration::PreActive,
        db_params,
    )
    .await?;

    let objs_ = db
        .retrieve(&uid, owner, ObjectOperationType::Get, db_params)
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();
    match objs_.len() {
        1 => {
            assert_eq!(StateEnumeration::PreActive, objs_[0].state);
            assert_eq!(
                objs_[0]
                    .object
                    .attributes()?
                    .link
                    .as_ref()
                    .ok_or_else(|| KmsError::ServerError("links should not be empty".to_owned()))?
                    [0]
                .linked_object_identifier,
                LinkedObjectIdentifier::TextString("foo".to_owned())
            );
        }
        _ => kms_bail!("There should be only one object"),
    }

    db.delete(&uid, owner, db_params).await?;

    if !db
        .retrieve(&uid, owner, ObjectOperationType::Get, db_params)
        .await?
        .is_empty()
    {
        kms_bail!("The object should have been deleted");
    }

    Ok(())
}

pub(crate) async fn crud<DB: Database>(
    db_and_params: &(DB, Option<ExtraDatabaseParams>),
) -> KResult<()> {
    log_init(None);
    let db = &db_and_params.0;
    let db_params = db_and_params.1.as_ref();

    let mut rng = CsRng::from_entropy();

    let owner = "eyJhbGciOiJSUzI1Ni";

    // test non existent row (with very high probability)
    if !db
        .retrieve(
            &Uuid::new_v4().to_string(),
            owner,
            ObjectOperationType::Get,
            db_params,
        )
        .await?
        .is_empty()
    {
        kms_bail!("There should be no object");
    }

    // Insert an object and query it, update it, delete it, query it
    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let mut symmetric_key =
        create_symmetric_key_kmip_object(symmetric_key.as_slice(), CryptographicAlgorithm::AES)?;

    let uid = Uuid::new_v4().to_string();

    let uid_ = db
        .create(
            Some(uid.clone()),
            owner,
            &symmetric_key,
            symmetric_key.attributes()?,
            &HashSet::new(),
            db_params,
        )
        .await?;
    assert_eq!(&uid, &uid_);

    let objs_ = db
        .retrieve(&uid, owner, ObjectOperationType::Get, db_params)
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();

    match objs_.len() {
        1 => {
            assert_eq!(StateEnumeration::Active, objs_[0].state);
            assert!(symmetric_key == objs_[0].object);
        }
        _ => kms_bail!("There should be only one object. Found {}", objs_.len()),
    }

    let attributes = symmetric_key.attributes_mut()?;
    attributes.link = Some(vec![Link {
        link_type: LinkType::PreviousLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString("foo".to_owned()),
    }]);

    db.update_object(
        &uid,
        &symmetric_key,
        symmetric_key.attributes()?,
        None,
        db_params,
    )
    .await?;

    let objs_ = db
        .retrieve(&uid, owner, ObjectOperationType::Get, db_params)
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();

    match objs_.len() {
        1 => {
            assert_eq!(StateEnumeration::Active, objs_[0].state);
            assert_eq!(
                objs_[0]
                    .object
                    .attributes()?
                    .link
                    .as_ref()
                    .ok_or_else(|| KmsError::ServerError("links should not be empty".to_owned()))?
                    [0]
                .linked_object_identifier,
                LinkedObjectIdentifier::TextString("foo".to_owned())
            );
        }
        _ => kms_bail!("There should be only one object"),
    }

    db.update_state(&uid, StateEnumeration::Deactivated, db_params)
        .await?;

    let objs_ = db
        .retrieve(&uid, owner, ObjectOperationType::Get, db_params)
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();

    match objs_.len() {
        1 => {
            assert_eq!(StateEnumeration::Deactivated, objs_[0].state);
            assert!(symmetric_key == objs_[0].object);
        }
        _ => kms_bail!("There should be only one object"),
    }

    db.delete(&uid, owner, db_params).await?;

    if !db
        .retrieve(&uid, owner, ObjectOperationType::Get, db_params)
        .await?
        .is_empty()
    {
        kms_bail!("The object should have been deleted");
    }

    Ok(())
}
