use std::collections::HashSet;

use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
use cosmian_kmip::{
    crypto::symmetric::create_symmetric_key_kmip_object,
    kmip::{
        kmip_objects::ObjectType,
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType,
            StateEnumeration,
        },
    },
};
use cosmian_kms_client::access::ObjectOperationType;
use uuid::Uuid;

use crate::{
    core::extra_database_params::ExtraDatabaseParams,
    database::{object_with_metadata::ObjectWithMetadata, Database},
    kms_bail,
    result::KResult,
};

pub(crate) async fn json_access<DB: Database>(
    db_and_params: &(DB, Option<ExtraDatabaseParams>),
) -> KResult<()> {
    cosmian_logger::log_utils::log_init(None);
    let db = &db_and_params.0;
    let db_params = db_and_params.1.as_ref();

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";
    //

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

    assert!(!objs_.is_empty());
    match objs_.len() {
        1 => {
            assert_eq!(StateEnumeration::Active, objs_[0].state);
            assert!(symmetric_key == objs_[0].object);
        }
        _ => kms_bail!("There should be one object"),
    }

    // Find with crypto algo attribute

    let researched_attributes = Some(Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(StateEnumeration::Active),
            owner,
            true,
            db_params,
        )
        .await?;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, uid);

    // Find with crypto length attribute

    let researched_attributes = Some(Attributes {
        cryptographic_length: Some(symmetric_key.attributes()?.cryptographic_length.unwrap()),
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(StateEnumeration::Active),
            owner,
            true,
            db_params,
        )
        .await?;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, uid);

    // Find with crypto attributes

    let researched_attributes = Some(Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(symmetric_key.attributes()?.cryptographic_length.unwrap()),
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(StateEnumeration::Active),
            owner,
            true,
            db_params,
        )
        .await?;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, uid);

    // Find with key format type attribute

    let researched_attributes = Some(Attributes {
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(StateEnumeration::Active),
            owner,
            true,
            db_params,
        )
        .await?;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, uid);

    // Find with all attributes

    let researched_attributes = Some(Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(symmetric_key.attributes()?.cryptographic_length.unwrap()),
        cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(StateEnumeration::Active),
            owner,
            true,
            db_params,
        )
        .await?;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, uid);

    // Find bad crypto algo

    let researched_attributes = Some(Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(StateEnumeration::Active),
            owner,
            true,
            db_params,
        )
        .await?;
    assert!(found.is_empty());

    // Find bad key format type

    let researched_attributes = Some(Attributes {
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(StateEnumeration::Active),
            owner,
            true,
            db_params,
        )
        .await?;
    assert!(found.is_empty());

    Ok(())
}
