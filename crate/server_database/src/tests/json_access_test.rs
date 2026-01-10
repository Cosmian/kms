use std::collections::HashSet;

use cosmian_kmip::{
    kmip_0::kmip_types::{CryptographicUsageMask, State},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_types::{CryptographicAlgorithm, KeyFormatType},
        requests::create_symmetric_key_kmip_object,
    },
};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_kms_interfaces::{ObjectsStore, PermissionsStore};
use uuid::Uuid;

use crate::{db_error, error::DbResult};

pub(super) async fn json_access<DB: ObjectsStore + PermissionsStore>(db: &DB) -> DbResult<()> {
    cosmian_logger::log_init(None);

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";

    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    let symmetric_key = create_symmetric_key_kmip_object(
        &symmetric_key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Attributes::default()
        },
    )?;

    let uid = Uuid::new_v4().to_string();

    db.create(
        Some(uid.clone()),
        owner,
        &symmetric_key,
        symmetric_key.attributes()?,
        &HashSet::new(),
    )
    .await?;

    assert!(db.is_object_owned_by(&uid, owner).await?);

    // Retrieve object with valid owner with `Get` operation type - OK
    let obj = db
        .retrieve(&uid)
        .await?
        .ok_or_else(|| db_error!("Object not found"))?;
    assert_eq!(State::PreActive, obj.state());
    assert_eq!(&symmetric_key, obj.object());

    // Find with crypto algo attribute

    let researched_attributes = Some(Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(State::PreActive),
            owner,
            true,
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
            Some(State::PreActive),
            owner,
            true,
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
            Some(State::PreActive),
            owner,
            true,
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
            Some(State::PreActive),
            owner,
            true,
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
            Some(State::PreActive),
            owner,
            true,
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
            Some(State::PreActive),
            owner,
            true,
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
            Some(State::PreActive),
            owner,
            true,
        )
        .await?;
    assert!(found.is_empty());

    Ok(())
}
