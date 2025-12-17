use std::collections::HashSet;

use cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, State},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::{Object, SymmetricKey},
        kmip_types::{CryptographicAlgorithm, Link, LinkType, LinkedObjectIdentifier},
        requests::create_symmetric_key_kmip_object,
    },
};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_kms_interfaces::{AtomicOperation, ObjectsStore};
use cosmian_logger::log_init;
use uuid::Uuid;

use crate::{
    db_bail,
    error::{DbError, DbResult},
};

pub(super) async fn tx_and_list<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";

    // Create key
    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let symmetric_key_1 = create_symmetric_key_kmip_object(
        symmetric_key.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    let uid_1 = Uuid::new_v4().to_string();

    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let symmetric_key_2 = create_symmetric_key_kmip_object(
        symmetric_key.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

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
    db.atomic(owner, &operations).await?;

    let list = db.find(None, None, owner, true).await?;
    match list.iter().find(|(id, _state, _attrs)| id == &uid_1) {
        Some((uid_, state_, _attrs)) => {
            assert_eq!(&uid_1, uid_);
            assert_eq!(&State::PreActive, state_);
        }
        None => db_bail!("The object 1, uid_1 should be in the list"),
    }
    match list.iter().find(|(id, _state, _attrs)| id == &uid_2) {
        Some((uid_, state_, _attrs)) => {
            assert_eq!(&uid_2, uid_);
            assert_eq!(&State::PreActive, state_);
        }
        None => db_bail!("The object 2, uid_2 should be in the list"),
    }

    db.delete(&uid_1).await?;
    db.delete(&uid_2).await?;

    if db.retrieve(&uid_1).await?.is_some() {
        db_bail!("The object 1 should have been deleted");
    }
    if db.retrieve(&uid_2).await?.is_some() {
        db_bail!("The object 2 should have been deleted");
    }

    Ok(())
}

pub(super) async fn atomic<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";

    // Create key

    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let symmetric_key_1 = create_symmetric_key_kmip_object(
        symmetric_key.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    let uid_1 = Uuid::new_v4().to_string();

    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let symmetric_key_2 = create_symmetric_key_kmip_object(
        symmetric_key.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

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
    )
    .await?;
    assert!(db.retrieve(&uid_1).await?.is_some());
    assert!(db.retrieve(&uid_2).await?.is_some());

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
        )
        .await;
    atomic.unwrap_err();

    // this however should work
    db.atomic(
        owner,
        &[
            AtomicOperation::Upsert((
                uid_1.clone(),
                symmetric_key_1.clone(),
                symmetric_key_1.attributes()?.clone(),
                Some(HashSet::new()),
                State::Deactivated,
            )),
            AtomicOperation::Upsert((
                uid_2.clone(),
                symmetric_key_2.clone(),
                symmetric_key_2.attributes()?.clone(),
                Some(HashSet::new()),
                State::Deactivated,
            )),
        ],
    )
    .await?;

    assert_eq!(
        db.retrieve(&uid_1)
            .await?
            .expect("uid_1 should be in the db")
            .state(),
        State::Deactivated
    );
    assert_eq!(
        db.retrieve(&uid_2)
            .await?
            .expect("uid_2 should be in the db")
            .state(),
        State::Deactivated
    );
    Ok(())
}

pub(super) async fn upsert<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";

    // Create key

    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let mut symmetric_key = create_symmetric_key_kmip_object(
        symmetric_key.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
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

    let owm = db.retrieve(&uid).await?.expect("uid should be in the db");
    assert_eq!(State::PreActive, owm.state());
    assert_eq!(&symmetric_key, owm.object());

    let attributes = symmetric_key.attributes_mut()?;
    attributes.link = Some(vec![Link {
        link_type: LinkType::PreviousLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString("foo".to_owned()),
    }]);

    // Upsert is only carried out via atomic operations
    db.atomic(
        owner,
        &[AtomicOperation::Upsert((
            uid.clone(),
            owm.object().clone(),
            attributes.clone(),
            Some(HashSet::new()),
            State::Deactivated,
        ))],
    )
    .await?;

    let owm = db.retrieve(&uid).await?.expect("uid should be in the db");
    assert_eq!(State::Deactivated, owm.state());
    assert!(
        owm.attributes()
            .link
            .as_ref()
            .ok_or_else(|| DbError::ServerError("links should not be empty".to_owned()))?[0]
            .linked_object_identifier
            == LinkedObjectIdentifier::TextString("foo".to_owned())
    );

    db.delete(&uid).await?;
    assert!(db.retrieve(&uid).await?.is_none());

    Ok(())
}

pub(super) async fn crud<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);

    let mut rng = CsRng::from_entropy();

    let owner = "eyJhbGciOiJSUzI1Ni";

    // test non-existent row (with very high probability)
    if db.retrieve(&Uuid::new_v4().to_string()).await?.is_some() {
        db_bail!("There should be no object");
    }

    // Insert an object and query it, update it, delete it, query it
    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let mut symmetric_key = create_symmetric_key_kmip_object(
        symmetric_key.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    let uid = Uuid::new_v4().to_string();

    let uid_ = db
        .create(
            Some(uid.clone()),
            owner,
            &symmetric_key,
            symmetric_key.attributes()?,
            &HashSet::new(),
        )
        .await?;
    assert_eq!(&uid, &uid_);

    let obj = db.retrieve(&uid).await?.expect("uid should be in the db");
    assert_eq!(State::PreActive, obj.state());
    assert_eq!(&symmetric_key, obj.object());

    let attributes = symmetric_key.attributes_mut()?;
    attributes.link = Some(vec![Link {
        link_type: LinkType::PreviousLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString("foo".to_owned()),
    }]);

    db.update_object(&uid, &symmetric_key, symmetric_key.attributes()?, None)
        .await?;

    let obj = db.retrieve(&uid).await?.expect("uid should be in the db");
    assert_eq!(State::PreActive, obj.state());
    assert!(
        obj.object()
            .attributes()?
            .link
            .as_ref()
            .ok_or_else(|| DbError::ServerError("links should not be empty".to_owned()))?[0]
            .linked_object_identifier
            == LinkedObjectIdentifier::TextString("foo".to_owned())
    );

    db.update_state(&uid, State::Deactivated).await?;

    let obj = db.retrieve(&uid).await?.expect("uid should be in the db");
    assert_eq!(State::Deactivated, obj.state());
    assert_eq!(&symmetric_key, obj.object());

    db.delete(&uid).await?;

    if db.retrieve(&uid).await?.is_some() {
        db_bail!("The object should have been deleted");
    }

    Ok(())
}

/// Test that any legacy value (`0x8000_000D`) is correctly migrated
/// to `BlockCipherMode::AESKeyWrapPadding` (`0x0000_000C`) when objects are retrieved from the database.
/// This ensures backward compatibility with some databases that might have been created by KMS versions prior to 5.15.
/// This test should should be deleted once `BlockCipherMode::LegacyNISTKeyWrap` is permanently removed from the codebase.
pub(super) async fn block_cipher_mode_migration_after_json_deserialization<DB: ObjectsStore>(
    db: &DB,
    db_params: Option<Arc<dyn SessionParams>>,
) -> DbResult<()> {
    cosmian_logger::log_init(None);

    let owner = "test_owner";
    let uid = Uuid::new_v4().to_string();

    // This is a sort of hack to trick the database into saving that deprecated value
    let json = r#"
    {
      "SymmetricKey": {
        "KeyBlock": {
          "KeyFormatType": "TransparentSymmetricKey",
          "CryptographicAlgorithm": "AES",
          "CryptographicLength": 256,
          "KeyWrappingData": {
            "WrappingMethod": "Encrypt",
            "EncryptionKeyInformation": {
              "UniqueIdentifier": "aes_wrapper",
              "CryptographicParameters": {
                "BlockCipherMode": "LegacyNISTKeyWrap",
                "CryptographicAlgorithm": "AES"
              }
            },
            "EncodingOption": "TTLVEncoding"
          }
        }
      }
    }
    "#;

    let object: Object = serde_json::from_str(json).expect("Deserialization failed");
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        ..Default::default()
    };

    // Store the object in the database, it will encode to 0x8000_000D
    db.create(
        Some(uid.clone()),
        owner,
        &object,
        &attributes,
        &HashSet::new(),
        db_params.clone(),
    )
    .await?;

    let retrieved = db
        .retrieve(&uid, db_params.clone())
        .await?
        .ok_or_else(|| DbError::ItemNotFound("Object should exist".to_owned()))?;

    // Verify the BlockCipherMode was migrated
    if let Object::SymmetricKey(SymmetricKey { key_block }) = retrieved.object() {
        let block_cipher_mode = key_block
            .key_wrapping_data
            .as_ref()
            .ok_or_else(|| DbError::ServerError("KeyWrappingData should exist".to_owned()))?
            .encryption_key_information
            .as_ref()
            .ok_or_else(|| {
                DbError::ServerError("EncryptionKeyInformation should exist".to_owned())
            })?
            .cryptographic_parameters
            .as_ref()
            .ok_or_else(|| DbError::ServerError("CryptographicParameters should exist".to_owned()))?
            .block_cipher_mode;

        if block_cipher_mode != Some(BlockCipherMode::AESKeyWrapPadding) {
            return Err(DbError::ServerError(format!(
                "Legacy BlockCipherMode should be migrated to AESKeyWrapPadding, found: {block_cipher_mode:?}"
            )));
        }
    } else {
        return Err(DbError::ServerError(
            "Expected SymmetricKey object".to_owned(),
        ));
    }

    Ok(())
}
