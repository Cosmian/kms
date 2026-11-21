use std::{collections::HashSet, future::Future};

use cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, State},
    kmip_2_1::{
        KmipOperation,
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_attributes::Attributes,
        kmip_objects::{Object, ObjectType, OpaqueObject, SymmetricKey},
        kmip_types::{
            CryptographicAlgorithm, Link, LinkType, LinkedObjectIdentifier, OpaqueDataType,
        },
        requests::create_symmetric_key_kmip_object,
    },
};
use cosmian_kms_crypto::{
    crypto::{KmsRng, rng::SeededCsRng},
    reexport::cosmian_crypto_core::reexport::rand_core::RngCore,
};
use cosmian_kms_interfaces::{
    AtomicOperation, DestroyedFilter, FindOptions, GCM_MAX_INVOCATIONS, InterfaceError,
    InterfaceResult, ObjectWithMetadata, ObjectsStore, PermissionsStore, UserId,
};
use cosmian_logger::log_init;
use uuid::Uuid;

use crate::{
    db_bail,
    error::{DbError, DbResult},
};

pub(super) async fn tx_and_list<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);

    let mut rng = KmsRng::new().seeded_csrng()?;
    let owner = "eyJhbGciOiJSUzI1Ni";

    // Create key
    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let symmetric_key_1 = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
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
        VENDOR_ID_COSMIAN,
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
            UserId::from(owner),
            symmetric_key_1.clone(),
            symmetric_key_1.attributes()?.clone(),
            HashSet::new(),
        )),
        AtomicOperation::Create((
            uid_2.clone(),
            UserId::from(owner),
            symmetric_key_2.clone(),
            symmetric_key_2.attributes()?.clone(),
            HashSet::new(),
        )),
    ];
    db.atomic(&UserId::from(owner), &operations).await?;

    let list = db
        .find(None, None, &UserId::from(owner), true, VENDOR_ID_COSMIAN)
        .await?;
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

    let mut rng = KmsRng::new().seeded_csrng()?;
    let owner = "eyJhbGciOiJSUzI1Ni";

    // Create key

    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let symmetric_key_1 = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
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
        VENDOR_ID_COSMIAN,
        symmetric_key.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    let uid_2 = Uuid::new_v4().to_string();

    db.atomic(
        &UserId::from(owner),
        &[
            AtomicOperation::Create((
                uid_1.clone(),
                UserId::from(owner),
                symmetric_key_1.clone(),
                symmetric_key_1.attributes()?.clone(),
                HashSet::new(),
            )),
            AtomicOperation::Create((
                uid_2.clone(),
                UserId::from(owner),
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
            &UserId::from(owner),
            &[
                AtomicOperation::Create((
                    uid_1.clone(),
                    UserId::from(owner),
                    symmetric_key_1.clone(),
                    symmetric_key_1.attributes()?.clone(),
                    HashSet::new(),
                )),
                AtomicOperation::Create((
                    uid_2.clone(),
                    UserId::from(owner),
                    symmetric_key_2.clone(),
                    symmetric_key_2.attributes()?.clone(),
                    HashSet::new(),
                )),
            ],
        )
        .await;
    let err = atomic.expect_err("an atomic create with an existing identifier must fail");
    if !matches!(&err, InterfaceError::ObjectAlreadyExists(_)) {
        return Err(DbError::Default(format!(
            "atomic duplicate create returned unexpected error: {err:?}"
        )));
    }

    // this however should work
    db.atomic(
        &UserId::from(owner),
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

    // Test UpdateObject + UpdateState in the same atomic call (revoke scenario).
    // This verifies that UpdateState builds on the result of UpdateObject rather
    // than re-reading from the store, which would clobber the object changes.
    let uid_3 = Uuid::new_v4().to_string();
    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let symmetric_key_3 = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        symmetric_key.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    db.create(
        Some(uid_3.clone()),
        &UserId::from(owner),
        &symmetric_key_3,
        symmetric_key_3.attributes()?,
        &HashSet::new(),
    )
    .await?;

    // Simulate revoke: UpdateObject with deactivated attributes + UpdateState
    let mut deactivated_attrs = symmetric_key_3.attributes()?.clone();
    deactivated_attrs.state = Some(State::Deactivated);
    let mut deactivated_object = symmetric_key_3.clone();
    deactivated_object.attributes_mut()?.state = Some(State::Deactivated);

    db.atomic(
        &UserId::from(owner),
        &[
            AtomicOperation::UpdateObject((
                uid_3.clone(),
                deactivated_object,
                deactivated_attrs.clone(),
                None,
            )),
            AtomicOperation::UpdateState((uid_3.clone(), State::Deactivated)),
        ],
    )
    .await?;

    let owm = db
        .retrieve(&uid_3)
        .await?
        .expect("uid_3 should be in the db");
    assert_eq!(owm.state(), State::Deactivated);
    // Verify internal object attributes also reflect deactivated state
    let obj_attrs = owm.object().attributes()?;
    assert_eq!(obj_attrs.state, Some(State::Deactivated));

    db.delete(&uid_3).await?;

    Ok(())
}

/// The version an object currently has in the store; a read without it fails the test.
async fn stored_version<DB: ObjectsStore>(db: &DB, uid: &str) -> DbResult<u64> {
    db.retrieve(uid)
        .await?
        .and_then(|owm| owm.version())
        .ok_or_else(|| DbError::Default(format!("no version read for {uid}")))
}

/// `CompareAndSwapObject` writes only when the caller owns the object, it is not destroyed
/// and its version is the expected one; otherwise the whole batch fails with `Conflict` and
/// leaves the store unchanged.
pub(super) async fn compare_and_swap_test<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);

    let mut rng = KmsRng::new().seeded_csrng()?;
    let mut new_key = || -> DbResult<Object> {
        let mut bytes = vec![0; 32];
        rng.fill_bytes(&mut bytes);
        Ok(create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            &bytes,
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Default::default()
            },
        )?)
    };
    let original = new_key()?;
    let first = new_key()?;
    let second = new_key()?;
    let owner = UserId::from("compare_and_swap_owner");
    let cas = |uid: &str, expected_version: u64, object: &Object| -> DbResult<AtomicOperation> {
        Ok(AtomicOperation::CompareAndSwapObject {
            uid: uid.to_owned(),
            expected_version,
            object: Box::new(object.clone()),
            attributes: object.attributes()?.clone(),
            tags: None,
        })
    };
    let no_tags = HashSet::new();
    let original_attributes = original.attributes()?.clone();
    let create = |uid: &str| {
        db.create(
            Some(uid.to_owned()),
            &owner,
            &original,
            &original_attributes,
            &no_tags,
        )
    };
    let expect_conflict = |result: InterfaceResult<Vec<String>>, case: &str| match result {
        Err(InterfaceError::Conflict(_)) => Ok(()),
        other => Err(DbError::Default(format!(
            "{case}: expected Conflict, got {other:?}"
        ))),
    };

    // Matching version: the content is swapped, the state kept, the version incremented once.
    let uid = Uuid::new_v4().to_string();
    create(&uid).await?;
    let version = stored_version(db, &uid).await?;
    db.atomic(&owner, &[cas(&uid, version, &first)?]).await?;
    let swapped = db.retrieve(&uid).await?.expect("swapped object");
    assert!(
        swapped.object() == &first,
        "the swap must write the new object"
    );
    assert_eq!(swapped.state(), State::PreActive);
    assert_eq!(swapped.version(), Some(version + 1));

    // Stale version: rejected, nothing written.
    expect_conflict(
        db.atomic(&owner, &[cas(&uid, version, &second)?]).await,
        "stale version",
    )?;
    let unchanged = db.retrieve(&uid).await?.expect("object after stale swap");
    assert!(unchanged.object() == &first, "a stale swap must not write");
    assert_eq!(unchanged.version(), Some(version + 1));

    // Foreign owner with the current version: rejected like a stale version.
    expect_conflict(
        db.atomic(
            &UserId::from("another-owner"),
            &[cas(&uid, version + 1, &second)?],
        )
        .await,
        "foreign owner",
    )?;
    assert_eq!(stored_version(db, &uid).await?, version + 1);

    // Destroyed objects: rejected with the current version, and the companion create of the
    // same batch is rolled back.
    for destroyed in [State::Destroyed, State::Destroyed_Compromised] {
        let uid = Uuid::new_v4().to_string();
        create(&uid).await?;
        db.update_state(&uid, destroyed).await?;
        let companion = Uuid::new_v4().to_string();
        expect_conflict(
            db.atomic(
                &owner,
                &[
                    AtomicOperation::Create((
                        companion.clone(),
                        owner.clone(),
                        first.clone(),
                        first.attributes()?.clone(),
                        HashSet::new(),
                    )),
                    cas(&uid, stored_version(db, &uid).await?, &first)?,
                ],
            )
            .await,
            "destroyed object",
        )?;
        assert!(db.retrieve(&companion).await?.is_none());
        assert_eq!(
            db.retrieve(&uid).await?.expect("destroyed object").object(),
            &original
        );
    }

    // Missing object: rejected.
    expect_conflict(
        db.atomic(&owner, &[cas(&Uuid::new_v4().to_string(), 0, &first)?])
            .await,
        "missing object",
    )?;

    // Two concurrent writers from the same version: exactly one batch commits.
    let uid = Uuid::new_v4().to_string();
    create(&uid).await?;
    let version = stored_version(db, &uid).await?;
    let version_uid_1 = Uuid::new_v4().to_string();
    let version_uid_2 = Uuid::new_v4().to_string();
    let batch = |object: &Object, version_uid: &str| -> DbResult<[AtomicOperation; 2]> {
        Ok([
            cas(&uid, version, object)?,
            AtomicOperation::Create((
                version_uid.to_owned(),
                owner.clone(),
                object.clone(),
                object.attributes()?.clone(),
                HashSet::new(),
            )),
        ])
    };
    let (batch_1, batch_2) = (
        batch(&first, &version_uid_1)?,
        batch(&second, &version_uid_2)?,
    );
    let (result_1, result_2) =
        tokio::join!(db.atomic(&owner, &batch_1), db.atomic(&owner, &batch_2));
    assert!(
        matches!(
            (&result_1, &result_2),
            (Ok(_), Err(InterfaceError::Conflict(_))) | (Err(InterfaceError::Conflict(_)), Ok(_))
        ),
        "concurrent stale writes must yield one success and one conflict: {result_1:?}, {result_2:?}"
    );
    assert_ne!(
        db.retrieve(&version_uid_1).await?.is_some(),
        db.retrieve(&version_uid_2).await?.is_some(),
        "the losing batch must not create its version object"
    );
    assert_eq!(stored_version(db, &uid).await?, version + 1);
    Ok(())
}

/// Reading an absent parameter never creates it; insertion chooses one stable value that
/// subsequent read-only lookups and competing inserts return unchanged.
pub(super) async fn get_or_insert_parameter<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    // Keep a process-unique static name so repeated runs on a live DB cannot collide.
    static NAME: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| format!("test_get_or_insert_parameter_{}", Uuid::new_v4()));
    let name = NAME.as_str();
    assert_eq!(db.get_parameter(name).await?, None);
    assert_eq!(
        db.get_parameter(name).await?,
        None,
        "a missing-parameter lookup must not create a value"
    );
    let first = Uuid::new_v4().to_string();
    let stored = db.get_or_insert_parameter(name, &first).await?;
    assert_eq!(stored, first);
    assert_eq!(
        db.get_parameter(name).await?.as_deref(),
        Some(stored.as_str())
    );
    let again = db
        .get_or_insert_parameter(name, &Uuid::new_v4().to_string())
        .await?;
    if again != stored {
        return Err(DbError::DatabaseError(format!(
            "parameter changed from {stored} to {again}"
        )));
    }
    assert_eq!(
        db.get_parameter(name).await?.as_deref(),
        Some(stored.as_str())
    );
    Ok(())
}

pub(super) async fn upsert<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);

    let mut rng = KmsRng::new().seeded_csrng()?;
    let owner = "eyJhbGciOiJSUzI1Ni";

    // Create key

    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let mut symmetric_key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        symmetric_key.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    let uid = Uuid::new_v4().to_string();

    db.create(
        Some(uid.clone()),
        &UserId::from(owner),
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
        &UserId::from(owner),
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
    assert_eq!(
        owm.attributes()
            .link
            .as_ref()
            .ok_or_else(|| DbError::ServerError("links should not be empty".to_owned()))?[0]
            .linked_object_identifier,
        LinkedObjectIdentifier::TextString("foo".to_owned())
    );

    db.delete(&uid).await?;
    assert!(db.retrieve(&uid).await?.is_none());

    Ok(())
}

pub(super) async fn crud<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);

    let mut rng = KmsRng::new().seeded_csrng()?;

    let owner = "eyJhbGciOiJSUzI1Ni";

    // test non-existent row (with very high probability)
    if db.retrieve(&Uuid::new_v4().to_string()).await?.is_some() {
        db_bail!("There should be no object");
    }

    // Insert an object and query it, update it, delete it, query it
    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let mut symmetric_key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
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
            &UserId::from(owner),
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
    assert_eq!(
        obj.object()
            .attributes()?
            .link
            .as_ref()
            .ok_or_else(|| DbError::ServerError("links should not be empty".to_owned()))?[0]
            .linked_object_identifier,
        LinkedObjectIdentifier::TextString("foo".to_owned())
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

/// Creating an object whose UID already exists must report `ObjectAlreadyExists`
/// (the `SQLite` backend maps a constraint violation), not a generic DB error.
pub(super) async fn create_duplicate_uid_test<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);
    let key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &[7_u8; 32],
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    let uid = Uuid::new_v4().to_string();
    let owner = UserId::from("duplicate_owner");
    db.create(
        Some(uid.clone()),
        &owner,
        &key,
        key.attributes()?,
        &HashSet::new(),
    )
    .await?;
    let second = db
        .create(Some(uid), &owner, &key, key.attributes()?, &HashSet::new())
        .await;
    assert!(
        matches!(second, Err(InterfaceError::ObjectAlreadyExists(_))),
        "expected ObjectAlreadyExists, got {second:?}"
    );
    Ok(())
}

/// Test that any legacy value (`0x8000_000D`) is correctly migrated
/// to `BlockCipherMode::AESKeyWrapPadding` (`0x0000_000C`) when objects are retrieved from the database.
/// This ensures backward compatibility with some databases that might have been created by KMS versions prior to 5.15.
/// This test should should be deleted once `BlockCipherMode::LegacyNISTKeyWrap` is permanently removed from the codebase.
pub(super) async fn block_cipher_mode_migration_after_json_deserialization<DB: ObjectsStore>(
    db: &DB,
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
        &UserId::from(owner),
        &object,
        &attributes,
        &HashSet::new(),
    )
    .await?;

    let retrieved = db
        .retrieve(&uid)
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

/// Verify that `find_due_for_rotation` returns exactly the objects that are
/// `Active`, have `rotate_automatic = true`, and whose rotation deadline has
/// already passed.
///
/// Three objects are created:
/// - `obj_due`    — past deadline  → **must** appear in the result
/// - `obj_not_due` — future deadline → must NOT appear
/// - `obj_no_auto` — `rotate_automatic` absent → must NOT appear
pub(super) async fn find_due_for_rotation_test<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    let owner = "rotation_test_owner";
    let now = time::OffsetDateTime::now_utc();

    // Helper: create a minimal AES symmetric key object
    let make_key = |rng: &mut SeededCsRng| -> DbResult<Object> {
        let mut bytes = vec![0_u8; 32];
        rng.fill_bytes(&mut bytes);
        create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            bytes.as_slice(),
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Default::default()
            },
        )
        .map_err(|e| DbError::ServerError(e.to_string()))
    };

    let mut rng = KmsRng::new().seeded_csrng()?;

    // ── obj_due: initial_date 2 h ago, interval 1 h → overdue ────────────
    let uid_due = Uuid::new_v4().to_string();
    let attrs_due = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        state: Some(State::Active),
        rotate_automatic: Some(true),
        rotate_interval: Some(3600),                        // 1 hour
        initial_date: Some(now - time::Duration::hours(2)), // 2 h ago
        ..Default::default()
    };
    db.create(
        Some(uid_due.clone()),
        &UserId::from(owner),
        &make_key(&mut rng)?,
        &attrs_due,
        &HashSet::new(),
    )
    .await?;

    // ── obj_not_due: initial_date 30 min ago, interval 1 h → not yet due ─
    let uid_not_due = Uuid::new_v4().to_string();
    let attrs_not_due = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        state: Some(State::Active),
        rotate_automatic: Some(true),
        rotate_interval: Some(3600),
        initial_date: Some(now - time::Duration::minutes(30)),
        ..Default::default()
    };
    db.create(
        Some(uid_not_due.clone()),
        &UserId::from(owner),
        &make_key(&mut rng)?,
        &attrs_not_due,
        &HashSet::new(),
    )
    .await?;

    // ── obj_no_auto: rotate_automatic absent → never scheduled ────────────
    let uid_no_auto = Uuid::new_v4().to_string();
    let attrs_no_auto = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        state: Some(State::Active),
        rotate_interval: Some(3600),
        initial_date: Some(now - time::Duration::hours(2)),
        ..Default::default()
    };
    db.create(
        Some(uid_no_auto.clone()),
        &UserId::from(owner),
        &make_key(&mut rng)?,
        &attrs_no_auto,
        &HashSet::new(),
    )
    .await?;

    // ── Assert ────────────────────────────────────────────────────────────
    let due = db.find_due_for_rotation(now).await?;
    let due_uids: HashSet<&str> = due.iter().map(|(uid, _)| uid.as_str()).collect();

    if !due_uids.contains(uid_due.as_str()) {
        return Err(DbError::ServerError(format!(
            "find_due_for_rotation: expected uid_due '{uid_due}' in result, got: {due_uids:?}"
        )));
    }
    if due_uids.contains(uid_not_due.as_str()) {
        return Err(DbError::ServerError(format!(
            "find_due_for_rotation: uid_not_due '{uid_not_due}' must NOT be in result"
        )));
    }
    if due_uids.contains(uid_no_auto.as_str()) {
        return Err(DbError::ServerError(format!(
            "find_due_for_rotation: uid_no_auto '{uid_no_auto}' must NOT be in result"
        )));
    }
    // Verify the owner is correct
    for (uid, owner_returned) in &due {
        if uid == &uid_due && owner_returned != owner {
            return Err(DbError::ServerError(format!(
                "find_due_for_rotation: wrong owner '{owner_returned}' for uid_due, expected '{owner}'"
            )));
        }
    }

    // ── Cleanup ───────────────────────────────────────────────────────────
    db.delete(&uid_due).await?;
    db.delete(&uid_not_due).await?;
    db.delete(&uid_no_auto).await?;

    Ok(())
}

/// Verify that `count_non_destroyed_keys` counts key objects by their
/// `ObjectType` attribute and state:
/// - `Active` and `Deactivated` keys are counted
/// - `Destroyed` and `Destroyed_Compromised` keys are not
/// - non-key objects (`OpaqueObject`) are not
pub(super) async fn count_non_destroyed_keys_test<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    let owner = UserId::from("count_keys_test_owner");
    let baseline = db.count_non_destroyed_keys().await?;

    let mut rng = KmsRng::new().seeded_csrng()?;
    let key_attributes = Attributes {
        object_type: Some(ObjectType::SymmetricKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        state: Some(State::Active),
        ..Default::default()
    };
    let mut uids = Vec::with_capacity(5);
    // key_active, key_deactivated, key_destroyed, key_destroyed_compromised
    for final_state in [
        State::Active,
        State::Deactivated,
        State::Destroyed,
        State::Destroyed_Compromised,
    ] {
        let mut bytes = vec![0_u8; 32];
        rng.fill_bytes(&mut bytes);
        let key = create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            bytes.as_slice(),
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Default::default()
            },
        )
        .map_err(|e| DbError::ServerError(e.to_string()))?;
        let uid = Uuid::new_v4().to_string();
        db.create(
            Some(uid.clone()),
            &owner,
            &key,
            &key_attributes,
            &HashSet::new(),
        )
        .await?;
        if final_state != State::Active {
            db.update_state(&uid, final_state).await?;
        }
        uids.push(uid);
    }

    // opaque: a non-key object must never be counted
    let uid_opaque = Uuid::new_v4().to_string();
    db.create(
        Some(uid_opaque.clone()),
        &owner,
        &Object::OpaqueObject(OpaqueObject {
            opaque_data_type: OpaqueDataType::Unknown,
            opaque_data_value: b"count-test".to_vec(),
        }),
        &Attributes {
            object_type: Some(ObjectType::OpaqueObject),
            state: Some(State::Active),
            ..Default::default()
        },
        &HashSet::new(),
    )
    .await?;
    uids.push(uid_opaque);

    let got = db.count_non_destroyed_keys().await?;
    let expected = baseline + 2;
    if got != expected {
        return Err(DbError::ServerError(format!(
            "count_non_destroyed_keys: expected {expected}, got {got}"
        )));
    }

    for uid in &uids {
        db.delete(uid).await?;
    }

    Ok(())
}

/// Compare the uids of `rows` with `expected`, duplicates included.
fn check_found(
    label: &str,
    rows: &[(String, State, Attributes)],
    expected: &[&String],
) -> DbResult<()> {
    let mut got: Vec<&String> = rows.iter().map(|(uid, _, _)| uid).collect();
    got.sort();
    let mut expected = expected.to_vec();
    expected.sort();
    if got != expected {
        return Err(DbError::ServerError(format!(
            "{label}: expected {expected:?}, got {got:?}"
        )));
    }
    Ok(())
}

/// Verify the Locate listing queries (`find_with_options` /
/// `find_all_with_options`):
/// - a tag search returns the objects carrying *all* the searched tags, once each;
/// - a user sees the objects granted to them directly or through the wildcard
///   user `*`, once each even when both grants exist, and nothing else;
/// - `destroyed` (`Exclude`/`Only`) filters destroyed objects unless that state is requested;
/// - `limit` caps the number of rows.
pub(super) async fn find_with_options_test<DB: ObjectsStore + PermissionsStore>(
    db: &DB,
) -> DbResult<()> {
    let owner = UserId::from("find_options_owner");
    let grantee = UserId::from("find_options_grantee");
    // Tags unique to this run, so that objects left by other tests never match.
    let run = Uuid::new_v4();
    let [t1, t2, t3] = ["t1", "t2", "t3"].map(|t| format!("{t}-{run}"));
    let search = |tags: &[&String]| -> DbResult<Attributes> {
        let mut attributes = Attributes::default();
        attributes.set_tags(VENDOR_ID_COSMIAN, tags)?;
        Ok(attributes)
    };

    // uids[0]: t1 t2 t3 | uids[1]: t1 t2 | uids[2]: t1 t3 | uids[3]: t1 t2, destroyed
    let mut rng = KmsRng::new().seeded_csrng()?;
    let mut uids = Vec::with_capacity(4);
    for (tags, destroyed) in [
        (vec![&t1, &t2, &t3], false),
        (vec![&t1, &t2], false),
        (vec![&t1, &t3], false),
        (vec![&t1, &t2], true),
    ] {
        let mut bytes = vec![0_u8; 32];
        rng.fill_bytes(&mut bytes);
        let key = create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            bytes.as_slice(),
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Default::default()
            },
        )
        .map_err(|e| DbError::ServerError(e.to_string()))?;
        let uid = Uuid::new_v4().to_string();
        let tags: HashSet<String> = tags.into_iter().cloned().collect();
        db.create(Some(uid.clone()), &owner, &key, key.attributes()?, &tags)
            .await?;
        if destroyed {
            db.update_state(&uid, State::Destroyed).await?;
        }
        uids.push(uid);
    }
    // uids[0] granted both directly and through `*`, uids[1] only through `*`.
    let get = HashSet::from([KmipOperation::Get]);
    db.grant_operations(&uids[0], &grantee, get.clone()).await?;
    db.grant_operations(&uids[0], &UserId::from("*"), get.clone())
        .await?;
    db.grant_operations(&uids[1], &UserId::from("*"), get)
        .await?;

    let unbounded = FindOptions::default();
    let live = FindOptions {
        destroyed: DestroyedFilter::Exclude,
        ..FindOptions::default()
    };
    let find = |tags: Attributes, state: Option<State>, user: &UserId, options: &FindOptions| {
        let (user, options) = (user.clone(), options.clone());
        async move {
            db.find_with_options(
                Some(&tags),
                state,
                &user,
                false,
                VENDOR_ID_COSMIAN,
                &options,
            )
            .await
        }
    };

    let rows = find(search(&[&t1, &t2, &t3])?, None, &owner, &unbounded).await?;
    check_found("all three tags", &rows, &[&uids[0]])?;
    let rows = find(search(&[&t1, &t2])?, None, &owner, &unbounded).await?;
    check_found("two tags", &rows, &[&uids[0], &uids[1], &uids[3]])?;
    let rows = find(search(&[&t1, &t2])?, None, &owner, &live).await?;
    check_found("two tags, destroyed excluded", &rows, &[&uids[0], &uids[1]])?;
    let rows = find(search(&[&t1, &t2])?, Some(State::Destroyed), &owner, &live).await?;
    check_found("two tags, destroyed requested", &rows, &[&uids[3]])?;
    let destroyed = FindOptions {
        destroyed: DestroyedFilter::Only,
        ..FindOptions::default()
    };
    let rows = find(search(&[&t1, &t2])?, None, &owner, &destroyed).await?;
    check_found("two tags, destroyed only", &rows, &[&uids[3]])?;
    let rows = find(search(&[&t1])?, None, &grantee, &unbounded).await?;
    check_found("grantee", &rows, &[&uids[0], &uids[1]])?;
    let rows = find(
        search(&[&t1])?,
        None,
        &owner,
        &FindOptions {
            limit: Some(2),
            ..FindOptions::default()
        },
    )
    .await?;
    if rows.len() != 2 {
        return Err(DbError::ServerError(format!(
            "limit 2: expected 2 rows, got {}",
            rows.len()
        )));
    }

    let rows = db
        .find_all_with_options(Some(&search(&[&t1, &t3])?), None, VENDOR_ID_COSMIAN, &live)
        .await?;
    check_found("find_all, two tags", &rows, &[&uids[0], &uids[2]])?;
    let rows = db
        .find_all_with_options(
            Some(&search(&[&t1])?),
            None,
            VENDOR_ID_COSMIAN,
            &FindOptions {
                limit: Some(3),
                ..FindOptions::default()
            },
        )
        .await?;
    if rows.len() != 3 {
        return Err(DbError::ServerError(format!(
            "find_all limit 3: expected 3 rows, got {}",
            rows.len()
        )));
    }

    for uid in &uids {
        db.delete(uid).await?;
    }
    Ok(())
}

/// Verify the `wrapping_key_id` write path and `find_wrapped_by` query across
/// every backend: a wrapped object must be discoverable by its wrapping key,
/// while an unwrapped object must never be returned.
pub(super) async fn wrapping_key_link_test<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);

    let owner = "wrapping_key_link_owner";
    let wrapping_key_uid = "wrapping_key_link_kek";

    // ── Wrapped object: KeyWrappingData references `wrapping_key_uid` ──────
    let wrapped_uid = Uuid::new_v4().to_string();
    let wrapped_obj: Object = serde_json::from_value(serde_json::json!({
        "SymmetricKey": {
            "KeyBlock": {
                "KeyFormatType": "TransparentSymmetricKey",
                "CryptographicAlgorithm": "AES",
                "CryptographicLength": 256,
                "KeyWrappingData": {
                    "WrappingMethod": "Encrypt",
                    "EncryptionKeyInformation": { "UniqueIdentifier": wrapping_key_uid },
                    "EncodingOption": "TTLVEncoding"
                }
            }
        }
    }))
    .map_err(|e| DbError::ServerError(format!("failed to build wrapped object: {e}")))?;
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        state: Some(State::Active),
        ..Default::default()
    };
    db.create(
        Some(wrapped_uid.clone()),
        &UserId::from(owner),
        &wrapped_obj,
        &attributes,
        &HashSet::new(),
    )
    .await?;

    // ── Unwrapped object: must not be returned by find_wrapped_by ─────────
    let mut rng = KmsRng::new().seeded_csrng()?;
    let mut key = vec![0_u8; 32];
    rng.fill_bytes(&mut key);
    let plain_uid = Uuid::new_v4().to_string();
    let plain_obj = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        key.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )
    .map_err(|e| DbError::ServerError(e.to_string()))?;
    db.create(
        Some(plain_uid.clone()),
        &UserId::from(owner),
        &plain_obj,
        &attributes,
        &HashSet::new(),
    )
    .await?;

    // ── Assert ────────────────────────────────────────────────────────────
    let found = db
        .find_wrapped_by(wrapping_key_uid, &UserId::from(owner))
        .await?;
    let found_uids: HashSet<&str> = found.iter().map(|(uid, _, _)| uid.as_str()).collect();

    if !found_uids.contains(wrapped_uid.as_str()) {
        return Err(DbError::ServerError(format!(
            "find_wrapped_by should return wrapped object '{wrapped_uid}', got: {found_uids:?}"
        )));
    }
    if found_uids.contains(plain_uid.as_str()) {
        return Err(DbError::ServerError(format!(
            "find_wrapped_by must NOT return unwrapped object '{plain_uid}'"
        )));
    }

    // ── Cleanup ───────────────────────────────────────────────────────────
    db.delete(&wrapped_uid).await?;
    db.delete(&plain_uid).await?;

    Ok(())
}

/// Conditional updates advance exactly once; stale or deleted snapshots conflict without
/// publishing earlier operations, and state/upsert writes invalidate old snapshots.
pub(super) async fn update_if_version_test<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);

    let owner = UserId::from("update_if_version_owner");
    let uid = Uuid::new_v4().to_string();
    let mut rng = KmsRng::new().seeded_csrng()?;
    let mut key = vec![0_u8; 32];
    rng.fill_bytes(&mut key);
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        state: Some(State::Active),
        ..Default::default()
    };
    let object = create_symmetric_key_kmip_object(VENDOR_ID_COSMIAN, key.as_slice(), &attributes)
        .map_err(|e| DbError::ServerError(e.to_string()))?;
    let tags = HashSet::from([format!("original-{uid}")]);
    db.create(Some(uid.clone()), &owner, &object, &attributes, &tags)
        .await?;
    let initial = db
        .retrieve(&uid)
        .await?
        .expect("created object must be present");
    let version = initial
        .version()
        .expect("retrieve must populate the version");

    let rejected_tags = HashSet::from([format!("rejected-{uid}")]);
    let update = |expected: u64| {
        AtomicOperation::UpdateObjectIfVersion((
            uid.clone(),
            object.clone(),
            attributes.clone(),
            Some(rejected_tags.clone()),
            expected,
        ))
    };
    let assert_unchanged = |actual: &ObjectWithMetadata, expected: &ObjectWithMetadata| {
        assert_eq!(
            actual.version(),
            expected.version(),
            "failed CAS changed the version"
        );
        assert_eq!(
            actual.attributes(),
            expected.attributes(),
            "failed CAS changed attributes"
        );
        assert_eq!(
            actual.state(),
            expected.state(),
            "failed CAS changed the state"
        );
        assert!(
            actual.object() == expected.object(),
            "failed CAS changed the object"
        );
    };
    let mut updated_attributes = attributes.clone();
    updated_attributes.sensitive = Some(true);
    let mut updated_object = object.clone();
    *updated_object.attributes_mut()? = updated_attributes.clone();
    let updated_tags = HashSet::from([format!("updated-{uid}")]);
    db.atomic(
        &owner,
        &[AtomicOperation::UpdateObjectIfVersion((
            uid.clone(),
            updated_object.clone(),
            updated_attributes.clone(),
            Some(updated_tags.clone()),
            version,
        ))],
    )
    .await?;
    let committed = db
        .retrieve(&uid)
        .await?
        .expect("successful CAS must retain the object");
    assert_eq!(
        committed.version(),
        Some(version + 1),
        "CAS must increment exactly once"
    );
    assert_eq!(committed.attributes(), &updated_attributes);
    assert_eq!(db.retrieve_tags(&uid).await?, updated_tags);

    let err = db
        .atomic(&owner, &[update(version)])
        .await
        .expect_err("a stale snapshot must conflict");
    assert!(matches!(err, InterfaceError::Conflict(_)), "{err}");
    assert_unchanged(
        &db.retrieve(&uid)
            .await?
            .expect("failed CAS must retain the object"),
        &committed,
    );
    assert_eq!(db.retrieve_tags(&uid).await?, updated_tags);

    let companion_uid = Uuid::new_v4().to_string();
    db.create(
        Some(companion_uid.clone()),
        &owner,
        &object,
        &attributes,
        &tags,
    )
    .await?;
    let companion = db
        .retrieve(&companion_uid)
        .await?
        .expect("companion must be present");
    let marker_uid = Uuid::new_v4().to_string();
    let err = db
        .atomic(
            &owner,
            &[
                AtomicOperation::Create((
                    marker_uid.clone(),
                    owner.clone(),
                    object.clone(),
                    attributes.clone(),
                    rejected_tags.clone(),
                )),
                AtomicOperation::UpdateObject((
                    companion_uid.clone(),
                    updated_object.clone(),
                    updated_attributes.clone(),
                    Some(rejected_tags.clone()),
                )),
                update(version),
            ],
        )
        .await
        .expect_err("a stale CAS must roll back earlier operations");
    assert!(matches!(err, InterfaceError::Conflict(_)), "{err}");
    assert!(
        db.retrieve(&marker_uid).await?.is_none(),
        "failed batch published its Create"
    );
    assert_unchanged(
        &db.retrieve(&companion_uid)
            .await?
            .expect("companion must survive rollback"),
        &companion,
    );
    assert_eq!(db.retrieve_tags(&companion_uid).await?, tags);
    assert_unchanged(
        &db.retrieve(&uid)
            .await?
            .expect("CAS target must survive rollback"),
        &committed,
    );
    assert_eq!(db.retrieve_tags(&uid).await?, updated_tags);
    assert!(
        db.list_uids_for_tags(&rejected_tags).await?.is_empty(),
        "failed batch published tags"
    );

    // `exact`: Upsert is not required to bump by exactly one (MySQL updates the object and
    // its state separately); snapshots only need to be invalidated.
    for (operation, expected_state, exact) in [
        (
            AtomicOperation::UpdateState((uid.clone(), State::Deactivated)),
            State::Deactivated,
            true,
        ),
        (
            AtomicOperation::Upsert((
                uid.clone(),
                updated_object,
                updated_attributes.clone(),
                Some(updated_tags.clone()),
                State::Active,
            )),
            State::Active,
            false,
        ),
    ] {
        let before = db
            .retrieve(&uid)
            .await?
            .expect("object must be present before mutation");
        let before_version = before
            .version()
            .expect("retrieve must populate the version");
        db.atomic(&owner, &[operation]).await?;
        let after = db
            .retrieve(&uid)
            .await?
            .expect("mutation must retain the object");
        if exact {
            assert_eq!(
                after.version(),
                Some(before_version + 1),
                "mutation must increment exactly once"
            );
        } else {
            assert!(
                after.version() > Some(before_version),
                "mutation must invalidate older snapshots"
            );
        }
        assert_eq!(after.state(), expected_state);
        assert_eq!(after.attributes(), &updated_attributes);
        let err = db
            .atomic(&owner, &[update(before_version)])
            .await
            .expect_err("state and upsert writes must invalidate snapshots");
        assert!(matches!(err, InterfaceError::Conflict(_)), "{err}");
        assert_unchanged(
            &db.retrieve(&uid)
                .await?
                .expect("stale CAS must retain the newer object"),
            &after,
        );
        assert_eq!(db.retrieve_tags(&uid).await?, updated_tags);
    }

    let current_version = db
        .retrieve(&uid)
        .await?
        .expect("object must be present before deletion")
        .version()
        .expect("retrieve must populate the version");
    db.delete(&uid).await?;
    let err = db
        .atomic(&owner, &[update(current_version)])
        .await
        .expect_err("deletion must invalidate a conditional update");
    assert!(matches!(err, InterfaceError::Conflict(_)), "{err}");
    assert!(
        db.retrieve(&uid).await?.is_none(),
        "conditional update resurrected a deleted object"
    );
    db.delete(&companion_uid).await?;
    Ok(())
}

/// The AES-GCM invocation count adds up across concurrent reservations, refuses to pass the cap of
/// SP 800-38D §8.3 without changing, and is forgotten on request.
pub(super) async fn gcm_invocations_test<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);

    let uid = Uuid::new_v4().to_string();
    assert_eq!(db.reserve_gcm_invocations(&uid, 1).await?, Some(1));
    assert_eq!(db.reserve_gcm_invocations(&uid, 4).await?, Some(5));
    let (a, b, c, d) = tokio::join!(
        db.reserve_gcm_invocations(&uid, 1),
        db.reserve_gcm_invocations(&uid, 1),
        db.reserve_gcm_invocations(&uid, 1),
        db.reserve_gcm_invocations(&uid, 1),
    );
    let mut totals = [a?, b?, c?, d?].map(Option::unwrap_or_default);
    totals.sort_unstable();
    assert_eq!(totals, [6, 7, 8, 9], "a concurrent reservation was lost");

    let capped = Uuid::new_v4().to_string();
    assert_eq!(
        db.reserve_gcm_invocations(&capped, GCM_MAX_INVOCATIONS + 1)
            .await?,
        None
    );
    assert_eq!(
        db.reserve_gcm_invocations(&capped, GCM_MAX_INVOCATIONS - 1)
            .await?,
        Some(GCM_MAX_INVOCATIONS - 1)
    );
    assert_eq!(db.reserve_gcm_invocations(&capped, 2).await?, None);
    assert_eq!(
        db.reserve_gcm_invocations(&capped, 1).await?,
        Some(GCM_MAX_INVOCATIONS)
    );
    assert_eq!(db.reserve_gcm_invocations(&capped, 1).await?, None);
    // a refusal leaves the count untouched
    assert_eq!(
        db.reserve_gcm_invocations(&capped, 0).await?,
        Some(GCM_MAX_INVOCATIONS)
    );

    db.delete_gcm_invocations(&capped).await?;
    assert_eq!(db.reserve_gcm_invocations(&capped, 0).await?, Some(0));
    Ok(())
}

/// Counters left behind by a KMS that was downgraded and deleted keys are purged at the next
/// startup, so a reused UID does not inherit a stale count; counters of live objects survive.
pub(super) async fn gcm_invocations_orphan_purge_test<DB, F, Fut>(
    db: &DB,
    reopen: F,
) -> DbResult<()>
where
    DB: ObjectsStore,
    F: FnOnce() -> Fut,
    Fut: Future<Output = DbResult<DB>>,
{
    log_init(None);
    let key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &[7_u8; 32],
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    let live_uid = Uuid::new_v4().to_string();
    db.create(
        Some(live_uid.clone()),
        &UserId::from("orphan_purge_owner"),
        &key,
        key.attributes()?,
        &HashSet::new(),
    )
    .await?;
    let orphan_uid = Uuid::new_v4().to_string();
    assert_eq!(db.reserve_gcm_invocations(&orphan_uid, 5).await?, Some(5));
    assert_eq!(db.reserve_gcm_invocations(&live_uid, 5).await?, Some(5));

    let reopened = reopen().await?;
    assert_eq!(
        reopened.reserve_gcm_invocations(&orphan_uid, 0).await?,
        Some(0)
    );
    assert_eq!(
        reopened.reserve_gcm_invocations(&live_uid, 0).await?,
        Some(5)
    );
    reopened.delete(&live_uid).await?;
    Ok(())
}

/// Lifecycle-state contract every multi-region-capable backend (`MainDbParams::supports_multi_region`)
/// must hold; SQLite and Redis keep blind writes and do not run it.
pub(super) async fn lifecycle_state_contract_test<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);

    let owner = UserId::from("lifecycle_contract_user");
    let key_obj = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &[0_u8; 32],
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )
    .map_err(|e| DbError::DatabaseError(e.to_string()))?;
    let key_json = serde_json::to_string(&key_obj)?;
    let zeroized = super::zeroized_copy(&key_obj)?;
    let zeroized_json = serde_json::to_string(&zeroized)?;
    let attrs = Attributes::default();

    let new_object = || async {
        db.create(None, &owner, &key_obj, &attrs, &HashSet::new())
            .await
    };
    let expect_state = |label: &str, got: Option<(State, Attributes)>, want: State| {
        if got.map(|(state, _)| state) == Some(want) {
            Ok(())
        } else {
            Err(DbError::ServerError(format!("{label}: expected {want:?}")))
        }
    };
    let expect_json = |label: &str, got: Option<ObjectWithMetadata>, want: &str| {
        let stored = got
            .ok_or_else(|| DbError::ServerError(format!("{label}: object missing")))
            .and_then(|owm| Ok(serde_json::to_string(owm.object())?))?;
        if stored == want {
            Ok(())
        } else {
            Err(DbError::ServerError(format!("{label}: unexpected payload")))
        }
    };
    // a Destroyed object whose payload is zeroized (the order `destroy` uses)
    let destroyed_object = || async {
        let uid = new_object().await?;
        db.atomic(
            &owner,
            &[
                AtomicOperation::UpdateObject((uid.clone(), zeroized.clone(), attrs.clone(), None)),
                AtomicOperation::UpdateState((uid.clone(), State::Destroyed)),
            ],
        )
        .await?;
        Ok::<_, DbError>(uid)
    };

    // a) a write planned on a stale read never regresses the state
    let uid = new_object().await?;
    db.update_state(&uid, State::Active).await?;
    db.update_state(&uid, State::PreActive).await?;
    expect_state("a1", db.retrieve_state(&uid).await?, State::Active)?;
    db.update_state(&uid, State::Deactivated).await?;
    db.update_state(&uid, State::Active).await?;
    expect_state("a2", db.retrieve_state(&uid).await?, State::Deactivated)?;

    // b) a compromise is never forgotten
    let uid = new_object().await?;
    db.update_state(&uid, State::Compromised).await?;
    db.update_state(&uid, State::Destroyed).await?;
    expect_state(
        "b1",
        db.retrieve_state(&uid).await?,
        State::Destroyed_Compromised,
    )?;
    db.update_state(&uid, State::Active).await?;
    expect_state(
        "b2",
        db.retrieve_state(&uid).await?,
        State::Destroyed_Compromised,
    )?;

    // c) an explicit downgrade replaces the state
    let uid = new_object().await?;
    db.update_state(&uid, State::Active).await?;
    db.update_state_allow_downgrade(&uid, State::PreActive)
        .await?;
    expect_state("c", db.retrieve_state(&uid).await?, State::PreActive)?;

    // d) a payload write cannot bring key material back on a Destroyed object
    let uid = destroyed_object().await?;
    db.update_object(&uid, &key_obj, &attrs, None).await?;
    expect_state("d", db.retrieve_state(&uid).await?, State::Destroyed)?;
    expect_json("d", db.retrieve(&uid).await?, &zeroized_json)?;

    // e) batch UNDO order: reset the state, then restore the payload
    db.update_state_allow_downgrade(&uid, State::Active).await?;
    db.update_object(&uid, &key_obj, &attrs, None).await?;
    expect_state("e", db.retrieve_state(&uid).await?, State::Active)?;
    expect_json("e", db.retrieve(&uid).await?, &key_json)?;

    // f) import replace may overwrite a Destroyed object
    let uid = destroyed_object().await?;
    db.atomic(
        &owner,
        &[AtomicOperation::Upsert((
            uid.clone(),
            key_obj.clone(),
            attrs.clone(),
            None,
            State::Active,
        ))],
    )
    .await?;
    expect_state("f", db.retrieve_state(&uid).await?, State::Active)?;
    expect_json("f", db.retrieve(&uid).await?, &key_json)?;

    Ok(())
}
