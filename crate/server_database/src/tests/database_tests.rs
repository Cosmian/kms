use std::collections::HashSet;

use cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, State},
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
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
use cosmian_kms_interfaces::{AtomicOperation, ObjectsStore, UserId};
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

    let mut rng = CsRng::from_entropy();
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
    atomic.unwrap_err();

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

pub(super) async fn upsert<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    log_init(None);

    let mut rng = CsRng::from_entropy();
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
    let make_key = |rng: &mut CsRng| -> DbResult<Object> {
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

    let mut rng = CsRng::from_entropy();

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
    let mut rng = CsRng::from_entropy();
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
