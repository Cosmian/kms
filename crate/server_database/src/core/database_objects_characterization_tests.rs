//! Characterization tests pinning the BASE behavior of `Database::atomic` and of the cache
//! parameters threaded through `Database::instantiate` (sqlite backend).

use std::{collections::HashMap, collections::HashSet, num::NonZeroUsize, time::Duration};

use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{
        extra::VENDOR_ID_COSMIAN, kmip_attributes::Attributes, kmip_objects::Object,
        kmip_types::CryptographicAlgorithm, requests::create_symmetric_key_kmip_object,
    },
};
use cosmian_kms_interfaces::{AtomicOperation, UserId};
use tempfile::TempDir;

use super::Database;
use crate::core::MainDbParams;

/// The ONLY place that calls `Database::instantiate` (its signature changes upstream).
async fn instantiate_db(
    max_age: Duration,
    max_size: usize,
    max_ttl: Option<Duration>,
    disabled: bool,
) -> (TempDir, Database) {
    let tmp = TempDir::new().unwrap();
    let db = Database::instantiate(
        &MainDbParams::Sqlite(tmp.path().to_path_buf(), None),
        false,
        HashMap::new(),
        max_age,
        NonZeroUsize::new(max_size).unwrap(),
        max_ttl,
        disabled,
        None,
        None,
    )
    .await
    .unwrap();
    (tmp, db)
}

async fn test_db() -> (TempDir, Database) {
    instantiate_db(Duration::from_secs(1), 100, None, false).await
}

fn key(fill: u8) -> Object {
    create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &[fill; 32],
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Attributes::default()
        },
    )
    .unwrap()
}

fn attrs(object: &Object) -> Attributes {
    object.attributes().unwrap().clone()
}

#[tokio::test]
async fn characterization_atomic_empty_operations_returns_empty_vec() {
    let (_tmp, db) = test_db().await;
    let owner = UserId::from("owner@example.com");
    let ids = db.atomic(&owner, &[]).await.unwrap();
    assert_eq!(ids, Vec::<String>::new());
}

#[tokio::test]
async fn characterization_atomic_empty_operations_on_fresh_db_leaves_it_empty() {
    let (_tmp, db) = test_db().await;
    let owner = UserId::from("owner@example.com");
    db.atomic(&owner, &[]).await.unwrap();
    assert_eq!(db.count_all_non_destroyed_objects().await.unwrap(), 0);
}

#[tokio::test]
async fn characterization_atomic_create_two_objects_returns_ids_in_order() {
    let (_tmp, db) = test_db().await;
    let owner = UserId::from("owner@example.com");
    let (k1, k2) = (key(1), key(2));
    let operations = vec![
        AtomicOperation::Create((
            "char-b".to_owned(),
            owner.clone(),
            k1.clone(),
            attrs(&k1),
            HashSet::new(),
        )),
        AtomicOperation::Create((
            "char-a".to_owned(),
            owner.clone(),
            k2.clone(),
            attrs(&k2),
            HashSet::from(["tag-1".to_owned()]),
        )),
    ];
    let ids = db.atomic(&owner, &operations).await.unwrap();
    assert_eq!(ids, vec!["char-b".to_owned(), "char-a".to_owned()]);

    let a = db.retrieve_object("char-a").await.unwrap().unwrap();
    assert_eq!(a.id(), "char-a");
    assert_eq!(a.owner(), "owner@example.com");
    assert_eq!(a.state(), State::PreActive);
    let b = db.retrieve_object("char-b").await.unwrap().unwrap();
    assert_eq!(b.id(), "char-b");
    assert_eq!(b.state(), State::PreActive);
    assert_eq!(db.count_all_non_destroyed_objects().await.unwrap(), 2);
}

#[tokio::test]
async fn characterization_atomic_mixed_operations_returns_ids_and_applies_effects() {
    let (_tmp, db) = test_db().await;
    let owner = UserId::from("owner@example.com");
    let (k1, k2, k3, k4) = (key(1), key(2), key(3), key(4));

    let ids = db
        .atomic(
            &owner,
            &[
                AtomicOperation::Create((
                    "char-1".to_owned(),
                    owner.clone(),
                    k1.clone(),
                    attrs(&k1),
                    HashSet::new(),
                )),
                AtomicOperation::Create((
                    "char-2".to_owned(),
                    owner.clone(),
                    k2.clone(),
                    attrs(&k2),
                    HashSet::new(),
                )),
            ],
        )
        .await
        .unwrap();
    assert_eq!(ids, vec!["char-1".to_owned(), "char-2".to_owned()]);

    // warm the object cache so that the atomic mutations must invalidate it
    let before = db.retrieve_object("char-1").await.unwrap().unwrap();
    assert_eq!(before.state(), State::PreActive);
    assert!(db.object_cache().get("char-1").await.is_some());

    let ids = db
        .atomic(
            &owner,
            &[
                AtomicOperation::UpdateState(("char-1".to_owned(), State::Active)),
                AtomicOperation::UpdateObject(("char-2".to_owned(), k4.clone(), attrs(&k4), None)),
                AtomicOperation::Upsert((
                    "char-3".to_owned(),
                    k3.clone(),
                    attrs(&k3),
                    Some(HashSet::new()),
                    State::Active,
                )),
                AtomicOperation::Delete("char-2".to_owned()),
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        ids,
        vec![
            "char-1".to_owned(),
            "char-2".to_owned(),
            "char-3".to_owned(),
            "char-2".to_owned()
        ]
    );

    assert!(db.object_cache().get("char-1").await.is_none());
    let after = db.retrieve_object("char-1").await.unwrap().unwrap();
    assert_eq!(after.state(), State::Active);
    assert!(db.retrieve_object("char-2").await.unwrap().is_none());
    let c3 = db.retrieve_object("char-3").await.unwrap().unwrap();
    assert_eq!(c3.state(), State::Active);
    assert_eq!(db.count_all_non_destroyed_objects().await.unwrap(), 2);
}

#[tokio::test]
async fn characterization_atomic_first_operation_selects_store_and_rejects_reserved_uid_anywhere() {
    let (_tmp, db) = test_db().await;
    let owner = UserId::from("owner@example.com");
    let k = key(5);
    let operations = vec![
        AtomicOperation::Delete("does-not-exist".to_owned()),
        AtomicOperation::Create((
            "*".to_owned(),
            owner.clone(),
            k.clone(),
            attrs(&k),
            HashSet::new(),
        )),
    ];
    let err = db.atomic(&owner, &operations).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "Invalid Request: '*' is a reserved identifier and cannot be used as an object unique identifier"
    );
}

#[tokio::test]
async fn characterization_instantiate_sqlite_disabled_unwrapped_cache() {
    let (_tmp, db) = instantiate_db(Duration::from_secs(3600), 100, None, true).await;
    let (wrapped, unwrapped) = (key(1), key(2));
    db.unwrapped_cache()
        .insert("uid".to_owned(), &wrapped, unwrapped)
        .await
        .unwrap();
    assert!(
        db.unwrapped_cache()
            .peek("uid", &wrapped)
            .await
            .unwrap()
            .is_none()
    );
    // the object cache is NOT affected by the `disabled` flag
    assert!(db.object_cache().get("uid").await.is_none());
}

#[tokio::test]
async fn characterization_instantiate_sqlite_enabled_unwrapped_cache() {
    let (_tmp, db) = instantiate_db(Duration::from_secs(3600), 100, None, false).await;
    let (wrapped, unwrapped) = (key(1), key(2));
    db.unwrapped_cache()
        .insert("uid".to_owned(), &wrapped, unwrapped.clone())
        .await
        .unwrap();
    assert_eq!(
        db.unwrapped_cache().peek("uid", &wrapped).await.unwrap(),
        Some(unwrapped)
    );
}

#[tokio::test]
async fn characterization_instantiate_sqlite_max_ttl_applies_to_both_caches() {
    let (_tmp, db) = instantiate_db(
        Duration::from_secs(3600),
        100,
        Some(Duration::from_millis(300)),
        false,
    )
    .await;
    let owner = UserId::from("owner@example.com");
    let k = key(1);
    db.create(
        Some("ttl-uid".to_owned()),
        &owner,
        &k,
        &attrs(&k),
        &HashSet::new(),
    )
    .await
    .unwrap();
    db.retrieve_object("ttl-uid").await.unwrap().unwrap();
    assert!(db.object_cache().get("ttl-uid").await.is_some());
    let (wrapped, unwrapped) = (key(1), key(2));
    db.unwrapped_cache()
        .insert("ttl-uid".to_owned(), &wrapped, unwrapped)
        .await
        .unwrap();
    assert!(
        db.unwrapped_cache()
            .peek("ttl-uid", &wrapped)
            .await
            .unwrap()
            .is_some()
    );

    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(db.object_cache().get("ttl-uid").await.is_none());
    assert!(
        db.unwrapped_cache()
            .peek("ttl-uid", &wrapped)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn characterization_instantiate_sqlite_without_max_ttl_keeps_entries() {
    let (_tmp, db) = instantiate_db(Duration::from_secs(3600), 100, None, false).await;
    let owner = UserId::from("owner@example.com");
    let k = key(1);
    db.create(
        Some("keep-uid".to_owned()),
        &owner,
        &k,
        &attrs(&k),
        &HashSet::new(),
    )
    .await
    .unwrap();
    db.retrieve_object("keep-uid").await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(db.object_cache().get("keep-uid").await.is_some());
}

#[tokio::test]
async fn characterization_instantiate_sqlite_main_db_kind() {
    let (_tmp, db) = test_db().await;
    assert_eq!(db.main_db_kind(), crate::MainDbKind::Sqlite);
}
