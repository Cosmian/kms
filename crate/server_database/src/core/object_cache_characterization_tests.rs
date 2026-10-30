//! Characterization tests pinning the BASE capacity / expiry behavior of [`ObjectCache::new`].

use std::{num::NonZeroUsize, time::Duration};

use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::{Object, OpaqueObject},
        kmip_types::OpaqueDataType,
    },
};
use cosmian_kms_interfaces::ObjectWithMetadata;

use super::ObjectCache;

fn make_owm(uid: &str) -> ObjectWithMetadata {
    ObjectWithMetadata::new(
        uid.to_owned(),
        Object::OpaqueObject(OpaqueObject {
            opaque_data_type: OpaqueDataType::Unknown,
            opaque_data_value: uid.as_bytes().to_vec(),
        }),
        "test-owner".to_owned(),
        State::Active,
        Attributes::default(),
    )
}

fn size(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap()
}

#[tokio::test]
async fn characterization_object_cache_new_capacity_is_max_size() {
    let cache = ObjectCache::new(Duration::from_secs(3600), size(2), None);
    for i in 0..10 {
        let uid = format!("uid-{i}");
        cache.insert(uid.clone(), make_owm(&uid)).await.unwrap();
    }
    cache.inner.run_pending_tasks().await;
    assert_eq!(cache.inner.entry_count(), 2);
}

#[tokio::test]
async fn characterization_object_cache_new_capacity_one() {
    let cache = ObjectCache::new(Duration::from_secs(3600), size(1), None);
    for i in 0..5 {
        let uid = format!("uid-{i}");
        cache.insert(uid.clone(), make_owm(&uid)).await.unwrap();
    }
    cache.inner.run_pending_tasks().await;
    assert_eq!(cache.inner.entry_count(), 1);
}

#[tokio::test]
async fn characterization_object_cache_new_large_capacity_keeps_all() {
    let cache = ObjectCache::new(Duration::from_secs(3600), size(usize::MAX), None);
    for i in 0..20 {
        let uid = format!("uid-{i}");
        cache.insert(uid.clone(), make_owm(&uid)).await.unwrap();
    }
    cache.inner.run_pending_tasks().await;
    assert_eq!(cache.inner.entry_count(), 20);
    for i in 0..20 {
        assert!(cache.get(&format!("uid-{i}")).await.is_some());
    }
}

#[tokio::test]
async fn characterization_object_cache_new_max_ttl_expires_hot_entry() {
    let cache = ObjectCache::new(
        Duration::from_secs(3600),
        size(100),
        Some(Duration::from_millis(300)),
    );
    cache
        .insert("hot".to_owned(), make_owm("hot"))
        .await
        .unwrap();
    assert!(cache.get("hot").await.is_some());
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(cache.get("hot").await.is_none());
}

#[tokio::test]
async fn characterization_object_cache_new_without_max_ttl_keeps_entry() {
    let cache = ObjectCache::new(Duration::from_secs(3600), size(100), None);
    cache
        .insert("cold".to_owned(), make_owm("cold"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(cache.get("cold").await.is_some());
}
