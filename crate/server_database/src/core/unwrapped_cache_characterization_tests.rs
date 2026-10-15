//! Characterization tests pinning the BASE capacity / expiry / disabled behavior of
//! [`UnwrappedCache::new`].

use std::{num::NonZeroUsize, time::Duration};

use cosmian_kmip::kmip_2_1::{
    extra::VENDOR_ID_COSMIAN, kmip_attributes::Attributes, kmip_objects::Object,
    kmip_types::CryptographicAlgorithm, requests::create_symmetric_key_kmip_object,
};

use super::UnwrappedCache;

fn size(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap()
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

#[tokio::test]
async fn characterization_unwrapped_cache_new_capacity_is_max_size() {
    let cache = UnwrappedCache::new(Duration::from_secs(3600), size(2), None, false);
    let wrapped = key(1);
    for i in 0..10_u8 {
        cache
            .insert(format!("uid-{i}"), &wrapped, key(i.saturating_add(10)))
            .await
            .unwrap();
    }
    cache.inner.run_pending_tasks().await;
    assert_eq!(cache.inner.entry_count(), 2);
}

#[tokio::test]
async fn characterization_unwrapped_cache_new_capacity_one() {
    let cache = UnwrappedCache::new(Duration::from_secs(3600), size(1), None, false);
    let wrapped = key(1);
    for i in 0..5_u8 {
        cache
            .insert(format!("uid-{i}"), &wrapped, key(i.saturating_add(10)))
            .await
            .unwrap();
    }
    cache.inner.run_pending_tasks().await;
    assert_eq!(cache.inner.entry_count(), 1);
}

#[tokio::test]
async fn characterization_unwrapped_cache_new_large_capacity_keeps_all() {
    let cache = UnwrappedCache::new(Duration::from_secs(3600), size(usize::MAX), None, false);
    let wrapped = key(1);
    for i in 0..20_u8 {
        cache
            .insert(format!("uid-{i}"), &wrapped, key(i.saturating_add(10)))
            .await
            .unwrap();
    }
    cache.inner.run_pending_tasks().await;
    assert_eq!(cache.inner.entry_count(), 20);
}

#[tokio::test]
async fn characterization_unwrapped_cache_new_disabled_is_noop() {
    let cache = UnwrappedCache::new(Duration::from_secs(3600), size(100), None, true);
    let wrapped = key(1);
    // insert is a silent no-op, even for identical wrapped/unwrapped objects
    cache
        .insert("uid".to_owned(), &wrapped, key(2))
        .await
        .unwrap();
    cache
        .insert("same".to_owned(), &wrapped, wrapped.clone())
        .await
        .unwrap();
    cache.inner.run_pending_tasks().await;
    assert_eq!(cache.inner.entry_count(), 0);
    assert!(cache.peek("uid", &wrapped).await.unwrap().is_none());
}

#[tokio::test]
async fn characterization_unwrapped_cache_new_enabled_roundtrip() {
    let cache = UnwrappedCache::new(Duration::from_secs(3600), size(100), None, false);
    let wrapped = key(1);
    let unwrapped = key(2);
    cache
        .insert("uid".to_owned(), &wrapped, unwrapped.clone())
        .await
        .unwrap();
    assert_eq!(cache.peek("uid", &wrapped).await.unwrap(), Some(unwrapped));
    // a different wrapped object (other fingerprint) must not be answered
    assert!(cache.peek("uid", &key(3)).await.unwrap().is_none());
    let err = cache
        .insert("same".to_owned(), &wrapped, wrapped.clone())
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "Unwrapped cache error: wrapped and unwrapped objects should be different"
    );
}

#[tokio::test]
async fn characterization_unwrapped_cache_new_max_ttl_expires_hot_entry() {
    let cache = UnwrappedCache::new(
        Duration::from_secs(3600),
        size(100),
        Some(Duration::from_millis(300)),
        false,
    );
    let wrapped = key(1);
    cache
        .insert("hot".to_owned(), &wrapped, key(2))
        .await
        .unwrap();
    assert!(cache.peek("hot", &wrapped).await.unwrap().is_some());
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(cache.peek("hot", &wrapped).await.unwrap().is_none());
}

#[tokio::test]
async fn characterization_unwrapped_cache_new_without_max_ttl_keeps_entry() {
    let cache = UnwrappedCache::new(Duration::from_secs(3600), size(100), None, false);
    let wrapped = key(1);
    cache
        .insert("cold".to_owned(), &wrapped, key(2))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(cache.peek("cold", &wrapped).await.unwrap().is_some());
}
