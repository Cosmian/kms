//! Characterization tests pinning the behaviour of `ObjectHandlesCache::new`
//! (capacity of the LRU caches) and its accessors.

use cosmian_kms_interfaces::{KeyType, SigningKeyMetadata};
use pkcs11_sys::CK_OBJECT_HANDLE;

use crate::ObjectHandlesCache;

fn key(i: u8) -> Vec<u8> {
    vec![i, 0xAB]
}

fn meta() -> SigningKeyMetadata {
    SigningKeyMetadata {
        key_type: KeyType::AesKey,
        curve: None,
    }
}

#[test]
fn characterization_object_handles_cache_new_handles_capacity_is_100() {
    let cache = ObjectHandlesCache::new();
    for i in 0_u8..100 {
        cache
            .insert(key(i), CK_OBJECT_HANDLE::from(i) + 1000)
            .unwrap();
    }
    // exactly 100 entries: none evicted
    assert_eq!(cache.get(&key(0)).unwrap(), Some(1000));
    assert_eq!(cache.get(&key(99)).unwrap(), Some(1099));
    // 101st insert evicts the least recently used one; key(0) was just read, so key(1) goes
    cache.insert(key(100), 2000).unwrap();
    assert_eq!(cache.get(&key(1)).unwrap(), None);
    assert_eq!(cache.get(&key(0)).unwrap(), Some(1000));
    assert_eq!(cache.get(&key(2)).unwrap(), Some(1002));
    assert_eq!(cache.get(&key(100)).unwrap(), Some(2000));
}

#[test]
fn characterization_object_handles_cache_default_handles_capacity_is_100() {
    let cache = ObjectHandlesCache::default();
    for i in 0_u8..101 {
        cache.insert(key(i), CK_OBJECT_HANDLE::from(i)).unwrap();
    }
    assert_eq!(cache.get(&key(0)).unwrap(), None);
    assert_eq!(cache.get(&key(1)).unwrap(), Some(1));
    assert_eq!(cache.get(&key(100)).unwrap(), Some(100));
}

#[test]
fn characterization_object_handles_cache_new_metadata_capacity_is_100() {
    let cache = ObjectHandlesCache::new();
    for i in 0_u8..100 {
        cache
            .insert_metadata(CK_OBJECT_HANDLE::from(i), meta())
            .unwrap();
    }
    assert_eq!(cache.get_metadata(5).unwrap(), Some(meta()));
    cache.insert_metadata(500, meta()).unwrap();
    // handle 0 was the least recently used (5 was refreshed)
    assert_eq!(cache.get_metadata(0).unwrap(), None);
    assert_eq!(cache.get_metadata(1).unwrap(), Some(meta()));
    assert_eq!(cache.get_metadata(5).unwrap(), Some(meta()));
    assert_eq!(cache.get_metadata(500).unwrap(), Some(meta()));
}

#[test]
fn characterization_object_handles_cache_remove_and_clear() {
    let cache = ObjectHandlesCache::new();
    cache.insert(key(1), 11).unwrap();
    cache.insert(key(2), 22).unwrap();
    cache.insert_metadata(11, meta()).unwrap();
    cache.insert_metadata(22, meta()).unwrap();
    // removing a handle also drops its metadata
    cache.remove(&key(1)).unwrap();
    assert_eq!(cache.get(&key(1)).unwrap(), None);
    assert_eq!(cache.get_metadata(11).unwrap(), None);
    assert_eq!(cache.get(&key(2)).unwrap(), Some(22));
    assert_eq!(cache.get_metadata(22).unwrap(), Some(meta()));
    // removing an unknown key is a no-op
    cache.remove(&key(9)).unwrap();
    cache.clear().unwrap();
    assert_eq!(cache.get(&key(2)).unwrap(), None);
    assert_eq!(cache.get_metadata(22).unwrap(), None);
}
