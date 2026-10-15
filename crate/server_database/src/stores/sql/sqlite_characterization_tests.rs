//! Characterization tests pinning the BASE round-robin reader selection of `SqlitePool`.

use std::{path::Path, sync::atomic::Ordering};

use tempfile::TempDir;

use super::SqlitePool;

#[tokio::test]
async fn characterization_sqlite_reader_round_robin_cycles_over_all_readers() {
    let tmp = TempDir::new().unwrap();
    let pool = SqlitePool::instantiate(&tmp.path().join("kms.db"), true, Some(3))
        .await
        .unwrap();
    assert_eq!(pool.readers.len(), 3);
    pool.reader_idx.store(0, Ordering::Relaxed);

    let expected = [0_usize, 1, 2, 0, 1, 2, 0];
    for want in expected {
        let got = pool.reader();
        assert!(std::ptr::eq(got, std::ptr::from_ref(&pool.readers[want])));
    }
    assert_eq!(pool.reader_idx.load(Ordering::Relaxed), 7);
}

#[tokio::test]
async fn characterization_sqlite_reader_single_reader_always_selected() {
    let tmp = TempDir::new().unwrap();
    let pool = SqlitePool::instantiate(Path::new(&tmp.path().join("kms.db")), true, Some(0))
        .await
        .unwrap();
    // `max_connections = 0` is clamped to one reader
    assert_eq!(pool.readers.len(), 1);
    for _ in 0..4 {
        assert!(std::ptr::eq(pool.reader(), pool.readers.first().unwrap()));
    }
}

#[tokio::test]
async fn characterization_sqlite_reader_counter_wraps_modulo_readers() {
    let tmp = TempDir::new().unwrap();
    let pool = SqlitePool::instantiate(&tmp.path().join("kms.db"), true, Some(4))
        .await
        .unwrap();
    // The counter wraps around usize::MAX: usize::MAX % 4 == 3, then wraps to 0.
    pool.reader_idx.store(usize::MAX, Ordering::Relaxed);
    assert!(std::ptr::eq(
        pool.reader(),
        std::ptr::from_ref(&pool.readers[3])
    ));
    assert!(std::ptr::eq(pool.reader(), pool.readers.first().unwrap()));
}
