//! Characterization tests: `sha256_file` digest and size for fixed contents.

use std::path::PathBuf;

use super::sha256_file;

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "kms_access_characterization_{name}_{}.bin",
        std::process::id()
    ))
}

#[test]
fn characterization_sha256_file_empty_file() {
    let path = scratch("empty");
    std::fs::write(&path, b"").unwrap();
    let result = sha256_file(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        result,
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
            0
        )
    );
}

#[test]
fn characterization_sha256_file_abc() {
    let path = scratch("abc");
    std::fs::write(&path, b"abc").unwrap();
    let result = sha256_file(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        result,
        (
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_owned(),
            3
        )
    );
}

#[test]
fn characterization_sha256_file_spans_multiple_read_chunks() {
    // 65_536-byte buffer: 65_537 bytes need two reads; 1_000_000 'a' is the classic SHA-256 vector.
    let path = scratch("million_a");
    std::fs::write(&path, vec![b'a'; 1_000_000]).unwrap();
    let result = sha256_file(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        result,
        (
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0".to_owned(),
            1_000_000
        )
    );
}

#[test]
fn characterization_sha256_file_missing_file_error() {
    let path = scratch("missing");
    std::fs::remove_file(&path).ok();
    let err = sha256_file(&path).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
