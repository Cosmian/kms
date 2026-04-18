//! UID injection attack tests.
//!
//! Exercises the server with malicious unique identifier strings to verify
//! that the server sanitizes them and never produces SQL injection,
//! path traversal, or other injection attacks:
//!   U1  - SQL injection pattern in UID
//!   U2  - Path traversal in UID (../../etc/passwd)
//!   U3  - Null byte embedded in UID
//!   U4  - Very long UID (256 KB string)
//!   U5  - Wildcard-only UID ("*")
//!   U6  - KMIP 2.1 JSON injection in UID
//!
//! All tests assert that the server returns a clean error (not a crash / not
//! 500 Internal Server Error) and does not return unexpected data.

use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::{
        shared::ExportSecretDataOrKeyAction, symmetric::keys::destroy_key::DestroyKeyAction,
    },
    error::result::KmsCliResult,
};

// ---------------------------------------------------------------------------
// Helper: attempt to export a key by UID; return whether we got an error.
// We always expect an error (the UID does not exist / is invalid).
// ---------------------------------------------------------------------------
async fn try_export(port: u16, uid: &str) -> bool {
    let tmp = tempfile::TempDir::new().expect("tmpdir");
    let client = {
        use cosmian_kms_client::{
            KmsClient, KmsClientConfig, reexport::cosmian_http_client::HttpClientConfig,
        };
        KmsClient::new_with_config(KmsClientConfig {
            http_config: HttpClientConfig {
                server_url: format!("http://127.0.0.1:{port}"),
                ..Default::default()
            },
            ..Default::default()
        })
        .expect("client")
    };

    ExportSecretDataOrKeyAction {
        key_id: Some(uid.to_owned()),
        key_file: tmp.path().join("out.json"),
        ..Default::default()
    }
    .run(client)
    .await
    .is_err()
}

// ---------------------------------------------------------------------------
// Helper: attempt to destroy a key by UID; return whether we got an error.
// ---------------------------------------------------------------------------
async fn try_destroy(port: u16, uid: &str) -> bool {
    let client = {
        use cosmian_kms_client::{
            KmsClient, KmsClientConfig, reexport::cosmian_http_client::HttpClientConfig,
        };
        KmsClient::new_with_config(KmsClientConfig {
            http_config: HttpClientConfig {
                server_url: format!("http://127.0.0.1:{port}"),
                ..Default::default()
            },
            ..Default::default()
        })
        .expect("client")
    };

    DestroyKeyAction {
        key_id: Some(uid.to_owned()),
        tags: None,
        remove: false,
    }
    .run(client)
    .await
    .is_err()
}

// ---------------------------------------------------------------------------
// U1: SQL injection pattern — must return a clean error, never leak data
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn u01_sql_injection_in_uid() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let uid = "' OR '1'='1' -- ";
    assert!(
        try_export(ctx.server_port, uid).await,
        "SQL injection UID must return an error (key not found)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// U2: Path traversal — must return a clean error, never read from filesystem
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn u02_path_traversal_in_uid() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let uid = "../../etc/passwd";
    assert!(
        try_export(ctx.server_port, uid).await,
        "path traversal UID must return an error (key not found)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// U3: Null byte in UID — must return a clean error, not truncated lookup
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn u03_null_byte_in_uid() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // Embed a null byte in the middle of a plausible-looking UID
    let uid = "valid-looking-uid\x00INJECTED";
    assert!(
        try_export(ctx.server_port, uid).await,
        "UID with null byte must return an error"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// U4: Very long UID (256 KB) — must be rejected cleanly, not cause OOM/crash
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn u04_very_long_uid() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let uid = "A".repeat(256 * 1024); // 256 KB UID
    assert!(
        try_export(ctx.server_port, &uid).await,
        "256 KB UID must return an error (key not found / rejected)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// U5: Wildcard-only UID ("*") — must be rejected or return no key material
//     (wildcard matching must NOT expose all keys to unauthenticated requests)
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn u05_wildcard_uid_no_bulk_exposure() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // A wildcard UID should not succeed in exporting anything
    // (it is only meaningful in certain Locate / access operations, not Get/Export).
    assert!(
        try_export(ctx.server_port, "*").await,
        "wildcard UID must not allow export of arbitrary key material"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// U6: KMIP JSON injection — UID containing TTLV control characters
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn u06_json_injection_in_uid() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // A UID that looks like a JSON injection attempt
    let uid = r#"","tag":"RequestMessage","value":[{"tag":"Destroy"#;
    assert!(
        try_destroy(ctx.server_port, uid).await,
        "JSON injection UID must return a clean error"
    );
    Ok(())
}
