//! UID injection attack tests (CLI-level).
//!
//! Exercises the server via the ckms binary with malicious unique identifier
//! strings to verify the server sanitizes them properly:
//!   U1  - SQL injection pattern in UID
//!   U2  - Path traversal in UID (../../etc/passwd)
//!   U5  - Wildcard-only UID ("*")
//!   U6  - KMIP JSON injection in UID
//!
//! Note: Null byte (U3) and 256KB UID (U4) cannot be tested via CLI arguments
//! due to OS limitations on argument passing. Those remain in the action-level tests.

use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::utils::{owner_config, run_ckms_expect_error},
};

/// U1: SQL injection pattern — must return a clean error
#[tokio::test]
async fn u01_sql_injection_in_uid() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    let uid = "' OR '1'='1' -- ";

    let result = run_ckms_expect_error(&conf, &["sym", "keys", "export", path, "-k", uid]);
    assert!(
        result.is_ok(),
        "SQL injection UID must return an error (key not found)"
    );

    Ok(())
}

/// U2: Path traversal — must return a clean error
#[tokio::test]
async fn u02_path_traversal_in_uid() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    let uid = "../../etc/passwd";

    let result = run_ckms_expect_error(&conf, &["sym", "keys", "export", path, "-k", uid]);
    assert!(
        result.is_ok(),
        "path traversal UID must return an error (key not found)"
    );

    Ok(())
}

/// U5: Wildcard-only UID — must be rejected, not expose all keys
#[tokio::test]
async fn u05_wildcard_uid_no_bulk_exposure() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();

    let result = run_ckms_expect_error(&conf, &["sym", "keys", "export", path, "-k", "*"]);
    assert!(
        result.is_ok(),
        "wildcard UID must not allow export of arbitrary key material"
    );

    Ok(())
}

/// U6: KMIP JSON injection — UID containing control characters
#[tokio::test]
async fn u06_json_injection_in_uid() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let uid = r#"","tag":"RequestMessage","value":[{"tag":"Destroy"#;

    let result = run_ckms_expect_error(&conf, &["sym", "keys", "destroy", "-k", uid]);
    assert!(
        result.is_ok(),
        "JSON injection UID must return a clean error"
    );

    Ok(())
}
