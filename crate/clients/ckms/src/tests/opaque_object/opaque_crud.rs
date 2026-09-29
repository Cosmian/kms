//! Opaque Object CRUD tests (CLI-level).
//!
//! Exercises the full lifecycle of an opaque object via the ckms binary:
//!   1. Create with inline data
//!   2. Export as JSON-TTLV
//!   3. Export as raw bytes
//!   4. Revoke
//!   5. Destroy

use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::utils::{extract_uids::extract_uid, owner_config, run_ckms},
};

/// Full CRUD lifecycle for an opaque object via the CLI.
#[tokio::test]
async fn test_opaque_object_crud() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    // 1. Create opaque object with inline data
    let output = run_ckms(
        &conf,
        &["opaque-object", "create", "--data", "opaque-bytes"],
    )?;
    let uid = extract_uid(&output, "Unique identifier").expect("Expected UID in create output");
    assert!(!uid.is_empty(), "Expected a non-empty UID from create");

    // 2. Export as JSON-TTLV
    let tmp_dir = tempfile::tempdir()?;
    let json_path = tmp_dir.path().join("opaque.json");
    run_ckms(
        &conf,
        &[
            "opaque-object",
            "export",
            json_path.to_str().unwrap(),
            "--key-id",
            uid,
            "--key-format",
            "json-ttlv",
        ],
    )?;
    assert!(json_path.exists(), "JSON-TTLV export file must exist");
    let json_content = std::fs::read_to_string(&json_path)?;
    assert!(
        json_content.contains("OpaqueObject") || json_content.contains("Opaque"),
        "Exported JSON should describe an OpaqueObject"
    );

    // 3. Export as raw bytes
    let raw_path = tmp_dir.path().join("opaque.raw");
    run_ckms(
        &conf,
        &[
            "opaque-object",
            "export",
            raw_path.to_str().unwrap(),
            "--key-id",
            uid,
            "--key-format",
            "raw",
        ],
    )?;
    let raw = std::fs::read(&raw_path)?;
    assert_eq!(
        raw, b"opaque-bytes",
        "Raw export should match original data"
    );

    // 4. Revoke
    run_ckms(
        &conf,
        &["opaque-object", "revoke", "test-revoke", "--key-id", uid],
    )?;

    // 5. Destroy
    run_ckms(&conf, &["opaque-object", "destroy", "--key-id", uid])?;

    Ok(())
}
