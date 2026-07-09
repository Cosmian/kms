use std::fs;

use cosmian_kms_cli_actions::reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::symmetric_utils::DataEncryptionAlgorithm;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::{
        symmetric::{
            create_key::create_symmetric_key,
            encrypt_decrypt::{decrypt, encrypt},
            rekey::rekey_symmetric_key,
        },
        utils::{owner_config, run_ckms, run_ckms_expect_error},
    },
};

/// Set the rotation policy for a symmetric key via the CLI.
pub(crate) fn set_rotation_policy(
    cli_conf_path: &str,
    key_id: &str,
    interval: i64,
    offset: Option<i64>,
    rotate_name: Option<&str>,
) -> CosmianResult<String> {
    let mut args = vec!["sym", "keys", "set-rotation-policy", "--key-id", key_id];
    let interval_str = interval.to_string();
    args.extend(["--interval", &interval_str]);
    let offset_str;
    if let Some(o) = offset {
        offset_str = o.to_string();
        args.extend(["--offset", &offset_str]);
    }
    if let Some(name) = rotate_name {
        args.extend(["--rotation-name", name]);
    }
    run_ckms(cli_conf_path, &args)
}

/// Get the rotation policy for a symmetric key via the CLI.
pub(crate) fn get_rotation_policy(cli_conf_path: &str, key_id: &str) -> CosmianResult<String> {
    let args = vec!["sym", "keys", "get-rotation-policy", "--key-id", key_id];
    run_ckms(cli_conf_path, &args)
}

#[tokio::test]
pub(crate) async fn test_set_and_get_rotation_policy() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create a symmetric key with the keyset name as UID
    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--number-of-bits", "256", "test-keyset"],
    )?;

    // Set rotation policy with interval, offset, and name
    let output = set_rotation_policy(
        &owner_client_conf_path,
        &key_id,
        86400,
        Some(3600),
        Some("test-keyset"),
    )?;
    assert!(output.contains("Rotation policy set successfully"));

    // Get rotation policy and verify
    let output = get_rotation_policy(&owner_client_conf_path, &key_id)?;
    assert!(
        output.contains("86400"),
        "expected interval=86400 in: {output}"
    );
    assert!(output.contains("3600"), "expected offset=3600 in: {output}");
    assert!(
        output.contains("test-keyset"),
        "expected name=test-keyset in: {output}"
    );

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_set_rotation_policy_name_rejects_at() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create a symmetric key
    let key_id = create_symmetric_key(&owner_client_conf_path, &["--number-of-bits", "256"])?;

    // Try to set rotation policy with a name containing '@' — should fail
    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &key_id,
        "--interval",
        "86400",
        "--rotation-name",
        "bad@name",
    ];
    let stderr = run_ckms_expect_error(&owner_client_conf_path, &args)?;
    assert!(
        stderr.contains('@'),
        "expected error mentioning '@' in: {stderr}"
    );

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_set_rotation_policy_interval_only() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create a symmetric key
    let key_id = create_symmetric_key(&owner_client_conf_path, &["--number-of-bits", "256"])?;

    // Set rotation policy with interval only (no offset, no name)
    let output = set_rotation_policy(&owner_client_conf_path, &key_id, 43200, None, None)?;
    assert!(output.contains("Rotation policy set successfully"));

    // Get rotation policy and verify
    let output = get_rotation_policy(&owner_client_conf_path, &key_id)?;
    assert!(
        output.contains("43200"),
        "expected interval=43200 in: {output}"
    );
    assert!(
        output.contains("not set") || !output.contains("offset"),
        "expected no offset set"
    );

    Ok(())
}

/// Full keyset workflow: create → set name → encrypt → rekey → decrypt via keyset name
#[tokio::test]
pub(crate) async fn test_keyset_workflow() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create AES-256 key with keyset name as UID
    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--number-of-bits", "256", "e2e-keyset"],
    )?;

    // Set rotation name (keyset) without interval
    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &key_id,
        "--rotation-name",
        "e2e-keyset",
    ];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(output.contains("Rotation policy set successfully"));

    // Encrypt a file using the keyset bare name
    let tmp_dir = TempDir::new()?;
    let input_file = tmp_dir.path().join("plain.txt");
    fs::write(&input_file, b"hello keyset rotation")?;
    let encrypted_file = tmp_dir.path().join("cipher.enc");

    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        "e2e-keyset",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(encrypted_file.to_str().unwrap()),
        None,
    )?;

    // ReKey: gen-0 → gen-1
    let _new_key_id = rekey_symmetric_key(&owner_client_conf_path, &key_id)?;

    // Decrypt via keyset bare name (should walk chain and find gen-0)
    let decrypted_file = tmp_dir.path().join("decrypted.txt");
    decrypt(
        &owner_client_conf_path,
        encrypted_file.to_str().unwrap(),
        "e2e-keyset",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(decrypted_file.to_str().unwrap()),
        None,
    )?;
    let decrypted = fs::read(&decrypted_file)?;
    assert_eq!(decrypted, b"hello keyset rotation");

    Ok(())
}

/// Encrypt with `name@first` after rotation: gen-0 is Deactivated per KMIP §4.57,
/// so encrypt MUST fail, but decrypt MUST still succeed.
#[tokio::test]
pub(crate) async fn test_keyset_encrypt_at_first() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--number-of-bits", "256", "kst-enc-first"],
    )?;

    // Set rotation name
    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &key_id,
        "--rotation-name",
        "kst-enc-first",
    ];
    run_ckms(&owner_client_conf_path, &args)?;

    // Encrypt with gen-0 BEFORE re-key (still Active)
    let tmp_dir = TempDir::new()?;
    let input_file = tmp_dir.path().join("plain.txt");
    fs::write(&input_file, b"first-gen-test")?;
    let encrypted_file = tmp_dir.path().join("cipher.enc");

    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        "kst-enc-first@first",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(encrypted_file.to_str().unwrap()),
        None,
    )?;

    // ReKey: gen-0 → gen-1 (gen-0 becomes Deactivated)
    let _new_key_id = rekey_symmetric_key(&owner_client_conf_path, &key_id)?;

    // Encrypt using @first AFTER re-key — must FAIL (gen-0 Deactivated)
    let input_file2 = tmp_dir.path().join("plain2.txt");
    fs::write(&input_file2, b"should-fail")?;
    let encrypted_file2 = tmp_dir.path().join("cipher2.enc");

    let result = encrypt(
        &owner_client_conf_path,
        input_file2.to_str().unwrap(),
        "kst-enc-first@first",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(encrypted_file2.to_str().unwrap()),
        None,
    );
    assert!(
        result.is_err(),
        "encrypt with @first after re-key must fail (gen-0 Deactivated)"
    );

    // Decrypt using @first AFTER re-key — must SUCCEED (Deactivated allows decrypt)
    let decrypted_file = tmp_dir.path().join("decrypted.txt");
    decrypt(
        &owner_client_conf_path,
        encrypted_file.to_str().unwrap(),
        "kst-enc-first@first",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(decrypted_file.to_str().unwrap()),
        None,
    )?;
    let decrypted = fs::read(&decrypted_file)?;
    assert_eq!(decrypted, b"first-gen-test");

    Ok(())
}

/// Encrypt with `name@0` after rotation: gen-0 is Deactivated per KMIP §4.57,
/// so encrypt MUST fail, but decrypt MUST still succeed.
#[tokio::test]
pub(crate) async fn test_keyset_encrypt_at_zero() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--number-of-bits", "256", "kst-enc-zero"],
    )?;

    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &key_id,
        "--rotation-name",
        "kst-enc-zero",
    ];
    run_ckms(&owner_client_conf_path, &args)?;

    // Encrypt with @0 BEFORE re-key (gen-0 still Active)
    let tmp_dir = TempDir::new()?;
    let input_file = tmp_dir.path().join("plain.txt");
    fs::write(&input_file, b"zero-gen-test")?;
    let encrypted_file = tmp_dir.path().join("cipher.enc");

    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        "kst-enc-zero@0",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(encrypted_file.to_str().unwrap()),
        None,
    )?;

    // ReKey: gen-0 → gen-1 (gen-0 becomes Deactivated)
    let _new_key_id = rekey_symmetric_key(&owner_client_conf_path, &key_id)?;

    // Encrypt using @0 AFTER re-key — must FAIL (gen-0 Deactivated)
    let input_file2 = tmp_dir.path().join("plain2.txt");
    fs::write(&input_file2, b"should-fail")?;
    let encrypted_file2 = tmp_dir.path().join("cipher2.enc");

    let result = encrypt(
        &owner_client_conf_path,
        input_file2.to_str().unwrap(),
        "kst-enc-zero@0",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(encrypted_file2.to_str().unwrap()),
        None,
    );
    assert!(
        result.is_err(),
        "encrypt with @0 after re-key must fail (gen-0 Deactivated)"
    );

    // Decrypt using @0 AFTER re-key — must SUCCEED (Deactivated allows decrypt)
    let decrypted_file = tmp_dir.path().join("decrypted.txt");
    decrypt(
        &owner_client_conf_path,
        encrypted_file.to_str().unwrap(),
        "kst-enc-zero@0",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(decrypted_file.to_str().unwrap()),
        None,
    )?;
    let decrypted = fs::read(&decrypted_file)?;
    assert_eq!(decrypted, b"zero-gen-test");

    Ok(())
}

/// Encrypt with `name@1` after double rotation: gen-1 is Deactivated per KMIP §4.57,
/// so encrypt MUST fail, but decrypt MUST still succeed.
#[tokio::test]
pub(crate) async fn test_keyset_encrypt_at_generation_n() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--number-of-bits", "256", "kst-enc-gen-n"],
    )?;

    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &key_id,
        "--rotation-name",
        "kst-enc-gen-n",
    ];
    run_ckms(&owner_client_conf_path, &args)?;

    // ReKey: gen-0 → gen-1
    let gen1_id = rekey_symmetric_key(&owner_client_conf_path, &key_id)?;

    // Encrypt using @1 BEFORE second re-key (gen-1 is Active/latest)
    let tmp_dir = TempDir::new()?;
    let input_file = tmp_dir.path().join("plain.txt");
    fs::write(&input_file, b"gen-1-test")?;
    let encrypted_file = tmp_dir.path().join("cipher.enc");

    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        "kst-enc-gen-n@1",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(encrypted_file.to_str().unwrap()),
        None,
    )?;

    // ReKey again: gen-1 → gen-2 (gen-1 becomes Deactivated)
    let _gen2_id = rekey_symmetric_key(&owner_client_conf_path, &gen1_id)?;

    // Encrypt using @1 AFTER second re-key — must FAIL (gen-1 Deactivated)
    let input_file2 = tmp_dir.path().join("plain2.txt");
    fs::write(&input_file2, b"should-fail")?;
    let encrypted_file2 = tmp_dir.path().join("cipher2.enc");

    let result = encrypt(
        &owner_client_conf_path,
        input_file2.to_str().unwrap(),
        "kst-enc-gen-n@1",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(encrypted_file2.to_str().unwrap()),
        None,
    );
    assert!(
        result.is_err(),
        "encrypt with @1 after second re-key must fail (gen-1 Deactivated)"
    );

    // Decrypt using @1 AFTER second re-key — must SUCCEED (Deactivated allows decrypt)
    let decrypted_file = tmp_dir.path().join("decrypted.txt");
    decrypt(
        &owner_client_conf_path,
        encrypted_file.to_str().unwrap(),
        "kst-enc-gen-n@1",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(decrypted_file.to_str().unwrap()),
        None,
    )?;
    let decrypted = fs::read(&decrypted_file)?;
    assert_eq!(decrypted, b"gen-1-test");

    Ok(())
}

/// Decrypt with `name@first` after rotation: resolves to gen-0
#[tokio::test]
pub(crate) async fn test_keyset_decrypt_at_first() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--number-of-bits", "256", "kst-dec-first"],
    )?;

    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &key_id,
        "--rotation-name",
        "kst-dec-first",
    ];
    run_ckms(&owner_client_conf_path, &args)?;

    // Encrypt with gen-0 UID
    let tmp_dir = TempDir::new()?;
    let input_file = tmp_dir.path().join("plain.txt");
    fs::write(&input_file, b"decrypt-first-test")?;
    let encrypted_file = tmp_dir.path().join("cipher.enc");

    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(encrypted_file.to_str().unwrap()),
        None,
    )?;

    // ReKey: gen-0 → gen-1
    let _new_key_id = rekey_symmetric_key(&owner_client_conf_path, &key_id)?;

    // Decrypt using @first — should resolve to gen-0
    let decrypted_file = tmp_dir.path().join("decrypted.txt");
    decrypt(
        &owner_client_conf_path,
        encrypted_file.to_str().unwrap(),
        "kst-dec-first@first",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(decrypted_file.to_str().unwrap()),
        None,
    )?;
    let decrypted = fs::read(&decrypted_file)?;
    assert_eq!(decrypted, b"decrypt-first-test");

    Ok(())
}

/// Decrypt with `name@0` after double rotation: resolves to gen-0
#[tokio::test]
pub(crate) async fn test_keyset_decrypt_at_generation_n() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--number-of-bits", "256", "kst-dec-gen-n"],
    )?;

    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &key_id,
        "--rotation-name",
        "kst-dec-gen-n",
    ];
    run_ckms(&owner_client_conf_path, &args)?;

    // Encrypt with gen-0 UID
    let tmp_dir = TempDir::new()?;
    let input_file = tmp_dir.path().join("plain.txt");
    fs::write(&input_file, b"decrypt-gen0-test")?;
    let encrypted_file = tmp_dir.path().join("cipher.enc");

    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        &key_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(encrypted_file.to_str().unwrap()),
        None,
    )?;

    // ReKey twice: gen-0 → gen-1 → gen-2
    let gen1_id = rekey_symmetric_key(&owner_client_conf_path, &key_id)?;
    let _gen2_id = rekey_symmetric_key(&owner_client_conf_path, &gen1_id)?;

    // Decrypt using @0 — should resolve to gen-0
    let decrypted_file = tmp_dir.path().join("decrypted.txt");
    decrypt(
        &owner_client_conf_path,
        encrypted_file.to_str().unwrap(),
        "kst-dec-gen-n@0",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(decrypted_file.to_str().unwrap()),
        None,
    )?;
    let decrypted = fs::read(&decrypted_file)?;
    assert_eq!(decrypted, b"decrypt-gen0-test");

    Ok(())
}

/// Encrypt with `name@99` — nonexistent generation — must fail
#[tokio::test]
pub(crate) async fn test_keyset_encrypt_at_invalid_generation() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--number-of-bits", "256", "kst-invalid-gen"],
    )?;

    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &key_id,
        "--rotation-name",
        "kst-invalid-gen",
    ];
    run_ckms(&owner_client_conf_path, &args)?;

    // Encrypt using @99 — generation doesn't exist
    let tmp_dir = TempDir::new()?;
    let input_file = tmp_dir.path().join("plain.txt");
    fs::write(&input_file, b"should-fail")?;
    let encrypted_file = tmp_dir.path().join("cipher.enc");

    let result = encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        "kst-invalid-gen@99",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(encrypted_file.to_str().unwrap()),
        None,
    );
    assert!(result.is_err(), "expected encrypt with @99 to fail");

    Ok(())
}

/// Attempting to re-key a non-latest keyset member is rejected
#[tokio::test]
pub(crate) async fn test_rekey_non_latest_rejected() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create AES-256 key with keyset name as UID
    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--number-of-bits", "256", "e2e-nlat"],
    )?;

    // Set rotation name (keyset) without interval
    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &key_id,
        "--rotation-name",
        "e2e-nlat",
    ];
    run_ckms(&owner_client_conf_path, &args)?;

    // ReKey: gen-0 → gen-1
    let _new_key_id = rekey_symmetric_key(&owner_client_conf_path, &key_id)?;

    // Attempt to re-key gen-0 (now non-latest, Deactivated) via @first — should fail
    let args = vec!["sym", "keys", "re-key", "--key-id", "e2e-nlat@first"];
    let stderr = run_ckms_expect_error(&owner_client_conf_path, &args)?;
    assert!(
        stderr.contains("not the latest"),
        "expected 'not the latest' error, got: {stderr}"
    );

    Ok(())
}

/// Full keyset lifecycle exercising KMIP §4.57 state enforcement across all
/// addressing forms: bare name, `@first`, `@0`, `@latest`, `@N`.
///
/// States tested: Active, Deactivated (via Re-Key), Compromised (via Revoke `KeyCompromise`).
/// Operations tested: Encrypt (protection op — Active only), Decrypt (processing op —
/// Active, Deactivated, Compromised).
#[tokio::test]
pub(crate) async fn test_keyset_full_lifecycle() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let tmp_dir = TempDir::new()?;
    let plaintext = b"lifecycle-test-data";

    // ── Step 1: Create AES-256 key with keyset name as UID ─────────────
    let gen0_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--number-of-bits", "256", "lc-keyset"],
    )?;

    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &gen0_id,
        "--rotation-name",
        "lc-keyset",
    ];
    run_ckms(&owner_client_conf_path, &args)?;

    // ── Step 2: Encrypt with gen-0 (Active) → OK ────────────────────────
    let input_file = tmp_dir.path().join("plain.txt");
    fs::write(&input_file, plaintext)?;
    let enc_gen0 = tmp_dir.path().join("enc_gen0.enc");

    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        "lc-keyset", // bare name → latest = gen-0
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(enc_gen0.to_str().unwrap()),
        None,
    )?;

    // ── Step 3: Re-Key gen-0 → gen-1 (gen-0 becomes Deactivated) ────────
    let gen1_id = rekey_symmetric_key(&owner_client_conf_path, &gen0_id)?;

    // ── Step 4: Encrypt with @0 (Deactivated) → FAIL ────────────────────
    let input_fail = tmp_dir.path().join("fail.txt");
    fs::write(&input_fail, b"should-fail")?;
    let enc_fail = tmp_dir.path().join("enc_fail.enc");

    let result = encrypt(
        &owner_client_conf_path,
        input_fail.to_str().unwrap(),
        "lc-keyset@0",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(enc_fail.to_str().unwrap()),
        None,
    );
    assert!(
        result.is_err(),
        "encrypt with @0 must fail (gen-0 Deactivated)"
    );

    // @first — same result
    let result = encrypt(
        &owner_client_conf_path,
        input_fail.to_str().unwrap(),
        "lc-keyset@first",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(enc_fail.to_str().unwrap()),
        None,
    );
    assert!(
        result.is_err(),
        "encrypt with @first must fail (gen-0 Deactivated)"
    );

    // ── Step 5: Decrypt with @0 (Deactivated) → OK ──────────────────────
    let dec_gen0 = tmp_dir.path().join("dec_gen0.txt");
    decrypt(
        &owner_client_conf_path,
        enc_gen0.to_str().unwrap(),
        "lc-keyset@0",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(dec_gen0.to_str().unwrap()),
        None,
    )?;
    assert_eq!(fs::read(&dec_gen0)?, plaintext);

    // @first — same result
    let dec_gen0_first = tmp_dir.path().join("dec_gen0_first.txt");
    decrypt(
        &owner_client_conf_path,
        enc_gen0.to_str().unwrap(),
        "lc-keyset@first",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(dec_gen0_first.to_str().unwrap()),
        None,
    )?;
    assert_eq!(fs::read(&dec_gen0_first)?, plaintext);

    // ── Step 6: Encrypt with gen-1 (Active) via multiple addressing forms ─
    let enc_gen1 = tmp_dir.path().join("enc_gen1.enc");
    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        "lc-keyset", // bare name → latest = gen-1
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(enc_gen1.to_str().unwrap()),
        None,
    )?;

    let enc_gen1_latest = tmp_dir.path().join("enc_gen1_latest.enc");
    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        "lc-keyset@latest",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(enc_gen1_latest.to_str().unwrap()),
        None,
    )?;

    let enc_gen1_at1 = tmp_dir.path().join("enc_gen1_at1.enc");
    encrypt(
        &owner_client_conf_path,
        input_file.to_str().unwrap(),
        "lc-keyset@1",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(enc_gen1_at1.to_str().unwrap()),
        None,
    )?;

    // Verify all gen-1 ciphertexts decrypt correctly
    let dec_gen1 = tmp_dir.path().join("dec_gen1.txt");
    decrypt(
        &owner_client_conf_path,
        enc_gen1.to_str().unwrap(),
        &gen1_id,
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(dec_gen1.to_str().unwrap()),
        None,
    )?;
    assert_eq!(fs::read(&dec_gen1)?, plaintext);

    // ── Step 7: Revoke gen-1 with KeyCompromise → Compromised ───────────
    run_ckms(
        &owner_client_conf_path,
        &[
            "sym",
            "keys",
            "revoke",
            "--key-id",
            &gen1_id,
            "--reason-code",
            "key-compromise",
            "compromised for lifecycle testing",
        ],
    )?;

    // ── Step 8: Encrypt with @1 (Compromised) → FAIL ────────────────────
    let result = encrypt(
        &owner_client_conf_path,
        input_fail.to_str().unwrap(),
        "lc-keyset@1",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(enc_fail.to_str().unwrap()),
        None,
    );
    assert!(
        result.is_err(),
        "encrypt with @1 must fail (gen-1 Compromised)"
    );

    // bare name (latest = gen-1, Compromised) → also FAIL
    let result = encrypt(
        &owner_client_conf_path,
        input_fail.to_str().unwrap(),
        "lc-keyset",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(enc_fail.to_str().unwrap()),
        None,
    );
    assert!(
        result.is_err(),
        "encrypt with bare name must fail (latest gen-1 Compromised)"
    );

    // ── Step 9: Decrypt with @1 (Compromised) → OK ──────────────────────
    let dec_gen1_comp = tmp_dir.path().join("dec_gen1_comp.txt");
    decrypt(
        &owner_client_conf_path,
        enc_gen1.to_str().unwrap(),
        "lc-keyset@1",
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(dec_gen1_comp.to_str().unwrap()),
        None,
    )?;
    assert_eq!(fs::read(&dec_gen1_comp)?, plaintext);

    // ── Step 10: Decrypt wrong key → crypto error ───────────────────────
    let dec_wrong = tmp_dir.path().join("dec_wrong.txt");
    let result = decrypt(
        &owner_client_conf_path,
        enc_gen0.to_str().unwrap(),
        "lc-keyset@1", // gen-0 ciphertext, gen-1 key
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(dec_wrong.to_str().unwrap()),
        None,
    );
    assert!(
        result.is_err(),
        "decrypt with wrong generation key must fail"
    );

    // ── Step 11: Decrypt via bare name (TryEach) finds correct key ──────
    let dec_bare = tmp_dir.path().join("dec_bare.txt");
    decrypt(
        &owner_client_conf_path,
        enc_gen0.to_str().unwrap(),
        "lc-keyset", // bare name walks chain → finds gen-0
        DataEncryptionAlgorithm::AesGcm,
        None,
        Some(dec_bare.to_str().unwrap()),
        None,
    )?;
    assert_eq!(fs::read(&dec_bare)?, plaintext);

    Ok(())
}
