use std::fs;

use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::utils::{
        ckms_bin,
        extract_uids::{extract_private_key, extract_public_key, extract_unique_identifier},
        owner_config, recover_cmd_logs, run_ckms, run_ckms_expect_error,
    },
};

/// Create an EC P-256 keypair whose private key UID equals `key_id`.
/// Returns `(private_key_id, public_key_id)`.
fn create_ec_keypair_with_id(cli_conf_path: &str, key_id: &str) -> CosmianResult<(String, String)> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND)
        .args(["keys", "create", "--curve", "nist-p256", key_id]);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let stdout = std::str::from_utf8(&output.stdout)?;
        let sk = extract_private_key(stdout)
            .ok_or_else(|| CosmianError::Default("failed extracting private key".to_owned()))?
            .to_owned();
        let pk = extract_public_key(stdout)
            .ok_or_else(|| CosmianError::Default("failed extracting public key".to_owned()))?
            .to_owned();
        return Ok((sk, pk));
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Rekey the EC keypair identified by `private_key_id`.
/// Returns the new private key UID.
fn rekey_ec_keypair(cli_conf_path: &str, private_key_id: &str) -> CosmianResult<String> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND)
        .args(["keys", "re-key", "--key-id", private_key_id]);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let stdout = std::str::from_utf8(&output.stdout)?;
        let uid = extract_unique_identifier(stdout)
            .ok_or_else(|| CosmianError::Default("failed extracting new key UID".to_owned()))?
            .to_owned();
        return Ok(uid);
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Sign `input_file` with `key_id` (private key).
/// Returns an error string on failure.
fn ec_sign(
    cli_conf_path: &str,
    input_file: &str,
    key_id: &str,
    output_file: &str,
) -> CosmianResult<()> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND)
        .args(["sign", input_file, "--key-id", key_id, "-o", output_file]);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Verify `sig_file` over `data_file` using `key_id` (public key).
/// Returns an error string on failure.
fn ec_verify(
    cli_conf_path: &str,
    data_file: &str,
    sig_file: &str,
    key_id: &str,
) -> CosmianResult<()> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND)
        .args(["sign-verify", data_file, sig_file, "--key-id", key_id]);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let stdout = std::str::from_utf8(&output.stdout)?;
        assert!(stdout.contains("Signature verification is Valid"));
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_ec_set_and_get_rotation_policy() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create an EC keypair whose UID equals the keyset name
    let (private_key_id, _public_key_id) =
        create_ec_keypair_with_id(&owner_client_conf_path, "ec-keyset")?;
    assert_eq!(private_key_id, "ec-keyset");

    // Set rotation policy — rotation-name must equal private key UID
    let args = vec![
        "ec",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &private_key_id,
        "--interval",
        "172800",
        "--rotation-name",
        "ec-keyset",
    ];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(
        output.contains("Rotation policy set successfully"),
        "expected success message in: {output}"
    );

    // Get rotation policy and verify
    let args = vec![
        "ec",
        "keys",
        "get-rotation-policy",
        "--key-id",
        &private_key_id,
    ];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(
        output.contains("172800"),
        "expected interval=172800 in: {output}"
    );
    assert!(
        output.contains("ec-keyset"),
        "expected name=ec-keyset in: {output}"
    );

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_ec_rekey() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create an EC keypair whose UID equals the keyset name
    let (private_key_id, _public_key_id) =
        create_ec_keypair_with_id(&owner_client_conf_path, "ec-rekey-test")?;

    // Set rotation policy — rotation-name must equal private key UID
    run_ckms(
        &owner_client_conf_path,
        &[
            "ec",
            "keys",
            "set-rotation-policy",
            "--key-id",
            &private_key_id,
            "--rotation-name",
            "ec-rekey-test",
        ],
    )?;

    // Re-Key the EC key pair
    let gen1_id = rekey_ec_keypair(&owner_client_conf_path, &private_key_id)?;
    assert!(
        gen1_id.contains("ec-rekey-test"),
        "new key UID should contain keyset name, got: {gen1_id}"
    );

    Ok(())
}

/// Full EC keyset lifecycle test — KMIP §4.57 state enforcement across all
/// addressing forms.
///
/// Sign (protection op — Active only) and Verify (processing op — Active,
/// Deactivated, and Compromised).
#[tokio::test]
pub(crate) async fn test_ec_keyset_full_lifecycle() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let tmp_dir = TempDir::new()?;
    let data_file = tmp_dir.path().join("data.txt");
    let plaintext = b"ec-lifecycle-test-data";
    fs::write(&data_file, plaintext)?;

    // ── Step 1: Create EC keypair with UID = keyset name ────────────────
    let (gen0_sk_id, gen0_pk_id) =
        create_ec_keypair_with_id(&owner_client_conf_path, "ec-lc-keyset")?;
    assert_eq!(gen0_sk_id, "ec-lc-keyset");
    assert_eq!(gen0_pk_id, "ec-lc-keyset_pk");

    run_ckms(
        &owner_client_conf_path,
        &[
            "ec",
            "keys",
            "set-rotation-policy",
            "--key-id",
            &gen0_sk_id,
            "--rotation-name",
            "ec-lc-keyset",
        ],
    )?;

    // ── Step 2: Sign with gen-0 (Active) → OK ───────────────────────────
    let sig_gen0 = tmp_dir.path().join("sig_gen0.sig");
    ec_sign(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        "ec-lc-keyset", // bare name → gen-0 private key
        sig_gen0.to_str().unwrap(),
    )?;

    // ── Step 3: Re-Key gen-0 → gen-1 (gen-0 private key Deactivated) ────
    let gen1_sk_id = rekey_ec_keypair(&owner_client_conf_path, &gen0_sk_id)?;
    let gen1_pk_id = format!("{gen1_sk_id}_pk");

    // ── Step 4: Sign with @0 (Deactivated private key) → FAIL ──────────
    let sig_fail = tmp_dir.path().join("sig_fail.sig");
    let result = ec_sign(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        "ec-lc-keyset@0",
        sig_fail.to_str().unwrap(),
    );
    assert!(
        result.is_err(),
        "Sign with gen-0 private key must fail (Deactivated)"
    );

    // ── Step 5: Verify with gen-0 public key (Deactivated) → OK ─────────
    // The old gen-0 public key keeps its original UID (ec-lc-keyset_pk) after
    // rekey — only the new generation gets an @N suffix.
    // Verify is a processing op; Deactivated keys are allowed.
    ec_verify(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        sig_gen0.to_str().unwrap(),
        &gen0_pk_id, // "ec-lc-keyset_pk"
    )?;

    // ── Step 6: Sign with bare name (→ gen-1, Active) → OK ──────────────
    let sig_gen1 = tmp_dir.path().join("sig_gen1.sig");
    ec_sign(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        "ec-lc-keyset", // bare name → latest = gen-1
        sig_gen1.to_str().unwrap(),
    )?;

    // ── Step 7: Verify gen-1 signature with gen-1 public key → OK ───────
    ec_verify(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        sig_gen1.to_str().unwrap(),
        &gen1_pk_id,
    )?;

    // ── Step 8: Revoke gen-1 private key with KeyCompromise → Compromised
    run_ckms(
        &owner_client_conf_path,
        &[
            "ec",
            "keys",
            "revoke",
            "--key-id",
            &gen1_sk_id,
            "--reason-code",
            "key-compromise",
            "compromised for lifecycle testing",
        ],
    )?;

    // ── Step 9: Sign with gen-1 (Compromised) → FAIL ────────────────────
    let sig_comp = tmp_dir.path().join("sig_comp.sig");
    let result = ec_sign(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        &gen1_sk_id,
        sig_comp.to_str().unwrap(),
    );
    assert!(
        result.is_err(),
        "Sign with Compromised gen-1 private key must fail"
    );

    // Sign with bare name also fails (latest = gen-1, Compromised)
    let result = ec_sign(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        "ec-lc-keyset",
        sig_comp.to_str().unwrap(),
    );
    assert!(
        result.is_err(),
        "Sign with bare name must fail (gen-1 Compromised)"
    );

    // ── Step 10: Verify gen-1 signature with Compromised public key → OK ─
    // Verify is a processing op; Compromised keys are allowed.
    ec_verify(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        sig_gen1.to_str().unwrap(),
        &gen1_pk_id,
    )?;

    // ── Step 11: Attempting to re-key non-latest (gen-0 via @first) → FAIL
    let stderr = run_ckms_expect_error(
        &owner_client_conf_path,
        &["ec", "keys", "re-key", "--key-id", "ec-lc-keyset@first"],
    )?;
    assert!(
        stderr.contains("not the latest"),
        "expected 'not the latest' error, got: {stderr}"
    );

    Ok(())
}
