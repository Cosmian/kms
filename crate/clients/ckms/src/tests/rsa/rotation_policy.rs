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

/// Create a 2048-bit RSA keypair whose private key UID equals `key_id`.
/// Returns `(private_key_id, public_key_id)`.
fn create_rsa_keypair_with_id(
    cli_conf_path: &str,
    key_id: &str,
) -> CosmianResult<(String, String)> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND)
        .args(["keys", "create", "--size_in_bits", "2048", key_id]);
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

/// Rekey the RSA keypair identified by `private_key_id`.
/// Returns the new private key UID.
fn rekey_rsa_keypair(cli_conf_path: &str, private_key_id: &str) -> CosmianResult<String> {
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
fn rsa_sign(
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
fn rsa_verify(
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
pub(crate) async fn test_rsa_set_and_get_rotation_policy() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create an RSA keypair whose UID equals the keyset name
    let (private_key_id, _public_key_id) =
        create_rsa_keypair_with_id(&owner_client_conf_path, "rsa-keyset")?;
    assert_eq!(private_key_id, "rsa-keyset");

    // Set rotation policy — rotation-name must equal private key UID
    let args = vec![
        "rsa",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &private_key_id,
        "--interval",
        "86400",
        "--offset",
        "7200",
        "--rotation-name",
        "rsa-keyset",
    ];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(
        output.contains("Rotation policy set successfully"),
        "expected success message in: {output}"
    );

    // Get rotation policy and verify
    let args = vec![
        "rsa",
        "keys",
        "get-rotation-policy",
        "--key-id",
        &private_key_id,
    ];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(
        output.contains("86400"),
        "expected interval=86400 in: {output}"
    );
    assert!(output.contains("7200"), "expected offset=7200 in: {output}");
    assert!(
        output.contains("rsa-keyset"),
        "expected name=rsa-keyset in: {output}"
    );

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_rsa_rekey() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create an RSA keypair whose UID equals the keyset name
    let (private_key_id, _public_key_id) =
        create_rsa_keypair_with_id(&owner_client_conf_path, "rsa-rekey-test")?;

    // Set rotation policy — rotation-name must equal private key UID
    run_ckms(
        &owner_client_conf_path,
        &[
            "rsa",
            "keys",
            "set-rotation-policy",
            "--key-id",
            &private_key_id,
            "--rotation-name",
            "rsa-rekey-test",
        ],
    )?;

    // Re-Key the RSA key pair
    let gen1_id = rekey_rsa_keypair(&owner_client_conf_path, &private_key_id)?;
    assert!(
        gen1_id.contains("rsa-rekey-test"),
        "new key UID should contain keyset name, got: {gen1_id}"
    );

    Ok(())
}

/// Full RSA keyset lifecycle test — KMIP §4.57 state enforcement across all
/// addressing forms.
///
/// Sign (protection op — Active only) and Verify (processing op — Active,
/// Deactivated, and Compromised).
#[tokio::test]
pub(crate) async fn test_rsa_keyset_full_lifecycle() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let tmp_dir = TempDir::new()?;
    let data_file = tmp_dir.path().join("data.txt");
    fs::write(&data_file, b"rsa-lifecycle-test-data")?;

    // ── Step 1: Create RSA keypair with UID = keyset name ────────────────
    let (gen0_sk_id, gen0_pk_id) =
        create_rsa_keypair_with_id(&owner_client_conf_path, "rsa-lc-keyset")?;
    assert_eq!(gen0_sk_id, "rsa-lc-keyset");
    assert_eq!(gen0_pk_id, "rsa-lc-keyset_pk");

    run_ckms(
        &owner_client_conf_path,
        &[
            "rsa",
            "keys",
            "set-rotation-policy",
            "--key-id",
            &gen0_sk_id,
            "--rotation-name",
            "rsa-lc-keyset",
        ],
    )?;

    // ── Step 2: Sign with gen-0 (Active) → OK ───────────────────────────
    let sig_gen0 = tmp_dir.path().join("sig_gen0.sig");
    rsa_sign(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        "rsa-lc-keyset", // bare name → gen-0 private key
        sig_gen0.to_str().unwrap(),
    )?;

    // ── Step 3: Re-Key gen-0 → gen-1 (gen-0 private key Deactivated) ────
    let gen1_sk_id = rekey_rsa_keypair(&owner_client_conf_path, &gen0_sk_id)?;
    let gen1_pk_id = format!("{gen1_sk_id}_pk");

    // ── Step 4: Sign with @0 (Deactivated private key) → FAIL ───────────
    let sig_fail = tmp_dir.path().join("sig_fail.sig");
    let result = rsa_sign(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        "rsa-lc-keyset@0",
        sig_fail.to_str().unwrap(),
    );
    assert!(
        result.is_err(),
        "Sign with gen-0 private key must fail (Deactivated)"
    );

    // ── Step 5: Verify with gen-0 public key (Deactivated) → OK ─────────
    // The old gen-0 public key keeps its original UID (rsa-lc-keyset_pk) after
    // rekey — only the new generation gets an @N suffix.
    // Verify is a processing op; Deactivated keys are allowed.
    rsa_verify(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        sig_gen0.to_str().unwrap(),
        &gen0_pk_id, // "rsa-lc-keyset_pk"
    )?;

    // ── Step 6: Sign with bare name (→ gen-1, Active) → OK ──────────────
    let sig_gen1 = tmp_dir.path().join("sig_gen1.sig");
    rsa_sign(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        "rsa-lc-keyset", // bare name → latest = gen-1
        sig_gen1.to_str().unwrap(),
    )?;

    // ── Step 7: Verify gen-1 signature with gen-1 public key → OK ───────
    rsa_verify(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        sig_gen1.to_str().unwrap(),
        &gen1_pk_id,
    )?;

    // ── Step 8: Revoke gen-1 private key with KeyCompromise → Compromised
    run_ckms(
        &owner_client_conf_path,
        &[
            "rsa",
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
    let result = rsa_sign(
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
    let result = rsa_sign(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        "rsa-lc-keyset",
        sig_comp.to_str().unwrap(),
    );
    assert!(
        result.is_err(),
        "Sign with bare name must fail (gen-1 Compromised)"
    );

    // ── Step 10: Verify gen-1 signature with Compromised public key → OK ─
    rsa_verify(
        &owner_client_conf_path,
        data_file.to_str().unwrap(),
        sig_gen1.to_str().unwrap(),
        &gen1_pk_id,
    )?;

    // ── Step 11: Attempting to re-key non-latest (gen-0 via @first) → FAIL
    let stderr = run_ckms_expect_error(
        &owner_client_conf_path,
        &["rsa", "keys", "re-key", "--key-id", "rsa-lc-keyset@first"],
    )?;
    assert!(
        stderr.contains("not the latest"),
        "expected 'not the latest' error, got: {stderr}"
    );

    Ok(())
}
