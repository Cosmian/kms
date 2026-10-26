use cosmian_kms_cli_actions::actions::pgp::keys::create_key::{CreatePgpKeyAction, PgpAlgorithm};
use test_kms_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::utils::{
        ckms_bin, extract_uids::extract_unique_identifier, owner_config, recover_cmd_logs,
    },
};

pub(crate) fn create_pgp_key(
    cli_conf_path: &str,
    action: &CreatePgpKeyAction,
) -> CosmianResult<String> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args = vec![SUB_COMMAND, "keys", "create"];

    let algo_str = match action.algorithm {
        PgpAlgorithm::Ed25519 => "ed25519",
        PgpAlgorithm::Rsa => "rsa",
    };
    args.push("--algorithm");
    args.push(algo_str);

    let size_str;
    if action.algorithm == PgpAlgorithm::Rsa {
        size_str = action.key_size.to_string();
        args.push("--size_in_bits");
        args.push(&size_str);
    }

    if let Some(user_id) = action.user_id.as_deref() {
        args.push("--user-id");
        args.push(user_id);
    }

    for tag in &action.tags {
        args.push("--tag");
        args.push(tag);
    }

    if action.sensitive {
        args.push("--sensitive");
    }

    if let Some(key_id) = action.key_id.as_deref() {
        args.push(key_id);
    }

    cmd.args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let stdout_str = std::str::from_utf8(&output.stdout)?;
        assert!(stdout_str.contains("The OpenPGP key was successfully generated."));
        let uid = extract_unique_identifier(stdout_str)
            .ok_or_else(|| {
                CosmianError::Default("failed extracting the unique identifier".to_owned())
            })?
            .to_owned();
        return Ok(uid);
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_pgp_create_ed25519_and_rsa() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let cli_conf_path = owner_config(ctx);

    // Create Ed25519 key
    let action_ed = CreatePgpKeyAction {
        algorithm: PgpAlgorithm::Ed25519,
        user_id: Some("Alice <alice@example.com>".to_owned()),
        tags: vec!["pgp-test-ed".to_owned()],
        ..Default::default()
    };
    let uid_ed = create_pgp_key(&cli_conf_path, &action_ed)?;
    assert!(!uid_ed.is_empty());

    // Create RSA-3072 key
    let action_rsa = CreatePgpKeyAction {
        algorithm: PgpAlgorithm::Rsa,
        key_size: 3072,
        user_id: Some("Bob <bob@example.com>".to_owned()),
        tags: vec!["pgp-test-rsa".to_owned()],
        ..Default::default()
    };
    let uid_rsa = create_pgp_key(&cli_conf_path, &action_rsa)?;
    assert!(!uid_rsa.is_empty());
    assert_ne!(uid_ed, uid_rsa);

    // Create with explicit key_id positional
    let explicit_id = format!("pgp-explicit-{}", uuid::Uuid::new_v4());
    let action_explicit = CreatePgpKeyAction {
        algorithm: PgpAlgorithm::Ed25519,
        key_id: Some(explicit_id.clone()),
        ..Default::default()
    };
    let returned_uid = create_pgp_key(&cli_conf_path, &action_explicit)?;
    assert_eq!(returned_uid, explicit_id);

    Ok(())
}

#[tokio::test]
async fn test_pgp_create_rejects_unsupported_rsa_size() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let cli_conf_path = owner_config(ctx);

    let action_bad_rsa = CreatePgpKeyAction {
        algorithm: PgpAlgorithm::Rsa,
        key_size: 1024,
        ..Default::default()
    };
    let res = create_pgp_key(&cli_conf_path, &action_bad_rsa);
    assert!(res.is_err(), "expected error for RSA size 1024");
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("2048"),
        "error message should contain accepted size 2048, got: {err_msg}"
    );

    Ok(())
}
