//! Integration tests of `ckms ssh` and `ckms password` against a server with Crypto Officers.
//!
//! `owner.client@acme.com` is the Crypto Officer (manages the CA and roles);
//! `user.client@acme.com` is an Operator that may request certificates only through a role.

use cosmian_kms_cli_actions::reexport::cosmian_kms_client::cosmian_kmip::kmip_2_1::kmip_types::Tag;
use serial_test::serial;
use tempfile::NamedTempFile;
use test_kms_server::{
    TestClientOptions, TestsContext, start_test_server_with_patch, test_config_path,
};

use crate::{
    error::result::CosmianResult,
    tests::utils::{load_client_config, run_ckms, run_ckms_expect_error},
};

const USER: &str = "user.client@acme.com";
const CERT_PREFIX: &str = "ecdsa-sha2-nistp256-cert-v01@openssh.com ";

async fn start_ssh_server() -> CosmianResult<(TestsContext, String, String)> {
    let ctx = start_test_server_with_patch(
        &test_config_path("auth/cert.toml"),
        |config| {
            config.google_cse_config.enable = false;
            config.roles.crypto_officer_users = Some(vec!["owner.client@acme.com".to_owned()]);
        },
        TestClientOptions::default(),
    )
    .await?;
    let owner = load_client_config("cert_owner.toml", &ctx);
    let user = load_client_config("cert_user.toml", &ctx);
    Ok((ctx, owner, user))
}

fn key_id_of(output: &str) -> &str {
    output
        .split("private key id: ")
        .nth(1)
        .and_then(|rest| rest.lines().next())
        .expect("the output names the CA private key id")
}

#[tokio::test]
#[serial]
async fn test_ssh_ca_role_and_sign_flow() -> CosmianResult<()> {
    let (ctx, owner, user) = start_ssh_server().await?;

    // No CA is configured yet.
    run_ckms_expect_error(&owner, &["ssh", "ca", "public-key"])?;

    // The Crypto Officer creates the CA: its public key is printed in OpenSSH format.
    let created = run_ckms(&owner, &["ssh", "ca", "create"])?;
    assert!(created.contains("ecdsa-sha2-nistp256 "), "{created}");
    let ca_public = run_ckms(&owner, &["ssh", "ca", "public-key"])?;
    assert!(
        created.contains(ca_public.trim()),
        "{created} / {ca_public}"
    );

    // The role lets `user` certify the principals alice and bob, for at most 1h.
    run_ckms(
        &owner,
        &[
            "ssh",
            "role",
            "put",
            "dev",
            "--allowed-principal",
            "alice",
            "bob",
            "--allowed-user",
            USER,
            "--default-ttl",
            "10m",
            "--max-ttl",
            "1h",
        ],
    )?;

    // The user generates a key pair and gets its certificate in one command.
    let dir = tempfile::tempdir()?;
    let key = dir.path().join("id_test");
    let key = key.to_str().expect("utf-8 temp path");
    let out = run_ckms(
        &user,
        &["ssh", "sign", "dev", "--generate-key", key, "-p", "alice"],
    )?;
    assert!(out.contains(&format!("{key}-cert.pub")), "{out}");
    let private = std::fs::read_to_string(key)?;
    assert!(private.contains("PRIVATE KEY"), "{private}");
    let public = std::fs::read_to_string(format!("{key}.pub"))?;
    assert!(public.starts_with("ecdsa-sha2-nistp256 "), "{public}");
    let cert = std::fs::read_to_string(format!("{key}-cert.pub"))?;
    assert!(cert.starts_with(CERT_PREFIX), "{cert}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(key)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // Existing files are never overwritten.
    let err = run_ckms_expect_error(
        &user,
        &["ssh", "sign", "dev", "--generate-key", key, "-p", "alice"],
    )?;
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(std::fs::read_to_string(key)?, private);

    // An existing public key can be certified: several principals, explicit ttl.
    let cert = run_ckms(
        &user,
        &[
            "ssh",
            "sign",
            "dev",
            public.trim(),
            "-p",
            "alice",
            "bob",
            "--ttl",
            "30m",
        ],
    )?;
    assert!(cert.starts_with(CERT_PREFIX), "{cert}");

    ctx.stop_server().await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_ssh_sign_rejections() -> CosmianResult<()> {
    let (ctx, owner, user) = start_ssh_server().await?;
    run_ckms(&owner, &["ssh", "ca", "create"])?;
    run_ckms(
        &owner,
        &[
            "ssh",
            "role",
            "put",
            "dev",
            "--allowed-principal",
            "alice",
            "--allowed-user",
            USER,
            "--max-ttl",
            "1h",
        ],
    )?;
    run_ckms(
        &owner,
        &[
            "ssh",
            "role",
            "put",
            "other",
            "--allowed-principal",
            "alice",
            "--allowed-user",
            "someone.else@acme.com",
        ],
    )?;
    let dir = tempfile::tempdir()?;
    let key = dir.path().join("k");
    let key = key.to_str().expect("utf-8 temp path");
    let public = {
        run_ckms(
            &user,
            &["ssh", "sign", "dev", "--generate-key", key, "-p", "alice"],
        )?;
        std::fs::read_to_string(format!("{key}.pub"))?
    };
    let public = public.trim();

    // A principal the role does not allow; a ttl above the role maximum.
    run_ckms_expect_error(&user, &["ssh", "sign", "dev", public, "-p", "mallory"])?;
    run_ckms_expect_error(
        &user,
        &["ssh", "sign", "dev", public, "-p", "alice", "--ttl", "2h"],
    )?;
    run_ckms_expect_error(
        &user,
        &["ssh", "sign", "dev", public, "-p", "alice", "--ttl", "soon"],
    )?;
    // Wildcard and duplicate principals.
    run_ckms_expect_error(&user, &["ssh", "sign", "dev", public, "-p", "*"])?;
    run_ckms_expect_error(
        &user,
        &["ssh", "sign", "dev", public, "-p", "alice", "alice"],
    )?;
    // Unknown role, role the user is not allowed to use, invalid role name.
    run_ckms_expect_error(&user, &["ssh", "sign", "nope", public, "-p", "alice"])?;
    run_ckms_expect_error(&user, &["ssh", "sign", "other", public, "-p", "alice"])?;
    let err = run_ckms_expect_error(&user, &["ssh", "sign", "../x", public, "-p", "alice"])?;
    assert!(err.contains("invalid role name"), "{err}");
    // Not an SSH public key.
    run_ckms_expect_error(&user, &["ssh", "sign", "dev", "not-a-key", "-p", "alice"])?;
    // Argument errors: no principal, no key source, both key sources.
    run_ckms_expect_error(&user, &["ssh", "sign", "dev", public])?;
    run_ckms_expect_error(&user, &["ssh", "sign", "dev", "-p", "alice"])?;
    run_ckms_expect_error(
        &user,
        &[
            "ssh",
            "sign",
            "dev",
            public,
            "--generate-key",
            key,
            "-p",
            "alice",
        ],
    )?;

    ctx.stop_server().await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_ssh_management_is_reserved_to_crypto_officers() -> CosmianResult<()> {
    let (ctx, owner, user) = start_ssh_server().await?;

    run_ckms_expect_error(&user, &["ssh", "ca", "create"])?;
    run_ckms_expect_error(
        &user,
        &["ssh", "role", "put", "dev", "--allowed-principal", "alice"],
    )?;

    // A Crypto Officer sets an existing key as the CA; an Operator cannot.
    let created = run_ckms(&owner, &["ec", "keys", "create"])?;
    let key_id = created
        .split("Private key unique identifier: ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .expect("the EC key pair creation prints the private key id");
    run_ckms_expect_error(&user, &["ssh", "ca", "set", key_id])?;
    let set = run_ckms(&owner, &["ssh", "ca", "set", key_id])?;
    assert!(set.contains("ecdsa-sha2-nistp256 "), "{set}");
    run_ckms_expect_error(&owner, &["ssh", "ca", "set", "does-not-exist"])?;

    // A role name is validated before reaching the server.
    let err = run_ckms_expect_error(
        &owner,
        &["ssh", "role", "put", "a/b", "--allowed-principal", "alice"],
    )?;
    assert!(err.contains("invalid role name"), "{err}");
    // A default ttl above the maximum is rejected by the server.
    run_ckms_expect_error(
        &owner,
        &[
            "ssh",
            "role",
            "put",
            "dev",
            "--allowed-principal",
            "alice",
            "--default-ttl",
            "2h",
            "--max-ttl",
            "1h",
        ],
    )?;

    // A CA created with a chosen id reports that id.
    let id = format!("ssh-ca-{}", uuid::Uuid::new_v4());
    let created = run_ckms(&owner, &["ssh", "ca", "create", &id])?;
    assert_eq!(key_id_of(&created), id);

    ctx.stop_server().await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_ssh_ca_create_options() -> CosmianResult<()> {
    let (ctx, owner, _user) = start_ssh_server().await?;

    // The curve, tag and sensitivity reach the CA key pair.
    let tag = format!("ssh-ca-{}", uuid::Uuid::new_v4());
    let created = run_ckms(
        &owner,
        &[
            "ssh",
            "ca",
            "create",
            "--curve",
            "nist-p384",
            "--tag",
            &tag,
            "--sensitive",
        ],
    )?;
    assert!(created.contains("ecdsa-sha2-nistp384 "), "{created}");
    let key_id = key_id_of(&created);
    let located = run_ckms(&owner, &["locate", "--tag", &tag])?;
    assert!(located.contains(key_id), "{located}");
    let attributes_file = NamedTempFile::new()?;
    let attributes_path = attributes_file.path().to_string_lossy().to_string();
    let sensitive = Tag::Sensitive.to_string();
    run_ckms(
        &owner,
        &[
            "attributes",
            "get",
            "--id",
            key_id,
            "--attribute",
            &sensitive,
            "--output-file",
            &attributes_path,
        ],
    )?;
    let attributes: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(attributes_file.path())?)?;
    assert_eq!(
        attributes
            .get(&sensitive)
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "{attributes}"
    );

    // A curve the SSH CA rejects fails before any key pair is created.
    let rejected = format!("ssh-ca-{}", uuid::Uuid::new_v4());
    let err = run_ckms_expect_error(
        &owner,
        &[
            "ssh",
            "ca",
            "create",
            "--curve",
            "secp256k1",
            "--tag",
            &rejected,
        ],
    )?;
    assert!(err.contains("an SSH CA key must use"), "{err}");
    let located = run_ckms(&owner, &["locate", "--tag", &rejected])?;
    assert!(located.contains("No object found."), "{located}");

    ctx.stop_server().await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_password_is_random_alphanumeric() -> CosmianResult<()> {
    let (ctx, owner, user) = start_ssh_server().await?;

    // Generating a password needs the Create right, which an Operator does not have.
    run_ckms_expect_error(&user, &["password"])?;
    let first = run_ckms(&owner, &["password"])?;
    let second = run_ckms(&owner, &["password"])?;
    for password in [first.trim(), second.trim()] {
        assert_eq!(password.len(), 32, "{password}");
        assert!(
            password.bytes().all(|b| b.is_ascii_alphanumeric()),
            "{password}"
        );
    }
    assert_ne!(first.trim(), second.trim());

    ctx.stop_server().await?;
    Ok(())
}
