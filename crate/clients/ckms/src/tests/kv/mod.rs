//! Integration tests of `ckms kv` against a server with the Vault KV v2-compatible store enabled.

use std::process::Output;

use serial_test::serial;
use test_kms_server::{
    TestClientOptions, TestsContext, start_default_test_kms_server, start_test_server_with_patch,
    test_config_path,
};

use crate::{
    config::CKMS_CONF_ENV,
    error::result::CosmianResult,
    tests::utils::{
        ckms_bin, load_client_config, owner_config, recover_cmd_logs, run_ckms,
        run_ckms_expect_error,
    },
};

/// Start a plain-HTTP server with the KV store enabled on `mount`; returns it with its unique
/// default owner.
async fn start_kv_server(mount: &str) -> CosmianResult<(TestsContext, String)> {
    // The shared server initializes the database; the KV server reuses it without clearing it.
    let _shared = start_default_test_kms_server().await;
    let owner = format!("kv-cli-{}", uuid::Uuid::new_v4());
    let ctx = start_test_server_with_patch(
        &test_config_path("auth/plain.toml"),
        |config| {
            config.db.clear_database = false;
            config.default_username.clone_from(&owner);
            config.google_cse_config.enable = false;
            config.kv.enabled = true;
            mount.clone_into(&mut config.kv.mount);
        },
        TestClientOptions::default(),
    )
    .await?;
    Ok((ctx, owner))
}

#[tokio::test]
#[serial]
async fn test_kv_put_get_list_delete() -> CosmianResult<()> {
    let (ctx, _) = start_kv_server("kv").await?;
    let conf = owner_config(&ctx);

    // Writes create versions.
    let out = run_ckms(
        &conf,
        &["kv", "put", "database/app", "user=app", "password=first"],
    )?;
    assert!(out.contains("version 1"), "{out}");
    let out = run_ckms(
        &conf,
        &["kv", "put", "database/app", "user=app", "password=second"],
    )?;
    assert!(out.contains("version 2"), "{out}");

    // Reads: latest, a given version, and a single field.
    let latest: serde_json::Value =
        serde_json::from_str(&run_ckms(&conf, &["kv", "get", "database/app"])?)?;
    assert_eq!(latest["password"], "second");
    let v1: serde_json::Value = serde_json::from_str(&run_ckms(
        &conf,
        &["kv", "get", "database/app", "--version", "1"],
    )?)?;
    assert_eq!(v1["password"], "first");
    let field = run_ckms(&conf, &["kv", "get", "database/app", "--field", "password"])?;
    assert_eq!(field.trim(), "second");
    let err = run_ckms_expect_error(&conf, &["kv", "get", "database/app", "--field", "nope"])?;
    assert!(err.contains("no field 'nope'"), "{err}");

    // Listing: root shows the directory, the prefix shows the key.
    let root = run_ckms(&conf, &["kv", "list"])?;
    assert!(root.lines().any(|line| line == "database/"), "{root}");
    let keys = run_ckms(&conf, &["kv", "list", "database"])?;
    assert_eq!(keys.trim(), "app");

    // A JSON file keeps every value type: nothing is converted to a string.
    let secret = serde_json::json!({
        "token": "abc",
        "port": 5432,
        "ratio": 0.25,
        "enabled": true,
        "none": null,
        "nested": { "hosts": ["a", "b"], "limits": { "max": 10 } }
    });
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("secret.json");
    std::fs::write(&file, serde_json::to_vec(&secret)?)?;
    let file = file.to_string_lossy().into_owned();
    let out = run_ckms(
        &conf,
        &["kv", "put", "ci/token", "--from-file", &file, "--ttl", "1h"],
    )?;
    assert!(out.contains("version 1"), "{out}");
    let stored: serde_json::Value =
        serde_json::from_str(&run_ckms(&conf, &["kv", "get", "ci/token"])?)?;
    assert_eq!(stored, secret);
    assert_eq!(
        run_ckms(&conf, &["kv", "get", "ci/token", "--field", "port"])?.trim(),
        "5432"
    );

    // Soft delete hides the latest version; destroy removes the path from listings.
    run_ckms(&conf, &["kv", "delete", "database/app"])?;
    run_ckms_expect_error(&conf, &["kv", "get", "database/app"])?;
    run_ckms(&conf, &["kv", "delete", "database/app", "--destroy"])?;
    // The server answers an empty LIST with 404, which the CLI shows as no keys.
    let keys = run_ckms(&conf, &["kv", "list", "database"])?;
    assert!(keys.trim().is_empty(), "{keys}");
    run_ckms_expect_error(&conf, &["kv", "delete", "database/app"])?;

    ctx.stop_server().await?;
    Ok(())
}

/// `--expected-owner` is sent only when given; on a new path it must name the caller.
#[tokio::test]
#[serial]
async fn test_kv_put_expected_owner() -> CosmianResult<()> {
    let (ctx, owner) = start_kv_server("kv").await?;
    let conf = owner_config(&ctx);

    run_ckms_expect_error(
        &conf,
        &[
            "kv",
            "put",
            "claimed/db",
            "--expected-owner",
            "somebody-else",
            "k=v",
        ],
    )?;
    run_ckms_expect_error(&conf, &["kv", "get", "claimed/db"])?;

    let out = run_ckms(
        &conf,
        &["kv", "put", "claimed/db", "--expected-owner", &owner, "k=v"],
    )?;
    assert!(out.contains("version 1"), "{out}");
    let out = run_ckms(
        &conf,
        &["kv", "put", "claimed/db", "--expected-owner", &owner, "k=w"],
    )?;
    assert!(out.contains("version 2"), "{out}");

    let err = run_ckms_expect_error(
        &conf,
        &["kv", "put", "claimed/db", "--expected-owner", "", "k=v"],
    )?;
    assert!(err.contains("expected-owner"), "{err}");

    ctx.stop_server().await?;
    Ok(())
}

/// Distinct certificate identities: another user can neither read, list, overwrite nor delete
/// the owner's secret, with or without `--expected-owner`.
#[tokio::test]
#[serial]
async fn test_kv_foreign_identity_is_denied() -> CosmianResult<()> {
    let ctx = start_test_server_with_patch(
        &test_config_path("auth/cert.toml"),
        |config| {
            config.google_cse_config.enable = false;
            config.kv.enabled = true;
        },
        TestClientOptions::default(),
    )
    .await?;
    let owner = load_client_config("cert_owner.toml", &ctx);
    let user = load_client_config("cert_user.toml", &ctx);
    let owner_id = "owner.client@acme.com";

    // The owner's certificate identity is what `--expected-owner` must name on a new path.
    let out = run_ckms(
        &owner,
        &[
            "kv",
            "put",
            "team/db",
            "--expected-owner",
            owner_id,
            "password=owner-secret",
        ],
    )?;
    assert!(out.contains("version 1"), "{out}");

    run_ckms_expect_error(&user, &["kv", "get", "team/db"])?;
    let listed = run_ckms(&user, &["kv", "list"])?;
    assert!(!listed.contains("team/"), "{listed}");
    run_ckms_expect_error(&user, &["kv", "put", "team/db", "password=stolen"])?;
    run_ckms_expect_error(
        &user,
        &[
            "kv",
            "put",
            "team/db",
            "--expected-owner",
            owner_id,
            "password=stolen",
        ],
    )?;
    run_ckms_expect_error(&user, &["kv", "delete", "team/db"])?;
    run_ckms_expect_error(&user, &["kv", "delete", "team/db", "--destroy"])?;
    // A new path cannot be created on behalf of another user.
    run_ckms_expect_error(
        &user,
        &[
            "kv",
            "put",
            "team/other",
            "--expected-owner",
            owner_id,
            "k=v",
        ],
    )?;

    // Nothing the user tried changed the owner's secret.
    assert_eq!(
        run_ckms(&owner, &["kv", "get", "team/db", "--field", "password"])?.trim(),
        "owner-secret"
    );
    let out = run_ckms(&owner, &["kv", "put", "team/db", "password=rotated"])?;
    assert!(out.contains("version 2"), "{out}");
    let listed = run_ckms(&owner, &["kv", "list", "team"])?;
    assert_eq!(listed.trim(), "db");

    ctx.stop_server().await?;
    Ok(())
}

/// The REST client never traces request or response bodies: at `RUST_LOG=trace` a write logs
/// nothing of the secret and a read shows it only once, as the requested output.
#[tokio::test]
#[serial]
async fn test_kv_secret_is_not_logged_at_trace_level() -> CosmianResult<()> {
    let (ctx, _) = start_kv_server("kv").await?;
    let conf = owner_config(&ctx);
    let secret = format!("sentinel-{}", uuid::Uuid::new_v4());
    let traced = |args: &[&str]| -> Output {
        let mut cmd = ckms_bin();
        cmd.env(CKMS_CONF_ENV, &conf)
            .env("RUST_LOG", "trace")
            .args(args);
        recover_cmd_logs(&mut cmd)
    };

    let put = traced(&["kv", "put", "log/sentinel", &format!("password={secret}")]);
    let (stdout, stderr) = (
        String::from_utf8_lossy(&put.stdout),
        String::from_utf8_lossy(&put.stderr),
    );
    assert!(put.status.success(), "{stdout}{stderr}");
    assert!(
        stdout.contains("Starting KMS CLI"),
        "trace logging is not active: {stdout}"
    );
    assert!(!stdout.contains(&secret) && !stderr.contains(&secret));

    let get = traced(&["kv", "get", "log/sentinel", "--field", "password"]);
    let (stdout, stderr) = (
        String::from_utf8_lossy(&get.stdout),
        String::from_utf8_lossy(&get.stderr),
    );
    assert!(get.status.success(), "{stdout}{stderr}");
    assert_eq!(stdout.matches(&secret).count(), 1, "{stdout}");
    assert!(!stderr.contains(&secret));

    ctx.stop_server().await?;
    Ok(())
}

/// `--mount` selects the server's KV mount; the default mount is not served when another is set.
#[tokio::test]
#[serial]
async fn test_kv_custom_mount() -> CosmianResult<()> {
    let (ctx, _) = start_kv_server("kvstore").await?;
    let conf = owner_config(&ctx);

    let out = run_ckms(
        &conf,
        &["kv", "put", "--mount", "kvstore", "app/db", "token=abc"],
    )?;
    assert!(out.contains("version 1"), "{out}");
    let field = run_ckms(
        &conf,
        &[
            "kv", "get", "--mount", "kvstore", "app/db", "--field", "token",
        ],
    )?;
    assert_eq!(field.trim(), "abc");
    let listed = run_ckms(&conf, &["kv", "list", "--mount", "kvstore", "app"])?;
    assert_eq!(listed.trim(), "db");
    run_ckms_expect_error(&conf, &["kv", "get", "app/db"])?;

    ctx.stop_server().await?;
    Ok(())
}

#[test]
fn test_kv_rejects_invalid_input_without_a_server() -> CosmianResult<()> {
    // Validation happens before any request, so the fixture's unreachable server is fine.
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../test_data/configs/client/default.toml"
    );
    let err = run_ckms_expect_error(conf, &["kv", "put", "a/b", "not-a-pair"])?;
    assert!(err.contains("not a KEY=VALUE pair"), "{err}");
    let err = run_ckms_expect_error(conf, &["kv", "put", "a/b"])?;
    assert!(err.contains("at least one KEY=VALUE"), "{err}");
    let err = run_ckms_expect_error(conf, &["kv", "put", "///", "k=v"])?;
    assert!(err.contains("must not be empty"), "{err}");
    Ok(())
}
