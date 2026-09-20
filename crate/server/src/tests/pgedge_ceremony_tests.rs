//! Live 2-node multi-region Crypto Officer ceremony tests against real pgEdge/Spock-replicated
//! `PostgreSQL`.
//!
//! Orchestrated by `mise run test:db:pgedge` (non-fips variant only); requires the
//! `pgedge-1`/`pgedge-2` Docker Compose services.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{path::PathBuf, sync::Arc, time::Duration};

use crate::{
    config::{ClapConfig, MainDBConfig, RegionRole, ServerParams},
    core::{KMS, operations::perform_crypto_officer_ceremony_activation},
    middlewares::UserId,
    result::KResult,
    tests::test_utils::wire_spock_bidirectional,
};

const PGEDGE_CEREMONY_SECRET: &str =
    "deadbeefcafebabe0102030405060708090a0b0c0d0e0f10deadbeefcafebabe";

async fn make_pgedge_ceremony_kms(
    pg_url: &str,
    region_role: RegionRole,
    co_users: Vec<String>,
    ceremony_secret: &str,
    clear_database: bool,
) -> KResult<Arc<KMS>> {
    let mut config = ClapConfig {
        db: MainDBConfig {
            database_type: Some("postgresql".to_owned()),
            database_url: Some(pg_url.to_owned()),
            sqlite_path: PathBuf::new(),
            clear_database,
            ..Default::default()
        },
        region_role,
        ..Default::default()
    };
    config.roles.crypto_officer_users = Some(co_users);
    config.roles.crypto_officer_require_ceremony = true;
    config.roles.ceremony_secret = Some(ceremony_secret.to_owned());
    Ok(Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(config)?)).await?,
    ))
}

/// Poll until `kms.is_crypto_officer(user)` returns `expected`, or time out.
async fn wait_for_co_status(kms: &Arc<KMS>, user: &UserId, expected: bool) -> KResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if kms.is_crypto_officer(user).await? == expected {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(crate::error::KmsError::ServerError(format!(
                "timed out waiting for CO status of '{user}' to become {expected}"
            )));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[ignore = "Orchestrated by `mise run test:db:pgedge` (requires the pgedge Docker Compose profile)."]
#[tokio::test]
async fn test_pgedge_crypto_officer_multi_region_activation_replication_and_fail_secure()
-> KResult<()> {
    cosmian_logger::log_init(option_env!("RUST_LOG"));

    let url1 = std::env::var("KMS_PGEDGE_1_URL")
        .unwrap_or_else(|_| "postgresql://kms:kms@127.0.0.1:6432/kms".to_owned());
    let url2 = std::env::var("KMS_PGEDGE_2_URL")
        .unwrap_or_else(|_| "postgresql://kms:kms@127.0.0.1:6433/kms".to_owned());

    let co_users = vec!["alice".to_owned(), "bob".to_owned(), "carol".to_owned()];

    let kms_a = Box::pin(make_pgedge_ceremony_kms(
        &url1,
        RegionRole::Leader,
        co_users.clone(),
        PGEDGE_CEREMONY_SECRET,
        true,
    ))
    .await?;
    let kms_b = Box::pin(make_pgedge_ceremony_kms(
        &url2,
        RegionRole::Follower,
        co_users.clone(),
        PGEDGE_CEREMONY_SECRET,
        true,
    ))
    .await?;
    wire_spock_bidirectional(&url1, &url2).await?;

    let alice = UserId::from("alice");
    let bob = UserId::from("bob");

    // Assertion 1: leader activates alice; follower recognizes her once the
    // `crypto_officer_activations` row replicates.
    kms_a
        .database
        .activate_crypto_officer_ceremony(
            "alice",
            &["bob".to_owned(), "carol".to_owned()],
            "test-hash-1",
        )
        .await?;
    assert!(
        kms_a.is_crypto_officer(&alice).await?,
        "alice must be CO on the leader immediately"
    );
    wait_for_co_status(&kms_b, &alice, true).await?;

    // Assertion 2: the follower cannot activate or revoke a ceremony (leader-only gate).
    let err = perform_crypto_officer_ceremony_activation(&kms_b, &[], &bob)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("leader region"),
        "expected a leader-region rejection, got: {err}"
    );
    let err = kms_b
        .disable_crypto_officer_ceremony(&alice, None)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("leader region"),
        "expected a leader-region rejection, got: {err}"
    );

    // Assertion 3: leader revokes alice; follower recognizes the revocation once replicated.
    kms_a.disable_crypto_officer_ceremony(&alice, None).await?;
    assert!(
        !kms_a.is_crypto_officer(&alice).await?,
        "alice must no longer be CO on the leader immediately"
    );
    wait_for_co_status(&kms_b, &alice, false).await?;

    // Assertion 4: a node reading the SAME replicated pgedge2 database but configured with a
    // MISMATCHED `ceremony_secret` fails secure (`Ok(false)`, not `Err`) against genuinely
    // Spock-replicated data — the multi-region analogue of the single-node regression test in
    // `key_ceremony_tests.rs::test_ceremony_verification_fails_secure_on_ceremony_keys_mismatch`.
    kms_a
        .database
        .activate_crypto_officer_ceremony(
            "bob",
            &["alice".to_owned(), "carol".to_owned()],
            "test-hash-2",
        )
        .await?;
    wait_for_co_status(&kms_b, &bob, true).await?;

    let kms_c = Box::pin(make_pgedge_ceremony_kms(
        &url2,
        RegionRole::Follower,
        co_users,
        "0".repeat(64).as_str(),
        false,
    ))
    .await?;
    assert!(
        !kms_c.is_crypto_officer(&bob).await?,
        "a ceremony_secret mismatch against real replicated data must fail secure, not error"
    );

    Ok(())
}
