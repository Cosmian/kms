//! Live 2-node multi-region CRL tests against real pgEdge/Spock-replicated `PostgreSQL`.
//!
//! Orchestrated by `mise run test:db:pgedge`; requires the `pgedge-1`/`pgedge-2` Docker Compose
//! services (see `crate/server_database/src/tests/mod.rs::test_db_pgedge_active_active` for the
//! sibling object-state/permission convergence test using the same containers).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{path::PathBuf, sync::Arc, time::Duration};

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::RevocationReasonCode,
    kmip_2_1::{kmip_operations::Get, kmip_types::UniqueIdentifier},
};

use crate::{
    config::{ClapConfig, MainDBConfig, RegionRole, ServerParams},
    core::{
        KMS,
        operations::generate_crl::{
            clear_generated_crl_cache_for_tests, generate_crl, get_cached_crl,
        },
    },
    middlewares::UserId,
    openssl_providers::init_openssl_providers_for_tests,
    result::KResult,
    tests::{
        crl_tests::{
            CA_EXT, LEAF_EXT, cert_serial, certify, get_cert_der, revoke_cert, revoked_serials,
        },
        test_utils::wire_spock_bidirectional,
    },
};

const PUBLIC_URL: &str = "https://kms.example.com";

async fn make_pgedge_kms(pg_url: &str, region_role: RegionRole) -> KResult<Arc<KMS>> {
    init_openssl_providers_for_tests();
    let config = ClapConfig {
        db: MainDBConfig {
            database_type: Some("postgresql".to_owned()),
            database_url: Some(pg_url.to_owned()),
            sqlite_path: PathBuf::new(),
            clear_database: true,
            ..Default::default()
        },
        region_role,
        kms_public_url: Some(PUBLIC_URL.to_owned()),
        ..Default::default()
    };
    Ok(Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(config)?)).await?,
    ))
}

/// Poll until `kms.get(...)` for `uid` succeeds (object has replicated), or time out.
async fn wait_for_object_replication(kms: &Arc<KMS>, owner: &UserId, uid: &str) -> KResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let ok = kms
            .get(
                Get {
                    unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                    ..Get::default()
                },
                owner,
            )
            .await
            .is_ok();
        if ok {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(crate::error::KmsError::ServerError(format!(
                "timed out waiting for object '{uid}' to replicate"
            )));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[ignore = "Orchestrated by `mise run test:db:pgedge` (requires the pgedge Docker Compose profile)."]
#[tokio::test]
async fn test_pgedge_crl_leader_only_generation_and_follower_cdp_replication() -> KResult<()> {
    cosmian_logger::log_init(option_env!("RUST_LOG"));

    let url1 = std::env::var("KMS_PGEDGE_1_URL")
        .unwrap_or_else(|_| "postgresql://kms:kms@127.0.0.1:6432/kms".to_owned());
    let url2 = std::env::var("KMS_PGEDGE_2_URL")
        .unwrap_or_else(|_| "postgresql://kms:kms@127.0.0.1:6433/kms".to_owned());

    let kms_a = make_pgedge_kms(&url1, RegionRole::Leader).await?;
    let kms_b = make_pgedge_kms(&url2, RegionRole::Follower).await?;
    wire_spock_bidirectional(&url1, &url2).await?;

    let owner = UserId::from("pgedge_crl_test_user");

    // Issue CA + leaf on the leader; wait for both to replicate to the follower.
    let (ca_id, ca_sk_id) =
        certify(&kms_a, &owner, "PGEdge Test Root CA", None, None, CA_EXT).await?;
    let (leaf_id, _leaf_sk_id) = certify(
        &kms_a,
        &owner,
        "pgedge-leaf",
        Some(&ca_id),
        Some(&ca_sk_id),
        LEAF_EXT,
    )
    .await?;
    wait_for_object_replication(&kms_b, &owner, &ca_id).await?;
    wait_for_object_replication(&kms_b, &owner, &leaf_id).await?;

    // Assertion 1: the follower cannot generate a CRL (leader-only gate → HTTP-422-equivalent
    // `KmsError::InvalidRequest`, per `require_leader_region`).
    let Err(err) = generate_crl(&kms_b, &ca_id, None, &owner).await else {
        panic!("follower must not be able to generate CRL");
    };
    assert!(
        err.to_string().contains("leader region"),
        "expected a leader-region rejection, got: {err}"
    );

    // Assertion 2: the leader generates an (empty) CRL; the follower serves the *same* bytes via
    // its own replicated `crls` row (DB fallback path), not via the shared process-global cache.
    let crl_1 = generate_crl(&kms_a, &ca_id, None, &owner).await?.to_der()?;
    assert!(
        revoked_serials(&crl_1).is_empty(),
        "CRL must be empty before any revocation"
    );

    clear_generated_crl_cache_for_tests().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let served = loop {
        if let Some((der, _, _)) = get_cached_crl(&ca_id, &kms_b).await {
            break der;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for the leader's CRL to replicate to the follower's crls table"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        served, crl_1,
        "follower must serve exactly the leader-generated CRL bytes"
    );

    // Assertion 3 (staleness gap): revoking on the follower does NOT auto-regenerate the CRL on
    // either node, even though `kms_public_url` is set on the follower (its `Revoke`-triggered
    // `generate_crl` attempt hits `require_leader_region` and silently no-ops). This holds
    // immediately — no replication wait needed, since nothing should have changed.
    revoke_cert(
        &kms_b,
        &owner,
        &leaf_id,
        RevocationReasonCode::KeyCompromise,
    )
    .await?;
    clear_generated_crl_cache_for_tests().await;
    let (leader_der_unchanged, _, _) = get_cached_crl(&ca_id, &kms_a)
        .await
        .expect("leader must still have its previously generated CRL stored");
    assert_eq!(
        leader_der_unchanged, crl_1,
        "a follower-side revoke must not silently regenerate the leader's stored CRL"
    );

    // Assertion 4 (eventual convergence): once the leader is explicitly asked to regenerate
    // (simulating a manual `generate-crl` call, or the leader-only cron), the now-replicated
    // revocation appears. Poll `generate_crl` because the `Compromised` state write from the
    // follower still needs to replicate back to the leader's own local Postgres node first.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let crl_2 = loop {
        let der = generate_crl(&kms_a, &ca_id, None, &owner).await?.to_der()?;
        let leaf_der = get_cert_der(&kms_a, &owner, &leaf_id).await;
        if revoked_serials(&der).contains(&cert_serial(&leaf_der)) {
            break der;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for the follower's revocation to replicate back to the leader"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    drop(crl_2); // regenerated CRL confirmed to contain the revoked leaf above

    Ok(())
}
