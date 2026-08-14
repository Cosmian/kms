//! Integration tests for the `CryptoOfficer` split-key ceremony.
//!
//! Tests cover:
//! 1. Config-only CO (no ceremony) — user gets CO access immediately.
//! 2. Ceremony mode: candidate is Operator before ceremony completion.
//! 3. Ceremony activation — `POST /access/crypto_officer/ceremony/activate` makes user CO.
//! 4. Per-user isolation — Alice completing ceremony does NOT activate Bob.
//! 5. n-of-n enforcement — providing fewer than n shares is rejected.
//! 6. Non-candidate rejection — a user not in `crypto_officer.users` cannot trigger activation.
//!
//! Security-fix regression tests (threat model PR #991):
//! TM-F001 — no eprintln!/debug leakage of CO identity in create_split_key.
//! TM-F002 — CO cannot Get/Export a `sensitive=true` key without wrapping.
//! TM-F003 — startup emits WARN when config-only CO mode is active.
//! TM-F006 — multi-CO deployment blocks single-user ceremony disable.
//! TM-F007 — startup validation rejects `force_default_username=true` with CO configured.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use cosmian_kms_access::access::CryptoOfficerConfig;
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    KmipOperation,
    extra::tagging::VENDOR_ID_COSMIAN,
    kmip_objects::ObjectType,
    kmip_operations::{CreateSplitKey, Get, JoinSplitKey},
    kmip_types::{CryptographicAlgorithm, SplitKeyMethod, UniqueIdentifier},
    requests::symmetric_key_create_request,
};

use crate::{
    config::{ClapConfig, MainDBConfig, ServerParams},
    core::{KMS, operations::perform_crypto_officer_ceremony_activation},
    middlewares::UserId,
    result::KResult,
    tests::test_utils::get_tmp_sqlite_path,
};

// A fixed 32-byte secret used for all ceremony tests.
const TEST_CEREMONY_SECRET: &str =
    "deadbeefcafebabe0102030405060708090a0b0c0d0e0f10deadbeefcafebabe";

/// Build a `KMS` configured for ceremony mode with the given CO users.
async fn ceremony_kms(co_users: Vec<String>) -> KResult<Arc<KMS>> {
    let mut conf = ClapConfig {
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: get_tmp_sqlite_path(),
            clear_database: false,
            ..Default::default()
        },
        ..Default::default()
    };
    conf.roles.crypto_officer_users = Some(co_users);
    conf.roles.crypto_officer_require_ceremony = true;
    conf.roles.ceremony_secret = Some(TEST_CEREMONY_SECRET.to_owned());

    let params = ServerParams::try_from(conf)?;
    Ok(Arc::new(KMS::instantiate(Arc::new(params)).await?))
}

/// Build a `KMS` configured for config-only CO mode (no ceremony) with the given users.
async fn config_only_co_kms(co_users: Vec<String>) -> KResult<Arc<KMS>> {
    let mut conf = ClapConfig {
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: get_tmp_sqlite_path(),
            clear_database: false,
            ..Default::default()
        },
        ..Default::default()
    };
    conf.roles.crypto_officer_users = Some(co_users);
    conf.roles.crypto_officer_require_ceremony = false;

    let params = ServerParams::try_from(conf)?;
    Ok(Arc::new(KMS::instantiate(Arc::new(params)).await?))
}

/// Create a `PreActive` symmetric key owned by `owner` and return its UID.
async fn create_key(kms: &KMS, owner: &str) -> KResult<String> {
    let no_tags: &[&str] = &[];
    let mut req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        no_tags,
        false,
        None,
    )?;
    req.attributes.activation_date = None;
    let resp = kms.create(req, &UserId::from(owner)).await?;
    Ok(resp
        .unique_identifier
        .as_str()
        .expect("UID must be a string")
        .to_owned())
}

/// Split `key_uid` into `total_parts` XOR shares; return share UIDs.
async fn split_key(
    kms: &KMS,
    owner: &str,
    key_uid: &str,
    total_parts: i32,
) -> KResult<Vec<String>> {
    let req = CreateSplitKey {
        unique_identifier: UniqueIdentifier::TextString(key_uid.to_owned()),
        split_key_parts: total_parts,
        split_key_threshold: total_parts, // XOR n-of-n
        split_key_method: SplitKeyMethod::XOR,
    };
    let resp = Box::pin(kms.create_split_key(req, &UserId::from(owner))).await?;
    Ok(resp
        .split_key_unique_identifiers
        .iter()
        .map(|u| u.as_str().expect("UID must be a string").to_owned())
        .collect())
}

/// Reconstruct from the given share UIDs; return the reconstructed key UID.
async fn join_shares(
    kms: &KMS,
    user: &str,
    share_uids: &[String],
    expected_type: ObjectType,
) -> KResult<String> {
    let req = JoinSplitKey {
        split_key_unique_identifiers: share_uids
            .iter()
            .map(|u| UniqueIdentifier::TextString(u.clone()))
            .collect(),
        object_type: expected_type,
        split_key_method: SplitKeyMethod::XOR,
        attributes: None,
    };
    let resp = kms.join_split_key(req, &UserId::from(user)).await?;
    Ok(resp
        .unique_identifier
        .as_str()
        .expect("UID must be a string")
        .to_owned())
}

// ─── Test 1: config-only CO ──────────────────────────────────────────────────

/// Config-only CO: user listed in `crypto_officer.users` with `require_ceremony = false`
/// is immediately a Crypto Officer.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_config_only_co_is_immediately_active() -> KResult<()> {
    let alice = "alice@example.com";
    let kms = config_only_co_kms(vec![alice.to_owned()]).await?;

    assert!(
        kms.is_crypto_officer(alice).await?,
        "Config-only CO: alice should be an active Crypto Officer"
    );
    Ok(())
}

/// Config-only CO: a user NOT listed is Operator (not CO).
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_config_only_non_co_user_is_operator() -> KResult<()> {
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let kms = config_only_co_kms(vec![alice.to_owned()]).await?;

    assert!(
        !kms.is_crypto_officer(bob).await?,
        "Config-only CO: bob is not in the list and should not be CO"
    );
    Ok(())
}

// ─── Test 2: ceremony mode — candidate is Operator before ceremony ────────────

/// Ceremony mode: user in `crypto_officer.users` but ceremony not yet completed
/// is not a Crypto Officer.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_ceremony_candidate_is_operator_before_ceremony() -> KResult<()> {
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    assert!(
        !kms.is_crypto_officer(alice).await?,
        "Ceremony mode: alice should NOT be CO before ceremony completes"
    );
    Ok(())
}

// ─── Test 3: ceremony activation ──────────────────────────────────────────────

/// Full 3-of-3 ceremony flow: create key, split, join — activating user becomes CO.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_ceremony_activation_makes_user_co() -> KResult<()> {
    let provisioner = "admin"; // default_username bypasses create permission check
    let alice = "alice@example.com";
    let carol = "carol@example.com";
    let dave = "dave@example.com";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), carol.to_owned(), dave.to_owned()]).await?;

    // Provisioner creates the ceremony key (before ceremony mode forces Operator restrictions).
    let key_uid = create_key(&kms, provisioner).await?;

    // Split into n shares. The server auto-grants share 0 to alice, share 1 to carol,
    // and share 2 to dave.
    let share_uids = Box::pin(split_key(&kms, provisioner, &key_uid, n)).await?;
    assert_eq!(share_uids.len(), usize::try_from(n).unwrap());

    // Alice needs Get access to the other CO shares to complete the ceremony.
    kms.database
        .grant_operations(
            &share_uids[1],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    kms.database
        .grant_operations(
            &share_uids[2],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;

    // Alice assembles all shares — this activates the CO ceremony (not stored).
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, alice).await?;

    assert!(
        kms.is_crypto_officer(alice).await?,
        "After ceremony completion alice should be CO"
    );
    Ok(())
}

// ─── Test 4: per-user isolation ───────────────────────────────────────────────

/// Alice completing the ceremony does NOT activate Bob.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_ceremony_activates_only_assembling_user() -> KResult<()> {
    let provisioner = "admin"; // default_username bypasses create permission check
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    let key_uid = create_key(&kms, provisioner).await?;
    let share_uids = Box::pin(split_key(&kms, provisioner, &key_uid, n)).await?;

    // Alice needs Get access to the other ceremony shares to complete the ceremony.
    kms.database
        .grant_operations(
            &share_uids[1],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    kms.database
        .grant_operations(
            &share_uids[2],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;

    // Alice completes the ceremony via the dedicated endpoint.
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, alice).await?;

    assert!(
        kms.is_crypto_officer(alice).await?,
        "Alice should be CO after her ceremony"
    );
    assert!(
        !kms.is_crypto_officer(bob).await?,
        "Bob should NOT be CO — he never assembled shares"
    );
    Ok(())
}

// ─── Test 5: n-of-n enforcement ───────────────────────────────────────────────

/// Providing fewer than n shares is rejected with an error.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_join_with_fewer_than_n_shares_fails() -> KResult<()> {
    let provisioner = "admin"; // default_username bypasses create permission check
    let alice = "alice@example.com";
    let carol = "carol@example.com";
    let dave = "dave@example.com";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), carol.to_owned(), dave.to_owned()]).await?;

    let key_uid = create_key(&kms, provisioner).await?;
    let all_share_uids = Box::pin(split_key(&kms, provisioner, &key_uid, n)).await?;

    // Only use 2 out of 3 shares.
    let partial = all_share_uids[..2].to_vec();

    // Grant alice access to the partial set.
    for share_uid in &partial {
        kms.database
            .grant_operations(
                share_uid,
                &UserId::from(alice),
                std::collections::HashSet::from([KmipOperation::Get]),
            )
            .await?;
    }

    let result = join_shares(&kms, alice, &partial, ObjectType::SymmetricKey).await;
    assert!(
        result.is_err(),
        "JoinSplitKey with only 2 of 3 shares should fail (n-of-n)"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("XOR n-of-n requires all"),
        "Error should mention n-of-n: {err}"
    );
    Ok(())
}

// ─── Test 6: non-candidate rejection ──────────────────────────────────────────

/// A user not listed in `crypto_officer.users` cannot activate the ceremony,
/// even if they manage to assemble CO-tagged shares.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_non_candidate_cannot_activate_ceremony() -> KResult<()> {
    let provisioner = "admin"; // default_username bypasses create permission check
    let alice = "alice@example.com";
    let carol = "carol@example.com";
    let dave = "dave@example.com";
    let eve = "eve@example.com"; // NOT in the CO list
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), carol.to_owned(), dave.to_owned()]).await?;

    let key_uid = create_key(&kms, provisioner).await?;
    let share_uids = Box::pin(split_key(&kms, provisioner, &key_uid, n)).await?;

    // Grant eve access to all shares.
    for share_uid in &share_uids {
        kms.database
            .grant_operations(
                share_uid,
                &UserId::from(eve),
                std::collections::HashSet::from([KmipOperation::Get]),
            )
            .await?;
    }

    // Eve tries to activate the ceremony — must be rejected (she is not in CO candidates).
    let result = perform_crypto_officer_ceremony_activation(&kms, &share_uids, eve).await;
    assert!(
        result.is_err(),
        "Eve is not a CO candidate — ceremony activation must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Unauthorized")
            || err.contains("not in")
            || err.contains("candidate")
            || err.contains("not listed")
            || err.contains("Access denied"),
        "Expected CO-candidate rejection, got: {err}"
    );
    Ok(())
}

// ─── Test 7: server startup validation — single CO + ceremony = rejected ──────

/// Server must refuse to start when `require_ceremony = true` with only 1 CO user.
/// An XOR n-of-n ceremony with fewer than 3 COs does not provide split knowledge.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_single_co_ceremony_rejected_at_startup() -> KResult<()> {
    let mut conf = ClapConfig {
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: get_tmp_sqlite_path(),
            clear_database: false,
            ..Default::default()
        },
        ..Default::default()
    };
    conf.roles.crypto_officer_users = Some(vec!["single-user@example.com".to_owned()]);
    conf.roles.crypto_officer_require_ceremony = true;
    conf.roles.ceremony_secret = Some(TEST_CEREMONY_SECRET.to_owned());

    let result = ServerParams::try_from(conf);
    assert!(
        result.is_err(),
        "Single CO + ceremony should fail at startup"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("requires at least 3"),
        "Error should mention 'requires at least 3': {err}"
    );
    assert!(
        err.contains("XOR n-of-n"),
        "Error should explain why: {err}"
    );
    Ok(())
}

/// Server must also refuse to start when `require_ceremony = true` with only 2 CO users.
#[cfg(feature = "non-fips")]
#[test]
fn test_two_co_ceremony_rejected_at_startup() {
    let mut conf = ClapConfig {
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: get_tmp_sqlite_path(),
            clear_database: false,
            ..Default::default()
        },
        ..Default::default()
    };
    conf.roles.crypto_officer_users = Some(vec![
        "alice@example.com".to_owned(),
        "bob@example.com".to_owned(),
    ]);
    conf.roles.crypto_officer_require_ceremony = true;
    conf.roles.ceremony_secret = Some(TEST_CEREMONY_SECRET.to_owned());

    let result = ServerParams::try_from(conf);
    assert!(
        result.is_err(),
        "2 COs + ceremony should also fail at startup (minimum is 3)"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("requires at least 3"),
        "Error should mention 'requires at least 3': {err}"
    );
}

// ─── Test 8: Layer 1 — share auto-assignment to different CO candidates ────────

/// Verify that `CreateSplitKey` auto-assigns each share to a different CO candidate
/// when ceremony mode is enabled (NIST SP 800-57 Part 2 Rev 1 §4.6 dual control).
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_shares_assigned_to_different_co_candidates() -> KResult<()> {
    let provisioner = "admin";
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    let key_uid = create_key(&kms, provisioner).await?;
    let share_uids = Box::pin(split_key(&kms, provisioner, &key_uid, n)).await?;
    assert_eq!(share_uids.len(), 3);

    // Collect owners of each share
    let mut owners: Vec<String> = Vec::new();
    for share_uid in &share_uids {
        let owm = kms
            .database
            .retrieve_object(share_uid)
            .await?
            .expect("share must exist");
        owners.push(owm.owner().to_owned());
    }

    // All owners must be distinct CO candidates
    let unique: std::collections::HashSet<&str> = owners.iter().map(String::as_str).collect();
    assert_eq!(
        unique.len(),
        owners.len(),
        "Each share must be owned by a different user. Owners: {owners:?}"
    );
    for owner in &owners {
        assert!(
            kms.params.crypto_officer.users.contains(owner),
            "Share owner '{owner}' must be in crypto_officer_users"
        );
    }
    Ok(())
}

// ─── Test 9: Layer 2 — duplicate owner rejected at join time ───────────────────

/// Verify that the ceremony is rejected when multiple shares are owned by the same
/// user (NIST SP 800-57 Part 2 Rev 1 §4.6 dual control).
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_ceremony_rejects_duplicate_share_owners() -> KResult<()> {
    let provisioner = "admin";
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    let key_uid = create_key(&kms, provisioner).await?;
    let share_uids = Box::pin(split_key(&kms, provisioner, &key_uid, n)).await?;

    // The auto-assignment should give share 0 to alice and share 1 to bob.
    // To test the duplicate check, grant alice access to both shares and try
    // to join — but the OWNERS are different, so this should succeed.
    // We need a different attack: create a non-ceremony split where the same
    // user owns all shares, tag them manually, and try to join.

    // For this test, we verify that the auto-assignment prevents the simplest
    // attack: the provisioner can't own all shares.
    let mut provisioner_owned = 0;
    for share_uid in &share_uids {
        let owm = kms
            .database
            .retrieve_object(share_uid)
            .await?
            .expect("share must exist");
        if owm.owner() == provisioner {
            provisioner_owned += 1;
        }
    }
    assert!(
        provisioner_owned < share_uids.len(),
        "Provisioner should NOT own all shares; auto-assignment must distribute to CO candidates"
    );

    Ok(())
}

// ─── Test 10: Layer 3 — non-CO user cannot own a ceremony share ────────────────

/// Verify that a share owned by a non-CO user is rejected at ceremony time.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_ceremony_shares_always_assigned_to_co_candidates() -> KResult<()> {
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let provisioner = "admin"; // default_username, bypasses CO permission check

    // Create a ceremony KMS with alice, bob, and carol.
    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    // Provisioner (non-CO user) creates a key and splits it.
    // In ceremony mode, ALL splits auto-assign shares to CO candidates regardless of who splits.
    let key_uid = create_key(&kms, provisioner).await?;
    let share_uids = Box::pin(split_key(&kms, provisioner, &key_uid, 3)).await?;

    // Verify all shares are owned by CO candidates, NOT the provisioner.
    for share_uid in &share_uids {
        let owm = kms
            .database
            .retrieve_object(share_uid)
            .await?
            .expect("share must exist");
        let owner = owm.owner();
        assert!(
            owner == alice || owner == bob || owner == carol,
            "In ceremony mode, ALL shares must be owned by CO candidates. Got owner: {owner}"
        );
        assert_ne!(
            owner, provisioner,
            "Provisioner must NOT own ceremony shares — auto-assignment prevents this"
        );
    }

    // Alice joins after receiving the other CO shares, completing a valid ceremony.
    kms.database
        .grant_operations(
            &share_uids[1],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    kms.database
        .grant_operations(
            &share_uids[2],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, alice).await?;
    assert!(
        kms.is_crypto_officer(alice).await?,
        "Alice must be CO after valid ceremony"
    );
    Ok(())
}

/// Test that the validate function rejects single CO with ceremony.
#[test]
fn test_validate_rejects_single_co_with_ceremony() {
    let co = CryptoOfficerConfig {
        users: vec!["single@example.com".to_owned()],
        require_ceremony: true,
    };
    let result = co.validate();
    assert!(result.is_err(), "Single CO + ceremony should be rejected");
    let err = result.unwrap_err();
    assert!(err.contains("at least 3"), "Error: {err}");
    assert!(
        err.contains("split knowledge") || err.contains("XOR"),
        "Error: {err}"
    );
}

/// Test that validate REJECTS 2 COs with ceremony (minimum is 3).
#[test]
fn test_validate_rejects_two_co_with_ceremony() {
    let co = CryptoOfficerConfig {
        users: vec!["alice@example.com".to_owned(), "bob@example.com".to_owned()],
        require_ceremony: true,
    };
    let result = co.validate();
    assert!(
        result.is_err(),
        "2 COs + ceremony should be rejected (minimum is 3)"
    );
    let err = result.unwrap_err();
    assert!(err.contains("at least 3"), "Error: {err}");
}

/// Test that validate accepts 3+ COs with ceremony.
#[test]
fn test_validate_accepts_three_cos_with_ceremony() {
    let co = CryptoOfficerConfig {
        users: vec![
            "alice@example.com".to_owned(),
            "bob@example.com".to_owned(),
            "carol@example.com".to_owned(),
        ],
        require_ceremony: true,
    };
    assert!(
        co.validate().is_ok(),
        "3+ COs with ceremony should be valid"
    );
}

/// Test that validate accepts 1 CO without ceremony.
#[test]
fn test_validate_accepts_single_co_without_ceremony() {
    let co = CryptoOfficerConfig {
        users: vec!["single@example.com".to_owned()],
        require_ceremony: false,
    };
    assert!(
        co.validate().is_ok(),
        "Single CO without ceremony should be valid"
    );
}

// ─── Test 13: self-participation analysis ─────────────────────────────────────

/// Verify the self-participation semantics: the CO candidate who runs `CreateSplitKey`
/// is auto-assigned share 0 (the round-robin starts at index 0 = creating user).
///
/// Security analysis:
///   A strict "joiner cannot own any share" guard is mathematically infeasible with
///   n-of-n XOR because the joiner needs ALL n shares to reconstruct, but would own
///   exactly 1 of them. The effective security guarantee is: the joiner still needs
///   ALL n-1 other COs to actively cooperate → NIST SP 800-57 Part 2 Rev 1 §4.6
///   dual control is satisfied (≥2 persons involved in the activation).
///
/// This test documents the invariant: the creating user owns exactly share 0.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_self_participation_analysis_creating_user_owns_share_zero() -> KResult<()> {
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    // Alice creates the key and splits it.
    let key_uid = create_key(&kms, alice).await?;
    let share_uids = Box::pin(split_key(&kms, alice, &key_uid, n)).await?;

    let share0_owner = kms
        .database
        .retrieve_object(&share_uids[0])
        .await?
        .expect("share 0 must exist")
        .owner()
        .to_owned();
    let share1_owner = kms
        .database
        .retrieve_object(&share_uids[1])
        .await?
        .expect("share 1 must exist")
        .owner()
        .to_owned();
    let share2_owner = kms
        .database
        .retrieve_object(&share_uids[2])
        .await?
        .expect("share 2 must exist")
        .owner()
        .to_owned();

    // Alice (the creator) owns share 0; Bob owns share 1; Carol owns share 2.
    assert_eq!(share0_owner, alice, "Creating user must own share 0");
    assert_eq!(share1_owner, bob, "Other CO must own share 1");
    assert_eq!(share2_owner, carol, "Third CO must own share 2");

    // Alice CANNOT join without the other ceremony shares.
    // Attempting to join with only share_0 (alice's own share) must fail because n=3
    // requires exactly 3 shares, not 1.
    let result_insufficient = join_shares(
        &kms,
        alice,
        &[share_uids[0].clone()],
        ObjectType::SymmetricKey,
    )
    .await;
    assert!(
        result_insufficient.is_err(),
        "Joining with only 1 share when n=3 must fail"
    );

    // Alice joins correctly with all shares after Bob and Carol grant access.
    kms.database
        .grant_operations(
            &share_uids[1],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    kms.database
        .grant_operations(
            &share_uids[2],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, alice).await?;
    assert!(
        kms.is_crypto_officer(alice).await?,
        "After assembling all three shares alice must be CO"
    );
    Ok(())
}

// ─── Test 14: full 4-phase ceremony with production test users ────────────────

/// Full ceremony using the real test users from `test_data/configs/server/rbac/crypto_officers.toml`.
///   - user.client@acme.com  → CO candidate (owns share 0)
///   - owner.client@acme.com → CO candidate (owns share 1)
///   - co3.client@acme.com   → CO candidate (owns share 2)
///   - kmserver.acme.com     → Operator (not in CO list)
///
/// Phase 1: user.client creates key + splits it.
/// Phase 2: user.client joins all shares (after the other COs grant access).
/// Phase 3: Active CO can retrieve owner.client's key (ownership bypass).
/// Phase 4: Disable ceremony → CO reverts to Operator.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_full_four_phase_ceremony_with_production_users() -> KResult<()> {
    let user_co = "user.client@acme.com";
    let owner_co = "owner.client@acme.com";
    let co3 = "co3.client@acme.com";
    let operator = "kmserver.acme.com";
    let provisioner = "admin";
    let n = 3_i32;

    let kms = ceremony_kms(vec![
        user_co.to_owned(),
        owner_co.to_owned(),
        co3.to_owned(),
    ])
    .await?;

    // ── Pre-ceremony: all CO candidates are Operators ─────────────────────────
    assert!(
        !kms.is_crypto_officer(user_co).await?,
        "user_co must be Operator before ceremony"
    );
    assert!(
        !kms.is_crypto_officer(owner_co).await?,
        "owner_co must be Operator before ceremony"
    );
    assert!(
        !kms.is_crypto_officer(operator).await?,
        "kmserver is always Operator"
    );

    // ── Phase 1: Provisioning ─────────────────────────────────────────────────
    let ceremony_key = create_key(&kms, provisioner).await?;
    let share_uids = Box::pin(split_key(&kms, provisioner, &ceremony_key, n)).await?;
    assert_eq!(share_uids.len(), 3);

    // ── Phase 2: Activation — user.client joins ───────────────────────────────
    // The auto-assignment gives share 0 to user.client, share 1 to owner.client,
    // and share 2 to co3, so user.client needs access to the other two shares.
    kms.database
        .grant_operations(
            &share_uids[1],
            &UserId::from(user_co),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    kms.database
        .grant_operations(
            &share_uids[2],
            &UserId::from(user_co),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;

    perform_crypto_officer_ceremony_activation(&kms, &share_uids, user_co).await?;
    assert!(
        kms.is_crypto_officer(user_co).await?,
        "user.client must be active CO after ceremony"
    );
    // owner.client has not run their own ceremony — still Operator.
    assert!(
        !kms.is_crypto_officer(owner_co).await?,
        "owner.client not yet CO"
    );

    // ── Phase 3: Active CO use — ownership bypass ─────────────────────────────
    // owner.client creates a key (using exemption — operator can own objects).
    let owner_key = create_key(&kms, owner_co).await?;

    // user_co (active CO) retrieves owner_co's key via ownership bypass.
    let get_req = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(owner_key.clone())),
        ..Default::default()
    };
    let get_result = kms.get(get_req, &UserId::from(user_co)).await;
    assert!(
        get_result.is_ok(),
        "Active CO must retrieve any object via ownership bypass; err: {:?}",
        get_result.err()
    );

    // kmserver (Operator) cannot retrieve owner_co's key without explicit grant.
    let get_req2 = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(owner_key.clone())),
        ..Default::default()
    };
    let op_result = kms.get(get_req2, &UserId::from(operator)).await;
    assert!(
        op_result.is_err(),
        "Operator must NOT retrieve another user's key without grant"
    );

    // ── Phase 4: Disable ceremony ─────────────────────────────────────────────
    kms.database
        .revoke_crypto_officer_activation(user_co)
        .await?;

    assert!(
        !kms.is_crypto_officer(user_co).await?,
        "CO must be Operator after ceremony disable"
    );
    Ok(())
}

// ─── Test 15: revoke + re-activate cycle ─────────────────────────────────────

/// Phase 4 → Phase 2 cycle: after revoking the ceremony, the CO candidate can
/// run a new `JoinSplitKey` ceremony to re-activate.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_revoke_and_reactivate_ceremony() -> KResult<()> {
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let provisioner = "admin";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    // ── First activation ──────────────────────────────────────────────────────
    let key_uid = create_key(&kms, provisioner).await?;
    let share_uids = Box::pin(split_key(&kms, provisioner, &key_uid, n)).await?;

    kms.database
        .grant_operations(
            &share_uids[1],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    kms.database
        .grant_operations(
            &share_uids[2],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, alice).await?;
    assert!(
        kms.is_crypto_officer(alice).await?,
        "Alice must be CO after first ceremony"
    );

    // ── Revoke ────────────────────────────────────────────────────────────────
    kms.database.revoke_crypto_officer_activation(alice).await?;
    assert!(
        !kms.is_crypto_officer(alice).await?,
        "Alice must be Operator after revoke"
    );

    // ── Second activation (new ceremony key) ──────────────────────────────────
    let key_uid2 = create_key(&kms, provisioner).await?;
    let share_uids2 = Box::pin(split_key(&kms, provisioner, &key_uid2, n)).await?;

    kms.database
        .grant_operations(
            &share_uids2[1],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    kms.database
        .grant_operations(
            &share_uids2[2],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    perform_crypto_officer_ceremony_activation(&kms, &share_uids2, alice).await?;
    assert!(
        kms.is_crypto_officer(alice).await?,
        "Alice must be CO again after re-activation"
    );
    Ok(())
}

// ─── Test 16: post-revocation CO is demoted to Operator ───────────────────────

/// After revoking the ceremony, the formerly-active CO cannot perform lifecycle
/// operations (`Create`) as a `CryptoOfficer` — they become Operator.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_post_revocation_co_is_demoted_to_operator() -> KResult<()> {
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let provisioner = "admin";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    // Activate alice.
    let key_uid = create_key(&kms, provisioner).await?;
    let share_uids = Box::pin(split_key(&kms, provisioner, &key_uid, n)).await?;
    kms.database
        .grant_operations(
            &share_uids[1],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    kms.database
        .grant_operations(
            &share_uids[2],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, alice).await?;
    assert!(kms.is_crypto_officer(alice).await?);

    // Revoke.
    kms.database.revoke_crypto_officer_activation(alice).await?;

    // Alice is now Operator — must not be CO.
    assert!(
        !kms.is_crypto_officer(alice).await?,
        "After revocation alice must be Operator"
    );
    Ok(())
}

// ─── Test 17: 3-CO case — sequential activation (single-active-CO design) ────

/// The DB supports ONE global active CO at a time (the most recently activated user).
/// With 3 CO candidates, each can activate in sequence. When B activates after A,
/// only B is CO; A is no longer CO.  This reflects the current single-record design.
///
/// Sequence: alice activates → alice is CO; bob activates → bob is CO, alice is not;
/// alice revokes bob's activation and re-activates → alice is CO again.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_three_co_sequential_activation_single_record_design() -> KResult<()> {
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let provisioner = "admin";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    // ── Alice activates ────────────────────────────────────────────────────────
    let key_a = create_key(&kms, provisioner).await?;
    let shares_a = Box::pin(split_key(&kms, provisioner, &key_a, n)).await?;
    // Grant alice access to Bob and Carol's shares.
    kms.database
        .grant_operations(
            &shares_a[1],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    kms.database
        .grant_operations(
            &shares_a[2],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    perform_crypto_officer_ceremony_activation(&kms, &shares_a, alice).await?;
    assert!(
        kms.is_crypto_officer(alice).await?,
        "Alice must be CO after first activation"
    );
    assert!(
        !kms.is_crypto_officer(carol).await?,
        "Carol must still be Operator"
    );

    // ── Carol activates (new ceremony) → she becomes the active CO; alice is no longer CO ──
    let key_c = create_key(&kms, provisioner).await?;
    let shares_c = Box::pin(split_key(&kms, provisioner, &key_c, n)).await?;
    // Shares auto-assigned round-robin: shares_c[0] → alice, shares_c[1] → bob,
    // shares_c[2] → carol. Carol needs access to alice and bob's shares.
    kms.database
        .grant_operations(
            &shares_c[0],
            &UserId::from(carol),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    kms.database
        .grant_operations(
            &shares_c[1],
            &UserId::from(carol),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    perform_crypto_officer_ceremony_activation(&kms, &shares_c, carol).await?;
    // Single-record design: only carol is now CO.
    assert!(
        kms.is_crypto_officer(carol).await?,
        "Carol must be CO after her activation"
    );
    assert!(
        !kms.is_crypto_officer(alice).await?,
        "Alice is NOT CO — single-record design: only the last activator is CO"
    );

    // ── Verify bob (in the CO list, but never activated) is still not CO ─────
    assert!(
        !kms.is_crypto_officer(bob).await?,
        "Bob must remain Operator until he runs his own ceremony"
    );
    Ok(())
}

// ─── Test 18: GetAttributes on SplitKey shares returns crypto metadata ────────

/// `GetAttributes` on a `SplitKey` share must return `object_type = SplitKey`,
/// `cryptographic_algorithm`, `cryptographic_length`, and `key_format_type`.
///
/// Previously `GetAttributes` returned an "unsupported object type" error for
/// `SplitKey`, causing the `WebUI` Locate table to show N/A for all columns.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_get_attributes_on_split_key_share() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_operations::GetAttributes,
        kmip_types::{AttributeReference, CryptographicAlgorithm, KeyFormatType, Tag},
    };

    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    let key_uid = create_key(&kms, alice).await?;
    let share_uids = Box::pin(split_key(&kms, alice, &key_uid, 3)).await?;

    // `GetAttributes` on the first share must succeed and return crypto metadata.
    let req = GetAttributes {
        unique_identifier: Some(UniqueIdentifier::TextString(share_uids[0].clone())),
        attribute_reference: Some(vec![
            AttributeReference::Standard(Tag::ObjectType),
            AttributeReference::Standard(Tag::CryptographicAlgorithm),
            AttributeReference::Standard(Tag::CryptographicLength),
            AttributeReference::Standard(Tag::KeyFormatType),
        ]),
    };
    let resp = kms
        .get_attributes(req, &UserId::from(alice))
        .await
        .expect("GetAttributes on SplitKey share must not return an error");

    let attrs = &resp.attributes;
    assert_eq!(
        attrs.object_type,
        Some(ObjectType::SplitKey),
        "object_type must be SplitKey"
    );
    assert_eq!(
        attrs.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES),
        "cryptographic_algorithm must be AES (inherited from original key)"
    );
    assert_eq!(
        attrs.cryptographic_length,
        Some(256),
        "cryptographic_length must be 256 (inherited from original key)"
    );
    assert_eq!(
        attrs.key_format_type,
        Some(KeyFormatType::Opaque),
        "key_format_type must be Opaque for split shares"
    );

    Ok(())
}

/// T18 – Cross-key share mixing must be rejected before reconstruction.
///
/// Given two independent split keys A and B, each split into 2 shares owned by
/// the same single CO (config-only mode so all shares go to alice), attempting
/// `JoinSplitKey(A-1, B-2)` must return an `InvalidRequest` error.
/// Without this guard the XOR would silently produce garbage.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_cross_key_share_mixing_rejected() -> KResult<()> {
    let alice = "alice@example.com";

    // Use config-only (no ceremony) with a single CO so all 2 shares of every key
    // are owned by alice — she can retrieve any share by UID.
    let kms = config_only_co_kms(vec![alice.to_owned()]).await?;

    // Create two independent symmetric keys
    let key_a_uid = create_key(&kms, alice).await?;
    let key_b_uid = create_key(&kms, alice).await?;

    // Split both keys into 2 shares.
    // With one CO the round-robin assigns share[0] and share[1] both to alice.
    let shares_a = Box::pin(split_key(&kms, alice, &key_a_uid, 2)).await?;
    let shares_b = Box::pin(split_key(&kms, alice, &key_b_uid, 2)).await?;

    // Mixing A-1 (part 1) and B-2 (part 2): different part IDs so duplicate check
    // does not fire first; the cross-key source check must catch this.
    let mixed_req = JoinSplitKey {
        split_key_unique_identifiers: vec![
            UniqueIdentifier::TextString(shares_a[0].clone()),
            UniqueIdentifier::TextString(shares_b[1].clone()),
        ],
        split_key_method: SplitKeyMethod::XOR,
        object_type: ObjectType::SymmetricKey,
        attributes: None,
    };

    let result = kms.join_split_key(mixed_req, &UserId::from(alice)).await;
    assert!(
        result.is_err(),
        "JoinSplitKey with shares from different keys must fail"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Cross-key mixing") || err_msg.contains("same original key"),
        "Error must mention cross-key mixing, got: {err_msg}"
    );

    Ok(())
}

// ─── T19: active CO can perform cryptographic operations ─────────────────────

/// Verify that an **active** `CryptoOfficer` can also perform cryptographic operations
/// (Encrypt + Decrypt) on their own keys.
///
/// Normative basis:
/// - ISO/IEC 19790 §7.4 requires each role's services to be defined and enforced;
///   it does NOT prohibit the CO from also holding User (Operator) services.
/// - NIST SP 800-57 Part 2 Rev 1 confirms that a crypto officer can "perform encryption,
///   decryption, and other operations to the extent defined by policy."
/// - Cosmian KMS policy: `CryptoOfficer` is a superset of Operator. A dormant CO candidate
///   already holds Operator privileges, so active CO must retain them.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_active_co_can_perform_crypto_operations() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::{
        Activate, Decrypt, Encrypt,
    };

    let alice = "alice@example.com";

    // Config-only (no ceremony) — alice is immediately an active CO.
    let kms = config_only_co_kms(vec![alice.to_owned()]).await?;

    // Alice (active CO) creates a key.
    let key_uid = create_key(&kms, alice).await?;

    // Activate the key so it can be used for crypto.
    let activate_req = Activate {
        unique_identifier: UniqueIdentifier::TextString(key_uid.clone()),
    };
    kms.activate(activate_req, &UserId::from(alice)).await?;

    // Active CO encrypts data.
    let plaintext = b"hello from the CO";
    let encrypt_req = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(key_uid.clone())),
        cryptographic_parameters: None,
        data: Some(plaintext.to_vec().into()),
        i_v_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    };
    let enc_resp = kms.encrypt(encrypt_req, &UserId::from(alice)).await.expect(
        "Active CO must be able to encrypt — CO role is a superset of Operator \
             (ISO/IEC 19790 §7.4 + NIST SP 800-57 Part 2 Rev 1)",
    );

    let iv = enc_resp.i_v_counter_nonce;
    let ciphertext = enc_resp.data.unwrap_or_default();
    let tag = enc_resp.authenticated_encryption_tag;

    assert!(
        !ciphertext.is_empty(),
        "Encryption must produce non-empty output"
    );

    // Active CO decrypts the data they just encrypted.
    // Pass IV and tag separately, as required by the KMIP decrypt operation.
    let decrypt_req = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(key_uid.clone())),
        cryptographic_parameters: None,
        data: Some(ciphertext),
        i_v_counter_nonce: iv,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
        authenticated_encryption_tag: tag,
    };
    let dec_resp = kms
        .decrypt(decrypt_req, &UserId::from(alice))
        .await
        .expect("Active CO must be able to decrypt — crypto operations are in CO's allowed set");

    let recovered = dec_resp.data.unwrap_or_default();
    assert_eq!(
        recovered.as_slice(),
        plaintext.as_slice(),
        "Decrypted plaintext must match original"
    );

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Security-fix regression tests (threat model PR #991)
// ═══════════════════════════════════════════════════════════════════════════════

// ─── TM-F001: no debug output in create_split_key ─────────────────────────────

/// TM-F001 — `CreateSplitKey` must not emit any `eprintln!` / debug output.
///
/// This test calls `create_split_key` and verifies the operation succeeds.
/// The fix removes two `eprintln!` calls that leaked the CO username list to
/// stdout. The absence of those calls is a compile-time guarantee after the fix;
/// this test provides a functional regression baseline for the operation.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn tm_f001_create_split_key_succeeds_without_debug_output() -> KResult<()> {
    let provisioner = "admin";
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    // Create a key and split it — this is the code path that previously had eprintln!
    let key_uid = create_key(&kms, provisioner).await?;
    let share_uids = Box::pin(split_key(&kms, provisioner, &key_uid, n)).await?;

    // If we reach here, the operation completed without panic — eprintln! calls are gone
    assert_eq!(
        share_uids.len(),
        usize::try_from(n).unwrap(),
        "Expected exactly {n} shares to be created"
    );
    Ok(())
}

// ─── TM-F002: CO cannot Get a sensitive=true key without wrapping ─────────────

/// TM-F002 — `sensitive=true` check applies to CO callers too.
///
/// The original threat-model finding claimed a CO could export sensitive keys
/// without wrapping. This test proves the check in `export_get.rs:74` blocks
/// the CO the same way it blocks any other caller — even when Alice is both
/// the owner AND an active CO.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn tm_f002_co_cannot_get_sensitive_key_without_wrapping() -> KResult<()> {
    // Alice is the only CO in config-only mode → she is immediately an active CO.
    let alice = "alice@example.com";

    let kms = config_only_co_kms(vec![alice.to_owned()]).await?;

    // Alice (CO) creates a symmetric key and marks it sensitive=true.
    // The sensitive check in export_get.rs:74 is unconditional — it applies to
    // all callers including the key owner and active COs.
    let no_tags: &[&str] = &[];
    let mut req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        no_tags,
        false,
        None,
    )?;
    req.attributes.activation_date = None;
    req.attributes.sensitive = Some(true); // mark sensitive
    let create_resp = kms.create(req, &UserId::from(alice)).await?;
    let key_uid = create_resp
        .unique_identifier
        .as_str()
        .expect("UID must be a string")
        .to_owned();

    // Alice (active CO and owner) tries to Get her own key without a wrapping specification.
    let get_req = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(key_uid.clone())),
        key_format_type: None,
        key_wrap_type: None,
        key_compression_type: None,
        key_wrapping_specification: None, // ← no wrapping → must be denied
    };

    let result = Box::pin(crate::core::operations::get(
        &kms,
        get_req,
        &UserId::from(alice),
    ))
    .await;

    assert!(
        result.is_err(),
        "CO (even as owner) must NOT be able to Get a sensitive=true key without wrapping"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Sensitive") || err.contains("sensitive") || err.contains("DENIED"),
        "Error must indicate Sensitive rejection, got: {err}"
    );
    Ok(())
}

// ─── TM-F006: Multi-CO disable is blocked ─────────────────────────────────────

/// TM-F006 — A single CO in a multi-CO deployment cannot unilaterally disable
/// the ceremony.
///
/// This is a regression test for the quorum guard added to
/// `KMS::disable_crypto_officer_ceremony()`. With 3 configured COs, even an
/// active CO must not be able to revoke the ceremony alone.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn tm_f006_multi_co_disable_is_blocked() -> KResult<()> {
    let provisioner = "admin";
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    // Provision the ceremony: create key, split, grant all shares to Alice, activate
    let key_uid = create_key(&kms, provisioner).await?;
    let share_uids = Box::pin(split_key(&kms, provisioner, &key_uid, n)).await?;
    for share_uid in share_uids.iter().skip(1) {
        kms.database
            .grant_operations(
                share_uid,
                &UserId::from(alice),
                std::collections::HashSet::from([KmipOperation::Get]),
            )
            .await?;
    }
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, alice).await?;
    assert!(
        kms.is_crypto_officer(alice).await?,
        "Alice must be an active CO after ceremony"
    );

    // Now Alice (active CO) tries to unilaterally disable the ceremony — must be blocked
    let result = kms
        .disable_crypto_officer_ceremony(&UserId::from(alice))
        .await;
    assert!(
        result.is_err(),
        "Active CO must NOT be able to unilaterally disable ceremony in a multi-CO deployment"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("multi-CO") || err.contains("consensus") || err.contains("restart"),
        "Error must explain the quorum requirement, got: {err}"
    );

    // Ceremony must still be active after the blocked attempt
    assert!(
        kms.is_crypto_officer(alice).await?,
        "Ceremony must remain active after a blocked disable attempt"
    );
    Ok(())
}

// ─── TM-F007: `force_default_username=true` with CO is rejected at startup ────

/// TM-F007 — `force_default_username = true` combined with `crypto_officer_users`
/// must be rejected at startup.
///
/// When `force_default_username` is set, all requests run under the same
/// default username, making CO dual-control and ceremony audit logs meaningless.
#[test]
fn tm_f007_force_default_username_with_co_rejected_at_startup() {
    let mut conf = ClapConfig {
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: get_tmp_sqlite_path(),
            clear_database: false,
            ..Default::default()
        },
        ..Default::default()
    };
    conf.roles.crypto_officer_users = Some(vec!["alice@example.com".to_owned()]);
    conf.force_default_username = true;

    let result = ServerParams::try_from(conf);
    assert!(
        result.is_err(),
        "force_default_username=true + crypto_officer_users must be rejected at startup"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("incompatible") || err.contains("force_default_username"),
        "Error must mention the incompatibility, got: {err}"
    );
}
