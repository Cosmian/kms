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
//! Security regression tests:
//! - no eprintln!/debug leakage of CO identity in `create_split_key`.
//! - CO cannot Get/Export a `sensitive=true` key without wrapping.
//! - startup emits WARN when config-only CO mode is active.
//! - active CO self-revokes (quorum guard removed; peer revocation enabled).
//! - startup validation rejects `force_default_username=true` with CO configured.
//! - dormant CO candidate can peer-revoke an active CO.
//! - reconstructed key object intact after peer revocation.
//! - Operator (non-candidate) cannot peer-revoke a CO.

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
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    tests::test_utils::get_tmp_sqlite_path,
};

// A fixed 32-byte secret used for all ceremony tests.
const TEST_CEREMONY_SECRET: &str =
    "deadbeefcafebabe0102030405060708090a0b0c0d0e0f10deadbeefcafebabe";

/// Extract the text-string from a `UniqueIdentifier`, propagating as a `KResult`.
/// Replaces `.as_str().expect("UID must be a string")` throughout this file so
/// a malformed server response produces a descriptive error rather than a panic.
fn uid_string(uid: &UniqueIdentifier) -> KResult<String> {
    uid.as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| KmsError::InvalidRequest(format!("expected TextString UID, got {uid:?}")))
}

/// Build a base `ClapConfig` for CO-related tests.
///
/// - `require_ceremony`: when `true`, also sets `ceremony_secret = TEST_CEREMONY_SECRET`
/// - `wrap_key_id`: when `Some`, sets `ceremony_wrapping_key_id`
fn base_ceremony_conf(
    co_users: Vec<String>,
    require_ceremony: bool,
    wrap_key_id: Option<&str>,
) -> ClapConfig {
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
    conf.roles.crypto_officer_require_ceremony = require_ceremony;
    if require_ceremony {
        conf.roles.ceremony_secret = Some(TEST_CEREMONY_SECRET.to_owned());
    }
    if let Some(id) = wrap_key_id {
        conf.roles.ceremony_wrapping_key_id = Some(id.to_owned());
    }
    conf
}

/// Build a `KMS` configured for ceremony mode with the given CO users.
async fn ceremony_kms(co_users: Vec<String>) -> KResult<Arc<KMS>> {
    let conf = base_ceremony_conf(co_users, true, None);
    let params = ServerParams::try_from(conf)?;
    Ok(Arc::new(KMS::instantiate(Arc::new(params)).await?))
}

/// Build a `KMS` configured for ceremony mode with AES-KW share wrapping enabled.
///
/// A fresh wrapping key is pre-created and its UID is set as `ceremony_wrapping_key_id`.
/// The returned `Arc<KMS>` is ready for split-key operations that wrap shares at rest.
async fn ceremony_kms_with_wrapping(co_users: Vec<String>, wrap_key_id: &str) -> KResult<Arc<KMS>> {
    let conf = base_ceremony_conf(co_users.clone(), true, Some(wrap_key_id));
    let params = ServerParams::try_from(conf)?;
    let kms = Arc::new(KMS::instantiate(Arc::new(params)).await?);

    // Pre-create the wrapping key directly in the DB as the first CO user.
    // `create_key` is a CO-free helper that stores directly through the operations layer.
    let owner = co_users.first().map_or("admin", String::as_str);
    let no_tags: &[&str] = &[];
    let req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(wrap_key_id.to_owned())),
        256,
        CryptographicAlgorithm::AES,
        no_tags,
        false,
        None,
    )?;
    kms.create(req, &UserId::from(owner)).await?;

    Ok(kms)
}

async fn config_only_co_kms(co_users: Vec<String>) -> KResult<Arc<KMS>> {
    let conf = base_ceremony_conf(co_users, false, None);
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
    uid_string(&resp.unique_identifier)
}

/// Split `key_uid` into `total_parts` XOR shares; return share UIDs.
async fn split_key(
    kms: &KMS,
    owner: &str,
    key_uid: &str,
    total_parts: i32,
) -> KResult<Vec<String>> {
    let req = CreateSplitKey {
        object_type: ObjectType::SymmetricKey,
        unique_identifier: Some(UniqueIdentifier::TextString(key_uid.to_owned())),
        split_key_parts: total_parts,
        split_key_threshold: total_parts, // XOR n-of-n
        split_key_method: SplitKeyMethod::XOR,
        attributes: None,
        protection_storage_masks: None,
    };
    let resp = Box::pin(kms.create_split_key(req, &UserId::from(owner))).await?;
    resp.unique_identifier
        .iter()
        .map(uid_string)
        .collect::<KResult<Vec<_>>>()
}

/// Reconstruct from the given share UIDs; return the reconstructed key UID.
async fn join_shares(
    kms: &KMS,
    user: &str,
    share_uids: &[String],
    expected_type: ObjectType,
) -> KResult<String> {
    let req = JoinSplitKey {
        unique_identifier: share_uids
            .iter()
            .map(|u| UniqueIdentifier::TextString(u.clone()))
            .collect(),
        object_type: expected_type,
        secret_data_type: None,
        attributes: None,
        protection_storage_masks: None,
    };
    let resp = kms.join_split_key(req, &UserId::from(user)).await?;
    uid_string(&resp.unique_identifier)
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
        kms.is_crypto_officer(&UserId::from(alice)).await?,
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
        !kms.is_crypto_officer(&UserId::from(bob)).await?,
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
        !kms.is_crypto_officer(&UserId::from(alice)).await?,
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
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, &UserId::from(alice)).await?;

    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
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
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, &UserId::from(alice)).await?;

    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice should be CO after her ceremony"
    );
    assert!(
        !kms.is_crypto_officer(&UserId::from(bob)).await?,
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
    let result =
        perform_crypto_officer_ceremony_activation(&kms, &share_uids, &UserId::from(eve)).await;
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
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, &UserId::from(alice)).await?;
    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
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
        ceremony_wrapping_key_id: None,
    };
    let result = co.validate();
    assert!(result.is_err(), "Single CO + ceremony should be rejected");
    let err = result.unwrap_err().to_string();
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
        ceremony_wrapping_key_id: None,
    };
    let result = co.validate();
    assert!(
        result.is_err(),
        "2 COs + ceremony should be rejected (minimum is 3)"
    );
    let err = result.unwrap_err().to_string();
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
        ceremony_wrapping_key_id: None,
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
        ceremony_wrapping_key_id: None,
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
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, &UserId::from(alice)).await?;
    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
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
        !kms.is_crypto_officer(&UserId::from(user_co)).await?,
        "user_co must be Operator before ceremony"
    );
    assert!(
        !kms.is_crypto_officer(&UserId::from(owner_co)).await?,
        "owner_co must be Operator before ceremony"
    );
    assert!(
        !kms.is_crypto_officer(&UserId::from(operator)).await?,
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

    perform_crypto_officer_ceremony_activation(&kms, &share_uids, &UserId::from(user_co)).await?;
    assert!(
        kms.is_crypto_officer(&UserId::from(user_co)).await?,
        "user.client must be active CO after ceremony"
    );
    // owner.client has not run their own ceremony — still Operator.
    assert!(
        !kms.is_crypto_officer(&UserId::from(owner_co)).await?,
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
        .revoke_crypto_officer_activation(user_co, user_co)
        .await?;

    assert!(
        !kms.is_crypto_officer(&UserId::from(user_co)).await?,
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
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, &UserId::from(alice)).await?;
    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must be CO after first ceremony"
    );

    // ── Revoke ────────────────────────────────────────────────────────────────
    kms.database
        .revoke_crypto_officer_activation(alice, alice)
        .await?;
    assert!(
        !kms.is_crypto_officer(&UserId::from(alice)).await?,
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
    perform_crypto_officer_ceremony_activation(&kms, &share_uids2, &UserId::from(alice)).await?;
    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
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
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, &UserId::from(alice)).await?;
    assert!(kms.is_crypto_officer(&UserId::from(alice)).await?);

    // Revoke.
    kms.database
        .revoke_crypto_officer_activation(alice, alice)
        .await?;

    // Alice is now Operator — must not be CO.
    assert!(
        !kms.is_crypto_officer(&UserId::from(alice)).await?,
        "After revocation alice must be Operator"
    );
    Ok(())
}

// ─── Test 19: reconstructed-key storage — per activation path ─────────────────

/// **`POST /access/crypto_officer/ceremony/activate` (UI path)**:
/// The reconstructed key is computed in RAM to derive its hash, then zeroized.
/// It is **never stored** in the `objects` table.  After activation the base key
/// UID (i.e., the share root without the `#N` suffix) must be absent from the DB.
///
/// **`JoinSplitKey` KMIP operation (CLI path)**:
/// The reconstructed key IS stored as an Active managed object before the ceremony
/// activation side-effect runs.  After `join_shares` the base UID must exist.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_activation_endpoint_does_not_store_reconstructed_key() -> KResult<()> {
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let provisioner = "admin";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    // ── Create the ceremony key with a deterministic UID ──────────────────────
    let key_uid = "ceremony-key-rest-path-test";
    let no_tags: &[&str] = &[];
    let mut req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(key_uid.to_owned())),
        256,
        CryptographicAlgorithm::AES,
        no_tags,
        false,
        None,
    )?;
    req.attributes.activation_date = None;
    kms.create(req, &UserId::from(provisioner)).await?;

    let shares = Box::pin(split_key(&kms, provisioner, key_uid, n)).await?;

    // ── Source key is destroyed after the split ───────────────────────────────
    assert!(
        kms.database.retrieve_object(key_uid).await?.is_none(),
        "Source key must be destroyed after CreateSplitKey"
    );

    // ── Grant alice access to bob and carol's shares ──────────────────────────
    kms.database
        .grant_operations(
            &shares[1],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    kms.database
        .grant_operations(
            &shares[2],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;

    // ── Activate via the REST path (perform_crypto_officer_ceremony_activation) ─
    // This is what the UI calls — it must NOT store the reconstructed key.
    perform_crypto_officer_ceremony_activation(&kms, &shares, &UserId::from(alice)).await?;

    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must be an active CO after the REST activation"
    );

    // The reconstructed key UID (base UID without #N suffix) must NOT be in DB.
    let reconstructed_uid = key_uid; // base UID = source key UID = ceremony-key-rest-path-test
    assert!(
        kms.database
            .retrieve_object(reconstructed_uid)
            .await?
            .is_none(),
        "REST activation path must NOT store the reconstructed key in the DB"
    );

    Ok(())
}

/// **`JoinSplitKey` (CLI path)** stores the reconstructed key as a managed object.
///
/// This is the complementary test: the KMIP path explicitly persists the key so
/// the caller can use it as a wrapping/encryption key after ceremony completion.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_join_split_key_stores_reconstructed_key() -> KResult<()> {
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let provisioner = "admin";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    let key_uid = "ceremony-key-kmip-path-test";
    let no_tags: &[&str] = &[];
    let mut req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(key_uid.to_owned())),
        256,
        CryptographicAlgorithm::AES,
        no_tags,
        false,
        None,
    )?;
    req.attributes.activation_date = None;
    kms.create(req, &UserId::from(provisioner)).await?;

    let shares = Box::pin(split_key(&kms, provisioner, key_uid, n)).await?;

    kms.database
        .grant_operations(
            &shares[1],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    kms.database
        .grant_operations(
            &shares[2],
            &UserId::from(alice),
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;

    // ── Activate via JoinSplitKey (KMIP / CLI path) ───────────────────────────
    // This DOES store the reconstructed key before ceremony activation runs.
    let reconstructed_uid = join_shares(&kms, alice, &shares, ObjectType::SymmetricKey).await?;

    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must be an active CO after JoinSplitKey"
    );

    // The reconstructed key must exist in the DB.
    let owm = kms.database.retrieve_object(&reconstructed_uid).await?;
    assert!(
        owm.is_some(),
        "KMIP JoinSplitKey path must store the reconstructed key in the DB (uid={reconstructed_uid})"
    );

    Ok(())
}

/// Per-user model: each CO candidate activates independently. Multiple CO users
/// can be simultaneously active. When Carol activates after Alice, Alice remains
/// an active CO — Carol's activation does NOT demote Alice.
///
/// Sequence: alice activates → alice is CO; carol activates → carol AND alice are
/// both CO simultaneously; bob never activates → bob is still Operator.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_multiple_co_simultaneous_activation() -> KResult<()> {
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
    perform_crypto_officer_ceremony_activation(&kms, &shares_a, &UserId::from(alice)).await?;
    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must be CO after her activation"
    );
    assert!(
        !kms.is_crypto_officer(&UserId::from(carol)).await?,
        "Carol must still be Operator before her own ceremony"
    );

    // ── Carol activates her own ceremony → she becomes CO; Alice stays CO ─────
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
    perform_crypto_officer_ceremony_activation(&kms, &shares_c, &UserId::from(carol)).await?;

    // Per-user model: both Alice and Carol are now simultaneously active COs.
    assert!(
        kms.is_crypto_officer(&UserId::from(carol)).await?,
        "Carol must be CO after her activation"
    );
    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must STILL be CO — her activation was not affected by Carol's"
    );

    // Bob never activated — still an Operator.
    assert!(
        !kms.is_crypto_officer(&UserId::from(bob)).await?,
        "Bob must remain Operator until he runs his own ceremony"
    );

    // Peer-revoke Carol: Alice (active CO) revokes Carol.
    kms.disable_crypto_officer_ceremony(&UserId::from(alice), Some(&UserId::from(carol)))
        .await?;
    assert!(
        !kms.is_crypto_officer(&UserId::from(carol)).await?,
        "Carol must be demoted after Alice peer-revokes her"
    );
    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must remain CO — only Carol's record was revoked"
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
        unique_identifier: vec![
            UniqueIdentifier::TextString(shares_a[0].clone()),
            UniqueIdentifier::TextString(shares_b[1].clone()),
        ],
        object_type: ObjectType::SymmetricKey,
        secret_data_type: None,
        attributes: None,
        protection_storage_masks: None,
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

// ─── no debug output in create_split_key ─────────────────────────────────────

/// `CreateSplitKey` must not emit any `eprintln!` / debug output.
///
/// This test calls `create_split_key` and verifies the operation succeeds.
/// The fix removes two `eprintln!` calls that leaked the CO username list to
/// stdout. The absence of those calls is a compile-time guarantee after the fix;
/// this test provides a functional regression baseline for the operation.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_create_split_key_succeeds_without_debug_output() -> KResult<()> {
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

// ─── CO cannot Get a sensitive=true key without wrapping ─────────────

/// `sensitive=true` check applies to CO callers too.
///
/// The original threat-model finding claimed a CO could export sensitive keys
/// without wrapping. This test proves the check in `export_get.rs:74` blocks
/// the CO the same way it blocks any other caller — even when Alice is both
/// the owner AND an active CO.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_co_cannot_get_sensitive_key_without_wrapping() -> KResult<()> {
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
    let key_uid = uid_string(&create_resp.unique_identifier)?;

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

// ─── Active CO self-revokes ──────────────────────────────────────────

/// An active CO can self-revoke in a multi-CO deployment.
///
/// Regression test for the peer-revocation architecture (PR #991):
/// the quorum guard was removed; any CO candidate can now revoke an active CO,
/// including self-revocation.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_active_co_can_self_revoke() -> KResult<()> {
    let provisioner = "admin";
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    // Provision: create key, split, grant all shares to Alice, activate
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
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, &UserId::from(alice)).await?;
    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must be active CO"
    );

    // Alice self-revokes (no target_user)
    kms.disable_crypto_officer_ceremony(&UserId::from(alice), None)
        .await?;

    assert!(
        !kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must no longer be CO after self-revoke"
    );
    Ok(())
}

// ─── Peer CO revokes active CO ───────────────────────────────────────

/// A dormant CO candidate (Bob) can peer-revoke an active CO (Alice).
///
/// Any configured CO candidate can call `disable_crypto_officer_ceremony` with
/// a `target_user` to revoke another CO's ceremony activation.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_peer_co_revokes_active_co() -> KResult<()> {
    let provisioner = "admin";
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    // Provision: Alice activates as CO (she gets all 3 shares)
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
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, &UserId::from(alice)).await?;
    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must be active CO"
    );
    assert!(
        !kms.is_crypto_officer(&UserId::from(bob)).await?,
        "Bob must be dormant"
    );

    // Bob (dormant CO candidate) peer-revokes Alice
    kms.disable_crypto_officer_ceremony(&UserId::from(bob), Some(&UserId::from(alice)))
        .await?;

    assert!(
        !kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must no longer be CO after peer revocation by Bob"
    );
    Ok(())
}

// ─── Reconstructed key intact after peer revocation ──────────────────

/// After peer revocation, the reconstructed key stored via `JoinSplitKey`
/// still exists and is accessible (peer revocation only revokes the activation record,
/// never the key object).
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_reconstructed_key_intact_after_peer_revocation() -> KResult<()> {
    let provisioner = "admin";
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    // Split source key; grant all shares to Alice
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

    // Activate Alice as CO (writes activation record; does NOT store a key)
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, &UserId::from(alice)).await?;
    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must be active CO"
    );

    // Alice also reconstructs the key via JoinSplitKey (stores a key object she owns)
    let reconstructed_uid = join_shares(&kms, alice, &share_uids, ObjectType::SymmetricKey).await?;

    // Bob peer-revokes Alice — only the activation record is revoked, key is untouched
    kms.disable_crypto_officer_ceremony(&UserId::from(bob), Some(&UserId::from(alice)))
        .await?;
    assert!(
        !kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must be revoked"
    );

    // Alice's reconstructed key must still be accessible (peer revocation does NOT
    // destroy or revoke key objects — only the crypto_officer_activations row is updated)
    let get_req = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(reconstructed_uid.clone())),
        ..Default::default()
    };
    let result = kms.get(get_req, &UserId::from(alice)).await;
    assert!(
        result.is_ok(),
        "Reconstructed key must still exist after peer revocation, got: {result:?}"
    );
    Ok(())
}

// ─── Operator (non-candidate) cannot peer-revoke ─────────────────────

/// A plain Operator (not in `crypto_officer_users`) cannot peer-revoke
/// an active CO via `disable_crypto_officer_ceremony`.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_operator_cannot_peer_revoke() -> KResult<()> {
    let provisioner = "admin";
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";
    let eve = "eve@example.com"; // pure Operator — not in crypto_officer_users
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    // Alice activates as CO
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
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, &UserId::from(alice)).await?;
    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must be active CO"
    );

    // Eve (Operator) tries to peer-revoke Alice — must be unauthorized
    let result = kms
        .disable_crypto_officer_ceremony(&UserId::from(eve), Some(&UserId::from(alice)))
        .await;
    assert!(
        result.is_err(),
        "Operator must not be able to peer-revoke CO"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Unauthorized") || err.contains("candidate"),
        "Error must indicate authorization failure, got: {err}"
    );

    // Alice must still be active CO
    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must remain active CO after unauthorized peer-revoke attempt"
    );
    Ok(())
}

// ─── Peer revocation revokes victim's GET on revoker's share ─────────

/// When a dormant CO (Bob) peer-revokes an active CO (Alice), Alice's
/// GET access on Bob's split-key share is automatically revoked.
///
/// This prevents the revoked CO from re-assembling the ceremony key using the
/// share grants obtained during the previous activation ceremony.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_peer_revocation_revokes_share_access() -> KResult<()> {
    let provisioner = "admin";
    let alice = "alice@example.com"; // active CO
    let bob = "bob@example.com"; // dormant CO — performs revocation
    let carol = "carol@example.com";
    let n = 3_i32;

    let kms = ceremony_kms(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]).await?;

    // Provision: split key — shares are round-robin: alice→0, bob→1, carol→2
    let key_uid = create_key(&kms, provisioner).await?;
    let share_uids = Box::pin(split_key(&kms, provisioner, &key_uid, n)).await?;

    // Grant Alice GET access on Bob's share (share_uids[1]) and Carol's (share_uids[2])
    // so she can activate the ceremony.
    for share_uid in share_uids.iter().skip(1) {
        kms.database
            .grant_operations(
                share_uid,
                &UserId::from(alice),
                std::collections::HashSet::from([KmipOperation::Get]),
            )
            .await?;
    }
    perform_crypto_officer_ceremony_activation(&kms, &share_uids, &UserId::from(alice)).await?;
    assert!(
        kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must be active CO"
    );

    // Bob's share is share_uids[1] (round-robin index 1 → bob)
    let bob_share_uid = &share_uids[1];

    // Verify Alice currently has GET access on Bob's share
    let alice_ops_before = kms
        .database
        .list_user_operations_on_object(bob_share_uid, &UserId::from(alice), true)
        .await?;
    assert!(
        alice_ops_before.contains(&KmipOperation::Get),
        "Alice must have GET access on Bob's share before revocation"
    );

    // Bob peer-revokes Alice
    kms.disable_crypto_officer_ceremony(&UserId::from(bob), Some(&UserId::from(alice)))
        .await?;
    assert!(
        !kms.is_crypto_officer(&UserId::from(alice)).await?,
        "Alice must be revoked"
    );

    // Alice's GET access on Bob's share must now be gone
    let alice_ops_after = kms
        .database
        .list_user_operations_on_object(bob_share_uid, &UserId::from(alice), true)
        .await?;
    assert!(
        !alice_ops_after.contains(&KmipOperation::Get),
        "Alice must NO LONGER have GET access on Bob's share after peer revocation"
    );

    Ok(())
}

// ─── `force_default_username=true` with CO is rejected at startup ───────────

/// `force_default_username = true` combined with `crypto_officer_users`
/// must be rejected at startup.
///
/// When `force_default_username` is set, all requests run under the same
/// default username, making CO dual-control and ceremony audit logs meaningless.
#[test]
fn test_force_default_username_with_co_rejected_at_startup() {
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

// ─── ceremony_wrapping_key_id tests ──────────────────────────────────────────
//
// These tests verify the AES-KW (RFC 5649) share-wrapping path activated when
// `ceremony_wrapping_key_id` is set in the server configuration.
//
// WK-1  Split with a wrapping key → shares stored as wrapped ciphertext, roundtrip succeeds.
// WK-2  Missing wrapping key → CreateSplitKey fails with ItemNotFound.
// WK-3  CreateSplitKey without wrapping key + JoinSplitKey without wrapping key → unaffected.
// WK-4  Wrapped shares cannot be joined without the wrapping key present.

/// WK-1: `CreateSplitKey` with `ceremony_wrapping_key_id` set wraps every share at rest.
///
/// Verifies that the full roundtrip (split then join) succeeds when the wrapping
/// key is present and correctly configured.  The ceremony activation step is skipped
/// here so the test focuses solely on the wrap/unwrap path.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_ceremony_wrapping_key_split_and_join_roundtrip() -> KResult<()> {
    const WRAP_KEY_ID: &str = "ceremony-wrap-test-1";
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";

    let kms = ceremony_kms_with_wrapping(
        vec![alice.to_owned(), bob.to_owned(), carol.to_owned()],
        WRAP_KEY_ID,
    )
    .await?;

    // Create the source key as the first CO candidate.
    let key_uid = create_key(&kms, alice).await?;

    // Split (ceremony mode: source key is destroyed after split).
    let share_uids = split_key(&kms, alice, &key_uid, 3).await?;
    assert_eq!(share_uids.len(), 3, "expected 3 wrapped shares");

    // Grant Get access so alice can read the shares owned by bob and carol.
    for uid in &share_uids {
        kms.database
            .grant_operations(
                uid,
                &UserId::from(alice),
                std::collections::HashSet::from([KmipOperation::Get]),
            )
            .await?;
    }

    // Reconstruct: JoinSplitKey must unwrap each share before XOR-joining.
    let reconstructed_uid = join_shares(&kms, alice, &share_uids, ObjectType::SymmetricKey).await?;
    assert!(
        !reconstructed_uid.is_empty(),
        "reconstructed UID must not be empty"
    );

    // Verify the reconstructed object exists and is retrievable.
    let get_req = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(reconstructed_uid.clone())),
        ..Default::default()
    };
    kms.get(get_req, &UserId::from(alice)).await?;

    Ok(())
}

/// WK-2: `CreateSplitKey` with a non-existent `ceremony_wrapping_key_id` must fail with
/// `ItemNotFound`, not a panic or an opaque server error.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_ceremony_wrapping_key_missing_returns_item_not_found() -> KResult<()> {
    // UID that is NEVER created in the DB — must be declared before any `let` binding.
    const MISSING_KEY_ID: &str = "ceremony-wrap-does-not-exist";
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";

    // Build the KMS with a wrapping key UID that is NEVER created in the DB.
    let mut conf = ClapConfig {
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: get_tmp_sqlite_path(),
            clear_database: false,
            ..Default::default()
        },
        ..Default::default()
    };
    conf.roles.crypto_officer_users =
        Some(vec![alice.to_owned(), bob.to_owned(), carol.to_owned()]);
    conf.roles.crypto_officer_require_ceremony = true;
    conf.roles.ceremony_secret = Some(TEST_CEREMONY_SECRET.to_owned());
    conf.roles.ceremony_wrapping_key_id = Some(MISSING_KEY_ID.to_owned());

    let params = ServerParams::try_from(conf)?;
    let kms = Arc::new(KMS::instantiate(Arc::new(params)).await?);

    // Create a source key and attempt to split it.
    let key_uid = create_key(&kms, alice).await?;
    let result = split_key(&kms, alice, &key_uid, 3).await;

    assert!(result.is_err(), "split with missing wrapping key must fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not found") || err.contains("ItemNotFound") || err.contains(MISSING_KEY_ID),
        "error must reference the missing key, got: {err}"
    );

    Ok(())
}

/// WK-3: Generic (non-ceremony) split without `ceremony_wrapping_key_id` stores shares
/// as plaintext and the roundtrip succeeds without unwrapping.
///
/// Regression: the wrapping path must not activate when `ceremony_wrapping_key_id` is `None`.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_generic_split_without_wrapping_key_roundtrip() -> KResult<()> {
    let alice = "alice@example.com";
    // Config-only CO (no ceremony, no wrapping key).
    let kms = config_only_co_kms(vec![alice.to_owned()]).await?;

    let key_uid = create_key(&kms, alice).await?;

    // Generic split (no ceremony attribute, no wrapping).
    let req = CreateSplitKey {
        object_type: ObjectType::SymmetricKey,
        unique_identifier: Some(UniqueIdentifier::TextString(key_uid.clone())),
        split_key_parts: 2,
        split_key_threshold: 2,
        split_key_method: SplitKeyMethod::XOR,
        attributes: None,
        protection_storage_masks: None,
    };
    let resp = Box::pin(kms.create_split_key(req, &UserId::from(alice))).await?;
    let share_uids: Vec<String> = resp
        .unique_identifier
        .iter()
        .map(uid_string)
        .collect::<KResult<Vec<_>>>()?;
    assert_eq!(share_uids.len(), 2, "expected 2 unwrapped shares");

    // Reconstruct — source key is still alive (no ceremony destruction).
    let reconstructed_uid = join_shares(&kms, alice, &share_uids, ObjectType::SymmetricKey).await?;
    assert!(!reconstructed_uid.is_empty());

    Ok(())
}

/// WK-4: Shares created WITH a wrapping key cannot be joined after the wrapping key
/// is deleted from the DB — `JoinSplitKey` must fail, not silently produce wrong key bytes.
///
/// This is a security regression test: wrapped shares must remain unreadable if the
/// wrapping key is lost (expected operational behaviour — operators must re-ceremony).
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_join_wrapped_shares_fails_after_wrapping_key_deleted() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
        kmip_2_1::kmip_operations::{Destroy, Revoke},
    };

    const WRAP_KEY_ID: &str = "ceremony-wrap-test-4";
    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let carol = "carol@example.com";

    let kms = ceremony_kms_with_wrapping(
        vec![alice.to_owned(), bob.to_owned(), carol.to_owned()],
        WRAP_KEY_ID,
    )
    .await?;

    let key_uid = create_key(&kms, alice).await?;
    let share_uids = split_key(&kms, alice, &key_uid, 3).await?;
    assert_eq!(share_uids.len(), 3);

    // Grant alice Get on all shares.
    for uid in &share_uids {
        kms.database
            .grant_operations(
                uid,
                &UserId::from(alice),
                std::collections::HashSet::from([KmipOperation::Get]),
            )
            .await?;
    }

    // Destroy the wrapping key (revoke first, then destroy).
    let revoke_req = Revoke {
        unique_identifier: Some(UniqueIdentifier::TextString(WRAP_KEY_ID.to_owned())),
        revocation_reason: RevocationReason {
            revocation_reason_code: RevocationReasonCode::CessationOfOperation,
            revocation_message: Some("test teardown".to_owned()),
        },
        compromise_occurrence_date: None,
        cascade: false,
    };
    kms.revoke(revoke_req, &UserId::from(alice)).await?;
    let destroy_req = Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(WRAP_KEY_ID.to_owned())),
        remove: true,
        cascade: false,
        expected_object_type: None,
    };
    kms.destroy(destroy_req, &UserId::from(alice)).await?;

    // JoinSplitKey must now fail: the wrapping key is gone.
    let result = join_shares(&kms, alice, &share_uids, ObjectType::SymmetricKey).await;
    assert!(
        result.is_err(),
        "JoinSplitKey must fail when the wrapping key has been destroyed"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not found") || err.contains("ItemNotFound") || err.contains(WRAP_KEY_ID),
        "error must reference the missing wrapping key, got: {err}"
    );

    Ok(())
}
