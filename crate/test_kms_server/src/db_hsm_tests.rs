//! DB-backend × `SoftHSM2` integration lifecycle tests.
//!
//! Each test function walks the **full KMIP key lifecycle** against a live KMS
//! server that uses `SoftHSM2` as its HSM Key Encryption Key (KEK) provider.
//! The HSM path is exercised at every step where the server must wrap or unwrap
//! key material (Create, Get, `ReKey`, …).
//!
//! The DB backend is selected at **runtime** via the `KMS_TEST_DB` environment
//! variable, which the MISE task sets before invoking `cargo test`.
//!
//! `HSM_SLOT_ID` must also be exported (the MISE task calls
//! `softhsm2_init_standard_tokens` which outputs the slot ID).
//! `start_default_test_kms_server_with_softhsm2_and_kek` panics with a
//! descriptive error if `HSM_SLOT_ID` is absent — **no silent skip**.
//!
//! # Running manually
//!
//! ```bash
//! # SQLite (always available, softhsm2 must be installed)
//! mise run test:db:sqlite
//!
//! # PostgreSQL
//! docker compose up -d postgres && mise run test:db:psql
//!
//! # MySQL / MariaDB
//! docker compose up -d mysql && mise run test:db:mysql
//!
//! # Redis-findex (non-FIPS only)
//! docker compose up -d redis && mise run test:db:redis --variant non-fips
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cosmian_kms_client::{
    KmsClientError,
    kmip_0::kmip_types::{RevocationReason, RevocationReasonCode, State},
    kmip_2_1::{
        extra::VENDOR_ID_COSMIAN,
        kmip_attributes::Attribute,
        kmip_operations::{Destroy, Get, GetAttributes, ReKey, Revoke, SetAttribute},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
        requests::{decrypt_request, encrypt_request, symmetric_key_create_request},
    },
};

use crate::{init_test_logging, start_default_test_kms_server_with_softhsm2_and_kek};

/// Full key lifecycle exercised against the HSM-backed KMS.
///
/// Stages (each one exercises HSM wrap/unwrap at the DB layer):
///
/// 1. **Create** — AES-256 key, server wraps with HSM KEK before DB insert.
/// 2. **Get** — server unwraps via HSM KEK; verifies key material is intact.
/// 3. **`GetAttributes`** — verify algorithm, length, and initial attributes.
/// 4. **State check** — `symmetric_key_create_request` sets `activation_date = now`,
///    so the server creates the key directly in Active state; verify via `GetAttributes`.
/// 5. **`SetAttribute`** (×3) — attach `RotateName` (= the key's own UID, required
///    by the SQL-key constraint), `RotateInterval`, and `RotateAutomatic`;
///    verify they survive a round-trip through the DB.
/// 6. **Encrypt / Decrypt** — AES-GCM round-trip with the active key; exercises
///    the HSM unwrap path during key material access for crypto operations.
/// 7. **`ReKey`** (first rotation, generation 0 → 1) — server creates a new key
///    (wraps it with HSM KEK), updates keyset metadata, deactivates the old key.
///    - Verify old key state = Deactivated.
///    - Verify new key attributes: `rotate_generation = 1`, `rotate_latest = true`.
///    - Verify old key's ciphertext is still decryptable (Deactivated allows decrypt).
///    - Encrypt / Decrypt round-trip with the new key.
/// 8. **`ReKey`** (second rotation, generation 1 → 2) — keyset chain progression.
///    - Verify `rotate_generation = 2`, `rotate_latest = true` on newest key.
/// 9. **Keyset enforcement** — attempt to re-key the superseded generation 0 key;
///    the server MUST reject it with an error.
/// 10. **Revoke + Destroy** — clean up all three key generations.
///
/// The DB backend is controlled by `KMS_TEST_DB`; `HSM_SLOT_ID` must be set.
async fn test_db_softhsm2_impl() -> Result<(), KmsClientError> {
    init_test_logging();

    // Panics if HSM_SLOT_ID is not set — the desired "fail, don't skip" behaviour.
    let ctx = start_default_test_kms_server_with_softhsm2_and_kek().await;
    let client = ctx.get_owner_client();

    // ── 1. Create ─────────────────────────────────────────────────────────────
    // The server wraps the generated key material with the HSM KEK before
    // persisting it to the DB backend.
    let create_req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        ["test_db_hsm"],
        false,
        None,
    )?;
    let uid_v1 = client
        .create(create_req)
        .await?
        .unique_identifier
        .to_string();

    // ── 2. Get ────────────────────────────────────────────────────────────────
    // Exercises the HSM unwrap path: the server must contact SoftHSM2 to
    // unwrap the stored key material before returning it.
    client.get(Get::from(uid_v1.as_str())).await?;

    // ── 3. GetAttributes ─────────────────────────────────────────────────────
    let attrs = client
        .get_attributes(GetAttributes::from(uid_v1.as_str()))
        .await?
        .attributes;
    assert_eq!(
        attrs.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES),
        "v1: unexpected cryptographic algorithm"
    );
    assert_eq!(
        attrs.cryptographic_length,
        Some(256),
        "v1: unexpected key length"
    );

    // ── 4. State check ────────────────────────────────────────────────────────
    // `symmetric_key_create_request` supplies `activation_date = now`, so the
    // server's `setup_lifecycle` creates the key directly in Active state.
    // Assert that without calling Activate.
    let attrs = client
        .get_attributes(GetAttributes::from(uid_v1.as_str()))
        .await?
        .attributes;
    assert_eq!(
        attrs.state,
        Some(State::Active),
        "v1: key must be Active immediately (activation_date = now in create request)"
    );

    // ── 5. SetAttribute — keyset + auto-rotation schedule ────────────────────
    // For non-prefixed (SQL-backed) keys the server enforces rotate_name == UID.
    // Use the key's UID directly as the keyset name.
    let keyset_name = uid_v1.clone();

    for attr in [
        Attribute::RotateName(keyset_name.clone()),
        Attribute::RotateInterval(3600),
        Attribute::RotateAutomatic(true),
    ] {
        client
            .set_attribute(SetAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid_v1.clone())),
                new_attribute: attr,
            })
            .await?;
    }

    // Verify rotation attributes survived the DB round-trip (HSM path).
    let attrs = client
        .get_attributes(GetAttributes::from(uid_v1.as_str()))
        .await?
        .attributes;
    assert_eq!(
        attrs.rotate_name.as_deref(),
        Some(keyset_name.as_str()),
        "v1: rotate_name not persisted"
    );
    assert_eq!(
        attrs.rotate_interval,
        Some(3600),
        "v1: rotate_interval not persisted"
    );
    assert_eq!(
        attrs.rotate_automatic,
        Some(true),
        "v1: rotate_automatic not persisted"
    );

    // ── 6. Encrypt / Decrypt round-trip with v1 ───────────────────────────────
    // The server must unwrap the HSM-wrapped key to perform crypto operations.
    let plaintext: Vec<u8> = b"HSM DB integration lifecycle test".to_vec();

    let enc_resp = client
        .encrypt(encrypt_request(
            &uid_v1,
            None,
            plaintext.clone(),
            None,
            None,
            None,
        )?)
        .await?;
    let ciphertext_v1 = enc_resp.data.expect("encrypt: no ciphertext in response");
    let nonce_v1 = enc_resp.i_v_counter_nonce;
    let tag_v1 = enc_resp.authenticated_encryption_tag;

    let dec_resp = client
        .decrypt(decrypt_request(
            &uid_v1,
            nonce_v1.clone(),
            ciphertext_v1.clone(),
            tag_v1.clone(),
            None,
            None,
        ))
        .await?;
    assert_eq!(
        *dec_resp.data.expect("decrypt: no data in response"),
        plaintext,
        "v1: encrypt/decrypt round-trip mismatch"
    );

    // ── 7. ReKey — first rotation (generation 0 → 1) ─────────────────────────
    // The server generates new key material, wraps it with the HSM KEK, stores
    // the new key in the DB, and deactivates the old key.
    let uid_v2 = client
        .rekey(ReKey {
            unique_identifier: Some(UniqueIdentifier::TextString(uid_v1.clone())),
            ..ReKey::default()
        })
        .await?
        .unique_identifier
        .to_string();

    assert_ne!(uid_v1, uid_v2, "ReKey must produce a distinct UID");

    // Get new key — exercises HSM unwrap for the freshly-created replacement.
    client.get(Get::from(uid_v2.as_str())).await?;

    // v2 keyset metadata
    let attrs_v2 = client
        .get_attributes(GetAttributes::from(uid_v2.as_str()))
        .await?
        .attributes;
    assert_eq!(
        attrs_v2.state,
        Some(State::Active),
        "v2: should be Active after ReKey"
    );
    assert_eq!(
        attrs_v2.rotate_name.as_deref(),
        Some(keyset_name.as_str()),
        "v2: must inherit keyset name"
    );
    assert_eq!(
        attrs_v2.rotate_generation,
        Some(1),
        "v2: should be generation 1"
    );
    assert_eq!(
        attrs_v2.rotate_latest,
        Some(true),
        "v2: should be marked latest"
    );
    assert_eq!(
        attrs_v2.rotate_automatic,
        Some(true),
        "v2: must inherit rotate_automatic"
    );

    // v1 should now be Deactivated (KMIP §4.57 transition 6 after Re-Key).
    let attrs_v1 = client
        .get_attributes(GetAttributes::from(uid_v1.as_str()))
        .await?
        .attributes;
    assert_eq!(
        attrs_v1.state,
        Some(State::Deactivated),
        "v1: should be Deactivated after ReKey"
    );
    assert_ne!(
        attrs_v1.rotate_latest,
        Some(true),
        "v1: must no longer be marked latest"
    );

    // Decrypt v1's ciphertext with the now-Deactivated v1 key.
    // Per KMIP §3.1.3 Deactivated state allows decryption for legacy data access.
    let dec_v1_after_rekey = client
        .decrypt(decrypt_request(
            &uid_v1,
            nonce_v1,
            ciphertext_v1,
            tag_v1,
            None,
            None,
        ))
        .await?;
    assert_eq!(
        *dec_v1_after_rekey
            .data
            .expect("decrypt v1 after rekey: no data"),
        plaintext,
        "v1: decrypt with deactivated key must still work for legacy data"
    );

    // Encrypt / Decrypt round-trip with v2 (the new active key).
    let enc_resp2 = client
        .encrypt(encrypt_request(
            &uid_v2,
            None,
            plaintext.clone(),
            None,
            None,
            None,
        )?)
        .await?;
    let ciphertext_v2 = enc_resp2.data.expect("encrypt v2: no ciphertext");
    let nonce_v2 = enc_resp2.i_v_counter_nonce;
    let tag_v2 = enc_resp2.authenticated_encryption_tag;

    let dec_resp2 = client
        .decrypt(decrypt_request(
            &uid_v2,
            nonce_v2,
            ciphertext_v2,
            tag_v2,
            None,
            None,
        ))
        .await?;
    assert_eq!(
        *dec_resp2.data.expect("decrypt v2: no data"),
        plaintext,
        "v2: encrypt/decrypt round-trip mismatch"
    );

    // ── 8. ReKey — second rotation (generation 1 → 2) ────────────────────────
    // Keyset chain: v1 (gen 0, Deactivated) → v2 (gen 1, Deactivated) → v3 (gen 2, Active)
    let uid_v3 = client
        .rekey(ReKey {
            unique_identifier: Some(UniqueIdentifier::TextString(uid_v2.clone())),
            ..ReKey::default()
        })
        .await?
        .unique_identifier
        .to_string();

    assert_ne!(uid_v2, uid_v3, "second ReKey must produce a distinct UID");

    client.get(Get::from(uid_v3.as_str())).await?;

    let attrs_v3 = client
        .get_attributes(GetAttributes::from(uid_v3.as_str()))
        .await?
        .attributes;
    assert_eq!(
        attrs_v3.rotate_generation,
        Some(2),
        "v3: should be generation 2"
    );
    assert_eq!(
        attrs_v3.rotate_latest,
        Some(true),
        "v3: should be marked latest"
    );
    assert_eq!(attrs_v3.state, Some(State::Active), "v3: should be Active");

    let attrs_v2_after = client
        .get_attributes(GetAttributes::from(uid_v2.as_str()))
        .await?
        .attributes;
    assert_eq!(
        attrs_v2_after.state,
        Some(State::Deactivated),
        "v2: should be Deactivated after second ReKey"
    );

    // ── 9. Keyset enforcement — rekeying a superseded generation must fail ────
    // Attempting to rotate a non-latest key in the keyset must be rejected.
    let old_gen_rekey_result = client
        .rekey(ReKey {
            unique_identifier: Some(UniqueIdentifier::TextString(uid_v1.clone())),
            ..ReKey::default()
        })
        .await;
    assert!(
        old_gen_rekey_result.is_err(),
        "rekeying superseded generation 0 must be rejected by the server"
    );

    // ── 10. Revoke + Destroy — clean up all three key generations ────────────
    // v3 is still Active; it must be revoked before it can be destroyed.
    client
        .revoke(Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(uid_v3.clone())),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::Superseded,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: false,
        })
        .await?;

    // v1 and v2 are already Deactivated; v3 is now Compromised. All can be destroyed.
    for uid in [&uid_v3, &uid_v2, &uid_v1] {
        client
            .destroy(Destroy {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                remove: true,
                ..Default::default()
            })
            .await?;
    }

    Ok(())
}

// ── Per-backend entry points ──────────────────────────────────────────────────
//
// Each function is `#[ignore]` so the standard `cargo test` run skips them.
// The MISE `test:db:xxx` tasks invoke them explicitly with `--ignored --exact`
// after setting `KMS_TEST_DB` and the HSM env vars.

/// `SQLite` + `SoftHSM2` integration smoke-test.
///
/// Invoked by: `mise run test:db:sqlite`
#[tokio::test]
#[ignore = "Requires softhsm2 — set up and invoked by mise run test:db:sqlite"]
async fn test_db_sqlite_softhsm2() {
    Box::pin(test_db_softhsm2_impl()).await.unwrap();
}

/// `PostgreSQL` + `SoftHSM2` integration smoke-test.
///
/// Invoked by: `mise run test:db:psql`
#[tokio::test]
#[ignore = "Requires softhsm2 + running PostgreSQL — set up and invoked by mise run test:db:psql"]
async fn test_db_postgresql_softhsm2() {
    Box::pin(test_db_softhsm2_impl()).await.unwrap();
}

/// `MySQL` / `MariaDB` + `SoftHSM2` integration smoke-test.
///
/// Invoked by: `mise run test:db:mysql` / `mise run test:db:mariadb`
#[tokio::test]
#[ignore = "Requires softhsm2 + running MySQL/MariaDB — set up and invoked by mise run test:db:mysql"]
async fn test_db_mysql_softhsm2() {
    Box::pin(test_db_softhsm2_impl()).await.unwrap();
}

/// Redis-findex + `SoftHSM2` integration smoke-test (non-FIPS only).
///
/// Invoked by: `mise run test:db:redis --variant non-fips`
#[cfg(feature = "non-fips")]
#[tokio::test]
#[ignore = "Requires softhsm2 + running Redis — set up and invoked by mise run test:db:redis --variant non-fips"]
async fn test_db_redis_with_findex_softhsm2() {
    Box::pin(test_db_softhsm2_impl()).await.unwrap();
}
