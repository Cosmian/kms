/// HSM key permissions non-regression tests.
///
/// Tests the full permission matrix for HSM keys with two actors:
/// - `owner.client@acme.com` — HSM admin
/// - `user.client@acme.com` — non-admin user
///
/// Decision record:
/// - Locate: non-admin sees only HSM keys with at least one granted operation
/// - Ownership: shared — all HSM admins are co-owners
/// - Destroy: admin-only, cannot be delegated
/// - Revoke grant: blocked on HSM keys (state changes not supported)
/// - Get-as-wildcard: removed for HSM keys — explicit grants required
/// - Server KEK: shared for wrapping/unwrapping only, direct ops require grants
use std::sync::Arc;

use cosmian_kms_access::access::Access;
use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::VENDOR_ID_COSMIAN,
    kmip_operations::{Decrypt, Destroy, Encrypt, Operation, Sign},
    kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
    requests::symmetric_key_create_request,
};
use cosmian_kms_interfaces::as_hsm_uid;
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::KmipOperation;
use cosmian_logger::info;
use uuid::Uuid;

use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    result::KResult,
    tests::{
        hsm::{
            EMPTY_TAGS, create_kek, create_key_pair, create_sym_key, delete_all_keys, delete_key,
            export_object, hsm_clap_config, locate_keys, revoke_key, send_message,
        },
        test_utils::get_tmp_sqlite_path,
    },
};

const ADMIN: &str = "owner.client@acme.com";
const USER: &str = "user.client@acme.com";

/// Helper: set up a KMS instance with HSM, ADMIN as HSM admin, and optionally a KEK.
async fn setup_kms(kek_uuid: Option<Uuid>) -> KResult<(Arc<KMS>, Option<String>, usize)> {
    let sqlite_path = get_tmp_sqlite_path();
    let mut clap_config = hsm_clap_config(ADMIN, kek_uuid)?;
    clap_config.db.sqlite_path = sqlite_path;
    let kek_uid = clap_config.key_encryption_key.clone();
    let slot = clap_config.hsm.hsm_slot[0];
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    Ok((kms, kek_uid, slot))
}

/// Helper: grant operations on an HSM key
async fn grant_ops(
    kms: &KMS,
    owner: &str,
    user_id: &str,
    uid: &str,
    ops: Vec<KmipOperation>,
) -> KResult<()> {
    let access = Access {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        user_id: user_id.to_owned(),
        operation_types: ops,
    };
    kms.grant_access(&access, owner, None).await
}

/// Helper: revoke operations on an HSM key
async fn revoke_ops(
    kms: &KMS,
    owner: &str,
    user_id: &str,
    uid: &str,
    ops: Vec<KmipOperation>,
) -> KResult<()> {
    let access = Access {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        user_id: user_id.to_owned(),
        operation_types: ops,
    };
    kms.revoke_access(&access, owner, None).await
}

/// Helper: encrypt data using a key.
///
/// Returns the full ciphertext as `iv || ciphertext || tag` — the format expected
/// by the decrypt oracle in `decrypt_using_crypto_oracle`.  The KMIP encrypt
/// response splits these into three separate fields; we reassemble them here so
/// that `decrypt_data` can pass the whole blob as `data` without needing to
/// supply `i_v_counter_nonce` / `authenticated_encryption_tag` separately.
async fn encrypt_data(kms: &Arc<KMS>, user: &str, uid: &str, data: &[u8]) -> KResult<Vec<u8>> {
    let request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        cryptographic_parameters: None,
        data: Some(data.to_vec().into()),
        i_v_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    };
    let response = kms.encrypt(request, user).await?;
    // Assemble iv || ciphertext || tag so that the decrypt oracle can split them
    // back out. The session_impl::decrypt expects the data in exactly this layout.
    let mut full = Vec::new();
    if let Some(iv) = response.i_v_counter_nonce {
        full.extend(iv);
    }
    full.extend(response.data.unwrap_or_default());
    if let Some(tag) = response.authenticated_encryption_tag {
        full.extend(tag);
    }
    Ok(full)
}

/// Helper: decrypt data using a key
async fn decrypt_data(kms: &Arc<KMS>, user: &str, uid: &str, ciphertext: &[u8]) -> KResult<()> {
    let request = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        cryptographic_parameters: None,
        data: Some(ciphertext.to_vec()),
        i_v_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
        authenticated_encryption_tag: None,
    };
    kms.decrypt(request, user).await?;
    Ok(())
}

/// Helper: sign data using a key
async fn sign_data(kms: &Arc<KMS>, user: &str, uid: &str, data: &[u8]) -> KResult<()> {
    let request = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        cryptographic_parameters: None,
        data: Some(data.to_vec().into()),
        digested_data: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    };
    kms.sign(request, user).await?;
    Ok(())
}

// ── Create tests ─────────────────────────────────────────────────────────

/// Create a non-sensitive AES key on the HSM so that raw-export tests (#25, #27) work.
/// HSM keys created with `sensitive = true` (the default) have `CKA_SENSITIVE = true` in
/// PKCS#11, which makes them non-extractable.  The server correctly blocks plain Export on
/// such keys (KMIP `Sensitive / DENIED`).  Permissions tests that call `export_object`
/// without a wrapping specification must therefore use a non-sensitive key.
async fn create_aes_key_non_sensitive(key_uid: &str, owner: &str, kms: &Arc<KMS>) -> KResult<()> {
    let create_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(key_uid.to_owned())),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false, // sensitive = false → CKA_SENSITIVE = false, key material is extractable
        None,
    )?;
    let response =
        send_message(kms.clone(), owner, vec![Operation::Create(create_request)]).await?;
    let Operation::CreateResponse(create_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    assert_eq!(
        create_response.unique_identifier,
        UniqueIdentifier::TextString(key_uid.to_owned())
    );
    Ok(())
}

/// #1: Admin can create AES key on HSM
async fn test_admin_create_aes(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #1: Admin creates AES key");
    // Use a non-sensitive key so that export tests (#25, #27) can retrieve the key material.
    create_aes_key_non_sensitive(aes_uid, ADMIN, kms).await?;
    Ok(())
}

/// #2: Admin can create RSA keypair on HSM
async fn test_admin_create_rsa(kms: &Arc<KMS>, rsa_uid: &str) -> KResult<()> {
    info!("Permissions #2: Admin creates RSA keypair");
    create_key_pair(rsa_uid, ADMIN, kms).await?;
    Ok(())
}

/// #3: Non-admin cannot create AES key on HSM
async fn test_non_admin_create_aes_fails(kms: &Arc<KMS>, slot: usize) -> KResult<()> {
    info!("Permissions #3: Non-admin cannot create AES key");
    let uid = as_hsm_uid!(slot, Uuid::new_v4());
    let result = create_sym_key(&uid, USER, kms).await;
    assert!(
        result.is_err(),
        "Non-admin should not be able to create HSM key"
    );
    Ok(())
}

/// #4: Non-admin cannot create RSA keypair on HSM
async fn test_non_admin_create_rsa_fails(kms: &Arc<KMS>, slot: usize) -> KResult<()> {
    info!("Permissions #4: Non-admin cannot create RSA keypair");
    let uid = as_hsm_uid!(slot, Uuid::new_v4());
    let result = create_key_pair(&uid, USER, kms).await;
    assert!(
        result.is_err(),
        "Non-admin should not be able to create HSM keypair"
    );
    Ok(())
}

// ── Destroy tests ────────────────────────────────────────────────────────

/// #5: Admin can destroy HSM key
async fn test_admin_destroy(kms: &Arc<KMS>, slot: usize) -> KResult<()> {
    info!("Permissions #5: Admin destroys HSM key");
    let uid = as_hsm_uid!(slot, Uuid::new_v4());
    create_sym_key(&uid, ADMIN, kms).await?;
    delete_key(&uid, ADMIN, kms).await?;
    Ok(())
}

/// #6: Non-admin cannot destroy HSM key (no grant)
async fn test_non_admin_destroy_fails(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #6: Non-admin cannot destroy HSM key");
    let result = delete_key(aes_uid, USER, kms).await;
    assert!(
        result.is_err(),
        "Non-admin should not be able to destroy HSM key"
    );
    Ok(())
}

/// #7: Granting Destroy on HSM key is blocked
async fn test_grant_destroy_blocked(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #7: Grant Destroy on HSM key is blocked");
    let result = grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Destroy]).await;
    assert!(
        result.is_err(),
        "Granting Destroy on HSM key should be blocked"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("reserved for HSM admins"),
        "Error should mention HSM admin restriction, got: {err_msg}"
    );
    Ok(())
}

// ── Locate tests ─────────────────────────────────────────────────────────

/// #8: Admin locates all HSM keys
async fn test_admin_locate_all(kms: &Arc<KMS>, expected_count: usize) -> KResult<()> {
    info!("Permissions #8: Admin locates all HSM keys");
    let found = locate_keys(ADMIN, kms, None).await?;
    assert_eq!(
        found.len(),
        expected_count,
        "Admin should see all {expected_count} HSM keys, found {}",
        found.len()
    );
    Ok(())
}

/// #9: Non-admin locates nothing (no grants)
async fn test_non_admin_locate_empty(kms: &Arc<KMS>) -> KResult<()> {
    info!("Permissions #9: Non-admin locates nothing without grants");
    let found = locate_keys(USER, kms, None).await?;
    assert!(
        found.is_empty(),
        "Non-admin without grants should see no HSM keys, found {}",
        found.len()
    );
    Ok(())
}

/// #10: Non-admin locates only granted key after Encrypt grant
async fn test_non_admin_locate_after_grant(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #10: Non-admin locates granted key");
    grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    let found = locate_keys(USER, kms, None).await?;
    assert_eq!(
        found.len(),
        1,
        "Non-admin should see exactly 1 granted HSM key"
    );
    assert_eq!(
        found[0],
        UniqueIdentifier::TextString(aes_uid.to_owned()),
        "Non-admin should see the granted key"
    );
    // cleanup grant for next tests
    revoke_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    Ok(())
}

/// #11: Non-admin sees nothing after grant is revoked
async fn test_non_admin_locate_after_revoke(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #11: Non-admin sees nothing after revoke");
    // Grant then revoke
    grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    revoke_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    let found = locate_keys(USER, kms, None).await?;
    assert!(
        found.is_empty(),
        "Non-admin should see no HSM keys after revoke, found {}",
        found.len()
    );
    Ok(())
}

// ── Grant/Revoke tests ───────────────────────────────────────────────────

/// #12: Admin can grant Encrypt
async fn test_admin_grant_encrypt(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #12: Admin grants Encrypt");
    grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    revoke_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    Ok(())
}

/// #13: Admin can grant Decrypt
async fn test_admin_grant_decrypt(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #13: Admin grants Decrypt");
    grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Decrypt]).await?;
    revoke_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Decrypt]).await?;
    Ok(())
}

/// #14: Admin can grant Get
async fn test_admin_grant_get(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #14: Admin grants Get");
    grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Get]).await?;
    revoke_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Get]).await?;
    Ok(())
}

/// #15: Granting Destroy on HSM key is blocked (same as #7, explicit test)
async fn test_admin_grant_destroy_blocked(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #15: Admin cannot grant Destroy on HSM key");
    let result = grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Destroy]).await;
    assert!(
        result.is_err(),
        "Granting Destroy on HSM key should be blocked"
    );
    Ok(())
}

/// #16: Granting Revoke on HSM key is blocked
async fn test_admin_grant_revoke_blocked(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #16: Admin cannot grant Revoke on HSM key");
    let result = grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Revoke]).await;
    assert!(
        result.is_err(),
        "Granting Revoke on HSM key should be blocked"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("reserved for HSM admins"),
        "Error should mention HSM admin restriction, got: {err_msg}"
    );
    Ok(())
}

/// #17: Admin can revoke a previously granted Encrypt
async fn test_admin_revoke_encrypt(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #17: Admin revokes Encrypt");
    grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    revoke_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    // Verify the user can no longer encrypt
    let result = encrypt_data(kms, USER, aes_uid, b"test").await;
    assert!(
        result.is_err(),
        "User should not be able to encrypt after grant is revoked"
    );
    Ok(())
}

/// #18: Non-admin cannot grant operations
async fn test_non_admin_grant_fails(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #18: Non-admin cannot grant");
    let result = grant_ops(kms, USER, ADMIN, aes_uid, vec![KmipOperation::Encrypt]).await;
    assert!(result.is_err(), "Non-admin should not be able to grant");
    Ok(())
}

/// #19: Non-admin cannot revoke operations
async fn test_non_admin_revoke_fails(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #19: Non-admin cannot revoke");
    // First, admin grants encrypt to user
    grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    // User tries to revoke their own access (should fail — not owner)
    let result = revoke_ops(kms, USER, USER, aes_uid, vec![KmipOperation::Encrypt]).await;
    assert!(result.is_err(), "Non-admin should not be able to revoke");
    // Cleanup
    revoke_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    Ok(())
}

// ── Encrypt/Decrypt tests ────────────────────────────────────────────────

/// #20: Admin can encrypt with HSM key
async fn test_admin_encrypt(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #20: Admin encrypts with HSM key");
    encrypt_data(kms, ADMIN, aes_uid, b"admin test data").await?;
    Ok(())
}

/// #21: Non-admin cannot encrypt without grant
async fn test_non_admin_encrypt_no_grant(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #21: Non-admin cannot encrypt without grant");
    let result = encrypt_data(kms, USER, aes_uid, b"test").await;
    assert!(
        result.is_err(),
        "Non-admin without grant should not be able to encrypt"
    );
    Ok(())
}

/// #22: Non-admin can encrypt with Encrypt grant
async fn test_non_admin_encrypt_with_grant(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #22: Non-admin encrypts with Encrypt grant");
    grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    encrypt_data(kms, USER, aes_uid, b"user test data").await?;
    revoke_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    Ok(())
}

/// #23: Non-admin cannot decrypt with only Encrypt grant (no Decrypt)
async fn test_non_admin_decrypt_with_encrypt_only(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #23: Non-admin cannot decrypt with Encrypt-only grant");
    grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    // Admin encrypts to get valid ciphertext
    let ciphertext = encrypt_data(kms, ADMIN, aes_uid, b"test data").await?;
    // User tries to decrypt — should fail (only has Encrypt, not Decrypt)
    let result = decrypt_data(kms, USER, aes_uid, &ciphertext).await;
    assert!(
        result.is_err(),
        "Non-admin with only Encrypt grant should not be able to decrypt"
    );
    revoke_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    Ok(())
}

/// #24: Non-admin can decrypt with Decrypt grant
async fn test_non_admin_decrypt_with_grant(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #24: Non-admin decrypts with Decrypt grant");
    grant_ops(
        kms,
        ADMIN,
        USER,
        aes_uid,
        vec![KmipOperation::Encrypt, KmipOperation::Decrypt],
    )
    .await?;
    let ciphertext = encrypt_data(kms, USER, aes_uid, b"decrypt test").await?;
    decrypt_data(kms, USER, aes_uid, &ciphertext).await?;
    revoke_ops(
        kms,
        ADMIN,
        USER,
        aes_uid,
        vec![KmipOperation::Encrypt, KmipOperation::Decrypt],
    )
    .await?;
    Ok(())
}

// ── Get/Export tests ─────────────────────────────────────────────────────

/// #25: Admin can export HSM key
async fn test_admin_export(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #25: Admin exports HSM key");
    export_object(kms, ADMIN, aes_uid).await?;
    Ok(())
}

/// #26: Non-admin cannot export without grant
async fn test_non_admin_export_no_grant(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #26: Non-admin cannot export without grant");
    let result = export_object(kms, USER, aes_uid).await;
    assert!(
        result.is_err(),
        "Non-admin without grant should not be able to export"
    );
    Ok(())
}

/// #27: Non-admin can export with Get grant
async fn test_non_admin_export_with_get(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #27: Non-admin exports with Get grant");
    grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Get]).await?;
    export_object(kms, USER, aes_uid).await?;
    revoke_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Get]).await?;
    Ok(())
}

/// #28: Non-admin with Encrypt-only cannot export (Get no longer wildcard for HSM)
async fn test_non_admin_export_encrypt_only_fails(kms: &Arc<KMS>, aes_uid: &str) -> KResult<()> {
    info!("Permissions #28: Non-admin with Encrypt-only cannot export");
    grant_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    let result = export_object(kms, USER, aes_uid).await;
    assert!(
        result.is_err(),
        "Non-admin with only Encrypt grant should not be able to export (Get is not wildcard for HSM)"
    );
    revoke_ops(kms, ADMIN, USER, aes_uid, vec![KmipOperation::Encrypt]).await?;
    Ok(())
}

// ── Sign/Verify tests ───────────────────────────────────────────────────

/// #29: Non-admin can sign with Sign grant (RSA)
async fn test_non_admin_sign_with_grant(kms: &Arc<KMS>, rsa_uid: &str) -> KResult<()> {
    info!("Permissions #29: Non-admin signs with Sign grant");
    grant_ops(kms, ADMIN, USER, rsa_uid, vec![KmipOperation::Sign]).await?;
    sign_data(kms, USER, rsa_uid, b"sign test data").await?;
    revoke_ops(kms, ADMIN, USER, rsa_uid, vec![KmipOperation::Sign]).await?;
    Ok(())
}

/// #30: Non-admin cannot sign without grant (RSA)
async fn test_non_admin_sign_no_grant(kms: &Arc<KMS>, rsa_uid: &str) -> KResult<()> {
    info!("Permissions #30: Non-admin cannot sign without grant");
    let result = sign_data(kms, USER, rsa_uid, b"sign test data").await;
    assert!(
        result.is_err(),
        "Non-admin without Sign grant should not be able to sign"
    );
    Ok(())
}

// ── Server KEK tests ────────────────────────────────────────────────────

/// #31: Non-admin can create KMS key wrapped by server KEK
async fn test_non_admin_create_wrapped_by_kek(kms: &Arc<KMS>, kek_uid: &str) -> KResult<()> {
    info!("Permissions #31: Non-admin creates KMS key wrapped by server KEK");
    let dek_uid = Uuid::new_v4().to_string();
    let create_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(dek_uid.clone())),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        Some(&kek_uid.to_owned()),
    )?;
    let response = send_message(kms.clone(), USER, vec![Operation::Create(create_request)]).await?;
    let Operation::CreateResponse(create_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    assert_eq!(
        create_response.unique_identifier,
        UniqueIdentifier::TextString(dek_uid.clone())
    );
    // Verify DEK is wrapped
    let exported = export_object(kms, USER, &dek_uid).await?;
    assert!(
        exported.is_wrapped(),
        "DEK must be stored wrapped by server KEK"
    );
    // Cleanup: revoke before destroy — KMIP lifecycle requires revocation for Active keys
    // (symmetric_key_create_request sets activation_date=now making the key Active).
    revoke_key(&dek_uid, USER, kms).await?;
    let destroy_request = Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(dek_uid.clone())),
        remove: true,
        cascade: true,
        expected_object_type: None,
    };
    send_message(kms.clone(), USER, vec![Operation::Destroy(destroy_request)]).await?;
    Ok(())
}

/// #32: Non-admin cannot directly encrypt with server KEK UID (no grant)
async fn test_non_admin_direct_encrypt_kek_fails(kms: &Arc<KMS>, kek_uid: &str) -> KResult<()> {
    info!("Permissions #32: Non-admin cannot directly encrypt with KEK");
    let result = encrypt_data(kms, USER, kek_uid, b"test data").await;
    assert!(
        result.is_err(),
        "Non-admin should not be able to directly encrypt with the server KEK"
    );
    Ok(())
}

// ── Main test orchestrator ───────────────────────────────────────────────

/// Run all 32 permission scenarios sequentially.
///
/// HSMs don't support parallel operations well, so all tests share a single
/// KMS instance and run in order.
pub(super) async fn test_hsm_permissions() -> KResult<()> {
    let kek_uuid = Uuid::new_v4();
    let aes_uuid = Uuid::new_v4();
    let rsa_uuid = Uuid::new_v4();

    let (kms, kek_uid, slot) = setup_kms(Some(kek_uuid)).await?;
    let kek_uid = kek_uid.expect("KEK should be configured");
    let aes_uid = as_hsm_uid!(slot, aes_uuid);
    let rsa_uid = as_hsm_uid!(slot, rsa_uuid);

    // Cleanup any leftover keys from previous runs
    delete_all_keys(ADMIN, &kms).await?;

    // Create the KEK first (needed for wrapping tests)
    create_kek(&kek_uid, ADMIN, &kms).await?;

    // ── Create tests (1-4) ───────────────────────────────────────────
    test_admin_create_aes(&kms, &aes_uid).await?;
    test_admin_create_rsa(&kms, &rsa_uid).await?;
    test_non_admin_create_aes_fails(&kms, slot).await?;
    test_non_admin_create_rsa_fails(&kms, slot).await?;

    // ── Destroy tests (5-7) ──────────────────────────────────────────
    test_admin_destroy(&kms, slot).await?;
    test_non_admin_destroy_fails(&kms, &aes_uid).await?;
    test_grant_destroy_blocked(&kms, &aes_uid).await?;

    // ── Locate tests (8-11) ──────────────────────────────────────────
    // At this point: aes_uid + rsa_uid (private) + rsa_uid_pk (public) + kek = 4 keys
    // (the key from test #5 was already destroyed)
    test_admin_locate_all(&kms, 4).await?;
    test_non_admin_locate_empty(&kms).await?;
    test_non_admin_locate_after_grant(&kms, &aes_uid).await?;
    test_non_admin_locate_after_revoke(&kms, &aes_uid).await?;

    // ── Grant/Revoke tests (12-19) ───────────────────────────────────
    test_admin_grant_encrypt(&kms, &aes_uid).await?;
    test_admin_grant_decrypt(&kms, &aes_uid).await?;
    test_admin_grant_get(&kms, &aes_uid).await?;
    test_admin_grant_destroy_blocked(&kms, &aes_uid).await?;
    test_admin_grant_revoke_blocked(&kms, &aes_uid).await?;
    test_admin_revoke_encrypt(&kms, &aes_uid).await?;
    test_non_admin_grant_fails(&kms, &aes_uid).await?;
    test_non_admin_revoke_fails(&kms, &aes_uid).await?;

    // ── Encrypt/Decrypt tests (20-24) ────────────────────────────────
    test_admin_encrypt(&kms, &aes_uid).await?;
    test_non_admin_encrypt_no_grant(&kms, &aes_uid).await?;
    test_non_admin_encrypt_with_grant(&kms, &aes_uid).await?;
    test_non_admin_decrypt_with_encrypt_only(&kms, &aes_uid).await?;
    test_non_admin_decrypt_with_grant(&kms, &aes_uid).await?;

    // ── Get/Export tests (25-28) ─────────────────────────────────────
    test_admin_export(&kms, &aes_uid).await?;
    test_non_admin_export_no_grant(&kms, &aes_uid).await?;
    test_non_admin_export_with_get(&kms, &aes_uid).await?;
    test_non_admin_export_encrypt_only_fails(&kms, &aes_uid).await?;

    // ── Sign/Verify tests (29-30) ────────────────────────────────────
    test_non_admin_sign_with_grant(&kms, &rsa_uid).await?;
    test_non_admin_sign_no_grant(&kms, &rsa_uid).await?;

    // ── Server KEK tests (31-32) ─────────────────────────────────────
    test_non_admin_create_wrapped_by_kek(&kms, &kek_uid).await?;
    test_non_admin_direct_encrypt_kek_fails(&kms, &kek_uid).await?;

    // Cleanup
    delete_key(&aes_uid, ADMIN, &kms).await?;
    delete_key(&rsa_uid, ADMIN, &kms).await?;
    let rsa_pk_uid = format!("{rsa_uid}_pk");
    delete_key(&rsa_pk_uid, ADMIN, &kms).await?;
    delete_key(&kek_uid, ADMIN, &kms).await?;

    info!("All 32 HSM permission tests passed");
    Ok(())
}
