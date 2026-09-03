//! Unit tests for the AWS XKS proxy authorization model (issue #1093).
//!
//! These tests exercise the handler *inner* functions directly (bypassing the `SigV4`
//! middleware, which is validated separately) to assert that:
//! - XKS operations run as the reserved [`AWS_XKS_SERVICE_USER`] least-privilege identity,
//!   while the keys stay owned by `default_username` so operators keep administering them;
//! - any `SigV4`-authenticated caller ARN can use a key (the #1093 regression);
//! - the XKS endpoints cannot reach arbitrary non-XKS keys owned by `default_username`;
//! - already-shipped keys are migrated so the reserved identity can operate them.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::panic_in_result_fn
)]

use std::{collections::HashSet, sync::Arc};

use actix_web::{HttpRequest, test::TestRequest};
use base64::{Engine, engine::general_purpose::STANDARD};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{
        CryptographicUsageMask, ErrorReason, RevocationReason, RevocationReasonCode,
    },
    kmip_2_1::{
        KmipOperation,
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, Destroy, Get, Revoke},
        kmip_types::{CryptographicAlgorithm, KeyFormatType, UniqueIdentifier},
    },
};
use time::OffsetDateTime;

use super::{
    AWS_XKS_SERVICE_USER,
    encrypt_decrypt::{
        DecryptRequest, EncryptRequest, EncryptResponse, EncryptionAlgorithm,
        RequestMetadata as CryptoRequestMetadata, decrypt_inner, encrypt_inner,
    },
    key_metadata::{
        GetKeyMetadataRequest, KeyUsage, RequestMetadata as MetadataRequestMetadata, create_key,
        get_key_metadata_inner,
    },
};
use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    start_kms_server::migrate_aws_xks_key_access,
    tests::test_utils::{https_clap_config, test_kms},
};

fn http_req() -> HttpRequest {
    TestRequest::default().to_http_request()
}

fn revoke_request(key_id: &str) -> Revoke {
    Revoke {
        unique_identifier: Some(UniqueIdentifier::TextString(key_id.to_owned())),
        revocation_reason: RevocationReason {
            revocation_reason_code: RevocationReasonCode::CessationOfOperation,
            revocation_message: None,
        },
        compromise_occurrence_date: None,
        cascade: false,
    }
}

fn destroy_request(key_id: &str) -> Destroy {
    Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(key_id.to_owned())),
        remove: true,
        cascade: false,
        expected_object_type: None,
    }
}

/// Is this result a rejection caused by missing permissions (as opposed to, say, a key
/// lifecycle violation)? Used to assert *why* an operation was denied.
///
/// Unauthorized access is reported as "not found" on some paths, because the server
/// deliberately does not disclose the existence of objects the caller cannot access.
fn is_permission_error<T>(result: &KResult<T>) -> bool {
    match result {
        Ok(_) => false,
        Err(e) => matches!(
            e,
            KmsError::Unauthorized(_)
                | KmsError::ItemNotFound(_)
                | KmsError::Kmip21Error(
                    ErrorReason::Permission_Denied
                        | ErrorReason::Item_Not_Found
                        | ErrorReason::Object_Not_Found,
                    _
                )
        ),
    }
}

fn metadata_request(arn: &str, operation: &str) -> GetKeyMetadataRequest {
    GetKeyMetadataRequest {
        requestMetadata: MetadataRequestMetadata {
            awsPrincipalArn: arn.to_owned(),
            awsSourceVpc: None,
            awsSourceVpce: None,
            kmsOperation: operation.to_owned(),
            kmsRequestId: "req-metadata".to_owned(),
        },
    }
}

fn crypto_meta(arn: &str, operation: &str) -> CryptoRequestMetadata {
    CryptoRequestMetadata {
        awsPrincipalArn: arn.to_owned(),
        awsSourceVpc: None,
        awsSourceVpce: None,
        kmsKeyArn: "arn:aws:kms:us-east-1:123456789012:key/xks-test".to_owned(),
        kmsOperation: operation.to_owned(),
        kmsRequestId: "req-crypto".to_owned(),
        kmsViaService: None,
    }
}

fn encrypt_request(arn: &str, plaintext: &[u8]) -> EncryptRequest {
    EncryptRequest {
        requestMetadata: crypto_meta(arn, "Encrypt"),
        plaintext: STANDARD.encode(plaintext),
        encryptionAlgorithm: EncryptionAlgorithm::AES_GCM,
        additionalAuthenticatedData: None,
        ciphertextDataIntegrityValueAlgorithm: None,
    }
}

fn decrypt_request(arn: &str, enc: &EncryptResponse) -> DecryptRequest {
    DecryptRequest {
        requestMetadata: crypto_meta(arn, "Decrypt"),
        ciphertext: enc.ciphertext.clone(),
        ciphertextMetadata: enc.ciphertextMetadata.clone(),
        encryptionAlgorithm: EncryptionAlgorithm::AES_GCM,
        additionalAuthenticatedData: None,
        initializationVector: enc.initializationVector.clone(),
        authenticationTag: enc.authenticationTag.clone(),
    }
}

/// Provision an XKS key through the public `create_key` path with the given caller ARN.
async fn provision_xks_key(kms: &Arc<KMS>, key_id: &str, creator_arn: &str) -> KResult<()> {
    create_key(
        http_req(),
        metadata_request(creator_arn, "CreateKey"),
        key_id.to_owned(),
        kms,
    )
    .await
    .map_err(|e| crate::error::KmsError::ServerError(format!("create_key failed: {e:?}")))?;
    Ok(())
}

/// Create an AES-256 symmetric key owned by `owner` **without** the `aws-xks` tag, to model
/// a non-XKS key that must remain unreachable from the XKS endpoints.
async fn create_plain_symmetric_key(kms: &Arc<KMS>, key_id: &str, owner: &UserId) -> KResult<()> {
    let uid = UniqueIdentifier::TextString(key_id.to_owned());
    let mut attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        unique_identifier: Some(uid.clone()),
        // Backdate activation so the key is Active (mirrors `create_key`), ensuring any
        // rejection is due to authorization rather than key state.
        activation_date: Some(OffsetDateTime::now_utc() - time::Duration::minutes(1)),
        ..Attributes::default()
    };
    attributes.set_tags(&kms.params.vendor_identification, ["not-xks"])?;
    let create = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    };
    kms.create(create, owner).await?;
    Ok(())
}

#[tokio::test]
async fn create_key_keeps_operator_ownership_and_grants_reserved_identity() -> KResult<()> {
    let kms = test_kms().await?;
    let key_id = "xks-key-ownership";
    let creator = UserId::from("arn:aws:iam::1:role/Creator");
    let xks_service_user = UserId::from(AWS_XKS_SERVICE_USER);
    provision_xks_key(&kms, key_id, "arn:aws:iam::1:role/Creator").await?;

    // Ownership stays with `default_username` so operators keep full administrative control
    // (list / revoke / destroy / export) over XKS keys.
    assert!(
        kms.database
            .is_object_owned_by(key_id, &UserId::from(kms.params.default_username.as_str()))
            .await?
    );
    // The caller ARN gets no rights at all: usage must not be bound to a transient principal.
    let arn_ops = kms
        .database
        .list_user_operations_on_object(key_id, &creator, false)
        .await?;
    assert!(arn_ops.is_empty(), "caller ARN must not receive any grant");

    // The reserved identity holds exactly the three operations XKS needs — no more.
    let ops = kms
        .database
        .list_user_operations_on_object(key_id, &xks_service_user, false)
        .await?;
    assert_eq!(
        ops,
        HashSet::from([
            KmipOperation::Encrypt,
            KmipOperation::Decrypt,
            KmipOperation::GetAttributes,
        ]),
        "the XKS identity must be a least-privilege delegate"
    );

    // The `aws-xks` marker tag is set.
    let tags = kms.database.retrieve_tags(key_id).await?;
    assert!(tags.contains("aws-xks"));
    Ok(())
}

#[tokio::test]
async fn create_key_succeeds_when_privileged_users_are_configured() -> KResult<()> {
    // Regression guard: XKS keys must be created under an identity accepted by
    // `enforce_create_permission`. Creating them under a non-privileged identity would break
    // `CreateKey` on every deployment that configures `privileged_users`.
    let mut clap_config = https_clap_config();
    clap_config.privileged_users = Some(vec!["someone-else@acme.com".to_owned()]);
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    provision_xks_key(&kms, "xks-key-privileged", "arn:aws:iam::1:role/Creator").await?;

    // And the key is immediately usable through the XKS endpoints.
    let enc = encrypt_inner(
        http_req(),
        encrypt_request("arn:aws:iam::1:role/Alice", b"payload"),
        "xks-key-privileged".to_owned(),
        &kms,
    )
    .await?;
    assert!(!enc.ciphertext.is_empty());
    Ok(())
}

#[tokio::test]
async fn create_key_is_idempotent_and_repairs_missing_grant() -> KResult<()> {
    let kms = test_kms().await?;
    let key_id = "xks-key-idempotent";
    let xks_service_user = UserId::from(AWS_XKS_SERVICE_USER);
    provision_xks_key(&kms, key_id, "arn:aws:iam::1:role/Creator").await?;

    // A second CreateKey for the same id (AWS retries) must succeed and leave the grant intact.
    provision_xks_key(&kms, key_id, "arn:aws:iam::1:role/Other").await?;

    let ops = kms
        .database
        .list_user_operations_on_object(key_id, &xks_service_user, false)
        .await?;
    assert!(ops.contains(&KmipOperation::Encrypt));
    assert!(ops.contains(&KmipOperation::Decrypt));

    // The key is still usable after the repeated call.
    let enc = encrypt_inner(
        http_req(),
        encrypt_request("arn:aws:iam::1:role/Alice", b"still works"),
        key_id.to_owned(),
        &kms,
    )
    .await?;
    let dec = decrypt_inner(
        http_req(),
        decrypt_request("arn:aws:iam::1:role/Bob", &enc),
        key_id.to_owned(),
        &kms,
    )
    .await?;
    assert_eq!(STANDARD.decode(dec.plaintext).unwrap(), b"still works");
    Ok(())
}

#[tokio::test]
async fn create_key_rejects_existing_non_xks_symmetric_key() -> KResult<()> {
    let kms = test_kms().await?;
    let key_id = "plain-key-create-collision";
    let default_username = UserId::from(kms.params.default_username.as_str());
    let xks_service_user = UserId::from(AWS_XKS_SERVICE_USER);
    create_plain_symmetric_key(&kms, key_id, &default_username).await?;

    let err = create_key(
        http_req(),
        metadata_request("arn:aws:iam::1:role/Attacker", "CreateKey"),
        key_id.to_owned(),
        &kms,
    )
    .await;
    let Err(err) = err else {
        panic!("CreateKey must reject collisions with non-XKS symmetric keys");
    };

    assert!(matches!(
        err.errorName,
        super::error::XksErrorName::InternalException
    ));
    assert_eq!(
        err.errorMessage.as_deref(),
        Some(
            "Key plain-key-create-collision already exists and is not an AWS XKS key; refusing to grant XKS access"
        )
    );

    let ops = kms
        .database
        .list_user_operations_on_object(key_id, &xks_service_user, false)
        .await?;
    assert!(
        ops.is_empty(),
        "the reserved XKS identity must not gain access to a non-XKS key"
    );
    Ok(())
}

#[tokio::test]
async fn operator_retains_administrative_control() -> KResult<()> {
    // Regression guard: XKS keys must stay administrable. If the reserved identity owned
    // them, no operator could list, revoke, destroy, or export XKS keys, because the
    // authorization model grants nothing to non-owners without an explicit grant.
    let kms = test_kms().await?;
    let key_id = "xks-key-admin-control";
    provision_xks_key(&kms, key_id, "arn:aws:iam::1:role/Creator").await?;
    let operator = kms.params.default_username.clone();
    let operator_id = UserId::from(operator.clone());

    // The operator sees the key among the objects they own.
    let owned = kms.list_owned_objects(&operator_id).await?;
    assert!(
        owned.iter().any(|o| o.object_id.to_string() == key_id),
        "operator must still see XKS keys in their owned objects"
    );

    // And can perform the full administrative lifecycle on it.
    kms.revoke(revoke_request(key_id), &operator_id).await?;
    kms.destroy(destroy_request(key_id), &operator_id).await?;
    Ok(())
}

#[tokio::test]
async fn xks_identity_cannot_perform_administrative_operations() -> KResult<()> {
    // The reserved identity is a least-privilege delegate: it may encrypt/decrypt but must
    // never be able to revoke or destroy the key. The assertions check the *reason* for the
    // rejection so the test cannot pass because of an unrelated lifecycle error.
    let kms = test_kms().await?;
    let key_id = "xks-key-least-privilege";
    let xks_service_user = UserId::from(AWS_XKS_SERVICE_USER);
    provision_xks_key(&kms, key_id, "arn:aws:iam::1:role/Creator").await?;

    let revoked = kms.revoke(revoke_request(key_id), &xks_service_user).await;
    assert!(
        is_permission_error(&revoked),
        "revoke by the XKS identity must be denied for lack of permission, got: {revoked:?}"
    );

    let destroyed = kms
        .destroy(destroy_request(key_id), &xks_service_user)
        .await;
    assert!(
        is_permission_error(&destroyed),
        "destroy by the XKS identity must be denied for lack of permission, got: {destroyed:?}"
    );

    // Most importantly, it must not be able to export the key material. The grant covers
    // `GetAttributes` only; `Get` is deliberately excluded so the XKS endpoints can never be
    // used to exfiltrate key bytes.
    let exported = kms
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(key_id.to_owned())),
                key_format_type: None,
                key_wrap_type: None,
                key_compression_type: None,
                key_wrapping_specification: None,
            },
            &xks_service_user,
        )
        .await;
    assert!(
        is_permission_error(&exported),
        "the XKS identity must not be able to export key material, got: {:?}",
        exported.map(|_| "<key material returned>")
    );

    // The operator (owner) is unaffected and can still administer the key.
    let operator = UserId::from(kms.params.default_username.clone());
    kms.revoke(revoke_request(key_id), &operator).await?;
    Ok(())
}

#[tokio::test]
async fn non_creator_arn_can_encrypt_and_decrypt() -> KResult<()> {
    // Regression test for issue #1093: key usage must not depend on the caller ARN.
    let kms = test_kms().await?;
    let key_id = "xks-key-regression";
    provision_xks_key(&kms, key_id, "arn:aws:iam::1:role/Creator").await?;

    let plaintext = b"Hello XKS World!";
    // A different ARN than the creator encrypts.
    let enc = encrypt_inner(
        http_req(),
        encrypt_request("arn:aws:iam::1:role/Alice", plaintext),
        key_id.to_owned(),
        &kms,
    )
    .await?;

    // Yet another ARN decrypts and recovers the original plaintext.
    let dec = decrypt_inner(
        http_req(),
        decrypt_request("arn:aws:iam::1:role/Bob", &enc),
        key_id.to_owned(),
        &kms,
    )
    .await?;

    let recovered = STANDARD.decode(dec.plaintext).unwrap();
    assert_eq!(recovered, plaintext);
    Ok(())
}

#[tokio::test]
async fn get_key_metadata_works_for_any_arn() -> KResult<()> {
    let kms = test_kms().await?;
    let key_id = "xks-key-metadata";
    provision_xks_key(&kms, key_id, "arn:aws:iam::1:role/Creator").await?;

    let md = get_key_metadata_inner(
        http_req(),
        metadata_request("arn:aws:iam::1:role/Stranger", "GetKeyMetadata"),
        key_id.to_owned(),
        &kms,
    )
    .await
    .expect("get_key_metadata_inner failed");

    assert_eq!(md.keySpec, "AES_256");
    assert_eq!(md.keyStatus, "ENABLED");
    assert!(md.keyUsage.contains(&KeyUsage::ENCRYPT));
    assert!(md.keyUsage.contains(&KeyUsage::DECRYPT));
    Ok(())
}

#[tokio::test]
async fn xks_cannot_reach_non_xks_admin_key() -> KResult<()> {
    // A non-XKS key owned by `default_username` must not be usable through the XKS endpoint:
    // the reserved identity neither owns it nor holds a grant.
    let kms = test_kms().await?;
    let key_id = "admin-only-key";
    let default_username = UserId::from(kms.params.default_username.as_str());
    create_plain_symmetric_key(&kms, key_id, &default_username).await?;

    let result = encrypt_inner(
        http_req(),
        encrypt_request("arn:aws:iam::1:role/Attacker", b"secret"),
        key_id.to_owned(),
        &kms,
    )
    .await;

    assert!(
        result.is_err(),
        "XKS encrypt must be rejected for a non-XKS admin-owned key"
    );
    Ok(())
}

#[tokio::test]
async fn legacy_key_owned_by_previous_default_user_is_migrated_to_reserved_identity() -> KResult<()>
{
    // Model an already-shipped XKS key after an operator rotates `default_username`: the key
    // is still owned by the previous default owner, carries the `aws-xks` tag, and has no
    // grant to the reserved identity. Before migration the reserved identity cannot use it;
    // after migration it can.
    let kms = test_kms().await?;
    let key_id = "legacy-xks-key";
    let default_username = kms.params.default_username.clone();
    let xks_service_user = UserId::from(AWS_XKS_SERVICE_USER);
    let previous_default_user = UserId::from("legacy-admin@acme.com");
    let previous_default_username = "legacy-admin@acme.com";
    assert_ne!(
        previous_default_username, default_username,
        "test setup requires a legacy owner distinct from the current default username"
    );

    let uid = UniqueIdentifier::TextString(key_id.to_owned());
    let mut attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        unique_identifier: Some(uid.clone()),
        // Backdate activation so the key is Active, matching a real (shipped) XKS key.
        activation_date: Some(OffsetDateTime::now_utc() - time::Duration::minutes(1)),
        ..Attributes::default()
    };
    attributes.set_tags(&kms.params.vendor_identification, ["aws-xks"])?;
    let create = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    };
    kms.create(create, &previous_default_user).await?;

    let owner = kms
        .database
        .retrieve_object(key_id)
        .await?
        .expect("legacy xks key should exist")
        .owner()
        .to_owned();
    assert_eq!(owner, previous_default_username);

    // Before migration: the reserved identity has no access.
    let before = encrypt_inner(
        http_req(),
        encrypt_request("arn:aws:iam::1:role/Alice", b"data"),
        key_id.to_owned(),
        &kms,
    )
    .await;
    assert!(
        before.is_err(),
        "legacy key should be inaccessible pre-migration"
    );

    // Run the startup migration.
    migrate_aws_xks_key_access(&kms).await?;

    // After migration: the reserved identity can encrypt and decrypt.
    let enc = encrypt_inner(
        http_req(),
        encrypt_request("arn:aws:iam::1:role/Alice", b"data"),
        key_id.to_owned(),
        &kms,
    )
    .await?;
    let dec = decrypt_inner(
        http_req(),
        decrypt_request("arn:aws:iam::1:role/Bob", &enc),
        key_id.to_owned(),
        &kms,
    )
    .await?;
    let ops = kms
        .database
        .list_user_operations_on_object(key_id, &xks_service_user, false)
        .await?;
    assert_eq!(
        ops,
        HashSet::from([
            KmipOperation::Encrypt,
            KmipOperation::Decrypt,
            KmipOperation::GetAttributes,
        ])
    );
    assert_eq!(
        STANDARD.decode(dec.plaintext).expect("valid base64"),
        b"data"
    );
    Ok(())
}

#[tokio::test]
async fn encrypt_decrypt_round_trip_with_aad() -> KResult<()> {
    let kms = test_kms().await?;
    let key_id = "xks-key-aad";
    provision_xks_key(&kms, key_id, "arn:aws:iam::1:role/Creator").await?;

    let plaintext = b"payload with aad";
    let aad = STANDARD.encode(b"project=nile");

    let mut enc_req = encrypt_request("arn:aws:iam::1:role/Alice", plaintext);
    enc_req.additionalAuthenticatedData = Some(aad.clone());
    let enc = encrypt_inner(http_req(), enc_req, key_id.to_owned(), &kms).await?;

    let mut dec_req = decrypt_request("arn:aws:iam::1:role/Bob", &enc);
    dec_req.additionalAuthenticatedData = Some(aad);
    let dec = decrypt_inner(http_req(), dec_req, key_id.to_owned(), &kms).await?;

    assert_eq!(STANDARD.decode(dec.plaintext).unwrap(), plaintext);
    Ok(())
}
