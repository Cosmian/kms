#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::time_normalize,
    kmip_0::kmip_types::{CryptographicUsageMask, RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PGPKey},
        kmip_operations::{
            Create, Decrypt, Destroy, Encrypt, Export, GetAttributes, Import, Revoke, Sign,
            SignatureVerify,
        },
        kmip_types::{CryptographicAlgorithm, KeyFormatType, UniqueIdentifier, ValidityIndicator},
    },
};

use crate::{init_test_logging, start_default_test_kms_server};

fn pgp_create_request(alg: CryptographicAlgorithm, bits: Option<i32>) -> Create {
    Create {
        object_type: ObjectType::PGPKey,
        attributes: Attributes {
            object_type: Some(ObjectType::PGPKey),
            cryptographic_algorithm: Some(alg),
            cryptographic_length: bits,
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Sign
                    | CryptographicUsageMask::Verify
                    | CryptographicUsageMask::Encrypt
                    | CryptographicUsageMask::Decrypt,
            ),
            activation_date: Some(time_normalize().unwrap()), /* REQUIRED: crypto ops need State::Active */
            ..Attributes::default()
        },
        protection_storage_masks: None,
    }
}

async fn destroy_key(client: &KmsClient, uid: &str) {
    drop(
        client
            .destroy(Destroy {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                remove: true,
                cascade: true,
                ..Destroy::default()
            })
            .await,
    );
}

#[tokio::test]
async fn test_pgp_create_and_get_attributes() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::RSA, Some(3072));
    let create_resp = client.create(create_req).await.unwrap();
    let uid = create_resp.unique_identifier.to_string();

    let get_attr_resp = client
        .get_attributes(GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            attribute_reference: None,
        })
        .await
        .unwrap();

    let attrs = get_attr_resp.attributes;
    assert_eq!(attrs.object_type, Some(ObjectType::PGPKey));
    assert_eq!(
        attrs.cryptographic_algorithm,
        Some(CryptographicAlgorithm::RSA)
    );
    assert_eq!(attrs.key_format_type, Some(KeyFormatType::OpenPgpSecretKey));

    destroy_key(&client, &uid).await;
}

#[tokio::test]
async fn test_pgp_revoke_then_destroy() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_resp = client
        .create(pgp_create_request(CryptographicAlgorithm::Ed25519, None))
        .await
        .expect("create OpenPGP key");
    let uid = create_resp.unique_identifier.to_string();

    let revoke_resp = client
        .revoke(Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::CessationOfOperation,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: true,
        })
        .await
        .expect("revoke OpenPGP key");
    assert_eq!(revoke_resp.unique_identifier.to_string(), uid);

    client
        .destroy(Destroy {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            remove: true,
            cascade: true,
            ..Destroy::default()
        })
        .await
        .expect("destroy revoked OpenPGP key");
}

#[tokio::test]
async fn test_pgp_export_secret_and_public() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    let create_resp = client.create(create_req).await.unwrap();
    let uid = create_resp.unique_identifier.to_string();

    // Default export (secret key armor)
    let export_resp = client.export(Export::from(uid.clone())).await.unwrap();
    assert_eq!(export_resp.object.object_type(), ObjectType::PGPKey);
    let key_block = export_resp.object.key_block().unwrap();
    assert_eq!(key_block.key_format_type, KeyFormatType::OpenPgpSecretKey);
    let bytes = key_block.key_bytes().unwrap();
    assert!(bytes.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----"));

    // Explicit export public key armor
    let export_pub_req = Export::new(
        UniqueIdentifier::TextString(uid.clone()),
        false,
        None,
        Some(KeyFormatType::OpenPgpPublicKey),
    );
    let export_pub_resp = client.export(export_pub_req).await.unwrap();
    assert_eq!(export_pub_resp.object.object_type(), ObjectType::PGPKey);
    let pub_key_block = export_pub_resp.object.key_block().unwrap();
    assert_eq!(
        pub_key_block.key_format_type,
        KeyFormatType::OpenPgpPublicKey
    );
    let pub_bytes = pub_key_block.key_bytes().unwrap();
    assert!(pub_bytes.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));

    destroy_key(&client, &uid).await;
}

#[tokio::test]
async fn test_pgp_import_public_then_export() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    let create_resp = client.create(create_req).await.unwrap();
    let uid_orig = create_resp.unique_identifier.to_string();

    let export_pub_req = Export::new(
        UniqueIdentifier::TextString(uid_orig.clone()),
        false,
        None,
        Some(KeyFormatType::OpenPgpPublicKey),
    );
    let export_pub_resp = client.export(export_pub_req).await.unwrap();
    let pub_bytes = export_pub_resp
        .object
        .key_block()
        .unwrap()
        .key_bytes()
        .unwrap();

    // Import public key
    let import_uid = format!(
        "imported-pgp-pub-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let import_object = Object::PGPKey(PGPKey {
        pgp_key_version: 4,
        key_block: KeyBlock {
            key_format_type: KeyFormatType::OpenPgpPublicKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(pub_bytes.clone()),
                attributes: None,
            }),
            cryptographic_algorithm: Some(CryptographicAlgorithm::Ed25519),
            cryptographic_length: Some(256),
            key_wrapping_data: None,
        },
    });

    let import_req = Import {
        unique_identifier: UniqueIdentifier::TextString(import_uid.clone()),
        replace_existing: Some(false),
        object_type: ObjectType::PGPKey,
        object: import_object,
        attributes: Attributes {
            object_type: Some(ObjectType::PGPKey),
            activation_date: Some(time_normalize().unwrap()),
            ..Attributes::default()
        },
        key_wrap_type: None,
    };

    client.import(import_req).await.unwrap();

    // Re-export and verify identical bytes
    let reexport_resp = client
        .export(Export::from(import_uid.clone()))
        .await
        .unwrap();
    let reexport_key_block = reexport_resp.object.key_block().unwrap();
    assert_eq!(
        reexport_key_block.key_format_type,
        KeyFormatType::OpenPgpPublicKey
    );
    let reexport_bytes = reexport_key_block.key_bytes().unwrap();
    assert_eq!(&reexport_bytes[..], &pub_bytes[..]);

    destroy_key(&client, &uid_orig).await;
    destroy_key(&client, &import_uid).await;
}

#[tokio::test]
async fn test_pgp_encrypt_decrypt_rsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::RSA, Some(2048));
    let create_resp = client.create(create_req).await.unwrap();
    let uid = create_resp.unique_identifier.to_string();

    let plaintext = b"Hello OpenPGP from the Eviden KMS";
    let enc_req = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(zeroize::Zeroizing::new(plaintext.to_vec())),
        ..Encrypt::default()
    };
    let enc_resp = client.encrypt(enc_req).await.unwrap();
    let ciphertext = enc_resp.data.expect("ciphertext present");
    assert!(!ciphertext.is_empty());
    assert_ne!(&ciphertext[..], plaintext);

    let dec_req = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(ciphertext),
        ..Decrypt::default()
    };
    let dec_resp = client.decrypt(dec_req).await.unwrap();
    let decrypted = dec_resp.data.expect("plaintext present");
    assert_eq!(&decrypted[..], plaintext);

    destroy_key(&client, &uid).await;
}

#[tokio::test]
async fn test_pgp_encrypt_decrypt_ed25519() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    let create_resp = client.create(create_req).await.unwrap();
    let uid = create_resp.unique_identifier.to_string();

    let plaintext = b"Hello OpenPGP from the Eviden KMS (Ed25519/cv25519)";
    let enc_req = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(zeroize::Zeroizing::new(plaintext.to_vec())),
        ..Encrypt::default()
    };
    let enc_resp = client.encrypt(enc_req).await.unwrap();
    let ciphertext = enc_resp.data.expect("ciphertext present");
    assert!(!ciphertext.is_empty());
    assert_ne!(&ciphertext[..], plaintext);

    let dec_req = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(ciphertext),
        ..Decrypt::default()
    };
    let dec_resp = client.decrypt(dec_req).await.unwrap();
    let decrypted = dec_resp.data.expect("plaintext present");
    assert_eq!(&decrypted[..], plaintext);

    destroy_key(&client, &uid).await;
}

#[tokio::test]
async fn test_pgp_sign_verify_rsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::RSA, Some(2048));
    let create_resp = client.create(create_req).await.unwrap();
    let uid = create_resp.unique_identifier.to_string();

    let data = b"detached-signature-payload-rsa";
    let sign_req = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(zeroize::Zeroizing::new(data.to_vec())),
        ..Sign::default()
    };
    let sign_resp = client.sign(sign_req).await.unwrap();
    let sig_data = sign_resp.signature_data.expect("signature present");

    let verify_req = SignatureVerify {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(data.to_vec()),
        signature_data: Some(sig_data.clone()),
        ..SignatureVerify::default()
    };
    let verify_resp = client.signature_verify(verify_req).await.unwrap();
    assert_eq!(
        verify_resp.validity_indicator,
        Some(ValidityIndicator::Valid)
    );

    let mut tampered = data.to_vec();
    if let Some(first) = tampered.first_mut() {
        *first ^= 0xFF;
    }
    let verify_tampered_req = SignatureVerify {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(tampered),
        signature_data: Some(sig_data),
        ..SignatureVerify::default()
    };
    let verify_tampered_resp = client.signature_verify(verify_tampered_req).await.unwrap();
    assert_eq!(
        verify_tampered_resp.validity_indicator,
        Some(ValidityIndicator::Invalid)
    );

    destroy_key(&client, &uid).await;
}

#[tokio::test]
async fn test_pgp_sign_verify_ed25519() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    let create_resp = client.create(create_req).await.unwrap();
    let uid = create_resp.unique_identifier.to_string();

    let data = b"detached-signature-payload-ed25519";
    let sign_req = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(zeroize::Zeroizing::new(data.to_vec())),
        ..Sign::default()
    };
    let sign_resp = client.sign(sign_req).await.unwrap();
    let sig_data = sign_resp.signature_data.expect("signature present");

    let verify_req = SignatureVerify {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(data.to_vec()),
        signature_data: Some(sig_data.clone()),
        ..SignatureVerify::default()
    };
    let verify_resp = client.signature_verify(verify_req).await.unwrap();
    assert_eq!(
        verify_resp.validity_indicator,
        Some(ValidityIndicator::Valid)
    );

    let mut tampered = data.to_vec();
    if let Some(first) = tampered.first_mut() {
        *first ^= 0xFF;
    }
    let verify_tampered_req = SignatureVerify {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(tampered),
        signature_data: Some(sig_data),
        ..SignatureVerify::default()
    };
    let verify_tampered_resp = client.signature_verify(verify_tampered_req).await.unwrap();
    assert_eq!(
        verify_tampered_resp.validity_indicator,
        Some(ValidityIndicator::Invalid)
    );

    destroy_key(&client, &uid).await;
}

#[tokio::test]
async fn test_pgp_decrypt_with_public_only_key_fails() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::RSA, Some(2048));
    let create_resp = client.create(create_req).await.unwrap();
    let uid_orig = create_resp.unique_identifier.to_string();

    let export_pub_req = Export::new(
        UniqueIdentifier::TextString(uid_orig.clone()),
        false,
        None,
        Some(KeyFormatType::OpenPgpPublicKey),
    );
    let export_pub_resp = client.export(export_pub_req).await.unwrap();
    let pub_bytes = export_pub_resp
        .object
        .key_block()
        .unwrap()
        .key_bytes()
        .unwrap();

    let pub_uid = format!(
        "imported-pgp-pub-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let import_object = Object::PGPKey(PGPKey {
        pgp_key_version: 4,
        key_block: KeyBlock {
            key_format_type: KeyFormatType::OpenPgpPublicKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(pub_bytes),
                attributes: None,
            }),
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            cryptographic_length: Some(2048),
            key_wrapping_data: None,
        },
    });

    client
        .import(Import {
            unique_identifier: UniqueIdentifier::TextString(pub_uid.clone()),
            replace_existing: Some(false),
            object_type: ObjectType::PGPKey,
            object: import_object,
            attributes: Attributes {
                object_type: Some(ObjectType::PGPKey),
                activation_date: Some(time_normalize().unwrap()),
                ..Attributes::default()
            },
            key_wrap_type: None,
        })
        .await
        .unwrap();

    let dec_res = client
        .decrypt(Decrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(pub_uid.clone())),
            data: Some(b"ciphertext".to_vec()),
            ..Decrypt::default()
        })
        .await;

    drop(dec_res.unwrap_err());

    destroy_key(&client, &uid_orig).await;
    destroy_key(&client, &pub_uid).await;
}
