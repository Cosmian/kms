use cosmian_cover_crypt::{EncryptionHint, MasterSecretKey, QualifiedAttribute};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kmip::kmip_2_1::{
    extra::tagging::EMPTY_TAGS,
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_operations::{
        CreateKeyPairResponse, CreateResponse, DecryptResponse, DecryptedData, DestroyResponse,
        EncryptResponse, Import, ReKeyKeyPairResponse, Revoke, RevokeResponse,
    },
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicParameters, KeyFormatType,
        RevocationReason, UniqueIdentifier,
    },
    requests::{decrypt_request, encrypt_request},
};
use cosmian_kms_crypto::crypto::cover_crypt::{
    attributes::RekeyEditAction,
    kmip_requests::{
        build_create_covercrypt_master_keypair_request,
        build_create_covercrypt_user_decryption_key_request, build_destroy_key_request,
        build_rekey_keypair_request,
    },
};

use crate::{
    kms_error,
    result::{KResult, KResultHelper},
    tests::test_utils,
};

const RSA_PRIVATE_KEY: &str = r"
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCNzNM2hQNhfdUO
7hTM9F/a4ZNfCBnIpTP6VRvHNLcA7T8Zt+2+ozC7zKneXGXAfs70zLfa00wAlcm0
FJ/4OJoPfEgDodN05rh0e8hmUjGs15HJAu5QS7b6p1zn/HUUmYSS4bffG6cV54BR
TcI1I7lf4hnedLet04gvrDABJUkoE+Az0Af3nGqbFdA04WmZuuK/9zlUCp3siHzc
fwoHOjCxhE1iJaogm8VU/bbinZQ02qmvRZf5A+SChBgfmEoZFHxuPcFViHOUQT7j
8FAunYQJ9JgJ7WRFiqV9KkFEeusqFn5VwSxiD/3NsAo+Ytzh9ExHropobkA2l7s6
x5UUsfI1AgMBAAECggEAFB4BvhufV+q7+icFTPGDkuBLYeFalRh4+BQwgXHFX8yI
1ft973yj+pTF6b3Wkrl634iWseUlxHR7vgBqFJNlKfrCFb/U6eIcu6vfCcMx+HlJ
3ch8amhfgI6Tc/chXieMgzEiPrUj3ovuLLq5KYRUtZl0fZa2A2N+D/NgCR2S1CxN
oy0Yvj7eMlRlGpOcoc/6dIJjJoS3PcxRMxAquIJsY8rBjkZ8F8AtaDS+F1nbTH6a
D3HazA4eIWmb3mxiRkRV3P1X6JVCplyr7yGmWnUN5T+mwygH89K2mP1K9Zxr9MWw
jUt84PtsR1WX+V8gGZWxHDqNCp8WiHH0qnqrzDqiYQKBgQDAy+PmePj36DmagxJO
p16usED7oYRvzab/XvYI/hQKQqiyey4G8JnEkKdtY2RV2sBLJmKiSdE+YsPRqhl3
mWBDtEg25UipEZAiH0BDu0Jg92iUP4FSPWc7h/Rt+W3O7Gt+UetpKRAnWWSyxgJ9
GG/mt+N58r8B79yOp4rynzxWIQKBgQC8SSdye2g31VmukxGZk1iDbVnVg1XYQcOj
E7MteFNUHLUeDO2XYgdhp1/hmLiaTCVvrhDp1WqwNthaOidV+ysSzABu316yq4Pm
qdcVsSoak69Rw50AXbxNju0Yz6YuYxUAjWQ5Jk8+gNplwRN3ha4lXpKUJBld92vM
el1ikCexlQKBgFlu+1QRL+TIC9iaDqb/ytMcHbjcbvPyIRJ7OYRoYGF2FI1eyLYd
bCcbtx7uKUAOTn9N2hlQRsk6xX1/+3pYYqhle85DRBZxeDvr5ULGHf+fJRsH7nR4
2WdrJL7TItYHI8IgPCS3ELBALo8jfUoMSPRsvw/1xBcg7l4aaEEuDq4hAoGBAIyF
EDKplVMuIDtguV7jj8iugMAPv66hDjAUEMJbrdz1e9qMjXlQiO/BqZZFk2hccggS
Yb8SLwiKNhfIlPjfdfsWUzBr9lHkHZG1qbcfvKuPEuYz1mWij1lW1O6ScpTmD5OU
8nqQc83S/qu4WB34n8p19XEoK+JsOICnxjA8I9OtAoGAVziHvUjC84B6BXVuC5B3
KLNVGWKs8oqvZIgRXhp3Yu4Kw41PKyQYPyQ91TAUbSvahkrNOwALmabx9OovNGtD
3IvcjbcH8hlJ1MmqxObwe4Hun4A3/ekv0G08kIRpkBgVeVhY3MJ2uKo+3LIk5AMf
jRuCab6FPsJq5BTA5QYDjR8=
-----END PRIVATE KEY-----
";

#[tokio::test]
async fn integration_tests_use_ids_no_tags() -> KResult<()> {
    cosmian_logger::log_init(None);
    let app = test_utils::test_app(None).await;
    let pem: pem::Pem = pem::parse(RSA_PRIVATE_KEY.as_bytes())
        .map_err(|e| kms_error!(format!("cannot parse RSA private key: {}", e)))?;

    let import_key = Import {
        unique_identifier: UniqueIdentifier::TextString(String::new()),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: Attributes::default(),
        object: Object::PublicKey {
            key_block: KeyBlock {
                key_format_type: KeyFormatType::PKCS8,
                key_compression_type: None,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(pem.contents().to_vec().into()),
                    attributes: None,
                },
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: None,
                key_wrapping_data: None,
            },
        },
    };

    let y = import_key.object_type;
    let binding = y.to_string();
    let u = binding.as_bytes();
    let mut msk = MasterSecretKey::deserialize(u)?;
    msk.access_structure.add_anarchy("Department".to_owned())?;
    [
        ("HR", EncryptionHint::Classic),
        ("MKG", EncryptionHint::Classic),
        ("FIN", EncryptionHint::Classic),
    ]
    .into_iter()
    .try_for_each(|(attribute, hint)| {
        msk.access_structure.add_attribute(
            QualifiedAttribute {
                dimension: "Department".to_owned(),
                name: attribute.to_owned(),
            },
            hint,
            None,
        )
    })?;

    msk.access_structure.add_hierarchy("Level".to_owned())?;

    msk.access_structure.add_attribute(
        QualifiedAttribute {
            dimension: "Level".to_owned(),
            name: "Confidential".to_owned(),
        },
        EncryptionHint::Classic,
        None,
    )?;
    msk.access_structure.add_attribute(
        QualifiedAttribute {
            dimension: "Level".to_owned(),
            name: "Top Secret".to_owned(),
        },
        EncryptionHint::Hybridized,
        None,
    )?;

    // create Key Pair
    let access_structure = msk.access_structure.serialize()?;
    let create_key_pair =
        build_create_covercrypt_master_keypair_request(&access_structure, EMPTY_TAGS, false)?;
    let create_key_pair_response: CreateKeyPairResponse =
        test_utils::post(&app, &create_key_pair).await?;

    let private_key_unique_identifier = create_key_pair_response
        .private_key_unique_identifier
        .as_str()
        .context("There should be a private key unique identifier as a string")?;
    let public_key_unique_identifier = create_key_pair_response
        .public_key_unique_identifier
        .as_str()
        .context("There should be a public key unique identifier as a string")?;

    // Encrypt
    let authentication_data = b"cc the uid".to_vec();
    let data = b"Confidential MKG Data";
    let encryption_policy = "Level::Confidential && Department::MKG";
    let header_metadata = vec![1, 2, 3];

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        Some(header_metadata.clone()),
        None,
        Some(authentication_data.clone()),
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )?;

    let encrypt_response: EncryptResponse = test_utils::post(&app, request).await?;
    let encrypted_data = encrypt_response
        .data
        .expect("There should be encrypted data");

    // Create a user decryption key
    let access_policy = "(Department::MKG || Department::FIN) && Level::Top Secret";
    let request = build_create_covercrypt_user_decryption_key_request(
        access_policy,
        private_key_unique_identifier,
        EMPTY_TAGS,
        false,
    )?;
    let create_response: CreateResponse = test_utils::post(&app, request).await?;
    let user_decryption_key_identifier = create_response
        .unique_identifier
        .as_str()
        .context("There should be a user decryption key unique identifier as a string")?;

    // decrypt
    let request = decrypt_request(
        user_decryption_key_identifier,
        None,
        encrypted_data,
        None,
        Some(authentication_data.clone()),
        None,
    );

    let decrypt_response: DecryptResponse = test_utils::post(&app, request).await?;

    let decrypted_data: DecryptedData = decrypt_response
        .data
        .context("There should be decrypted data")?
        .as_slice()
        .try_into()?;

    assert_eq!(data, &decrypted_data.plaintext[..]);
    assert_eq!(header_metadata, decrypted_data.metadata);

    // revocation

    // Encrypt
    let authentication_data = b"cc the uid".to_vec();
    let data = "Voilà voilà".as_bytes();
    let encryption_policy = "Level::Confidential && Department::MKG";

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        None,
        Some(authentication_data.clone()),
        None,
    )?;

    let encrypt_response: EncryptResponse = test_utils::post(&app, &request).await?;

    let encrypted_data = encrypt_response
        .data
        .expect("There should be encrypted data");

    //
    // Create a user decryption key
    let access_policy = "(Department::MKG || Department::FIN) && Level::Confidential";
    let request = build_create_covercrypt_user_decryption_key_request(
        access_policy,
        private_key_unique_identifier,
        EMPTY_TAGS,
        false,
    )?;
    let create_response: CreateResponse = test_utils::post(&app, &request).await?;
    let user_decryption_key_identifier_1 = create_response
        .unique_identifier
        .as_str()
        .context("There should be a user decryption key unique identifier as a string")?;

    //
    // Create another user decryption key
    let access_policy = "Department::MKG && Level::Confidential";
    let request = build_create_covercrypt_user_decryption_key_request(
        access_policy,
        private_key_unique_identifier,
        EMPTY_TAGS,
        false,
    )?;
    let create_response2: CreateResponse = test_utils::post(&app, &request).await?;
    let user_decryption_key_identifier_2 = &create_response2
        .unique_identifier
        .as_str()
        .context("There should be a user decryption key unique identifier as a string")?;

    // test user1 can decrypt
    let request = decrypt_request(
        user_decryption_key_identifier_1,
        None,
        encrypted_data.clone(),
        None,
        Some(authentication_data.clone()),
        None,
    );
    let decrypt_response: DecryptResponse = test_utils::post(&app, &request).await?;

    let decrypted_data: DecryptedData = decrypt_response
        .data
        .context("There should be decrypted data")?
        .as_slice()
        .try_into()?;

    assert_eq!(&data, &decrypted_data.plaintext.to_vec());
    assert!(decrypted_data.metadata.is_empty());

    // test user2 can decrypt
    let request = decrypt_request(
        user_decryption_key_identifier_2,
        None,
        encrypted_data.clone(),
        None,
        Some(authentication_data.clone()),
        None,
    );

    let decrypt_response: DecryptResponse = test_utils::post(&app, &request).await?;

    let decrypted_data: DecryptedData = decrypt_response
        .data
        .context("There should be decrypted data")?
        .as_slice()
        .try_into()?;

    assert_eq!(&data, &decrypted_data.plaintext.to_vec());
    assert!(decrypted_data.metadata.is_empty());

    // Revoke key of user 1
    let _revoke_response: RevokeResponse = test_utils::post(
        &app,
        &Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(
                user_decryption_key_identifier_1.to_owned(),
            )),
            revocation_reason: RevocationReason::TextString("Revocation test".to_owned()),
            compromise_occurrence_date: None,
        },
    )
    .await?;

    //
    // Rekey all key pairs with matching access policy
    let ap_to_edit = "Department::MKG".to_owned();
    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::RekeyAccessPolicy(ap_to_edit.clone()),
    )?;
    let rekey_keypair_response: ReKeyKeyPairResponse = test_utils::post(&app, &request).await?;
    assert_eq!(
        rekey_keypair_response
            .private_key_unique_identifier
            .as_str()
            .context("There should be a private key unique identifier as a string")?,
        private_key_unique_identifier
    );
    assert_eq!(
        rekey_keypair_response
            .public_key_unique_identifier
            .as_str()
            .context("There should be a public key unique identifier as a string")?,
        public_key_unique_identifier
    );

    // ReEncrypt with same ABE attribute (which has been previously rekeyed)
    let authentication_data = b"cc the uid".to_vec();
    let data = "Voilà voilà".as_bytes();
    let encryption_policy = "Level::Confidential && Department::MKG";

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        None,
        Some(authentication_data.clone()),
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )?;
    let encrypt_response: EncryptResponse = test_utils::post(&app, &request).await?;
    let new_encrypted_data = encrypt_response
        .data
        .expect("There should be encrypted data");

    // Make sure first user decryption key cannot decrypt new encrypted message (message being encrypted with new `MKG` value)
    let request = decrypt_request(
        user_decryption_key_identifier_1,
        None,
        new_encrypted_data.clone(),
        None,
        Some(authentication_data.clone()),
        None,
    );
    let post_ttlv_decrypt: KResult<DecryptResponse> = test_utils::post(&app, &request).await;
    assert!(post_ttlv_decrypt.is_err());

    // decrypt
    let request = decrypt_request(
        user_decryption_key_identifier_2,
        None,
        new_encrypted_data,
        None,
        Some(authentication_data.clone()),
        None,
    );
    let decrypt_response: DecryptResponse = test_utils::post(&app, &request).await?;
    let decrypted_data: DecryptedData = decrypt_response
        .data
        .context("There should be decrypted data")?
        .as_slice()
        .try_into()?;

    assert_eq!(&data, &decrypted_data.plaintext.to_vec());
    assert!(decrypted_data.metadata.is_empty());

    //
    // Prune old keys associated to the access policy
    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::PruneAccessPolicy(ap_to_edit),
    )?;
    let rekey_keypair_response: KResult<ReKeyKeyPairResponse> =
        test_utils::post(&app, &request).await;
    rekey_keypair_response?;

    // test user2 can no longer decrypt old message
    let request = decrypt_request(
        user_decryption_key_identifier_2,
        None,
        encrypted_data,
        None,
        Some(authentication_data.clone()),
        None,
    );
    let post_ttlv_decrypt: KResult<DecryptResponse> = test_utils::post(&app, &request).await;
    assert!(post_ttlv_decrypt.is_err());

    let encryption_policy = "Level::Confidential && (Department::IT || Department::R&D)";

    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::AddAttribute(vec![(
            QualifiedAttribute::new("Security Level", "LOW"),
            EncryptionHint::Classic,
            None,
        )]),
    )?;
    let rekey_keypair_response: KResult<ReKeyKeyPairResponse> =
        test_utils::post(&app, &request).await;
    rekey_keypair_response?;

    // Encrypt for new attribute
    let data = b"New tech research data";

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        None,
        Some(authentication_data.clone()),
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )?;
    let encrypt_response: KResult<EncryptResponse> = test_utils::post(&app, &request).await;
    encrypt_response?;

    //
    // Rename Attributes
    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::RenameAttribute(vec![(
            QualifiedAttribute::new("Department", "HR"),
            "HumanResources".to_owned(),
        )]),
    )?;
    let rekey_keypair_response: KResult<ReKeyKeyPairResponse> =
        test_utils::post(&app, &request).await;
    rekey_keypair_response?;

    // Encrypt for renamed attribute
    let data = b"hr data";
    let encryption_policy = "Level::Confidential && Department::HumanResources";

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        None,
        Some(authentication_data.clone()),
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )?;
    let encrypt_response: KResult<EncryptResponse> = test_utils::post(&app, &request).await;
    encrypt_response?;

    //
    // Disable ABE Attribute
    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::DisableAttribute(vec![QualifiedAttribute::from(("Department", "FIN"))]),
    )?;
    let rekey_keypair_response: KResult<ReKeyKeyPairResponse> =
        test_utils::post(&app, &request).await;
    rekey_keypair_response?;

    // Encrypt with disabled ABE attribute will fail
    let authentication_data = b"cc the uid".to_vec();
    let data = b"Will fail";
    let encryption_policy = "Level::Confidential && Department::MKG";

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        None,
        Some(authentication_data.clone()),
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )?;
    let encrypt_response: KResult<EncryptResponse> = test_utils::post(&app, &request).await;
    assert!(encrypt_response.is_err());

    //
    // Delete attribute
    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::DeleteAttribute(vec![(QualifiedAttribute::new("Department", "HR"))]),
    )?;
    let rekey_keypair_response: KResult<ReKeyKeyPairResponse> =
        test_utils::post(&app, &request).await;
    rekey_keypair_response?;

    // Encrypt for removed attribute will fail
    let data = b"New hr data";
    let encryption_policy = "Level::Confidential && Department::HumanResources";

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        None,
        Some(authentication_data.clone()),
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )?;
    let encrypt_response: KResult<EncryptResponse> = test_utils::post(&app, &request).await;
    assert!(encrypt_response.is_err());

    //
    // Destroy user decryption key
    let request = build_destroy_key_request(user_decryption_key_identifier_1)?;
    let destroy_response: DestroyResponse = test_utils::post(&app, &request).await?;
    assert_eq!(
        user_decryption_key_identifier_1,
        destroy_response
            .unique_identifier
            .as_str()
            .context("There should be a user decryption key unique identifier as a string")?
    );

    Ok(())
}
