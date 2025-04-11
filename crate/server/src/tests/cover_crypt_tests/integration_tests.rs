use cosmian_cover_crypt::{AccessPolicy, EncryptionHint, QualifiedAttribute};
use cosmian_kmip::{
    kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        extra::tagging::EMPTY_TAGS,
        kmip_operations::{
            CreateKeyPairResponse, CreateResponse, DecryptResponse, DecryptedData, DestroyResponse,
            EncryptResponse, ReKeyKeyPairResponse, Revoke, RevokeResponse,
        },
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
        requests::{decrypt_request, encrypt_request},
    },
};
use cosmian_kms_client_utils::cover_crypt_utils::{
    build_create_covercrypt_master_keypair_request, build_create_covercrypt_usk_request,
};
use cosmian_kms_crypto::crypto::cover_crypt::{
    attributes::RekeyEditAction, kmip_requests::build_rekey_keypair_request,
};

use crate::{
    result::{KResult, KResultHelper},
    tests::test_utils,
};
#[tokio::test]
async fn integration_tests_use_ids_no_tags() -> KResult<()> {
    cosmian_logger::log_init(None);
    let app = test_utils::test_app(None, None).await;
    let access_structure = r#"{"Security Level::<":["Protected","Confidential","Top Secret::+"],"Department":["RnD","HR","MKG","FIN"]}"#;

    // create Key Pair
    let create_key_pair =
        build_create_covercrypt_master_keypair_request(access_structure, EMPTY_TAGS, false)?;
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
    let encryption_policy = "Security Level::Confidential && Department::MKG";

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        Some(authentication_data.clone()),
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )?;

        let encrypt_response: EncryptResponse = test_utils::post_2_1(&app, request).await?;
        let encrypted_data = encrypt_response
            .data
            .expect("There should be encrypted data");

    // Create a user decryption key
    let access_policy = "(Department::MKG || Department::FIN) && Security Level::Top Secret";
    let request = build_create_covercrypt_usk_request(
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

    let decrypt_response: DecryptResponse = test_utils::post_2_1(&app, request).await?;

    let decrypted_data = decrypt_response
        .data
        .context("There should be decrypted data")?;

    assert_eq!(data, &**decrypted_data);

    // revocation

    // Encrypt
    let authentication_data = b"cc the uid".to_vec();
    let data = "Voilà voilà".as_bytes();
    let encryption_policy = "Security Level::Confidential && Department::MKG";

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        Some(authentication_data.clone()),
        None,
    )?;

    let encrypt_response: EncryptResponse = test_utils::post_2_1(&app, &request).await?;

    let encrypted_data = encrypt_response
        .data
        .expect("There should be encrypted data");

    //
    // Create a user decryption key
    let access_policy = "(Department::MKG || Department::FIN) && Security Level::Confidential";
    let request = build_create_covercrypt_usk_request(
        access_policy,
        private_key_unique_identifier,
        EMPTY_TAGS,
        false,
    )?;
    let create_response: CreateResponse = test_utils::post_2_1(&app, &request).await?;
    let user_decryption_key_identifier_1 = create_response
        .unique_identifier
        .as_str()
        .context("There should be a user decryption key unique identifier as a string")?;

    //
    // Create another user decryption key
    let access_policy = "Department::MKG && Security Level::Confidential";
    let request = build_create_covercrypt_usk_request(
        access_policy,
        private_key_unique_identifier,
        EMPTY_TAGS,
        false,
    )?;
    let create_response2: CreateResponse = test_utils::post_2_1(&app, &request).await?;
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

    let decrypted_data = decrypt_response
        .data
        .context("There should be decrypted data")?;

    assert_eq!(data, &*decrypted_data);

    // test user2 can decrypt
    let request = decrypt_request(
        user_decryption_key_identifier_2,
        None,
        encrypted_data.clone(),
        None,
        Some(authentication_data.clone()),
        None,
    );

    let decrypt_response: DecryptResponse = test_utils::post_2_1(&app, &request).await?;

    let decrypted_data = decrypt_response
        .data
        .context("There should be decrypted data")?;

    assert_eq!(data, &*decrypted_data);

    // Revoke key of user 1
    let _revoke_response: RevokeResponse = test_utils::post_2_1(
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
    let rekey_keypair_response: ReKeyKeyPairResponse = test_utils::post_2_1(&app, &request).await?;
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
    let encryption_policy = "Security Level::Confidential && Department::MKG";

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        Some(authentication_data.clone()),
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )?;
    let encrypt_response: EncryptResponse = test_utils::post_2_1(&app, &request).await?;
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
    let post_ttlv_decrypt: KResult<DecryptResponse> = test_utils::post_2_1(&app, &request).await;
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
    let decrypt_response: DecryptResponse = test_utils::post_21(&app, &request).await?;
    let decrypted_data = decrypt_response
        .data
        .context("There should be decrypted data")?;

    assert_eq!(data, &*decrypted_data);

    //
    // Prune old keys associated to the access policy
    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::PruneAccessPolicy(ap_to_edit),
    )?;
    let rekey_keypair_response: KResult<ReKeyKeyPairResponse> =
        test_utils::post_2_1(&app, &request).await;
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
    let post_ttlv_decrypt: KResult<DecryptResponse> = test_utils::post_2_1(&app, &request).await;
    assert!(post_ttlv_decrypt.is_err());

    let encryption_policy = "Security Level::Confidential && (Department::IT || Department::RnD)";

    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::AddAttribute(vec![(
            QualifiedAttribute::new("Department", "IT"),
            EncryptionHint::Classic,
            None,
        )]),
    )?;
    let rekey_keypair_response: KResult<ReKeyKeyPairResponse> =
        test_utils::post_2_1(&app, &request).await;
    rekey_keypair_response?;

    // Encrypt for new attribute
    let data = b"New tech research data";

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        Some(authentication_data.clone()),
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )?;
    let encrypt_response: KResult<EncryptResponse> = test_utils::post_2_1(&app, &request).await;
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
        test_utils::post_2_1(&app, &request).await;
    rekey_keypair_response?;

    // Encrypt for renamed attribute
    let data = b"hr data";
    let encryption_policy = "Security Level::Confidential && Department::HumanResources";

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        Some(authentication_data.clone()),
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )?;
    let encrypt_response: KResult<EncryptResponse> = test_utils::post_2_1(&app, &request).await;
    encrypt_response?;

    //
    // Disable ABE Attribute
    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::DisableAttribute(vec![QualifiedAttribute::from(("Department", "MKG"))]),
    )?;
    let rekey_keypair_response: KResult<ReKeyKeyPairResponse> =
        test_utils::post_2_1(&app, &request).await;
    rekey_keypair_response?;

    // Encrypt with disabled ABE attribute will fail
    let authentication_data = b"cc the uid".to_vec();
    let data = b"Will fail";
    let encryption_policy = "Security Level::Confidential && Department::MKG";

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        Some(authentication_data.clone()),
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )?;
    let encrypt_response: KResult<EncryptResponse> = test_utils::post_2_1(&app, &request).await;
    assert!(encrypt_response.is_err());

    //
    // Delete attribute
    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::DeleteAttribute(vec![
            (QualifiedAttribute::new("Department", "HumanResources")),
        ]),
    )?;
    let rekey_keypair_response: KResult<ReKeyKeyPairResponse> =
        test_utils::post_2_1(&app, &request).await;
    rekey_keypair_response?;

    // Encrypt for removed attribute will fail
    let data = b"New hr data";
    let encryption_policy = "Security Level::Confidential && Department::HumanResources";

    let request = encrypt_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        Some(authentication_data.clone()),
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )?;
    let encrypt_response: KResult<EncryptResponse> = test_utils::post_2_1(&app, &request).await;
    assert!(encrypt_response.is_err());

    //
    // Destroy user decryption key
    let request = Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(
            user_decryption_key_identifier_1.to_owned(),
        )),
        remove: false,
    };
    let destroy_response: DestroyResponse = test_utils::post_2_1(&app, &request).await?;
    assert_eq!(
        user_decryption_key_identifier_1,
        destroy_response
            .unique_identifier
            .as_str()
            .context("There should be a user decryption key unique identifier as a string")?
    );

    Ok(())
}

#[test]
fn test_access_policy_parsing() -> KResult<()> {
    let access_policy = "Security Level::Confidential && (Department::IT || Department::RnD)";
    let _ap = AccessPolicy::parse(access_policy)?;
    Ok(())
}
