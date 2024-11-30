use cloudproof::reexport::cover_crypt::abe_policy::{
    Attribute, DimensionBuilder, EncryptionHint, Policy,
};
use cosmian_kmip::{
    crypto::{
        cover_crypt::{
            attributes::RekeyEditAction,
            kmip_requests::{
                build_create_master_keypair_request,
                build_create_user_decryption_private_key_request, build_destroy_key_request,
                build_rekey_keypair_request,
            },
        },
        generic::kmip_requests::{build_decryption_request, build_encryption_request},
    },
    kmip::{
        extra::tagging::EMPTY_TAGS,
        kmip_operations::{
            CreateKeyPairResponse, CreateResponse, DecryptResponse, DecryptedData, DestroyResponse,
            EncryptResponse, ReKeyKeyPairResponse, Revoke, RevokeResponse,
        },
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, RevocationReason, UniqueIdentifier,
        },
    },
};

use crate::{
    result::{KResult, KResultHelper},
    tests::test_utils,
};

#[tokio::test]
async fn integration_tests_use_ids_no_tags() -> KResult<()> {
    cosmian_logger::log_utils::log_init(None);
    let app = test_utils::test_app(None).await;

    let mut policy = Policy::new();
    policy.add_dimension(DimensionBuilder::new(
        "Department",
        vec![
            ("MKG", EncryptionHint::Classic),
            ("FIN", EncryptionHint::Classic),
            ("HR", EncryptionHint::Classic),
        ],
        false,
    ))?;
    policy.add_dimension(DimensionBuilder::new(
        "Level",
        vec![
            ("Confidential", EncryptionHint::Classic),
            ("Top Secret", EncryptionHint::Hybridized),
        ],
        true,
    ))?;

    // create Key Pair
    let create_key_pair = build_create_master_keypair_request(&policy, EMPTY_TAGS, false)?;
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

    let request = build_encryption_request(
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
    let request = build_create_user_decryption_private_key_request(
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
    let request = build_decryption_request(
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

    let request = build_encryption_request(
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
    let request = build_create_user_decryption_private_key_request(
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
    let request = build_create_user_decryption_private_key_request(
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
    let request = build_decryption_request(
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
    let request = build_decryption_request(
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

    let request = build_encryption_request(
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
    let request = build_decryption_request(
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
    let request = build_decryption_request(
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
    let request = build_decryption_request(
        user_decryption_key_identifier_2,
        None,
        encrypted_data,
        None,
        Some(authentication_data.clone()),
        None,
    );
    let post_ttlv_decrypt: KResult<DecryptResponse> = test_utils::post(&app, &request).await;
    assert!(post_ttlv_decrypt.is_err());

    //
    // Add new Attributes
    let new_policy_attributes = vec![
        (
            Attribute::from(("Department", "IT")),
            EncryptionHint::Classic,
        ),
        (
            Attribute::from(("Department", "R&D")),
            EncryptionHint::Hybridized,
        ),
    ];
    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::AddAttribute(new_policy_attributes),
    )?;
    let rekey_keypair_response: KResult<ReKeyKeyPairResponse> =
        test_utils::post(&app, &request).await;
    rekey_keypair_response?;

    // Encrypt for new attribute
    let data = b"New tech research data";
    let encryption_policy = "Level::Confidential && (Department::IT || Department::R&D)";

    let request = build_encryption_request(
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
    let rename_policy_attributes_pair = vec![(
        Attribute::from(("Department", "HR")),
        "HumanResources".to_owned(),
    )];
    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::RenameAttribute(rename_policy_attributes_pair),
    )?;
    let rekey_keypair_response: KResult<ReKeyKeyPairResponse> =
        test_utils::post(&app, &request).await;
    rekey_keypair_response?;

    // Encrypt for renamed attribute
    let data = b"hr data";
    let encryption_policy = "Level::Confidential && Department::HumanResources";

    let request = build_encryption_request(
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
    let disable_policy_attributes = vec![Attribute::from(("Department", "MKG"))];
    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::DisableAttribute(disable_policy_attributes),
    )?;
    let rekey_keypair_response: KResult<ReKeyKeyPairResponse> =
        test_utils::post(&app, &request).await;
    rekey_keypair_response?;

    // Encrypt with disabled ABE attribute will fail
    let authentication_data = b"cc the uid".to_vec();
    let data = b"Will fail";
    let encryption_policy = "Level::Confidential && Department::MKG";

    let request = build_encryption_request(
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
    let remove_policy_attributes = vec![Attribute::from(("Department", "HumanResources"))];
    let request = build_rekey_keypair_request(
        private_key_unique_identifier,
        &RekeyEditAction::RemoveAttribute(remove_policy_attributes),
    )?;
    let rekey_keypair_response: KResult<ReKeyKeyPairResponse> =
        test_utils::post(&app, &request).await;
    rekey_keypair_response?;

    // Encrypt for removed attribute will fail
    let data = b"New hr data";
    let encryption_policy = "Level::Confidential && Department::HumanResources";

    let request = build_encryption_request(
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
