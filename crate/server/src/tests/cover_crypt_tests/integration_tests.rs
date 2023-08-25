use cloudproof::reexport::cover_crypt::abe_policy::{
    Attribute, EncryptionHint, Policy, PolicyAxis,
};
use cosmian_kmip::kmip::{
    kmip_operations::{
        CreateKeyPairResponse, CreateResponse, DecryptResponse, DecryptedData, DestroyResponse,
        EncryptResponse, ReKeyKeyPairResponse, Revoke, RevokeResponse,
    },
    kmip_types::RevocationReason,
};
use cosmian_kms_utils::{
    crypto::{
        cover_crypt::kmip_requests::{
            build_create_master_keypair_request, build_create_user_decryption_private_key_request,
            build_destroy_key_request, build_rekey_keypair_request,
        },
        generic::kmip_requests::{build_decryption_request, build_encryption_request},
    },
    tagging::EMPTY_TAGS,
};

use crate::{
    log_utils,
    result::{KResult, KResultHelper},
    tests::test_utils,
};

#[actix_web::test]
async fn integration_tests_use_ids_no_tags() -> KResult<()> {
    log_utils::log_init("cosmian_kms_server=info");

    let app = test_utils::test_app().await;

    let mut policy = Policy::new(10);
    policy.add_axis(PolicyAxis::new(
        "Department",
        vec![
            ("MKG", EncryptionHint::Classic),
            ("FIN", EncryptionHint::Classic),
            ("HR", EncryptionHint::Classic),
        ],
        false,
    ))?;
    policy.add_axis(PolicyAxis::new(
        "Level",
        vec![
            ("Confidential", EncryptionHint::Classic),
            ("Top Secret", EncryptionHint::Hybridized),
        ],
        true,
    ))?;

    // create Key Pair
    let create_key_pair = build_create_master_keypair_request(&policy, EMPTY_TAGS)?;
    let create_key_pair_response: CreateKeyPairResponse =
        test_utils::post(&app, &create_key_pair).await?;

    let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;
    let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

    // Encrypt
    let authentication_data = b"cc the uid".to_vec();
    let data = b"Confidential MKG Data";
    let encryption_policy = "Level::Confidential && Department::MKG";
    let header_metadata = vec![1, 2, 3];
    let request = build_encryption_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_string()),
        data.to_vec(),
        Some(header_metadata.clone()),
        Some(authentication_data.clone()),
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
    )?;
    let create_response: CreateResponse = test_utils::post(&app, request).await?;
    let user_decryption_key_identifier = &create_response.unique_identifier;

    // decrypt
    let request = build_decryption_request(
        user_decryption_key_identifier,
        None,
        encrypted_data.clone(),
        None,
        Some(authentication_data.clone()),
    );
    let decrypt_response: DecryptResponse = test_utils::post(&app, request).await?;

    let decrypted_data: DecryptedData = decrypt_response
        .data
        .context("There should be decrypted data")?
        .as_slice()
        .try_into()
        .unwrap();

    assert_eq!(data, &decrypted_data.plaintext[..]);
    assert_eq!(header_metadata, decrypted_data.metadata);

    // revocation

    // Encrypt
    let authentication_data = b"cc the uid".to_vec();
    let data = "Voilà voilà".as_bytes();
    let encryption_policy = "Level::Confidential && Department::MKG";
    let request = build_encryption_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_string()),
        data.to_vec(),
        None,
        Some(authentication_data.clone()),
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
    )?;
    let create_response: CreateResponse = test_utils::post(&app, &request).await?;
    let user_decryption_key_identifier_1 = &create_response.unique_identifier;

    //
    // Create another user decryption key
    let access_policy = "Department::MKG && Level::Confidential";
    let request = build_create_user_decryption_private_key_request(
        access_policy,
        private_key_unique_identifier,
        EMPTY_TAGS,
    )?;
    let create_response2: CreateResponse = test_utils::post(&app, &request).await?;
    let user_decryption_key_identifier_2 = &create_response2.unique_identifier;

    // test user1 can decrypt
    let request = build_decryption_request(
        user_decryption_key_identifier_1,
        None,
        encrypted_data.clone(),
        None,
        Some(authentication_data.clone()),
    );
    let decrypt_response: DecryptResponse = test_utils::post(&app, &request).await?;

    let decrypted_data: DecryptedData = decrypt_response
        .data
        .context("There should be decrypted data")?
        .as_slice()
        .try_into()
        .unwrap();

    assert_eq!(data, &decrypted_data.plaintext);
    assert_eq!(Vec::<u8>::new(), decrypted_data.metadata);

    // test user2 can decrypt
    let request = build_decryption_request(
        user_decryption_key_identifier_2,
        None,
        encrypted_data.clone(),
        None,
        Some(authentication_data.clone()),
    );
    let decrypt_response: DecryptResponse = test_utils::post(&app, &request).await?;

    let decrypted_data: DecryptedData = decrypt_response
        .data
        .context("There should be decrypted data")?
        .as_slice()
        .try_into()
        .unwrap();

    assert_eq!(data, &decrypted_data.plaintext);
    assert_eq!(Vec::<u8>::new(), decrypted_data.metadata);

    // Revoke key of user 1
    let _revoke_response: RevokeResponse = test_utils::post(
        &app,
        &Revoke {
            unique_identifier: Some(user_decryption_key_identifier_1.clone()),
            revocation_reason: RevocationReason::TextString("Revocation test".to_owned()),
            compromise_occurrence_date: None,
        },
    )
    .await?;

    //
    // Rekey all key pairs with matching ABE attributes
    let abe_policy_attributes = vec![Attribute::from(("Department", "MKG"))];

    let request =
        build_rekey_keypair_request(private_key_unique_identifier, abe_policy_attributes)?;
    let rekey_keypair_response: ReKeyKeyPairResponse = test_utils::post(&app, &request).await?;
    assert_eq!(
        &rekey_keypair_response.private_key_unique_identifier,
        private_key_unique_identifier
    );
    assert_eq!(
        &rekey_keypair_response.public_key_unique_identifier,
        public_key_unique_identifier
    );

    // ReEncrypt with same ABE attribute (which has been previously incremented)
    let authentication_data = b"cc the uid".to_vec();
    let data = "Voilà voilà".as_bytes();
    let encryption_policy = "Level::Confidential && Department::MKG";
    let request = build_encryption_request(
        public_key_unique_identifier,
        Some(encryption_policy.to_string()),
        data.to_vec(),
        None,
        Some(authentication_data.clone()),
    )?;
    let encrypt_response: EncryptResponse = test_utils::post(&app, &request).await?;
    let encrypted_data = encrypt_response
        .data
        .expect("There should be encrypted data");

    // Make sure first user decryption key cannot decrypt new encrypted message (message being encrypted with new `MKG` value)
    let request = build_decryption_request(
        user_decryption_key_identifier_1,
        None,
        encrypted_data.clone(),
        None,
        Some(authentication_data.clone()),
    );
    let post_ttlv_decrypt: KResult<DecryptResponse> = test_utils::post(&app, &request).await;
    assert!(post_ttlv_decrypt.is_err());

    // decrypt
    let request = build_decryption_request(
        user_decryption_key_identifier_2,
        None,
        encrypted_data,
        None,
        Some(authentication_data.clone()),
    );
    let decrypt_response: DecryptResponse = test_utils::post(&app, &request).await?;
    let decrypted_data: DecryptedData = decrypt_response
        .data
        .context("There should be decrypted data")?
        .as_slice()
        .try_into()
        .unwrap();

    assert_eq!(data, &decrypted_data.plaintext);
    assert_eq!(Vec::<u8>::new(), decrypted_data.metadata);

    //
    // Destroy user decryption key
    let request = build_destroy_key_request(user_decryption_key_identifier_1)?;
    let destroy_response: DestroyResponse = test_utils::post(&app, &request).await?;
    assert_eq!(
        user_decryption_key_identifier_1,
        &destroy_response.unique_identifier
    );

    Ok(())
}
