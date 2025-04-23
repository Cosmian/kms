use cosmian_kmip::{
    kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        kmip_operations::{
            CreateKeyPairResponse, CreateResponse, DecryptResponse, Destroy, DestroyResponse,
            EncryptResponse, ReKeyKeyPairResponse, Revoke, RevokeResponse,
        },
        kmip_types::UniqueIdentifier,
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
async fn test_re_key_with_tags() -> KResult<()> {
    let app = test_utils::test_app(None, None).await;
    // create Key Pair
    let mkp_tag = "mkp";
    let mkp_json_tag = serde_json::to_string(&[mkp_tag.to_owned()])?;
    let access_structure = r#"{"Security Level::<":["Protected","Confidential","Top Secret::+"],"Department":["RnD","HR","MKG","FIN"]}"#;

    let create_key_pair =
        build_create_covercrypt_master_keypair_request(access_structure, [mkp_tag], false)?;
    let create_key_pair_response: CreateKeyPairResponse =
        test_utils::post_2_1(&app, &create_key_pair).await?;

    cosmian_logger::log_init(None);
    let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;
    let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

    //
    // Re_key all key pairs with matching access policy
    let request = build_rekey_keypair_request(
        &mkp_json_tag,
        &RekeyEditAction::RekeyAccessPolicy("Department::MKG".to_owned()),
    )?;
    let rekey_keypair_response: ReKeyKeyPairResponse = test_utils::post_2_1(&app, &request).await?;
    assert_eq!(
        &rekey_keypair_response.private_key_unique_identifier,
        private_key_unique_identifier
    );
    assert_eq!(
        &rekey_keypair_response.public_key_unique_identifier,
        public_key_unique_identifier
    );

    // Encrypt with the re-keyed public key
    let authentication_data = b"cc the uid".to_vec();
    let data = "Voilà voilà".as_bytes();
    let encryption_policy = "Security Level::Confidential && Department::MKG";
    let request = encrypt_request(
        &mkp_json_tag,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        Some(authentication_data.clone()),
        None,
        None,
    )?;
    let encrypt_response: EncryptResponse = test_utils::post_2_1(&app, &request).await?;
    let _encrypted_data = encrypt_response
        .data
        .expect("There should be encrypted data");

    Ok(())
}

#[tokio::test]
async fn integration_tests_with_tags() -> KResult<()> {
    cosmian_logger::log_init(None);

    let app = test_utils::test_app(None, None).await;
    // create Key Pair
    let mkp_tag = "mkp";
    let mkp_json_tag = serde_json::to_string(&[mkp_tag.to_owned()])?;
    let access_structure = r#"{"Security Level::<":["Protected","Confidential","Top Secret::+"],"Department":["RnD","HR","MKG","FIN"]}"#;

    let create_key_pair =
        build_create_covercrypt_master_keypair_request(access_structure, [mkp_tag], false)?;
    let create_key_pair_response: CreateKeyPairResponse =
        test_utils::post_2_1(&app, &create_key_pair).await?;

    let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;
    let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

    // Encrypt
    let authentication_data = b"cc the uid".to_vec();
    let data = b"Confidential MKG Data";
    let encryption_policy = "Security Level::Confidential && Department::MKG";

    let request = encrypt_request(
        &mkp_json_tag,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        Some(authentication_data.clone()),
        None,
    )?;

    let encrypt_response: EncryptResponse = test_utils::post_2_1(&app, request).await?;
    let encrypted_data = encrypt_response
        .data
        .expect("There should be encrypted data");

    // Create a user decryption key
    let udk_tag = "udk";
    let udk_json_tag = serde_json::to_string(&[udk_tag.to_owned()])?;
    let access_policy = "(Department::MKG || Department::FIN) && Security Level::Top Secret";
    let request = build_create_covercrypt_usk_request(
        access_policy,
        &private_key_unique_identifier.to_string(),
        [udk_tag],
        false,
    )?;
    let _create_response: CreateResponse = test_utils::post_2_1(&app, request).await?;
    // let user_decryption_key_identifier = &create_response.unique_identifier;

    // decrypt
    let request = decrypt_request(
        &udk_json_tag,
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
        &mkp_json_tag,
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
    let udk1_tag = "udk1";
    let udk1_json_tag = serde_json::to_string(&[udk1_tag.to_owned()])?;
    let access_policy = "(Department::MKG || Department::FIN) && Security Level::Confidential";
    let request = build_create_covercrypt_usk_request(
        access_policy,
        &private_key_unique_identifier.to_string(),
        [udk1_tag],
        false,
    )?;
    let _create_response: CreateResponse = test_utils::post_2_1(&app, &request).await?;

    //
    // Create another user decryption key
    let udk2_tag = "udk2";
    let udk2_json_tag = serde_json::to_string(&[udk2_tag.to_owned()])?;
    let access_policy = "Department::MKG && Security Level::Confidential";
    let request = build_create_covercrypt_usk_request(
        access_policy,
        &private_key_unique_identifier.to_string(),
        [udk2_tag],
        false,
    )?;
    let _create_response2: CreateResponse = test_utils::post_2_1(&app, &request).await?;

    // test user1 can decrypt
    let request = decrypt_request(
        &udk1_json_tag,
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

    // test user2 can decrypt
    let request = decrypt_request(
        &udk2_json_tag,
        None,
        encrypted_data,
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
            unique_identifier: Some(UniqueIdentifier::TextString(udk1_json_tag.clone())),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::AffiliationChanged,
                revocation_message: Some("Revocation test".to_owned()),
            },
            compromise_occurrence_date: None,
        },
    )
    .await?;

    //
    // Rekey all key pairs with matching access policy
    let request = build_rekey_keypair_request(
        &mkp_json_tag,
        &RekeyEditAction::RekeyAccessPolicy("Department::MKG".to_owned()),
    )?;
    let rekey_keypair_response: ReKeyKeyPairResponse = test_utils::post_2_1(&app, &request).await?;
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
    let encryption_policy = "Security Level::Confidential && Department::MKG";
    let request = encrypt_request(
        &mkp_json_tag,
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

    // Make sure first user decryption key cannot decrypt new encrypted message (message being encrypted with new `MKG` value)
    let request = decrypt_request(
        &udk1_json_tag,
        None,
        encrypted_data.clone(),
        None,
        Some(authentication_data.clone()),
        None,
    );
    let post_ttlv_decrypt: KResult<DecryptResponse> = test_utils::post_2_1(&app, &request).await;
    post_ttlv_decrypt.unwrap_err();

    // decrypt
    let request = decrypt_request(
        &udk2_json_tag,
        None,
        encrypted_data,
        None,
        Some(authentication_data.clone()),
        None,
    );
    let decrypt_response: DecryptResponse = test_utils::post_2_1(&app, &request).await?;
    let decrypted_data = decrypt_response
        .data
        .context("There should be decrypted data")?;
    assert_eq!(data, &*decrypted_data);

    //
    // Destroy user decryption key
    let request = Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(udk1_json_tag.clone())),
        remove: false,
    };
    let destroy_response: DestroyResponse = test_utils::post_2_1(&app, &request).await?;
    assert_eq!(
        &udk1_json_tag,
        &destroy_response
            .unique_identifier
            .as_str()
            .context("There should be a unique identifier in the destroy response")?
    );

    Ok(())
}
