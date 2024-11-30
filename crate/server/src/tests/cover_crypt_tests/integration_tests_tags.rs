use cloudproof::reexport::cover_crypt::abe_policy::{DimensionBuilder, EncryptionHint, Policy};
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
        kmip_operations::{
            CreateKeyPairResponse, CreateResponse, DecryptResponse, DecryptedData, DestroyResponse,
            EncryptResponse, ReKeyKeyPairResponse, Revoke, RevokeResponse,
        },
        kmip_types::{RevocationReason, UniqueIdentifier},
    },
};

use crate::{
    error::KmsError,
    result::{KResult, KResultHelper},
    tests::test_utils,
};

#[tokio::test]
async fn test_re_key_with_tags() -> KResult<()> {
    let app = test_utils::test_app(None).await;

    let policy = policy()?;

    // create Key Pair
    let mkp_tag = "mkp";
    let mkp_json_tag = serde_json::to_string(&[mkp_tag.to_owned()])?;
    let create_key_pair = build_create_master_keypair_request(&policy, [mkp_tag], false)?;
    let create_key_pair_response: CreateKeyPairResponse =
        test_utils::post(&app, &create_key_pair).await?;

    cosmian_logger::log_utils::log_init(None);
    let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;
    let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

    //
    // Re_key all key pairs with matching access policy
    let request = build_rekey_keypair_request(
        &mkp_json_tag,
        &RekeyEditAction::RekeyAccessPolicy("Department::MKG".to_owned()),
    )?;
    let rekey_keypair_response: ReKeyKeyPairResponse = test_utils::post(&app, &request).await?;
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
    let encryption_policy = "Level::Confidential && Department::MKG";
    let request = build_encryption_request(
        &mkp_json_tag,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        None,
        Some(authentication_data.clone()),
        None,
        None,
    )?;
    let encrypt_response: EncryptResponse = test_utils::post(&app, &request).await?;
    let _encrypted_data = encrypt_response
        .data
        .expect("There should be encrypted data");

    Ok(())
}

fn policy() -> Result<Policy, KmsError> {
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
    Ok(policy)
}

#[tokio::test]
async fn integration_tests_with_tags() -> KResult<()> {
    cosmian_logger::log_utils::log_init(None);

    let app = test_utils::test_app(None).await;

    let policy = policy()?;

    // create Key Pair
    let mkp_tag = "mkp";
    let mkp_json_tag = serde_json::to_string(&[mkp_tag.to_owned()])?;
    let create_key_pair = build_create_master_keypair_request(&policy, [mkp_tag], false)?;
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
        &mkp_json_tag,
        Some(encryption_policy.to_owned()),
        data.to_vec(),
        Some(header_metadata.clone()),
        None,
        Some(authentication_data.clone()),
        None,
    )?;

    let encrypt_response: EncryptResponse = test_utils::post(&app, request).await?;
    let encrypted_data = encrypt_response
        .data
        .expect("There should be encrypted data");

    // Create a user decryption key
    let udk_tag = "udk";
    let udk_json_tag = serde_json::to_string(&[udk_tag.to_owned()])?;
    let access_policy = "(Department::MKG || Department::FIN) && Level::Top Secret";
    let request = build_create_user_decryption_private_key_request(
        access_policy,
        &mkp_json_tag,
        [udk_tag],
        false,
    )?;
    let _create_response: CreateResponse = test_utils::post(&app, request).await?;
    // let user_decryption_key_identifier = &create_response.unique_identifier;

    // decrypt
    let request = build_decryption_request(
        &udk_json_tag,
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
        &mkp_json_tag,
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
    let udk1_tag = "udk1";
    let udk1_json_tag = serde_json::to_string(&[udk1_tag.to_owned()])?;
    let access_policy = "(Department::MKG || Department::FIN) && Level::Confidential";
    let request = build_create_user_decryption_private_key_request(
        access_policy,
        &mkp_json_tag,
        [udk1_tag],
        false,
    )?;
    let _create_response: CreateResponse = test_utils::post(&app, &request).await?;

    //
    // Create another user decryption key
    let udk2_tag = "udk2";
    let udk2_json_tag = serde_json::to_string(&[udk2_tag.to_owned()])?;
    let access_policy = "Department::MKG && Level::Confidential";
    let request = build_create_user_decryption_private_key_request(
        access_policy,
        &mkp_json_tag,
        [udk2_tag],
        false,
    )?;
    let _create_response2: CreateResponse = test_utils::post(&app, &request).await?;

    // test user1 can decrypt
    let request = build_decryption_request(
        &udk1_json_tag,
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
        .try_into()
        .unwrap();

    assert_eq!(&data, &decrypted_data.plaintext.to_vec());
    assert!(decrypted_data.metadata.is_empty());

    // test user2 can decrypt
    let request = build_decryption_request(
        &udk2_json_tag,
        None,
        encrypted_data,
        None,
        Some(authentication_data.clone()),
        None,
    );
    let decrypt_response: DecryptResponse = test_utils::post(&app, &request).await?;

    let decrypted_data: DecryptedData = decrypt_response
        .data
        .context("There should be decrypted data")?
        .as_slice()
        .try_into()
        .unwrap();

    assert_eq!(&data, &decrypted_data.plaintext.to_vec());
    assert!(decrypted_data.metadata.is_empty());

    // Revoke key of user 1
    let _revoke_response: RevokeResponse = test_utils::post(
        &app,
        &Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(udk1_json_tag.clone())),
            revocation_reason: RevocationReason::TextString("Revocation test".to_owned()),
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
        &mkp_json_tag,
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

    // Make sure first user decryption key cannot decrypt new encrypted message (message being encrypted with new `MKG` value)
    let request = build_decryption_request(
        &udk1_json_tag,
        None,
        encrypted_data.clone(),
        None,
        Some(authentication_data.clone()),
        None,
    );
    let post_ttlv_decrypt: KResult<DecryptResponse> = test_utils::post(&app, &request).await;
    assert!(post_ttlv_decrypt.is_err());

    // decrypt
    let request = build_decryption_request(
        &udk2_json_tag,
        None,
        encrypted_data,
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
    // Destroy user decryption key
    let request = build_destroy_key_request(&udk1_json_tag)?;
    let destroy_response: DestroyResponse = test_utils::post(&app, &request).await?;
    assert_eq!(
        &udk1_json_tag,
        &destroy_response
            .unique_identifier
            .as_str()
            .context("There should be a unique identifier in the destroy response")?
    );

    Ok(())
}
