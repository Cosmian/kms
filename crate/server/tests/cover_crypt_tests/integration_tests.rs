use abe_policy::{ap, Attribute, Policy, PolicyAxis};
use cosmian_kmip::kmip::{
    kmip_operations::{
        CreateKeyPairResponse, CreateResponse, DecryptResponse, DestroyResponse, EncryptResponse,
        ReKeyKeyPairResponse, Revoke, RevokeResponse,
    },
    kmip_types::RevocationReason,
};
use cosmian_kms_server::{
    config::{auth::AuthConfig, init_config, Config},
    log_utils,
    result::{KResult, KResultHelper},
};
use cosmian_kms_utils::crypto::cover_crypt::kmip_requests::{
    build_create_master_keypair_request, build_create_user_decryption_private_key_request,
    build_decryption_request, build_destroy_key_request, build_hybrid_encryption_request,
    build_rekey_keypair_request,
};

use crate::test_utils;

#[actix_web::test]
async fn integration_tests() -> KResult<()> {
    log_utils::log_init("cosmian_kms_server=trace");

    let config = Config {
        auth: AuthConfig {
            delegated_authority_domain: "dev-1mbsbmin.us.auth0.com".to_string(),
        },
        ..Default::default()
    };
    init_config(&config).await?;

    let app = test_utils::test_app().await;

    let mut policy = Policy::new(10);
    policy.add_axis(&PolicyAxis::new("Department", &["MKG", "FIN", "HR"], false))?;
    policy.add_axis(&PolicyAxis::new(
        "Level",
        &["Confidential", "Top Secret"],
        true,
    ))?;

    // create Key Pair
    let create_key_pair = build_create_master_keypair_request(&policy)?;
    let create_key_pair_response: CreateKeyPairResponse =
        test_utils::post(&app, &create_key_pair).await?;

    let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;
    let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

    // Encrypt
    let resource_uid = "cc the uid".as_bytes().to_vec();
    let data = "Confidential MKG Data".as_bytes();
    let policy_attributes = vec![
        Attribute::new("Level", "Confidential"),
        Attribute::new("Department", "MKG"),
    ];
    let request = build_hybrid_encryption_request(
        public_key_unique_identifier,
        policy_attributes.clone(),
        resource_uid.clone(),
        data.to_vec(),
    )?;

    let encrypt_response: EncryptResponse = test_utils::post(&app, request).await?;
    let encrypted_data = encrypt_response
        .data
        .expect("There should be encrypted data");

    // Create a user decryption key
    let access_policy =
        (ap("Department", "MKG") | ap("Department", "FIN")) & ap("Level", "Top Secret");
    let request = build_create_user_decryption_private_key_request(
        &access_policy,
        private_key_unique_identifier,
    )?;
    let create_response: CreateResponse = test_utils::post(&app, request).await?;
    let user_decryption_key_identifier = &create_response.unique_identifier;

    // decrypt
    let request = build_decryption_request(
        user_decryption_key_identifier,
        resource_uid.clone(),
        encrypted_data.clone(),
    );
    let decrypt_response: DecryptResponse = test_utils::post(&app, request).await?;
    assert_eq!(
        data,
        &decrypt_response
            .data
            .context("There should be decrypted data")?
    );

    // revocation

    // Encrypt
    let resource_uid = "cc the uid".as_bytes().to_vec();
    let data = "Voilà voilà".as_bytes();
    let policy_attributes = vec![
        Attribute::new("Level", "Confidential"),
        Attribute::new("Department", "MKG"),
    ];
    let request = build_hybrid_encryption_request(
        public_key_unique_identifier,
        policy_attributes.clone(),
        resource_uid.clone(),
        data.to_vec(),
    )?;
    let encrypt_response: EncryptResponse = test_utils::post(&app, &request).await?;
    let encrypted_data = encrypt_response
        .data
        .expect("There should be encrypted data");

    //
    // Create a user decryption key
    let access_policy =
        (ap("Department", "MKG") | ap("Department", "FIN")) & ap("Level", "Confidential");
    let request = build_create_user_decryption_private_key_request(
        &access_policy,
        private_key_unique_identifier,
    )?;
    let create_response: CreateResponse = test_utils::post(&app, &request).await?;
    let user_decryption_key_identifier_1 = &create_response.unique_identifier;

    //
    // Create another user decryption key
    let access_policy = (ap("Department", "MKG")) & ap("Level", "Confidential");
    let request = build_create_user_decryption_private_key_request(
        &access_policy,
        private_key_unique_identifier,
    )?;
    let create_response2: CreateResponse = test_utils::post(&app, &request).await?;
    let user_decryption_key_identifier_2 = &create_response2.unique_identifier;

    // test user1 can decrypt
    let request = build_decryption_request(
        user_decryption_key_identifier_1,
        resource_uid.clone(),
        encrypted_data.clone(),
    );
    let decrypt_response: DecryptResponse = test_utils::post(&app, &request).await?;
    assert_eq!(
        data,
        &decrypt_response
            .data
            .context("There should be decrypted data")?
    );

    // test user2 can decrypt
    let request = build_decryption_request(
        user_decryption_key_identifier_2,
        resource_uid.clone(),
        encrypted_data.clone(),
    );
    let decrypt_response: DecryptResponse = test_utils::post(&app, &request).await?;
    assert_eq!(
        data,
        &decrypt_response
            .data
            .context("There should be decrypted data")?
    );

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
    let resource_uid = "cc the uid".as_bytes().to_vec();
    let data = "Voilà voilà".as_bytes();
    let policy_attributes = vec![
        Attribute::new("Level", "Confidential"),
        Attribute::new("Department", "MKG"),
    ];
    let request = build_hybrid_encryption_request(
        public_key_unique_identifier,
        policy_attributes,
        resource_uid.clone(),
        data.to_vec(),
    )?;
    let encrypt_response: EncryptResponse = test_utils::post(&app, &request).await?;
    let encrypted_data = encrypt_response
        .data
        .expect("There should be encrypted data");

    // Make sure first user decryption key cannot decrypt new encrypted message (message being encrypted with new `MKG` value)
    let request = build_decryption_request(
        user_decryption_key_identifier_1,
        resource_uid.clone(),
        encrypted_data.clone(),
    );
    let post_ttlv_decrypt: KResult<DecryptResponse> = test_utils::post(&app, &request).await;
    assert!(post_ttlv_decrypt.is_err());

    // TODO: fix rekey not touching expected keys ! Following tests must be activated

    // decrypt
    // let request = build_decryption_request(
    //     user_decryption_key_identifier_2,
    //     resource_uid.clone(),
    //     encrypted_data,
    // );
    // let decrypt_response: DecryptResponse = test_utils::post(&app, &request).await?;
    // assert_eq!(
    //     data,
    //     &decrypt_response
    //         .data
    //         .context("There should be decrypted data")?
    // );

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
