use std::sync::Arc;

use cloudproof::reexport::cover_crypt::abe_policy::{DimensionBuilder, EncryptionHint, Policy};
use cosmian_kmip::{
    crypto::{
        cover_crypt::kmip_requests::{
            build_create_master_keypair_request, build_create_user_decryption_private_key_request,
        },
        generic::kmip_requests::{build_decryption_request, build_encryption_request},
    },
    kmip::{
        extra::tagging::EMPTY_TAGS,
        kmip_objects::{Object, ObjectType},
        kmip_operations::{DecryptedData, Get, Import, Locate},
        kmip_types::{
            Attributes, CryptographicAlgorithm, KeyFormatType, Link, LinkType,
            LinkedObjectIdentifier, UniqueIdentifier,
        },
    },
};
use tracing::debug;
use uuid::Uuid;

use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
    tests::test_utils::https_clap_config,
};

#[tokio::test]
async fn test_cover_crypt_keys() -> KResult<()> {
    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(ServerParams::try_from(clap_config)?).await?);
    let owner = "cceyJhbGciOiJSUzI1Ni";

    //
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
            ("confidential", EncryptionHint::Classic),
            ("secret", EncryptionHint::Hybridized),
        ],
        true,
    ))?;

    // create Key Pair
    debug!("ABE Create Master Key Pair");

    let cr = kms
        .create_key_pair(
            build_create_master_keypair_request(&policy, EMPTY_TAGS, false)?,
            owner,
            None,
        )
        .await?;
    debug!("  -> response {:?}", cr);
    let sk_uid = cr.private_key_unique_identifier.to_string();
    // check the generated id is an UUID
    let sk_uid_ = Uuid::parse_str(&sk_uid).map_err(|e| KmsError::InvalidRequest(e.to_string()))?;
    assert_eq!(&sk_uid, &sk_uid_.to_string());

    // get Private Key
    debug!("ABE Get Master Secret Key");
    let gr_sk = kms.get(Get::from(sk_uid.as_str()), owner, None).await?;
    assert_eq!(
        &sk_uid,
        &gr_sk
            .unique_identifier
            .as_str()
            .context("No uid in response as string")?
    );
    assert_eq!(ObjectType::PrivateKey, gr_sk.object_type);

    // check sk
    let object = &gr_sk.object;
    let recovered_kms_sk_key_block = match object {
        Object::PrivateKey { key_block } => key_block,
        _other => {
            kms_bail!("The object at uid: {sk_uid} is not a CC Master secret key");
        }
    };
    debug!(
        "  -> ABE kms_sk: {:?}",
        recovered_kms_sk_key_block.cryptographic_algorithm
    );
    assert_eq!(
        Some(CryptographicAlgorithm::CoverCrypt),
        recovered_kms_sk_key_block.cryptographic_algorithm
    );

    // get Public Key
    debug!("ABE Get Master Public Key");
    let pk_uid = cr.public_key_unique_identifier.to_string();
    let gr_pk = kms.get(Get::from(pk_uid.as_str()), owner, None).await?;
    assert_eq!(pk_uid, gr_pk.unique_identifier.to_string());
    assert_eq!(ObjectType::PublicKey, gr_pk.object_type);

    // check pk
    let pk = &gr_pk.object;
    let recovered_kms_pk_key_block = match pk {
        Object::PublicKey { key_block } => key_block,
        _other => {
            kms_bail!("The object at uid: {pk_uid} is not a CC Master secret key");
        }
    };
    debug!(
        "  -> CC kms_pk: {:?}",
        recovered_kms_pk_key_block.cryptographic_algorithm
    );
    assert_eq!(
        Some(CryptographicAlgorithm::CoverCrypt),
        recovered_kms_pk_key_block.cryptographic_algorithm
    );

    // re-import public key - should fail
    let request = Import {
        unique_identifier: UniqueIdentifier::TextString(pk_uid.clone()),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes: Attributes {
            object_type: Some(ObjectType::PublicKey),
            ..Attributes::default()
        },
        object: pk.clone(),
    };
    kms.import(request, owner, None).await.unwrap_err();

    // re-import public key - should succeed
    let request = Import {
        unique_identifier: UniqueIdentifier::TextString(pk_uid.clone()),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: Attributes {
            object_type: Some(ObjectType::PublicKey),
            ..Attributes::default()
        },
        object: pk.clone(),
    };
    let _update_response = kms.import(request, owner, None).await?;

    // User decryption key
    let access_policy = "(Department::MKG ||Department::FIN) && Level::confidential";

    // ...via KeyPair
    debug!(" .... user key via Keypair");
    let request = build_create_user_decryption_private_key_request(
        access_policy,
        &sk_uid,
        EMPTY_TAGS,
        false,
    )?;
    let cr = kms.create(request, owner, None).await?;
    debug!("Create Response for User Decryption Key {:?}", cr);

    let usk_uid = cr.unique_identifier.to_string();
    // check the generated id is an UUID
    let usk_uid_ =
        Uuid::parse_str(&usk_uid).map_err(|e| KmsError::InvalidRequest(e.to_string()))?;
    assert_eq!(&usk_uid, &usk_uid_.to_string());

    // get object
    let gr = kms.get(Get::from(usk_uid.as_str()), owner, None).await?;
    let object = &gr.object;
    assert_eq!(
        &usk_uid,
        &gr.unique_identifier
            .as_str()
            .context("No uid in response")?
    );
    let _recovered_kms_uk_key_block = match object {
        Object::PrivateKey { key_block } => key_block,
        _other => {
            kms_bail!("The object at uid: {usk_uid} is not a CC user decryption key");
        }
    };
    // debug!("CC kms_uk: {:?}", _recovered_kms_uk_key_block);

    // ...via Private key
    debug!(" .... user key via Private Key");
    let request = build_create_user_decryption_private_key_request(
        access_policy,
        &sk_uid,
        EMPTY_TAGS,
        false,
    )?;
    let cr = kms.create(request, owner, None).await?;
    debug!("Create Response for User Decryption Key {:?}", cr);

    let usk_uid = cr.unique_identifier.to_string();
    // check the generated id is an UUID
    let usk_uid_ =
        Uuid::parse_str(&usk_uid).map_err(|e| KmsError::InvalidRequest(e.to_string()))?;
    assert_eq!(&usk_uid, &usk_uid_.to_string());

    // get object
    let gr = kms.get(Get::from(usk_uid.as_str()), owner, None).await?;
    let object = &gr.object;
    assert_eq!(
        &usk_uid,
        gr.unique_identifier
            .as_str()
            .context("No uid in response")?
    );
    let recovered_kms_uk_key_block = match object {
        Object::PrivateKey { key_block } => key_block,
        _other => {
            kms_bail!("The object at uid: {usk_uid} is not a CC user decryption key");
        }
    };
    debug!("ABE kms_uk: {}", recovered_kms_uk_key_block);

    Ok(())
}

#[test]
pub(crate) fn access_policy_serialization() -> KResult<()> {
    let access_policy = "(Department::MKG ||Department::FIN) && Level::confidential";
    let _json = serde_json::to_string(&access_policy)?;
    Ok(())
}

#[tokio::test]
async fn test_abe_encrypt_decrypt() -> KResult<()> {
    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(ServerParams::try_from(clap_config)?).await?);
    let owner = "cceyJhbGciOiJSUzI1Ni";
    let nonexistent_owner = "invalid_owner";
    //
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
            ("confidential", EncryptionHint::Classic),
            ("secret", EncryptionHint::Hybridized),
        ],
        true,
    ))?;

    // create Key Pair
    let ckr = kms
        .create_key_pair(
            build_create_master_keypair_request(&policy, EMPTY_TAGS, false)?,
            owner,
            None,
        )
        .await?;
    let master_private_key_id = ckr
        .private_key_unique_identifier
        .as_str()
        .context("There should be a private key unique identifier in the response")?;
    let master_public_key_id = ckr
        .public_key_unique_identifier
        .as_str()
        .context("There should be a public key unique identifier in the response")?;

    // encrypt a resource MKG + confidential
    let confidential_authentication_data = b"cc the uid confidential".to_vec();
    let confidential_mkg_data = b"Confidential MKG Data";
    let confidential_mkg_policy_attributes = "Level::confidential && Department::MKG";
    let er = kms
        .encrypt(
            build_encryption_request(
                master_public_key_id,
                Some(confidential_mkg_policy_attributes.to_owned()),
                confidential_mkg_data.to_vec(),
                None,
                None,
                Some(confidential_authentication_data.clone()),
                None,
            )?,
            owner,
            None,
        )
        .await?;
    assert_eq!(
        master_public_key_id,
        er.unique_identifier
            .as_str()
            .context("There should be a unique identifier in the response")?
    );
    let confidential_mkg_encrypted_data = er.data.context("There should be encrypted data")?;

    // check it doesn't work with invalid tenant
    let er = kms
        .encrypt(
            build_encryption_request(
                master_public_key_id,
                Some(confidential_mkg_policy_attributes.to_owned()),
                confidential_mkg_data.to_vec(),
                None,
                None,
                Some(confidential_authentication_data.clone()),
                None,
            )?,
            nonexistent_owner,
            None,
        )
        .await;
    assert!(er.is_err());

    // encrypt a resource FIN + Secret
    let secret_authentication_data = b"cc the uid secret".to_vec();
    let secret_fin_data = b"Secret FIN data";
    let secret_fin_policy_attributes = "Level::secret && Department::FIN";
    let er = kms
        .encrypt(
            build_encryption_request(
                master_public_key_id,
                Some(secret_fin_policy_attributes.to_owned()),
                secret_fin_data.to_vec(),
                None,
                None,
                Some(secret_authentication_data.clone()),
                None,
            )?,
            owner,
            None,
        )
        .await?;
    assert_eq!(
        master_public_key_id,
        er.unique_identifier
            .as_str()
            .context("There should be a unique identifier in the response")?
    );
    let secret_fin_encrypted_data = er.data.context("There should be encrypted data")?;

    // check it doesn't work with invalid tenant
    let er = kms
        .encrypt(
            build_encryption_request(
                master_public_key_id,
                Some(secret_fin_policy_attributes.to_owned()),
                secret_fin_data.to_vec(),
                None,
                None,
                Some(secret_authentication_data.clone()),
                None,
            )?,
            nonexistent_owner,
            None,
        )
        .await;
    assert!(er.is_err());

    // Create a user decryption key MKG | FIN + secret
    let secret_mkg_fin_access_policy = "(Department::MKG || Department::FIN) && Level::secret";
    let cr = kms
        .create(
            build_create_user_decryption_private_key_request(
                secret_mkg_fin_access_policy,
                master_private_key_id,
                EMPTY_TAGS,
                false,
            )?,
            owner,
            None,
        )
        .await?;
    let secret_mkg_fin_user_key = &cr
        .unique_identifier
        .as_str()
        .context("There should be a unique identifier in the response")?;

    // decrypt resource MKG + confidential
    let dr = kms
        .decrypt(
            build_decryption_request(
                secret_mkg_fin_user_key,
                None,
                confidential_mkg_encrypted_data.clone(),
                None,
                Some(confidential_authentication_data.clone()),
                None,
            ),
            owner,
            None,
        )
        .await?;

    let decrypted_data: DecryptedData = dr
        .data
        .context("There should be decrypted data")?
        .as_slice()
        .try_into()
        .unwrap();

    assert_eq!(confidential_mkg_data, &decrypted_data.plaintext[..]);
    assert!(decrypted_data.metadata.is_empty());

    // check it doesn't work with invalid tenant
    let dr = kms
        .decrypt(
            build_decryption_request(
                secret_mkg_fin_user_key,
                None,
                confidential_mkg_encrypted_data,
                None,
                Some(confidential_authentication_data),
                None,
            ),
            nonexistent_owner,
            None,
        )
        .await;
    assert!(dr.is_err());

    // decrypt resource FIN + Secret
    let dr = kms
        .decrypt(
            build_decryption_request(
                secret_mkg_fin_user_key,
                None,
                secret_fin_encrypted_data.clone(),
                None,
                Some(secret_authentication_data.clone()),
                None,
            ),
            owner,
            None,
        )
        .await?;

    let decrypted_data: DecryptedData = dr
        .data
        .context("There should be decrypted data")?
        .as_slice()
        .try_into()
        .unwrap();

    assert_eq!(secret_fin_data, &decrypted_data.plaintext[..]);
    assert!(decrypted_data.metadata.is_empty());

    // check it doesn't work with invalid tenant
    let dr = kms
        .decrypt(
            build_decryption_request(
                secret_mkg_fin_user_key,
                None,
                secret_fin_encrypted_data,
                None,
                Some(secret_authentication_data),
                None,
            ),
            nonexistent_owner,
            None,
        )
        .await;
    assert!(dr.is_err());

    Ok(())
}

#[tokio::test]
async fn test_abe_json_access() -> KResult<()> {
    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(ServerParams::try_from(clap_config)?).await?);
    let owner = "cceyJhbGciOiJSUzI1Ni";
    //
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
            ("confidential", EncryptionHint::Classic),
            ("secret", EncryptionHint::Hybridized),
        ],
        true,
    ))?;

    let secret_mkg_fin_access_policy = "(Department::MKG||Department::FIN) && Level::secret";

    // Create CC master key pair
    let master_keypair = build_create_master_keypair_request(&policy, EMPTY_TAGS, false)?;

    // create Key Pair
    let ckr = kms.create_key_pair(master_keypair, owner, None).await?;
    let master_private_key_uid = ckr.private_key_unique_identifier.to_string();

    // define search criteria
    let search_attrs = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        cryptographic_length: None,
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        link: Some(vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                master_private_key_uid.clone(),
            ),
        }]),
        object_type: Some(ObjectType::PrivateKey),
        ..Attributes::default()
    };

    // locate request
    let locate = Locate {
        attributes: search_attrs.clone(),
        ..Locate::default()
    };

    let locate_response = kms.locate(locate, owner, None).await?;

    // we only have 1 master keypair, but 0 decryption keys as
    // requested in `locate` request
    assert_eq!(locate_response.located_items.unwrap(), 0);

    // Create a decryption key
    let cr = kms
        .create(
            build_create_user_decryption_private_key_request(
                secret_mkg_fin_access_policy,
                &master_private_key_uid,
                EMPTY_TAGS,
                false,
            )?,
            owner,
            None,
        )
        .await?;
    let secret_mkg_fin_user_key_id = &cr.unique_identifier;

    // Redo search
    let locate = Locate {
        attributes: search_attrs.clone(),
        ..Locate::default()
    };

    let locate_response = kms.locate(locate, owner, None).await?;

    // now we have 1 key
    assert_eq!(locate_response.located_items.unwrap(), 1);
    assert_eq!(
        &locate_response.unique_identifiers.unwrap()[0],
        secret_mkg_fin_user_key_id
    );

    Ok(())
}

#[tokio::test]
async fn test_import_decrypt() -> KResult<()> {
    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(ServerParams::try_from(clap_config)?).await?);
    let owner = "cceyJhbGciOiJSUzI1Ni";

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
            ("confidential", EncryptionHint::Classic),
            ("secret", EncryptionHint::Hybridized),
        ],
        true,
    ))?;

    // create Key Pair
    let cr = kms
        .create_key_pair(
            build_create_master_keypair_request(&policy, EMPTY_TAGS, false)?,
            owner,
            None,
        )
        .await?;
    debug!("  -> response {:?}", cr);
    let sk_uid = cr.private_key_unique_identifier.to_string();
    let pk_uid = cr.public_key_unique_identifier.to_string();

    // check the generated id is an UUID
    let sk_uid_ = Uuid::parse_str(&sk_uid).map_err(|e| KmsError::InvalidRequest(e.to_string()))?;
    assert_eq!(&sk_uid, &sk_uid_.to_string());

    // encrypt a resource MKG + confidential
    let confidential_authentication_data = b"cc the uid confidential".to_vec();
    let confidential_mkg_data = b"Confidential MKG Data";
    let confidential_mkg_policy_attributes = "Level::confidential && Department::MKG";
    let er = kms
        .encrypt(
            build_encryption_request(
                &pk_uid,
                Some(confidential_mkg_policy_attributes.to_owned()),
                confidential_mkg_data.to_vec(),
                None,
                None,
                Some(confidential_authentication_data.clone()),
                None,
            )?,
            owner,
            None,
        )
        .await?;
    assert_eq!(
        &pk_uid,
        er.unique_identifier
            .as_str()
            .context("There should be a unique identifier in the response")?
    );
    let confidential_mkg_encrypted_data = er.data.context("There should be encrypted data")?;

    // Create a user decryption key MKG | FIN + secret
    let secret_mkg_fin_access_policy = "(Department::MKG|| Department::FIN) && Level::secret";
    let cr = kms
        .create(
            build_create_user_decryption_private_key_request(
                secret_mkg_fin_access_policy,
                &sk_uid,
                EMPTY_TAGS,
                false,
            )?,
            owner,
            None,
        )
        .await?;
    let secret_mkg_fin_user_key = cr.unique_identifier.to_string();

    // Retrieve the user key...
    let gr_sk = kms
        .get(Get::from(secret_mkg_fin_user_key.as_str()), owner, None)
        .await?;
    assert_eq!(
        secret_mkg_fin_user_key,
        gr_sk
            .unique_identifier
            .as_str()
            .context("There should be a unique identifier in the response")?
    );
    assert_eq!(ObjectType::PrivateKey, gr_sk.object_type);

    // ...and reimport it under custom uid (won't work)
    let custom_sk_uid = Uuid::new_v4().to_string();
    let request = Import {
        unique_identifier: UniqueIdentifier::TextString(custom_sk_uid.clone()),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        // Bad attributes. Import will succeed, but
        // researched attributes won't matched stored attributes
        attributes: Attributes {
            object_type: Some(ObjectType::PrivateKey),
            ..Attributes::default()
        },
        object: gr_sk.object.clone(),
    };
    kms.import(request, owner, None)
        .await
        .context(&custom_sk_uid)?;
    // decrypt resource MKG + confidential
    let dr = kms
        .decrypt(
            build_decryption_request(
                &custom_sk_uid,
                None,
                confidential_mkg_encrypted_data.clone(),
                None,
                Some(confidential_authentication_data.clone()),
                None,
            ),
            owner,
            None,
        )
        .await?;
    // Decryption used to fails: import attributes were incorrect;
    // this seems fixed since #71. Leaving the test in case this pops-up again
    let decrypted_data: DecryptedData = dr
        .data
        .context("There should be decrypted data")?
        .as_slice()
        .try_into()
        .unwrap();
    assert_eq!(confidential_mkg_data, &decrypted_data.plaintext[..]);
    assert!(decrypted_data.metadata.is_empty());

    // ...and reimport it under custom uid (will work)
    let custom_sk_uid = Uuid::new_v4().to_string();
    let request = Import {
        unique_identifier: UniqueIdentifier::TextString(custom_sk_uid.clone()),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        // Okay! attributes are correctly set in the import request
        // These attributes are matching the object's one
        attributes: gr_sk.object.attributes()?.clone(),
        object: gr_sk.object.clone(),
    };
    kms.import(request, owner, None)
        .await
        .context(&custom_sk_uid)?;
    // decrypt resource MKG + confidential
    let dr = kms
        .decrypt(
            build_decryption_request(
                // secret_mkg_fin_user_key,
                &custom_sk_uid,
                None,
                confidential_mkg_encrypted_data.clone(),
                None,
                Some(confidential_authentication_data.clone()),
                None,
            ),
            owner,
            None,
        )
        .await?;

    let decrypted_data: DecryptedData = dr
        .data
        .context("There should be decrypted data")?
        .as_slice()
        .try_into()
        .unwrap();

    assert_eq!(confidential_mkg_data, &decrypted_data.plaintext[..]);
    assert!(decrypted_data.metadata.is_empty());

    Ok(())
}
