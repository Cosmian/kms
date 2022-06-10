use std::sync::Arc;

use abe_gpsw::core::policy::{ap, attr, Policy};
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Get, Import, Locate},
    kmip_types::{
        Attributes, CryptographicAlgorithm, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
    },
};
use cosmian_kms_utils::crypto::abe::{
    attributes::access_policy_as_vendor_attribute,
    kmip_requests::{
        build_create_master_keypair_request, build_create_user_decryption_key_pair_request,
        build_create_user_decryption_private_key_request, build_decryption_request,
        build_hybrid_encryption_request,
    },
};
use tracing::debug;
use uuid::Uuid;

use crate::{
    config::init_config,
    core::crud::KmipServer,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
    KMSServer,
};

#[actix_rt::test]
async fn test_abe_keys() -> KResult<()> {
    let config = crate::config::Config {
        delegated_authority_domain: Some("dev-1mbsbmin.us.auth0.com".to_string()),
        ..Default::default()
    };
    init_config(&config).await?;

    let kms = Arc::new(KMSServer::instantiate().await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    //
    let policy = Policy::new(10)
        .add_axis("Department", &["MKG", "FIN", "HR"], false)?
        .add_axis("Level", &["confidential", "secret"], true)?;

    // create Key Pair
    debug!("ABE Create Master Key Pair");

    let cr = kms
        .create_key_pair(build_create_master_keypair_request(&policy)?, owner)
        .await?;
    debug!("  -> response {:?}", cr);
    let sk_uid = cr.private_key_unique_identifier;
    // check the generated id is an UUID
    let sk_uid_ = Uuid::parse_str(&sk_uid).map_err(|e| KmsError::InvalidRequest(e.to_string()))?;
    assert_eq!(&sk_uid, &sk_uid_.to_string());

    // get Private Key
    debug!("ABE Get Master Secret Key");
    let gr_sk = kms.get(Get::from(sk_uid.as_str()), owner).await?;
    assert_eq!(&sk_uid, &gr_sk.unique_identifier);
    assert_eq!(ObjectType::PrivateKey, gr_sk.object_type);

    // check sk
    let object = &gr_sk.object;
    let recovered_kms_sk_key_block = match object {
        Object::PrivateKey { key_block } => key_block,
        _other => {
            kms_bail!("The objet at uid: {sk_uid} is not an ABE Master secret key");
        }
    };
    debug!(
        "  -> ABE kms_sk: {:?}",
        recovered_kms_sk_key_block.cryptographic_algorithm
    );
    assert_eq!(
        CryptographicAlgorithm::ABE,
        recovered_kms_sk_key_block.cryptographic_algorithm
    );

    // get Public Key
    debug!("ABE Get Master Public Key");
    let pk_uid = cr.public_key_unique_identifier;
    let gr_pk = kms.get(Get::from(pk_uid.as_str()), owner).await?;
    assert_eq!(pk_uid, gr_pk.unique_identifier);
    assert_eq!(ObjectType::PublicKey, gr_pk.object_type);

    // check pk
    let pk = &gr_pk.object;
    let recovered_kms_pk_key_block = match pk {
        Object::PublicKey { key_block } => key_block,
        _other => {
            kms_bail!("The objet at uid: {pk_uid} is not an ABE Master secret key");
        }
    };
    debug!(
        "  -> ABE kms_pk: {:?}",
        recovered_kms_pk_key_block.cryptographic_algorithm
    );
    assert_eq!(
        CryptographicAlgorithm::ABE,
        recovered_kms_pk_key_block.cryptographic_algorithm
    );

    // re-import public key - should fail
    let request = Import {
        unique_identifier: pk_uid.clone(),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes: Attributes::new(ObjectType::PublicKey),
        object: pk.clone(),
    };
    assert!(kms.import(request, owner).await.is_err());

    // re-import public key - should succeed
    let request = Import {
        unique_identifier: pk_uid.clone(),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: Attributes::new(ObjectType::PublicKey),
        object: pk.clone(),
    };
    let _update_response = kms.import(request, owner).await?;

    // User decryption key

    let access_policy =
        (ap("Department", "MKG") | ap("Department", "FIN")) & ap("Level", "confidential");

    // ...via KeyPair
    debug!(" .... user key via Keypair");
    let request = build_create_user_decryption_key_pair_request(&access_policy, &sk_uid, &pk_uid)?;
    let cr = kms.create_key_pair(request, owner).await?;
    debug!("Create Response for User Decryption Key {:?}", cr);

    let usk_uid = cr.private_key_unique_identifier;
    // check the generated id is an UUID
    let usk_uid_ =
        Uuid::parse_str(&usk_uid).map_err(|e| KmsError::InvalidRequest(e.to_string()))?;
    assert_eq!(&usk_uid, &usk_uid_.to_string());

    // get object
    let gr = kms.get(Get::from(usk_uid.as_str()), owner).await?;
    let object = &gr.object;
    assert_eq!(&usk_uid, &gr.unique_identifier);
    let _recovered_kms_uk_key_block = match object {
        Object::PrivateKey { key_block } => key_block,
        _other => {
            kms_bail!("The objet at uid: {usk_uid} is not an ABE user decryption key");
        }
    };
    // debug!("ABE kms_uk: {:?}", recovered_kms_uk_key_block);

    // ...via Private key
    debug!(" .... user key via Private Key");
    let request = build_create_user_decryption_private_key_request(&access_policy, &sk_uid)?;
    let cr = kms.create(request, owner).await?;
    debug!("Create Response for User Decryption Key {:?}", cr);

    let usk_uid = cr.unique_identifier;
    // check the generated id is an UUID
    let usk_uid_ =
        Uuid::parse_str(&usk_uid).map_err(|e| KmsError::InvalidRequest(e.to_string()))?;
    assert_eq!(&usk_uid, &usk_uid_.to_string());

    // get object
    let gr = kms.get(Get::from(usk_uid.as_str()), owner).await?;
    let object = &gr.object;
    assert_eq!(&usk_uid, &gr.unique_identifier);
    let recovered_kms_uk_key_block = match object {
        Object::PrivateKey { key_block } => key_block,
        _other => {
            kms_bail!("The objet at uid: {usk_uid} is not an ABE user decryption key");
        }
    };
    debug!("ABE kms_uk: {:?}", recovered_kms_uk_key_block);

    Ok(())
}

#[test]
pub fn access_policy_serialization() -> KResult<()> {
    let access_policy =
        (ap("Department", "MKG") | ap("Department", "FIN")) & ap("Level", "confidential");
    let _json = serde_json::to_string(&access_policy)?;
    // println!("{}", &json);
    Ok(())
}

#[actix_rt::test]
async fn test_abe_encrypt_decrypt() -> KResult<()> {
    // cosmian_kms_common::log_utils::log_init("debug,cosmian_kms::kmip_server=trace");

    let config = crate::config::Config {
        delegated_authority_domain: Some("dev-1mbsbmin.us.auth0.com".to_string()),
        ..Default::default()
    };
    init_config(&config).await?;

    let kms = Arc::new(KMSServer::instantiate().await?);
    let owner = "eyJhbGciOiJSUzI1Ni";
    let nonexistent_owner = "invalid_owner";
    //
    let policy = Policy::new(10)
        .add_axis("Department", &["MKG", "FIN", "HR"], false)?
        .add_axis("Level", &["confidential", "secret"], true)?;

    // create Key Pair
    let ckr = kms
        .create_key_pair(build_create_master_keypair_request(&policy)?, owner)
        .await?;
    let master_private_key_id = &ckr.private_key_unique_identifier;
    let master_public_key_id = &ckr.public_key_unique_identifier;

    // encrypt a resource MKG + confidential
    let confidential_resource_uid = "the uid confidential".as_bytes().to_vec();
    let confidential_mkg_data = "Confidential MKG Data".as_bytes();
    let confidential_mkg_policy_attributes =
        vec![attr("Level", "confidential"), attr("Department", "MKG")];
    let er = kms
        .encrypt(
            build_hybrid_encryption_request(
                master_public_key_id,
                confidential_mkg_policy_attributes.clone(),
                confidential_resource_uid.clone(),
                confidential_mkg_data.to_vec(),
            )?,
            owner,
        )
        .await?;
    assert_eq!(master_public_key_id, &er.unique_identifier);
    let confidential_mkg_encrypted_data = er.data.context("There should be encrypted data")?;

    // check it doesn't work with invalid tenant
    let er = kms
        .encrypt(
            build_hybrid_encryption_request(
                master_public_key_id,
                confidential_mkg_policy_attributes,
                confidential_resource_uid.clone(),
                confidential_mkg_data.to_vec(),
            )?,
            nonexistent_owner,
        )
        .await;
    assert!(er.is_err());

    // encrypt a resource FIN + Secret
    let secret_resource_uid = "the uid secret".as_bytes().to_vec();
    let secret_fin_data = "Secret FIN data".as_bytes();
    let secret_fin_policy_attributes = vec![attr("Level", "secret"), attr("Department", "FIN")];
    let er = kms
        .encrypt(
            build_hybrid_encryption_request(
                master_public_key_id,
                secret_fin_policy_attributes.clone(),
                secret_resource_uid.clone(),
                secret_fin_data.to_vec(),
            )?,
            owner,
        )
        .await?;
    assert_eq!(master_public_key_id, &er.unique_identifier);
    let secret_fin_encrypted_data = er.data.context("There should be encrypted data")?;

    // check it doesn't work with invalid tenant
    let er = kms
        .encrypt(
            build_hybrid_encryption_request(
                master_public_key_id,
                secret_fin_policy_attributes,
                secret_resource_uid.clone(),
                secret_fin_data.to_vec(),
            )?,
            nonexistent_owner,
        )
        .await;
    assert!(er.is_err());

    // Create a user decryption key MKG | FIN + secret
    let secret_mkg_fin_access_policy =
        (ap("Department", "MKG") | ap("Department", "FIN")) & ap("Level", "secret");
    let cr = kms
        .create(
            build_create_user_decryption_private_key_request(
                &secret_mkg_fin_access_policy,
                master_private_key_id,
            )?,
            owner,
        )
        .await?;
    let secret_mkg_fin_user_key = &cr.unique_identifier;

    // decrypt resource MKG + confidential
    let dr = kms
        .decrypt(
            build_decryption_request(
                secret_mkg_fin_user_key,
                confidential_resource_uid.clone(),
                confidential_mkg_encrypted_data.clone(),
            ),
            owner,
        )
        .await?;
    assert_eq!(
        confidential_mkg_data,
        &dr.data.context("There should be decrypted data")?
    );

    // check it doesn't work with invalid tenant
    let dr = kms
        .decrypt(
            build_decryption_request(
                secret_mkg_fin_user_key,
                confidential_resource_uid,
                confidential_mkg_encrypted_data,
            ),
            nonexistent_owner,
        )
        .await;
    assert!(dr.is_err());

    // decrypt resource FIN + Secret
    let dr = kms
        .decrypt(
            build_decryption_request(
                secret_mkg_fin_user_key,
                secret_resource_uid.clone(),
                secret_fin_encrypted_data.clone(),
            ),
            owner,
        )
        .await?;
    assert_eq!(
        secret_fin_data,
        &dr.data.context("There should be decrypted data")?
    );

    // check it doesn't work with invalid tenant
    let dr = kms
        .decrypt(
            build_decryption_request(
                secret_mkg_fin_user_key,
                secret_resource_uid,
                secret_fin_encrypted_data,
            ),
            nonexistent_owner,
        )
        .await;
    assert!(dr.is_err());

    Ok(())
}

#[actix_rt::test]
async fn test_abe_json_access() -> KResult<()> {
    let config = crate::config::Config {
        delegated_authority_domain: Some("dev-1mbsbmin.us.auth0.com".to_string()),
        ..Default::default()
    };
    init_config(&config).await?;

    let kms = Arc::new(KMSServer::instantiate().await?);
    let owner = "eyJhbGciOiJSUzI1Ni";
    //
    let policy = Policy::new(10)
        .add_axis("Department", &["MKG", "FIN", "HR"], false)?
        .add_axis("Level", &["confidential", "secret"], true)?;

    let secret_mkg_fin_access_policy =
        (ap("Department", "MKG") | ap("Department", "FIN")) & ap("Level", "secret");

    // Create ABE master key pair
    let master_keypair = build_create_master_keypair_request(&policy)?;

    // create Key Pair
    let ckr = kms.create_key_pair(master_keypair, owner).await?;
    let master_private_key_uid = &ckr.private_key_unique_identifier;

    // define search criterias
    let search_attrs = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::ABE),
        cryptographic_length: Some(5344),
        key_format_type: Some(KeyFormatType::AbeUserDecryptionKey),
        vendor_attributes: Some(vec![access_policy_as_vendor_attribute(
            &secret_mkg_fin_access_policy,
        )?]),
        link: vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                master_private_key_uid.to_owned(),
            ),
        }],
        ..Attributes::new(ObjectType::PrivateKey)
    };

    // locate request
    let locate = Locate {
        attributes: search_attrs.clone(),
        ..Locate::new(ObjectType::PrivateKey)
    };

    // println!("Rq attrs: {:#?}", locate.attributes);

    let locate_response = kms.locate(locate, owner).await?;
    // println!("1 - {locate_response:#?}");

    // we only have 1 master keypair, but 0 decryption keys as
    // requested in `locate` request
    assert_eq!(locate_response.located_items.unwrap(), 0);

    // Create a decryption key
    let cr = kms
        .create(
            build_create_user_decryption_private_key_request(
                &secret_mkg_fin_access_policy,
                master_private_key_uid,
            )?,
            owner,
        )
        .await?;
    let secret_mkg_fin_user_key_id = &cr.unique_identifier;

    // Redo search
    let locate = Locate {
        attributes: search_attrs.clone(),
        ..Locate::new(ObjectType::PrivateKey)
    };

    let locate_response = kms.locate(locate, owner).await?;
    // println!("2 - {locate_response:#?}");

    // now we have 1 key
    assert_eq!(locate_response.located_items.unwrap(), 1);
    assert_eq!(
        &locate_response.unique_identifiers.unwrap()[0],
        secret_mkg_fin_user_key_id
    );

    Ok(())
}
