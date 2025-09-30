use cosmian_kms_client::{
    kmip_2_1::kmip_types::{CryptographicAlgorithm, KeyFormatType},
    reexport::cosmian_kms_client_utils::create_utils::Curve,
};
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server_with_cert_auth;

#[cfg(feature = "non-fips")]
use crate::actions::kms::cover_crypt::keys::{
    create_key_pair::CreateMasterKeyPairAction, create_user_key::CreateUserKeyAction,
};
use crate::{
    actions::kms::{
        elliptic_curves::keys::create_key_pair::CreateKeyPairAction as CreateEcKeyPairAction,
        shared::LocateObjectsAction, symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_locate_cover_crypt() -> KmsCliResult<()> {
    use std::path::PathBuf;

    use cosmian_kms_client::kmip_2_1::kmip_types::{CryptographicAlgorithm, KeyFormatType};

    use crate::actions::kms::shared::LocateObjectsAction;

    log_init(option_env!("RUST_LOG"));

    // init the test server
    let ctx = start_default_test_kms_server_with_cert_auth().await;

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec!["test_cc".to_string()],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0, key_ids.1)
    };

    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_cc".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));

    // Locate with cryptographic algorithm
    // this should be case insensitive
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_cc".to_string()]),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));

    // locate using the key format type
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_cc".to_string()]),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_private_key_id));
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_cc".to_string()]),
        key_format_type: Some(KeyFormatType::CoverCryptPublicKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_public_key_id));

    // locate using tags and cryptographic algorithm and key format type
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_cc".to_string()]),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_private_key_id));

    // generate a user key
    let user_key_id = CreateUserKeyAction {
        master_secret_key_id: master_private_key_id.to_string(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
            .to_string(),
        tags: vec!["test_cc".to_string(), "another_tag".to_string()],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_cc".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));
    assert!(ids.contains(&user_key_id));

    // locate using tags and cryptographic algorithm and key format type
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_cc".to_string()]),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&user_key_id));
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_cc".to_string(), "another_tag".to_string()]),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&user_key_id));

    // test using system Tags
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_cc".to_string(), "_uk".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&user_key_id));
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_cc".to_string(), "_sk".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_private_key_id));
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_cc".to_string(), "_pk".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_public_key_id));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_locate_elliptic_curve() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    // init the test server
    let ctx = start_default_test_kms_server_with_cert_auth().await;

    // generate a new key pair
    let (private_key_id, public_key_id) = CreateEcKeyPairAction {
        curve: Curve::NistP256,
        tags: vec!["test_ec".to_owned()],
        sensitive: false,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_ec".to_owned()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&private_key_id));
    assert!(ids.contains(&public_key_id));

    // Locate with cryptographic algorithm
    // this should be case insensitive
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_ec".to_owned()]),
        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&private_key_id));
    assert!(ids.contains(&public_key_id));

    // locate using the key format type
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_ec".to_owned()]),
        key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&private_key_id));
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_ec".to_owned()]),
        key_format_type: Some(KeyFormatType::TransparentECPublicKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&public_key_id));

    // locate using tags and cryptographic algorithm and key format type
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_ec".to_owned()]),
        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
        key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&private_key_id));

    // test using system Tags
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_ec".to_owned(), "_sk".to_owned()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&private_key_id));
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_ec".to_owned(), "_pk".to_owned()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&public_key_id));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_locate_symmetric_key() -> KmsCliResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server_with_cert_auth().await;

    // generate a new key
    let key_id = CreateKeyAction {
        tags: vec!["test_sym".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_sym".to_owned()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    // Locate with cryptographic algorithm
    // this should be case insensitive
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_sym".to_owned()]),
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    // locate using the key format type
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_sym".to_owned()]),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    // locate using tags and cryptographic algorithm and key format type
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_sym".to_owned()]),
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    // test using system Tags
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_sym".to_owned(), "_kk".to_owned()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_locate_grant() -> KmsCliResult<()> {
    // init the test server

    use std::path::PathBuf;

    use cosmian_kms_client::kmip_2_1::KmipOperation;

    use crate::actions::kms::access::{GrantAccess, RevokeAccess};
    let ctx = start_default_test_kms_server_with_cert_auth().await;

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec!["test_grant".to_string()],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0, key_ids.1)
    };

    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_grant".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));

    // Locate with cryptographic algorithm
    // this should be case insensitive
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_grant".to_string()]),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));

    // generate a user key
    let user_key_id = CreateUserKeyAction {
        master_secret_key_id: master_private_key_id.to_string(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
            .to_string(),
        tags: vec!["test_grant".to_string(), "another_tag".to_string()],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_grant".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(&master_private_key_id));
    assert!(ids.contains(&master_public_key_id));
    assert!(ids.contains(&user_key_id));

    // the user should not be able to locate anything
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_grant".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?;
    assert_eq!(ids.len(), 0);

    // Grant access to the user decryption key
    GrantAccess {
        user: "user.client@acme.com".to_owned(),
        object_uid: Some(user_key_id.to_string()),
        operations: vec![KmipOperation::Encrypt],
    }
    .run(ctx.get_owner_client())
    .await?;

    // The user should be able to locate the user key and only that one
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_grant".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&user_key_id));

    // revoke the access
    RevokeAccess {
        user: "user.client@acme.com".to_owned(),
        object_uid: Some(user_key_id.to_string()),
        operations: vec![KmipOperation::Encrypt],
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user should no more be able to locate the key
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_grant".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?;
    assert_eq!(ids.len(), 0);

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_locate_secret_data() -> KmsCliResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server_with_cert_auth().await;

    // generate a new secret
    let secret_id = crate::actions::kms::secret_data::create_secret::CreateSecretDataAction {
        tags: vec!["test_secret".to_string()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_secret".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&secret_id));

    // locate using the key format type
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_secret".to_string()]),
        key_format_type: Some(KeyFormatType::Raw),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&secret_id));

    // test using system Tags
    let ids = LocateObjectsAction {
        tags: Some(vec!["test_secret".to_string(), "_sd".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&secret_id));

    Ok(())
}
