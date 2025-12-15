use std::path::PathBuf;

use cosmian_kmip::kmip_2_1::kmip_objects::ObjectType;
use cosmian_kms_client::{
    kmip_2_1::kmip_types::{CryptographicAlgorithm, KeyFormatType},
    reexport::cosmian_kms_client_utils::create_utils::Curve,
};
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server_with_cert_auth;

use crate::{
    actions::kms::{
        cover_crypt::keys::{
            create_key_pair::CreateMasterKeyPairAction, create_user_key::CreateUserKeyAction,
        },
        elliptic_curves::keys::create_key_pair::CreateKeyPairAction as CreateEcKeyPairAction,
        shared::LocateObjectsAction,
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_locate_cover_crypt() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));

    // Generate unique tags to avoid cross-test collisions when tests run concurrently
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos();
    let base_tag = format!("test_cc_{ts}");
    let another_tag = format!("another_tag_{ts}");

    // init the test server
    let ctx = start_default_test_kms_server_with_cert_auth().await;

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![base_tag.clone()],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0, key_ids.1)
    };

    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
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
        tags: Some(vec![base_tag.clone()]),
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
        tags: Some(vec![base_tag.clone()]),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_private_key_id));
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
        key_format_type: Some(KeyFormatType::CoverCryptPublicKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_public_key_id));

    // locate using tags and cryptographic algorithm and key format type
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
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
        tags: vec![base_tag.clone(), another_tag.clone()],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
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
        tags: Some(vec![base_tag.clone()]),
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
        tags: Some(vec![base_tag.clone(), another_tag.clone()]),
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
        tags: Some(vec![base_tag.clone(), "_uk".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&user_key_id));
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone(), "_sk".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_private_key_id));
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag, "_pk".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&master_public_key_id));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_locate_key_pair_and_sym_key() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));

    // Generate unique tags to avoid cross-test collisions when tests run concurrently.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos();
    let base_tag = format!("test_locate_kp_{ts}");

    let ctx = start_default_test_kms_server_with_cert_auth().await;

    // Create an EC keypair WITHOUT the "cat" tag
    let (_private_key_id, _public_key_id) = CreateEcKeyPairAction {
        curve: Curve::NistP256,
        tags: vec![base_tag.clone()],
        sensitive: false,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Locate PublicKey with tag "cat" => expect 0 (tag wasn't set on creation)
    let ids = LocateObjectsAction {
        tags: Some(vec!["cat".to_string()]),
        object_type: Some(ObjectType::PublicKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 0);

    // Locate PrivateKey with AND CryptographicAlgorithm => expect 1
    let ids = LocateObjectsAction {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);

    // Create a symmetric AES key and locate by ObjectType::SymmetricKey
    let _sym_id = CreateKeyAction {
        tags: vec![base_tag.clone()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let ids = LocateObjectsAction {
        object_type: Some(ObjectType::SymmetricKey),
        tags: Some(vec![base_tag]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert!(!ids.is_empty());

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_locate_elliptic_curve() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    // init the test server
    let ctx = start_default_test_kms_server_with_cert_auth().await;

    // Generate unique tags to avoid cross-test collisions when tests run concurrently
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos();
    let base_tag = format!("test_ec_{ts}");

    // generate a new key pair
    let (private_key_id, public_key_id) = CreateEcKeyPairAction {
        curve: Curve::NistP256,
        tags: vec![base_tag.clone()],
        sensitive: false,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
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
        tags: Some(vec![base_tag.clone()]),
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
        tags: Some(vec![base_tag.clone()]),
        key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&private_key_id));
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
        key_format_type: Some(KeyFormatType::TransparentECPublicKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&public_key_id));

    // locate using tags and cryptographic algorithm and key format type
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
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
        tags: Some(vec![base_tag.clone(), "_sk".to_owned()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&private_key_id));
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone(), "_pk".to_owned()]),
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

    // Generate unique tags to avoid cross-test collisions when tests run concurrently
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos();
    let base_tag = format!("test_sym_{ts}");

    // generate a new key
    let key_id = CreateKeyAction {
        tags: vec![base_tag.clone()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    // Locate with cryptographic algorithm
    // this should be case insensitive
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    // locate using the key format type
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    // locate using tags and cryptographic algorithm and key format type
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
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
        tags: Some(vec![base_tag.clone(), "_kk".to_owned()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&key_id));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_locate_grant() -> KmsCliResult<()> {
    // init the test server

    use std::path::PathBuf;

    use cosmian_kms_client::kmip_2_1::KmipOperation;

    use crate::actions::kms::access::{GrantAccess, RevokeAccess};
    let ctx = start_default_test_kms_server_with_cert_auth().await;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos();
    let base_tag = format!("test_grant_{ts}");
    let another_tag = format!("another_tag_{ts}");

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![base_tag.clone()],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0, key_ids.1)
    };

    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
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
        tags: Some(vec![base_tag.clone()]),
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
        tags: vec![base_tag.clone(), another_tag.clone()],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
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
        tags: Some(vec![base_tag.clone()]),
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
        tags: Some(vec![base_tag.clone()]),
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
        tags: Some(vec![base_tag.clone()]),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?;
    assert_eq!(ids.len(), 0);

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_locate_secret_data() -> KmsCliResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server_with_cert_auth().await;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos();
    let base_tag = format!("test_secret_{ts}");

    // generate a new secret
    let secret_id = crate::actions::kms::secret_data::create_secret::CreateSecretDataAction {
        tags: vec![base_tag.clone()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    // Locate with Tags
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&secret_id));

    // locate using the key format type
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone()]),
        key_format_type: Some(KeyFormatType::Raw),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&secret_id));

    // test using system Tags
    let ids = LocateObjectsAction {
        tags: Some(vec![base_tag.clone(), "_sd".to_string()]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&secret_id));

    Ok(())
}
