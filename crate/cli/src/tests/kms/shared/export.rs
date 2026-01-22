#[cfg(feature = "non-fips")]
use std::path::{Path, PathBuf};

use cosmian_kmip::kmip_2_1::kmip_objects::Object;
use cosmian_kms_client::{
    kmip_0::kmip_types::BlockCipherMode,
    kmip_2_1::kmip_types::KeyFormatType,
    read_bytes_from_file, read_object_from_json_ttlv_file,
    reexport::cosmian_kms_client_utils::export_utils::{ExportKeyFormat, WrappingAlgorithm},
};
#[cfg(feature = "non-fips")]
use cosmian_kms_client::{
    kmip_2_1::{
        kmip_data_structures::KeyMaterial,
        kmip_types::{CryptographicAlgorithm, RecommendedCurve},
    },
    pad_be_bytes,
};
use cosmian_logger::log_init;
#[cfg(feature = "non-fips")]
use openssl::pkey::{Id, PKey};
use tempfile::TempDir;
#[cfg(feature = "non-fips")]
use test_kms_server::TestsContext;
use test_kms_server::start_default_test_kms_server;

#[cfg(feature = "non-fips")]
use crate::actions::kms::cover_crypt::keys::{
    create_key_pair::CreateMasterKeyPairAction, create_user_key::CreateUserKeyAction,
};
use crate::{
    actions::kms::{
        elliptic_curves::keys::create_key_pair::CreateKeyPairAction as CreateEcKeyPairAction,
        rsa::keys::create_key_pair::CreateKeyPairAction, shared::ExportSecretDataOrKeyAction,
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::{KmsCliResult, KmsCliResultHelper},
};

#[tokio::test]
pub(crate) async fn test_export_sym() -> KmsCliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate a symmetric key
    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Export as default (JsonTTLV with Raw Key Format Type)
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_string()),
        key_file: tmp_path.join("output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // read the bytes from the exported file
    let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
    let key_block = object.key_block()?;
    assert_eq!(key_block.key_format_type, KeyFormatType::Raw);
    let key_bytes = key_block.key_bytes()?;

    // Export the bytes only
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_string()),
        key_file: tmp_path.join("output.export.bytes"),
        export_format: ExportKeyFormat::Raw,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;
    assert_eq!(&*key_bytes, bytes.as_slice());

    // wrong export format
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_string()),
        key_file: tmp_path.join("output.export.bytes"),
        export_format: ExportKeyFormat::Pkcs1Pem,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_export_sym_allow_revoked() -> KmsCliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate a symmetric key
    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Export
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_string()),
        key_file: tmp_path.join("output.export"),
        allow_revoked: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_export_wrapped() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("info,cosmian_kms_server=debug"));

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate a RSA key pair
    let (private_key_id, _public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // generate a symmetric key
    let sym_key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Export wrapped key with a symmetric key as default (JsonTTLV with Raw Key Format Type)
    ExportSecretDataOrKeyAction {
        key_id: Some(private_key_id.to_string()),
        key_file: tmp_path.join("output.export"),
        wrap_key_id: Some(sym_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
    let key_bytes = object
        .key_block()?
        .wrapped_key_bytes()
        .context("exported wrapped key")?;
    let cryptographic_parameters = object
        .key_block()?
        .key_wrapping_data
        .clone()
        .unwrap()
        .encryption_key_information
        .unwrap()
        .cryptographic_parameters;
    assert!(cryptographic_parameters.is_none());

    // Wrapping with symmetric key should be by default with rfc5649
    ExportSecretDataOrKeyAction {
        key_id: Some(private_key_id.to_string()),
        key_file: tmp_path.join("output_2.export"),
        wrap_key_id: Some(sym_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let object_2 = read_object_from_json_ttlv_file(&tmp_path.join("output_2.export"))?;
    let key_bytes_2 = object_2
        .key_block()?
        .wrapped_key_bytes()
        .context("object 2")?;
    let cryptographic_parameters = object_2
        .key_block()?
        .key_wrapping_data
        .clone()
        .unwrap()
        .encryption_key_information
        .unwrap()
        .cryptographic_parameters;
    assert!(cryptographic_parameters.is_none());

    assert_eq!(key_bytes, key_bytes_2);

    ExportSecretDataOrKeyAction {
        key_id: Some(private_key_id.to_string()),
        key_file: tmp_path.join("output.export"),
        wrap_key_id: Some(sym_key_id.to_string()),
        wrapping_algorithm: Some(WrappingAlgorithm::AESKeyWrapPadding),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Export wrapped key with a symmetric key using AESGCM as default (JsonTTLV with Raw Key Format Type)
    ExportSecretDataOrKeyAction {
        key_id: Some(private_key_id.to_string()),
        key_file: tmp_path.join("output.export"),
        wrap_key_id: Some(sym_key_id.to_string()),
        wrapping_algorithm: Some(WrappingAlgorithm::AesGCM),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
    let block_cipher_mode = object
        .key_block()?
        .key_wrapping_data
        .clone()
        .unwrap()
        .encryption_key_information
        .unwrap()
        .cryptographic_parameters
        .unwrap()
        .block_cipher_mode
        .unwrap();
    assert_eq!(block_cipher_mode, BlockCipherMode::GCM);

    // Block-cipher-mode option raises an error when not using symmetric key for wrapping
    ExportSecretDataOrKeyAction {
        key_id: Some(sym_key_id.to_string()),
        key_file: tmp_path.join("output.export"),
        wrap_key_id: Some(private_key_id.to_string()),
        wrapping_algorithm: Some(WrappingAlgorithm::AesGCM),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_export_covercrypt() -> KmsCliResult<()> {
    async fn export_cc_test(
        key_format_type: KeyFormatType,
        key_id: &str,
        tmp_path: &Path,
        ctx: &TestsContext,
    ) -> KmsCliResult<()> {
        // Export the key
        ExportSecretDataOrKeyAction {
            key_id: Some(key_id.to_owned()),
            key_file: tmp_path.join("output.export"),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        // read the bytes from the exported file
        let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
        let key_block = object.key_block()?;
        assert_eq!(key_block.key_format_type, key_format_type);
        let key_bytes = key_block.covercrypt_key_bytes()?;

        // Export the key bytes only
        ExportSecretDataOrKeyAction {
            key_id: Some(key_id.to_owned()),
            key_file: tmp_path.join("output.export.bytes"),
            export_format: ExportKeyFormat::Raw,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;
        let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;
        assert_eq!(&*key_bytes, bytes.as_slice());
        Ok(())
    }

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0.to_string(), key_ids.1.to_string())
    };

    export_cc_test(
        KeyFormatType::CoverCryptSecretKey,
        &master_private_key_id,
        tmp_path,
        ctx,
    )
    .await?;
    export_cc_test(
        KeyFormatType::CoverCryptPublicKey,
        &master_public_key_id,
        tmp_path,
        ctx,
    )
    .await?;

    let user_key_id = CreateUserKeyAction {
        master_secret_key_id: master_private_key_id.clone(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
            .to_string(),
        tags: vec![],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();
    export_cc_test(
        KeyFormatType::CoverCryptSecretKey,
        &user_key_id,
        tmp_path,
        ctx,
    )
    .await?;

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_export_error_cover_crypt() -> KmsCliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // key does not exist
    ExportSecretDataOrKeyAction {
        key_id: Some("does_not_exist".to_owned()),
        key_file: tmp_path.join("output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .err()
    .unwrap();

    // generate a new master key pair
    let (master_private_key_id, _master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0.to_string(), key_ids.1.to_string())
    };

    // Export to non existing dir
    ExportSecretDataOrKeyAction {
        key_id: Some(master_private_key_id),
        key_file: PathBuf::from("/does_not_exist/output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .err()
    .unwrap();

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_export_x25519() -> KmsCliResult<()> {
    // create a temp dir

    use cosmian_kms_client::{
        kmip_2_1::kmip_data_structures::KeyValue,
        reexport::cosmian_kms_client_utils::create_utils::Curve,
    };
    use cosmian_logger::trace;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate a new key pair
    let (private_key_id, public_key_id) = CreateEcKeyPairAction {
        curve: Curve::X25519,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Private Key
    //
    ExportSecretDataOrKeyAction {
        key_id: Some(private_key_id.to_string()),
        key_file: tmp_path.join("output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // read the bytes from the exported file
    let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
    let key_block = object.key_block()?;
    assert_eq!(
        key_block.key_format_type,
        KeyFormatType::TransparentECPrivateKey
    );
    assert_eq!(
        key_block.cryptographic_algorithm,
        Some(CryptographicAlgorithm::ECDH)
    );
    let Some(KeyValue::Structure { key_material, .. }) = &key_block.key_value else {
        panic!("Invalid key value type");
    };
    let KeyMaterial::TransparentECPrivateKey {
        d,
        recommended_curve,
    } = key_material
    else {
        panic!("Invalid key material ");
    };
    assert_eq!(recommended_curve, &RecommendedCurve::CURVE25519);
    let (_, mut d_vec) = d.to_bytes_be();
    // 32 is privkey size on x25519.
    pad_be_bytes(&mut d_vec, 32);
    trace!("d_vec size is {:?}", d_vec.len());
    let pkey_1 = PKey::private_key_from_raw_bytes(&d_vec, Id::X25519).unwrap();

    // Export the bytes only
    ExportSecretDataOrKeyAction {
        key_id: Some(private_key_id.to_string()),
        key_file: tmp_path.join("output.export.bytes"),
        export_format: ExportKeyFormat::Pkcs8Der,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;
    let pkey_2 = PKey::private_key_from_der(&bytes).unwrap();

    assert_eq!(
        pkey_1.private_key_to_pkcs8().unwrap(),
        pkey_2.private_key_to_pkcs8().unwrap()
    );

    // Public Key
    //
    ExportSecretDataOrKeyAction {
        key_id: Some(public_key_id.to_string()),
        key_file: tmp_path.join("output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // read the bytes from the exported file
    let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
    let key_block = object.key_block()?;
    assert_eq!(
        key_block.key_format_type,
        KeyFormatType::TransparentECPublicKey
    );
    assert_eq!(
        key_block.cryptographic_algorithm,
        Some(CryptographicAlgorithm::ECDH)
    );
    let Some(KeyValue::Structure { key_material, .. }) = &key_block.key_value else {
        panic!("Invalid key value type");
    };
    let KeyMaterial::TransparentECPublicKey {
        q_string,
        recommended_curve,
    } = key_material
    else {
        panic!("Invalid key value type")
    };
    assert_eq!(recommended_curve, &RecommendedCurve::CURVE25519);
    let pkey_1 = PKey::public_key_from_raw_bytes(q_string, Id::X25519).unwrap();

    // Export the bytes only
    ExportSecretDataOrKeyAction {
        key_id: Some(public_key_id.to_string()),
        key_file: tmp_path.join("output.export.bytes"),
        export_format: ExportKeyFormat::Pkcs8Der,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;
    let pkey_2 = PKey::public_key_from_der(&bytes).unwrap();

    assert_eq!(
        pkey_1.public_key_to_der().unwrap(),
        pkey_2.public_key_to_der().unwrap()
    );

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_sensitive_sym() -> KmsCliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate a symmetric key
    let key_id = CreateKeyAction {
        sensitive: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // the key should not be exportable
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_string()),
        key_file: tmp_path.join("output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_sensitive_ec_key() -> KmsCliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate an ec key pair
    let (private_key_id, public_key_id) = CreateEcKeyPairAction {
        sensitive: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // the private key should not be exportable
    ExportSecretDataOrKeyAction {
        key_id: Some(private_key_id.to_string()),
        key_file: tmp_path.join("output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    // the public key should be exportable
    ExportSecretDataOrKeyAction {
        key_id: Some(public_key_id.to_string()),
        key_file: tmp_path.join("output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_sensitive_rsa_key() -> KmsCliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate an rsa key pair
    let (private_key_id, public_key_id) = CreateKeyPairAction {
        sensitive: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // the private key should not be exportable
    ExportSecretDataOrKeyAction {
        key_id: Some(private_key_id.to_string()),
        key_file: tmp_path.join("output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    // the public key should be exportable
    ExportSecretDataOrKeyAction {
        key_id: Some(public_key_id.to_string()),
        key_file: tmp_path.join("output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_sensitive_covercrypt_key() -> KmsCliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate a new master key pair
    let (master_private_key_id, master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: true,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0.to_string(), key_ids.1.to_string())
    };

    // master secret key should not be exportable
    ExportSecretDataOrKeyAction {
        key_id: Some(master_private_key_id.clone()),
        key_file: tmp_path.join("output.sk.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    // Master public key should be exportable
    ExportSecretDataOrKeyAction {
        key_id: Some(master_public_key_id),
        key_file: tmp_path.join("output.sk.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();

    let user_key_id = CreateUserKeyAction {
        master_secret_key_id: master_private_key_id.clone(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
            .to_string(),
        tags: vec![],
        sensitive: true,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    ExportSecretDataOrKeyAction {
        key_id: Some(user_key_id),
        key_file: tmp_path.join("output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_export_secret_data() -> KmsCliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate a secret data
    let secret_id =
        crate::actions::kms::secret_data::create_secret::CreateSecretDataAction::default()
            .run(ctx.get_owner_client())
            .await?;

    // Export as default (JsonTTLV with Raw Key Format Type)
    ExportSecretDataOrKeyAction {
        key_id: Some(secret_id.to_string()),
        key_file: tmp_path.join("output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // read the bytes from the exported file
    let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
    // Ensure we're working with SecretData
    let Object::SecretData(secret_data) = object else {
        panic!("Expected SecretData object");
    };
    // Get the key block
    let key_block = &secret_data.key_block;
    assert_eq!(key_block.key_format_type, KeyFormatType::Raw);
    let key_bytes = key_block.secret_data_bytes()?;
    // Now you can use the bytes:
    assert_eq!(key_bytes.len(), 32);
    // Export the bytes only
    ExportSecretDataOrKeyAction {
        key_id: Some(secret_id.to_string()),
        key_file: tmp_path.join("output.export.bytes"),
        export_format: ExportKeyFormat::Raw,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;
    assert_eq!(key_bytes.as_slice(), bytes.as_slice());

    // wrong export format
    ExportSecretDataOrKeyAction {
        key_id: Some(secret_id.to_string()),
        key_file: tmp_path.join("output.export.bytes"),
        export_format: ExportKeyFormat::Pkcs1Pem,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    Ok(())
}
