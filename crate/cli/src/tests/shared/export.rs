#[cfg(not(feature = "fips"))]
use std::path::Path;
use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::{
    kmip::kmip_types::{BlockCipherMode, KeyFormatType},
    read_bytes_from_file, read_object_from_json_ttlv_file, KMS_CLI_CONF_ENV,
};
#[cfg(not(feature = "fips"))]
use cosmian_kms_client::{
    kmip::{
        kmip_data_structures::KeyMaterial,
        kmip_types::{CryptographicAlgorithm, RecommendedCurve},
    },
    pad_be_bytes,
};
use kms_test_server::start_default_test_kms_server;
#[cfg(not(feature = "fips"))]
use kms_test_server::TestsContext;
#[cfg(not(feature = "fips"))]
use openssl::pkey::{Id, PKey};
use tempfile::TempDir;

#[cfg(not(feature = "fips"))]
use crate::tests::cover_crypt::{
    master_key_pair::create_cc_master_key_pair, user_decryption_keys::create_user_decryption_key,
};
#[cfg(not(feature = "fips"))]
use crate::tests::elliptic_curve::create_key_pair::create_ec_key_pair;
use crate::{
    actions::shared::ExportKeyFormat,
    error::{result::CliResult, CliError},
    tests::{
        rsa::create_key_pair::create_rsa_4096_bits_key_pair,
        symmetric::create_key::create_symmetric_key, utils::recover_cmd_logs, PROG_NAME,
    },
};

#[derive(Debug, Default)]
pub(crate) struct ExportKeyParams {
    pub cli_conf_path: String,
    pub sub_command: String,
    pub key_id: String,
    pub key_file: String,
    pub key_format: Option<ExportKeyFormat>,
    pub unwrap: bool,
    pub wrap_key_id: Option<String>,
    pub allow_revoked: bool,
    pub block_cipher_mode: Option<String>,
    pub authenticated_additional_data: Option<String>,
}

pub(crate) fn export_key(params: ExportKeyParams) -> CliResult<()> {
    let mut args: Vec<String> = [
        "keys",
        "export",
        "--key-id",
        &params.key_id,
        &params.key_file,
    ]
    .iter()
    .map(std::string::ToString::to_string)
    .collect();
    if let Some(key_format) = params.key_format {
        args.push("--key-format".to_owned());
        let arg_value = match key_format {
            ExportKeyFormat::JsonTtlv => "json-ttlv",
            ExportKeyFormat::Sec1Pem => "sec1-pem",
            ExportKeyFormat::Sec1Der => "sec1-der",
            ExportKeyFormat::Pkcs1Pem => "pkcs1-pem",
            ExportKeyFormat::Pkcs1Der => "pkcs1-der",
            ExportKeyFormat::Pkcs8Pem => "pkcs8-pem",
            ExportKeyFormat::Pkcs8Der => "pkcs8-der",
            ExportKeyFormat::SpkiPem => "spki-pem",
            ExportKeyFormat::SpkiDer => "spki-der",
            ExportKeyFormat::Base64 => "base64",
            ExportKeyFormat::Raw => "raw",
        };
        args.push(arg_value.to_owned());
    }
    if params.unwrap {
        args.push("--unwrap".to_owned());
    }
    if let Some(wrap_key_id) = params.wrap_key_id {
        args.push("--wrap-key-id".to_owned());
        args.push(wrap_key_id);
    }
    if params.allow_revoked {
        args.push("--allow-revoked".to_owned());
    }
    if let Some(block_cipher_mode) = params.block_cipher_mode {
        args.push("--block-cipher-mode".to_owned());
        args.push(block_cipher_mode);
    }
    if let Some(authenticated_additional_data) = params.authenticated_additional_data {
        args.push("--authenticated-additional-data".to_owned());
        args.push(authenticated_additional_data);
    }
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, params.cli_conf_path);

    cmd.arg(params.sub_command).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_export_sym() -> CliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate a symmetric key
    let key_id = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;

    // Export as default (JsonTTLV with Raw Key Format Type)
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_id.clone(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        ..Default::default()
    })?;

    // read the bytes from the exported file
    let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
    let key_block = object.key_block()?;
    assert_eq!(key_block.key_format_type, KeyFormatType::Raw);
    let key_bytes = key_block.key_bytes()?;

    // Export the bytes only
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_id.clone(),
        key_file: tmp_path
            .join("output.export.bytes")
            .to_str()
            .unwrap()
            .to_owned(),
        key_format: Some(ExportKeyFormat::Raw),
        ..Default::default()
    })?;
    let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;
    assert_eq!(&*key_bytes, bytes.as_slice());

    // wrong export format
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: ctx.owner_client_conf_path.clone(),
            sub_command: "sym".to_owned(),
            key_id,
            key_file: tmp_path
                .join("output.export.bytes")
                .to_str()
                .unwrap()
                .to_owned(),
            key_format: Some(ExportKeyFormat::Pkcs1Pem),
            ..Default::default()
        })
        .is_err()
    );

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_export_sym_allow_revoked() -> CliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate a symmetric key
    let key_id = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;
    // Export
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id,
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        allow_revoked: true,
        ..Default::default()
    })?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_export_wrapped() -> CliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate a symmetric key
    let (private_key_id, _public_key_id) =
        create_rsa_4096_bits_key_pair(&ctx.owner_client_conf_path, &[])?;

    // generate a symmetric key
    let sym_key_id = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;

    // Export wrapped key with symmetric key as default (JsonTTLV with Raw Key Format Type)
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "rsa".to_owned(),
        key_id: private_key_id.clone(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        wrap_key_id: Some(sym_key_id.clone()),
        ..Default::default()
    })?;

    let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
    let key_bytes = object.key_block()?.key_bytes()?;
    let cryptographic_parameters = object
        .key_block()?
        .key_wrapping_data
        .clone()
        .unwrap()
        .encryption_key_information
        .unwrap()
        .cryptographic_parameters;
    assert_eq!(cryptographic_parameters, None);

    // Wrapping with symmetric key should be by default with rfc5649
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "rsa".to_owned(),
        key_id: private_key_id.clone(),
        key_file: tmp_path
            .join("output_2.export")
            .to_str()
            .unwrap()
            .to_owned(),
        wrap_key_id: Some(sym_key_id.clone()),
        ..Default::default()
    })?;

    let object_2 = read_object_from_json_ttlv_file(&tmp_path.join("output_2.export"))?;
    let key_bytes_2 = object_2.key_block()?.key_bytes()?;
    let cryptographic_parameters = object_2
        .key_block()?
        .key_wrapping_data
        .clone()
        .unwrap()
        .encryption_key_information
        .unwrap()
        .cryptographic_parameters;
    assert_eq!(cryptographic_parameters, None);

    assert_eq!(key_bytes, key_bytes_2);

    // Can't specify nist-key-wrap with aad
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: ctx.owner_client_conf_path.clone(),
            sub_command: "rsa".to_owned(),
            key_id: private_key_id.clone(),
            key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
            wrap_key_id: Some(sym_key_id.clone()),
            block_cipher_mode: Some(BlockCipherMode::NISTKeyWrap.to_string()),
            authenticated_additional_data: Some("encryption_data".to_owned()),
            ..Default::default()
        })
        .is_err()
    );

    // Export wrapped key with symmetric key using AESGCM as default (JsonTTLV with Raw Key Format Type)
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "rsa".to_owned(),
        key_id: private_key_id.clone(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        wrap_key_id: Some(sym_key_id.clone()),
        block_cipher_mode: Some(BlockCipherMode::GCM.to_string()),
        ..Default::default()
    })?;

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
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: ctx.owner_client_conf_path.clone(),
            sub_command: "rsa".to_owned(),
            key_id: sym_key_id,
            key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
            wrap_key_id: Some(private_key_id),
            block_cipher_mode: Some(BlockCipherMode::GCM.to_string()),
            ..Default::default()
        })
        .is_err()
    );

    Ok(())
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
pub(crate) async fn test_export_covercrypt() -> CliResult<()> {
    fn _export_cc_test(
        key_format_type: KeyFormatType,
        key_id: &str,
        tmp_path: &Path,
        ctx: &TestsContext,
    ) -> CliResult<()> {
        // Export the key
        export_key(ExportKeyParams {
            cli_conf_path: ctx.owner_client_conf_path.clone(),
            sub_command: "cc".to_owned(),
            key_id: key_id.to_owned(),
            key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
            ..Default::default()
        })?;

        // read the bytes from the exported file
        let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
        let key_block = object.key_block()?;
        assert_eq!(key_block.key_format_type, key_format_type);
        let key_bytes = key_block.key_bytes()?;

        // Export the key bytes only
        export_key(ExportKeyParams {
            cli_conf_path: ctx.owner_client_conf_path.clone(),
            sub_command: "cc".to_owned(),
            key_id: key_id.to_owned(),
            key_file: tmp_path
                .join("output.export.bytes")
                .to_str()
                .unwrap()
                .to_owned(),
            key_format: Some(ExportKeyFormat::Raw),
            ..Default::default()
        })?;
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
    let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &[],
    )?;

    _export_cc_test(
        KeyFormatType::CoverCryptSecretKey,
        &master_private_key_id,
        tmp_path,
        ctx,
    )?;
    _export_cc_test(
        KeyFormatType::CoverCryptPublicKey,
        &master_public_key_id,
        tmp_path,
        ctx,
    )?;

    let user_key_id = create_user_decryption_key(
        &ctx.owner_client_conf_path,
        &master_private_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &[],
    )?;
    _export_cc_test(
        KeyFormatType::CoverCryptSecretKey,
        &user_key_id,
        tmp_path,
        ctx,
    )?;

    Ok(())
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
pub(crate) async fn test_export_error_cover_crypt() -> CliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // key does not exist
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "cc".to_owned(),
        key_id: "does_not_exist".to_owned(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        ..Default::default()
    })
    .err()
    .unwrap();

    // generate a new master key pair
    let (master_private_key_id, _master_public_key_id) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &[],
    )?;

    // Export to non existing dir
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "cc".to_owned(),
        key_id: master_private_key_id,
        key_file: "/does_not_exist/output.export".to_owned(),
        ..Default::default()
    })
    .err()
    .unwrap();

    Ok(())
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
pub(crate) async fn test_export_x25519() -> CliResult<()> {
    // create a temp dir

    use tracing::trace;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // generate a new key pair
    let (private_key_id, public_key_id) =
        create_ec_key_pair(&ctx.owner_client_conf_path, "x25519", &[])?;

    //
    // Private Key
    //
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "ec".to_owned(),
        key_id: private_key_id.clone(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        ..Default::default()
    })?;

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
    let kv = &key_block.key_value;
    let KeyMaterial::TransparentECPrivateKey {
        d,
        recommended_curve,
    } = &kv.key_material
    else {
        panic!("Invalid key value type");
    };
    assert_eq!(recommended_curve, &RecommendedCurve::CURVE25519);
    let mut d_vec = d.to_bytes_be();
    // 32 is privkey size on x25519.
    pad_be_bytes(&mut d_vec, 32);
    trace!("d_vec size is {:?}", d_vec.len());
    let pkey_1 = PKey::private_key_from_raw_bytes(&d_vec, Id::X25519).unwrap();

    // Export the bytes only
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "ec".to_owned(),
        key_id: private_key_id,
        key_file: tmp_path
            .join("output.export.bytes")
            .to_str()
            .unwrap()
            .to_owned(),
        key_format: Some(ExportKeyFormat::Pkcs8Der),
        ..Default::default()
    })?;
    let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;
    let pkey_2 = PKey::private_key_from_der(&bytes).unwrap();

    assert_eq!(
        pkey_1.private_key_to_pkcs8().unwrap(),
        pkey_2.private_key_to_pkcs8().unwrap()
    );

    //
    // Public Key
    //
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "ec".to_owned(),
        key_id: public_key_id.clone(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        ..Default::default()
    })?;

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
    let kv = &key_block.key_value;
    let KeyMaterial::TransparentECPublicKey {
        q_string,
        recommended_curve,
    } = &kv.key_material
    else {
        panic!("Invalid key value type")
    };
    assert_eq!(recommended_curve, &RecommendedCurve::CURVE25519);
    let pkey_1 = PKey::public_key_from_raw_bytes(q_string, Id::X25519).unwrap();

    // Export the bytes only
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "ec".to_owned(),
        key_id: public_key_id,
        key_file: tmp_path
            .join("output.export.bytes")
            .to_str()
            .unwrap()
            .to_owned(),
        key_format: Some(ExportKeyFormat::SpkiDer),
        ..Default::default()
    })?;
    let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;
    let pkey_2 = PKey::public_key_from_der(&bytes).unwrap();

    assert_eq!(
        pkey_1.public_key_to_der().unwrap(),
        pkey_2.public_key_to_der().unwrap()
    );

    Ok(())
}
