#[cfg(not(feature = "fips"))]
use std::path::Path;
use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::{
    kmip::kmip_types::KeyFormatType, read_bytes_from_file, read_object_from_json_ttlv_file,
    KMS_CLI_CONF_ENV,
};
#[cfg(not(feature = "fips"))]
use cosmian_kms_client::{
    kmip::{
        kmip_data_structures::KeyMaterial,
        kmip_types::{CryptographicAlgorithm, RecommendedCurve},
    },
    pad_be_bytes,
};
#[cfg(not(feature = "fips"))]
use kms_test_server::TestsContext;
use kms_test_server::{start_default_test_kms_server, ONCE};
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
    error::CliError,
    tests::{symmetric::create_key::create_symmetric_key, utils::recover_cmd_logs, PROG_NAME},
};

#[allow(clippy::too_many_arguments)]
pub fn export_key(
    cli_conf_path: &str,
    sub_command: &str,
    key_id: &str,
    key_file: &str,
    key_format: Option<ExportKeyFormat>,
    unwrap: bool,
    wrap_key_id: Option<String>,
    allow_revoked: bool,
) -> Result<(), CliError> {
    let mut args: Vec<String> = ["keys", "export", "--key-id", key_id, key_file]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    if let Some(key_format) = key_format {
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
            ExportKeyFormat::Raw => "raw",
        };
        args.push(arg_value.to_owned());
    }
    if unwrap {
        args.push("--unwrap".to_owned());
    }
    if let Some(wrap_key_id) = wrap_key_id {
        args.push("--wrap-key-id".to_owned());
        args.push(wrap_key_id);
    }
    if allow_revoked {
        args.push("--allow-revoked".to_owned());
    }
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
    cmd.arg(sub_command).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub async fn test_export_sym() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;

    // generate a symmetric key
    let key_id = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;

    // Export as default (JsonTTLV with Raw Key Format Type)
    export_key(
        &ctx.owner_client_conf_path,
        "sym",
        &key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        None,
        false,
        None,
        false,
    )?;

    // read the bytes from the exported file
    let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
    let key_block = object.key_block()?;
    assert_eq!(key_block.key_format_type, KeyFormatType::Raw);
    let key_bytes = key_block.key_bytes()?;

    // Export the bytes only
    export_key(
        &ctx.owner_client_conf_path,
        "sym",
        &key_id,
        tmp_path.join("output.export.bytes").to_str().unwrap(),
        Some(ExportKeyFormat::Raw),
        false,
        None,
        false,
    )?;
    let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;
    assert_eq!(&*key_bytes, bytes.as_slice());

    // wrong export format
    assert!(
        export_key(
            &ctx.owner_client_conf_path,
            "sym",
            &key_id,
            tmp_path.join("output.export.bytes").to_str().unwrap(),
            Some(ExportKeyFormat::Pkcs1Pem),
            false,
            None,
            false,
        )
        .is_err()
    );

    Ok(())
}

#[tokio::test]
pub async fn test_export_sym_allow_revoked() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;

    // generate a symmetric key
    let key_id = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;
    // Export
    export_key(
        &ctx.owner_client_conf_path,
        "sym",
        &key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        None,
        false,
        None,
        true,
    )?;

    Ok(())
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
pub async fn test_export_covercrypt() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;

    // generate a new master key pair
    let (master_private_key_id, _master_public_key_id) = create_cc_master_key_pair(
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
        &_master_public_key_id,
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

    fn _export_cc_test(
        key_format_type: KeyFormatType,
        key_id: &str,
        tmp_path: &Path,
        ctx: &TestsContext,
    ) -> Result<(), CliError> {
        // Export the key
        export_key(
            &ctx.owner_client_conf_path,
            "cc",
            key_id,
            tmp_path.join("output.export").to_str().unwrap(),
            None,
            false,
            None,
            false,
        )?;

        // read the bytes from the exported file
        let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
        let key_block = object.key_block()?;
        assert_eq!(key_block.key_format_type, key_format_type);
        let key_bytes = key_block.key_bytes()?;

        // Export the key bytes only
        export_key(
            &ctx.owner_client_conf_path,
            "cc",
            key_id,
            tmp_path.join("output.export.bytes").to_str().unwrap(),
            Some(ExportKeyFormat::Raw),
            false,
            None,
            false,
        )?;
        let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;
        assert_eq!(&*key_bytes, bytes.as_slice());
        Ok(())
    }

    Ok(())
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
pub async fn test_export_error_cover_crypt() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;

    // key does not exist
    export_key(
        &ctx.owner_client_conf_path,
        "cc",
        "does_not_exist",
        tmp_path.join("output.export").to_str().unwrap(),
        None,
        false,
        None,
        false,
    )
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
    export_key(
        &ctx.owner_client_conf_path,
        "cc",
        &master_private_key_id,
        "/does_not_exist/output.export",
        None,
        false,
        None,
        false,
    )
    .err()
    .unwrap();

    Ok(())
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
pub async fn test_export_x25519() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;

    // generate a new key pair
    let (private_key_id, public_key_id) =
        create_ec_key_pair(&ctx.owner_client_conf_path, "x25519", &[])?;

    //
    // Private Key
    //
    export_key(
        &ctx.owner_client_conf_path,
        "ec",
        &private_key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        None,
        false,
        None,
        false,
    )?;

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
    let (d, recommended_curve) = match &kv.key_material {
        KeyMaterial::TransparentECPrivateKey {
            d,
            recommended_curve,
        } => (d, recommended_curve),
        _ => panic!("Invalid key value type"),
    };
    assert_eq!(recommended_curve, &RecommendedCurve::CURVE25519);
    let mut d_vec = d.to_bytes_be();
    // 32 is privkey size on x25519.
    pad_be_bytes(&mut d_vec, 32);
    println!("dvec size is {:?}", d_vec.len());
    let pkey_1 = PKey::private_key_from_raw_bytes(&d_vec, Id::X25519).unwrap();

    // Export the bytes only
    export_key(
        &ctx.owner_client_conf_path,
        "ec",
        &private_key_id,
        tmp_path.join("output.export.bytes").to_str().unwrap(),
        Some(ExportKeyFormat::Pkcs8Der),
        false,
        None,
        false,
    )?;
    let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;
    let pkey_2 = PKey::private_key_from_der(&bytes).unwrap();

    assert_eq!(
        pkey_1.private_key_to_pkcs8().unwrap(),
        pkey_2.private_key_to_pkcs8().unwrap()
    );

    //
    // Public Key
    //
    export_key(
        &ctx.owner_client_conf_path,
        "ec",
        &public_key_id,
        tmp_path.join("output.export").to_str().unwrap(),
        None,
        false,
        None,
        false,
    )?;

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
    let (q_string, recommended_curve) = match &kv.key_material {
        KeyMaterial::TransparentECPublicKey {
            q_string,
            recommended_curve,
        } => (q_string, recommended_curve),
        _ => panic!("Invalid key value type"),
    };
    assert_eq!(recommended_curve, &RecommendedCurve::CURVE25519);
    let pkey_1 = PKey::public_key_from_raw_bytes(q_string, Id::X25519).unwrap();

    // Export the bytes only
    export_key(
        &ctx.owner_client_conf_path,
        "ec",
        &public_key_id,
        tmp_path.join("output.export.bytes").to_str().unwrap(),
        Some(ExportKeyFormat::SpkiDer),
        false,
        None,
        false,
    )?;
    let bytes = read_bytes_from_file(&tmp_path.join("output.export.bytes"))?;
    let pkey_2 = PKey::public_key_from_der(&bytes).unwrap();

    assert_eq!(
        pkey_1.public_key_to_der().unwrap(),
        pkey_2.public_key_to_der().unwrap()
    );

    Ok(())
}
