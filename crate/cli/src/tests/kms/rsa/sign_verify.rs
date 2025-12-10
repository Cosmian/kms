use std::{fs, path::PathBuf};

use cosmian_kmip::kmip_2_1::{
    kmip_operations::Sign,
    kmip_types::{CryptographicParameters, UniqueIdentifier, ValidityIndicator},
};
use cosmian_logger::{log_init, trace};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::rsa::{
        keys::create_key_pair::CreateKeyPairAction, sign::SignAction,
        signature_verify::SignatureVerifyAction,
    },
    error::result::KmsCliResult,
};

// RSA digested sign/verify end-to-end via CLI actions
#[tokio::test]
async fn rsa_digested_sign_verify_cli() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let digest_file = tmp_path.join("plain.sha256");
    let sig_file = tmp_path.join("plain.sha256.sig");

    // compute SHA-256 digest of input and write to digest_file
    let data = std::fs::read(&input_file)?;
    let digest = openssl::sha::sha256(&data);
    std::fs::write(&digest_file, digest)?;

    let (private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Sign digested input
    SignAction {
        input_file: digest_file.clone(),
        key_id: Some(private_key_id.to_string()),
        tags: None,

        output_file: Some(sig_file.clone()),
        digested: true,
    }
    .run(ctx.get_owner_client())
    .await?;

    // Verify digested input
    let validity = SignatureVerifyAction {
        data_file: digest_file.clone(),
        signature_file: sig_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,

        output_file: None,
        digested: true,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(validity, ValidityIndicator::Valid);
    Ok(())
}

// RSA streaming sign (raw data) and verify (non-digested)
#[tokio::test]
async fn rsa_streaming_sign_and_verify_cli() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain_1k.bin");
    let sig_file = tmp_path.join("plain.stream.rs.sig");

    let (private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Stream raw data using KMIP Sign directly
    let data = std::fs::read(&input_file)?;
    let chunk_size: usize = 64;
    let mut offset: usize = 0;
    let mut correlation_value: Option<Vec<u8>> = None;

    while offset < data.len() {
        let end = (offset + chunk_size).min(data.len());
        let chunk = data[offset..end].to_vec();
        let init_indicator = if offset == 0 { Some(true) } else { None };
        let final_indicator = if end == data.len() { Some(true) } else { None };
        let cp_chunk = if init_indicator == Some(true) {
            None
        } else {
            None
        };
        let sign_req = cosmian_kmip::kmip_2_1::kmip_operations::Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(private_key_id.to_string())),
            cryptographic_parameters: cp_chunk,
            data: Some(chunk.into()),
            digested_data: None,
            correlation_value: correlation_value.clone(),
            init_indicator,
            final_indicator,
        };
        let response = ctx.get_owner_client().sign(sign_req).await?;
        correlation_value = response.correlation_value.clone();
        if final_indicator == Some(true) {
            let signature = response.signature_data.expect("signature_data");
            std::fs::write(&sig_file, &signature)?;
        }
        offset = end;
    }

    let validity = SignatureVerifyAction {
        data_file: input_file.clone(),
        signature_file: sig_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,

        output_file: None,
        digested: false,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(validity, ValidityIndicator::Valid);
    Ok(())
}

#[tokio::test]
async fn test_rsa_sign() -> KmsCliResult<()> {
    // to enable this, add cosmian_logger = { workspace = true } to dev-dependencies in Cargo.toml
    log_init(None);

    let ctx = start_default_test_kms_server().await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain_1k.bin");
    let output_file = tmp_path.join("plain.sha256.sig");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");

    // compute SHA-256 digest of input and write to a temp file
    let data = std::fs::read(&input_file)?;
    let digest = openssl::sha::sha256(&data);
    let digest_file = tmp_path.join("plain.sha256");
    std::fs::write(&digest_file, digest)?;

    // sign digested data
    SignAction {
        input_file: digest_file.clone(),
        key_id: Some(private_key_id.to_string()),
        tags: None,

        output_file: Some(output_file.clone()),
        digested: true,
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to verify the signature
    let signature_result = SignatureVerifyAction {
        data_file: digest_file.clone(),
        signature_file: output_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,

        output_file: Some(recovered_file.clone()),
        digested: true,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(signature_result, ValidityIndicator::Valid);

    Ok(())
}

#[tokio::test]
async fn test_rsa_sign_with_digested_data() -> KmsCliResult<()> {
    log_init(None);

    let ctx = start_default_test_kms_server().await;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let digest_file = tmp_path.join("plain.sha256");
    let sig_file = tmp_path.join("plain.sha256.sig");

    // compute SHA-256 digest of input and write to digest_file
    let data = std::fs::read(&input_file)?;
    let digest = openssl::sha::sha256(&data);
    std::fs::write(&digest_file, digest)?;

    let (private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Sign the pre-digested data
    SignAction {
        input_file: digest_file.clone(),
        key_id: Some(private_key_id.to_string()),
        tags: None,

        output_file: Some(sig_file.clone()),
        digested: true,
    }
    .run(ctx.get_owner_client())
    .await?;

    // Verify using digested_data
    let validity = SignatureVerifyAction {
        data_file: digest_file.clone(),
        signature_file: sig_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        output_file: None,
        digested: true,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(validity, ValidityIndicator::Valid);

    Ok(())
}

#[tokio::test]
async fn test_rsa_streaming_sign_and_verify() -> KmsCliResult<()> {
    log_init(None);

    let ctx = start_default_test_kms_server().await;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain_1k.bin");
    let sig_file = tmp_path.join("plain.stream.rs.sig");

    let (private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Read data and split into chunks
    let data = std::fs::read(&input_file)?;
    let chunk_size: usize = 64;
    let mut offset: usize = 0;
    let mut correlation_value: Option<Vec<u8>> = None;

    // Stream: init, middle, final
    while offset < data.len() {
        let end = (offset + chunk_size).min(data.len());
        let chunk = data[offset..end].to_vec();
        let init_indicator = if offset == 0 { Some(true) } else { None };
        let final_indicator = if end == data.len() { Some(true) } else { None };

        let cp_chunk = if init_indicator == Some(true) {
            None
        } else {
            None
        };
        let sign_request = Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(private_key_id.to_string())),
            cryptographic_parameters: cp_chunk,
            data: Some(chunk.into()),
            digested_data: None,
            correlation_value: correlation_value.clone(),
            init_indicator,
            final_indicator,
        };

        let response = ctx.get_owner_client().sign(sign_request).await?;
        // Carry forward accumulated correlation value for streaming
        correlation_value = response.correlation_value.clone();
        if final_indicator == Some(true) {
            let signature = response.signature_data.expect("signature_data");
            std::fs::write(&sig_file, &signature)?;
        }

        offset = end;
    }

    // Verify full message using non-digested data
    let validity = SignatureVerifyAction {
        data_file: input_file.clone(),
        signature_file: sig_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,

        output_file: None,
        digested: false,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(validity, ValidityIndicator::Valid);

    Ok(())
}

// Deterministic RSA-PSS with salt_length=0 via KMIP Sign
#[tokio::test]
async fn rsa_pss_zero_salt_deterministic_cli() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let (private_key_id, _public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    let data = std::fs::read("../../test_data/plain.txt")?;

    // KMIP Sign with RSASSA-PSS and SaltLength=0
    let mut cp = cosmian_kmip::kmip_2_1::kmip_types::CryptographicParameters::default();
    cp.cryptographic_algorithm =
        Some(cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm::RSA);
    cp.padding_method = Some(cosmian_kmip::kmip_0::kmip_types::PaddingMethod::PSS);
    cp.hashing_algorithm = Some(cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm::SHA256);
    cp.mask_generator_hashing_algorithm =
        Some(cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm::SHA256);
    cp.salt_length = Some(0);
    let sign_req = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(private_key_id.to_string())),
        cryptographic_parameters: Some(cp),
        data: Some(data.clone().into()),
        digested_data: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    };

    let sig1 = ctx
        .get_owner_client()
        .sign(sign_req.clone())
        .await?
        .signature_data
        .expect("signature_data");
    let sig2 = ctx
        .get_owner_client()
        .sign(sign_req)
        .await?
        .signature_data
        .expect("signature_data");

    assert_eq!(sig1, sig2, "RSA-PSS with zero salt must be deterministic");
    Ok(())
}

// Deterministic RSA PKCS#1 v1.5 via KMIP Sign
#[tokio::test]
async fn rsa_pkcs1_v15_deterministic_cli() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let (private_key_id, _public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    let data = std::fs::read("../../test_data/plain.txt")?;

    // Use fully qualified paths to avoid local `use` items after statements
    let cp = CryptographicParameters {
        cryptographic_algorithm: Some(
            cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm::RSA,
        ),
        hashing_algorithm: Some(cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm::SHA256),
        digital_signature_algorithm: Some(
            cosmian_kmip::kmip_2_1::kmip_types::DigitalSignatureAlgorithm::SHA256WithRSAEncryption,
        ),
        ..Default::default()
    };
    let sign_req = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(private_key_id.to_string())),
        cryptographic_parameters: Some(cp),
        data: Some(data.clone().into()),
        digested_data: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    };

    let sig1 = ctx
        .get_owner_client()
        .sign(sign_req.clone())
        .await?
        .signature_data
        .expect("signature_data");
    let sig2 = ctx
        .get_owner_client()
        .sign(sign_req)
        .await?
        .signature_data
        .expect("signature_data");

    assert_eq!(
        sig1, sig2,
        "RSA PKCS#1 v1.5 signatures must be deterministic"
    );
    Ok(())
}
