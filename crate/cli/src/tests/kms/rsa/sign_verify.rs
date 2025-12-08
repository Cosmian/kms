use std::{fs, path::PathBuf};

use cosmian_kmip::kmip_2_1::{
    kmip_operations::Sign,
    kmip_types::{CryptographicParameters, UniqueIdentifier, ValidityIndicator},
};
use cosmian_logger::{log_init, trace};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{
        rsa::{
            keys::create_key_pair::CreateKeyPairAction, sign::SignAction,
            signature_verify::SignatureVerifyAction,
        },
        shared::CDigitalSignatureAlgorithmRSA,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
async fn test_rsa_sign() -> KmsCliResult<()> {
    // to enable this, add cosmian_logger = { workspace = true } to dev-dependencies in Cargo.toml
    log_init(None);

    let ctx = start_default_test_kms_server().await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.sha256.sign");
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
        signature_algorithm: CDigitalSignatureAlgorithmRSA::RSASSAPSS,
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
        signature_algorithm: CDigitalSignatureAlgorithmRSA::RSASSAPSS,
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
    let sig_file = tmp_path.join("plain.sha256.sign");

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
        signature_algorithm: CDigitalSignatureAlgorithmRSA::RSASSAPSS,
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
        signature_algorithm: CDigitalSignatureAlgorithmRSA::RSASSAPSS,
        output_file: None,
        digested: true,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(validity, ValidityIndicator::Valid);

    Ok(())
}

#[tokio::test]
#[ignore = "Streaming Sign with chunked data currently verifies as Invalid; requires server-side streaming aggregation semantics"]
async fn test_rsa_streaming_sign_and_verify() -> KmsCliResult<()> {
    log_init(None);

    let ctx = start_default_test_kms_server().await;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let sig_file = tmp_path.join("plain.stream.rs.sign");

    let (private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Read data and split into chunks
    let data = std::fs::read(&input_file)?;
    let chunk_size: usize = 64;
    let mut offset: usize = 0;
    let correlation_value = Some(b"stream-1".to_vec());

    // Prepare cryptographic parameters for RSASSA-PSS
    let cryptographic_parameters: Option<CryptographicParameters> =
        Some(CDigitalSignatureAlgorithmRSA::RSASSAPSS.to_cryptographic_parameters());

    // Stream: init, middle, final
    while offset < data.len() {
        let end = (offset + chunk_size).min(data.len());
        let chunk = data[offset..end].to_vec();
        let init_indicator = if offset == 0 { Some(true) } else { None };
        let final_indicator = if end == data.len() { Some(true) } else { None };

        let cp_chunk = if init_indicator == Some(true) {
            cryptographic_parameters.clone()
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
        signature_algorithm: CDigitalSignatureAlgorithmRSA::RSASSAPSS,
        output_file: None,
        digested: false,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(validity, ValidityIndicator::Valid);

    Ok(())
}
