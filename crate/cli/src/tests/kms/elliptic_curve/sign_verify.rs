use std::path::PathBuf;

use cosmian_kmip::kmip_2_1::{
    kmip_operations::Sign,
    kmip_types::{CryptographicParameters, UniqueIdentifier, ValidityIndicator},
};
use cosmian_logger::log_init;
use sha2::Digest;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{
        elliptic_curves::{
            keys::create_key_pair::CreateKeyPairAction, signature_verify::SignatureVerifyAction,
        },
        shared::CDigitalSignatureAlgorithmEC,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
async fn test_ecdsa_sign_with_digested_data() -> KmsCliResult<()> {
    log_init(None);

    let ctx = start_default_test_kms_server().await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let digest_file = tmp_path.join("plain.sha256");
    let sig_file = tmp_path.join("plain.sha256.ec.sign");

    // compute SHA-256 digest of input and write to digest_file
    let data = std::fs::read(&input_file)?;
    let digest = sha2::Sha256::digest(&data);
    std::fs::write(&digest_file, digest)?;

    let (private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Sign the pre-digested data using direct KMIP Sign request
    let cryptographic_parameters: Option<CryptographicParameters> =
        Some(CDigitalSignatureAlgorithmEC::ECDSAWithSHA256.to_cryptographic_parameters());
    let sign_request = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(private_key_id.to_string())),
        cryptographic_parameters,
        data: None,
        digested_data: Some(std::fs::read(&digest_file)?),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    };
    let sign_response = ctx.get_owner_client().sign(sign_request).await?;
    let signature = sign_response.signature_data.expect("signature_data");
    std::fs::write(&sig_file, &signature)?;

    // Verify using digested_data
    let validity = SignatureVerifyAction {
        data_file: digest_file.clone(),
        signature_file: sig_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        signature_algorithm: CDigitalSignatureAlgorithmEC::ECDSAWithSHA256,
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
async fn test_ecdsa_streaming_sign_and_verify() -> KmsCliResult<()> {
    log_init(None);

    let ctx = start_default_test_kms_server().await;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let sig_file = tmp_path.join("plain.stream.ec.sign");

    let (private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    let data = std::fs::read(&input_file)?;
    let chunk_size: usize = 64;
    let mut offset: usize = 0;
    let correlation_value = Some(b"ec-stream-1".to_vec());

    let cryptographic_parameters: Option<CryptographicParameters> =
        Some(CDigitalSignatureAlgorithmEC::ECDSAWithSHA256.to_cryptographic_parameters());

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

    let validity = SignatureVerifyAction {
        data_file: input_file.clone(),
        signature_file: sig_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        signature_algorithm: CDigitalSignatureAlgorithmEC::ECDSAWithSHA256,
        output_file: None,
        digested: false,
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(validity, ValidityIndicator::Valid);

    Ok(())
}
