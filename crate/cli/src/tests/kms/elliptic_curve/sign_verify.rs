use std::path::PathBuf;

use cosmian_kmip::kmip_2_1::{
    kmip_operations::Sign,
    kmip_types::{CryptographicParameters, UniqueIdentifier, ValidityIndicator},
};
use cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::Curve;
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

// Deterministic ECDSA under RFC6979 (non-fips): two signatures over same digest must match
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn ecdsa_deterministic_cli_rfc6979() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let digest_file = tmp_path.join("plain.sha256");

    // Pre-compute SHA-256 digest
    let data = std::fs::read(&input_file)?;
    let digest = sha2::Sha256::digest(&data);
    std::fs::write(&digest_file, digest)?;

    // Create P-256 key pair
    let (private_key_id, _public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // KMIP Sign on digested data twice
    let cp = Some(CDigitalSignatureAlgorithmEC::ECDSAWithSHA256.to_cryptographic_parameters());
    let sign_req = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(private_key_id.to_string())),
        cryptographic_parameters: cp,
        data: None,
        digested_data: Some(std::fs::read(&digest_file)?),
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
        "ECDSA signatures must be deterministic under RFC6979 path"
    );
    Ok(())
}

// Additional coverage: end-to-end EC CLI digested sign and verify
#[tokio::test]
async fn ecdsa_digested_sign_verify_cli_end_to_end() -> crate::error::result::KmsCliResult<()> {
    cosmian_logger::log_init(None);
    let ctx = test_kms_server::start_default_test_kms_server().await;

    let tmp_dir = tempfile::TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = std::path::PathBuf::from("../../test_data/plain.txt");
    let digest_file = tmp_path.join("plain.sha256");
    let sig_file = tmp_path.join("plain.sha256.ec.sig");

    // Pre-compute digest
    let data = std::fs::read(&input_file)?;
    let digest = sha2::Sha256::digest(&data);
    std::fs::write(&digest_file, digest)?;

    // Create EC key pair
    let (private_key_id, public_key_id) =
        crate::actions::kms::elliptic_curves::keys::create_key_pair::CreateKeyPairAction::default()
            .run(ctx.get_owner_client())
            .await?;

    // Use CLI SignAction with --digested path and explicit output
    crate::actions::kms::elliptic_curves::sign::SignAction {
        curve:
            cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::Curve::NistP256,
        input_file: digest_file.clone(),
        key_id: Some(private_key_id.to_string()),
        tags: None,
        signature_algorithm:
            crate::actions::kms::shared::CDigitalSignatureAlgorithmEC::ECDSAWithSHA256,
        output_file: Some(sig_file.clone()),
        digested: true,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(sig_file.exists());

    // Verify via CLI with digested flag
    let validity = crate::actions::kms::elliptic_curves::signature_verify::SignatureVerifyAction {
        data_file: digest_file.clone(),
        signature_file: sig_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        signature_algorithm:
            crate::actions::kms::shared::CDigitalSignatureAlgorithmEC::ECDSAWithSHA256,
        output_file: None,
        digested: true,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(
        validity,
        cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator::Valid
    );
    Ok(())
}

// Negative test: providing both data and digested_data must fail
#[tokio::test]
#[ignore = "Server currently accepts either data or digested_data; revisit when strict validation is enforced"]
async fn ecdsa_sign_both_data_and_digest_should_fail() -> crate::error::result::KmsCliResult<()> {
    cosmian_logger::log_init(None);
    let ctx = test_kms_server::start_default_test_kms_server().await;

    let input_file = std::path::PathBuf::from("../../test_data/plain.txt");
    let data = std::fs::read(&input_file)?;
    let digest = sha2::Sha256::digest(&data).to_vec();

    // Create EC key pair
    let (private_key_id, _public_key_id) =
        crate::actions::kms::elliptic_curves::keys::create_key_pair::CreateKeyPairAction::default()
            .run(ctx.get_owner_client())
            .await?;

    let cp = Some(
        crate::actions::kms::shared::CDigitalSignatureAlgorithmEC::ECDSAWithSHA256
            .to_cryptographic_parameters(),
    );

    // Build invalid KMIP Sign request with both fields
    let sign_request = cosmian_kmip::kmip_2_1::kmip_operations::Sign {
        unique_identifier: Some(
            cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                private_key_id.to_string(),
            ),
        ),
        cryptographic_parameters: cp,
        data: Some(data.into()),
        digested_data: Some(digest),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    };

    // Expect server-side error
    let res = ctx.get_owner_client().sign(sign_request).await;
    assert!(
        res.is_err(),
        "Expected error when both data and digested_data are set"
    );
    Ok(())
}

#[tokio::test]
async fn test_ecdsa_sign_with_digested_data() -> KmsCliResult<()> {
    log_init(None);

    let ctx = start_default_test_kms_server().await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain_1k.bin");
    let digest_file = tmp_path.join("plain.sha256");
    let sig_file = tmp_path.join("plain.sha256.ec.sig");

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
async fn test_ecdsa_streaming_sign_and_verify() -> KmsCliResult<()> {
    log_init(None);

    let ctx = start_default_test_kms_server().await;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain_1k.bin");
    let sig_file = tmp_path.join("plain.stream.ec.sig");

    let (private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    let data = std::fs::read(&input_file)?;
    let chunk_size: usize = 64;
    let mut offset: usize = 0;
    let mut correlation_value: Option<Vec<u8>> = None;

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
        // Carry forward accumulated correlation value for streaming
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
        signature_algorithm: CDigitalSignatureAlgorithmEC::ECDSAWithSHA256,
        output_file: None,
        digested: false,
    }
    .run(ctx.get_owner_client())
    .await?;
    assert_eq!(validity, ValidityIndicator::Valid);

    Ok(())
}

// Deterministic Ed25519: two signatures over same data must match
#[tokio::test]
async fn ed25519_deterministic_cli() -> KmsCliResult<()> {
    log_init(None);

    let ctx = start_default_test_kms_server().await;

    // Create Ed25519 key pair via CLI action
    let (private_key_id, _public_key_id) = CreateKeyPairAction {
        curve: Curve::Ed25519,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Prepare raw data
    let data = std::fs::read("../../test_data/plain.txt")?;

    // Build KMIP Sign request; EDDSA is selected by key type, CP can be None
    let sign_req = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(private_key_id.to_string())),
        cryptographic_parameters: None,
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

    assert_eq!(sig1, sig2, "Ed25519 signatures must be deterministic");
    Ok(())
}
