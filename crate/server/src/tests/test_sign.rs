use std::sync::Arc;

use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::kmip_types::RecommendedCurve;
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::EMPTY_TAGS,
    kmip_operations::{Sign, SignResponse, SignatureVerify, SignatureVerifyResponse},
    kmip_types::ValidityIndicator,
    requests::{create_ec_key_pair_request, create_rsa_key_pair_request},
};
use cosmian_logger::log_init;
use zeroize::Zeroizing;

use crate::{
    config::ServerParams, core::KMS, result::KResult, tests::test_utils::https_clap_config,
};

const TEST_DATA: &[u8] = b"Hello, world! This is a test message for signing.";

#[tokio::test]
async fn test_rsa_sign() -> KResult<()> {
    log_init(None);

    // Use a simpler configuration without TLS
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_user_rsa_sign";

    // Create RSA key pair
    let request = create_rsa_key_pair_request(
        None,       // private_key_id
        EMPTY_TAGS, // tags
        2048,       // cryptographic_length
        false,      // sensitive
        None,       // wrapping_key_id
    )?;
    let response = kms.create_key_pair(request, owner, None, None).await?;
    let private_key_id = response.private_key_unique_identifier;
    let public_key_id = response.public_key_unique_identifier;

    // Test signing with data
    let sign_request = Sign {
        unique_identifier: Some(private_key_id.clone()),
        data: Some(Zeroizing::new(TEST_DATA.to_vec())),
        ..Default::default()
    };

    let sign_response: SignResponse = kms.sign(sign_request, owner, None).await?;

    // Verify we got a signature back
    assert_eq!(sign_response.unique_identifier, private_key_id);
    assert!(sign_response.signature_data.is_some());
    let signature = sign_response.signature_data.unwrap();

    // RSA 2048 PSS signature should be 256 bytes
    assert_eq!(signature.len(), 256);

    // Test signature verification using the public key
    let verify_request = SignatureVerify {
        unique_identifier: Some(public_key_id.clone()),
        data: Some(TEST_DATA.to_vec()),
        signature_data: Some(signature.clone()),
        ..Default::default()
    };

    let verify_response: SignatureVerifyResponse =
        kms.signature_verify(verify_request, owner, None).await?;

    // Verify the signature verification response
    assert_eq!(verify_response.unique_identifier, public_key_id);
    assert_eq!(
        verify_response.validity_indicator,
        Some(ValidityIndicator::Valid)
    );

    // Test verification with wrong data should fail
    let wrong_data = b"Wrong data for verification";
    let verify_wrong_request = SignatureVerify {
        unique_identifier: Some(public_key_id),
        data: Some(wrong_data.to_vec()),
        signature_data: Some(signature),
        ..Default::default()
    };

    let verify_wrong_response: SignatureVerifyResponse = kms
        .signature_verify(verify_wrong_request, owner, None)
        .await?;
    assert_eq!(
        verify_wrong_response.validity_indicator,
        Some(ValidityIndicator::Invalid)
    );

    Ok(())
}

#[tokio::test]
async fn test_ecdsa_sign() -> KResult<()> {
    log_init(None);

    // Use a simpler configuration without TLS
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_user_ecdsa_sign";

    // Create ECDSA key pair (P-256)
    let request = create_ec_key_pair_request(
        None,                   // private_key_id
        EMPTY_TAGS,             // tags
        RecommendedCurve::P256, // curve
        false,                  // sensitive
        None,                   // wrapping_key_id
    )?;
    let response = kms.create_key_pair(request, owner, None, None).await?;
    let private_key_id = response.private_key_unique_identifier;
    let public_key_id = response.public_key_unique_identifier;

    // Test signing with data
    let sign_request = Sign {
        unique_identifier: Some(private_key_id.clone()),
        data: Some(Zeroizing::new(TEST_DATA.to_vec())),
        ..Default::default()
    };

    let sign_response: SignResponse = kms.sign(sign_request, owner, None).await?;

    // Verify we got a signature back
    assert_eq!(sign_response.unique_identifier, private_key_id);
    assert!(sign_response.signature_data.is_some());
    let signature = sign_response.signature_data.unwrap();

    // ECDSA P-256 signature should be around 70-72 bytes (DER encoded)
    assert!(
        signature.len() >= 64 && signature.len() <= 72,
        "Expected ECDSA signature length between 64-72 bytes, got {}",
        signature.len()
    );

    // Test signature verification using the public key
    let verify_request = SignatureVerify {
        unique_identifier: Some(public_key_id.clone()),
        data: Some(TEST_DATA.to_vec()),
        signature_data: Some(signature.clone()),
        ..Default::default()
    };

    let verify_response: SignatureVerifyResponse =
        kms.signature_verify(verify_request, owner, None).await?;

    // Verify the signature verification response
    assert_eq!(verify_response.unique_identifier, public_key_id);
    assert_eq!(
        verify_response.validity_indicator,
        Some(ValidityIndicator::Valid)
    );

    // Test verification with wrong data should fail
    let wrong_data = b"Wrong data for verification";
    let verify_wrong_request = SignatureVerify {
        unique_identifier: Some(public_key_id),
        data: Some(wrong_data.to_vec()),
        signature_data: Some(signature),
        ..Default::default()
    };

    let verify_wrong_response: SignatureVerifyResponse = kms
        .signature_verify(verify_wrong_request, owner, None)
        .await?;
    assert_eq!(
        verify_wrong_response.validity_indicator,
        Some(ValidityIndicator::Invalid)
    );

    Ok(())
}
