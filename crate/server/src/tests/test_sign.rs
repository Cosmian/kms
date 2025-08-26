use std::sync::Arc;

use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::kmip_types::{
    RecommendedCurve, UniqueIdentifier,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::EMPTY_TAGS,
    kmip_operations::{
        CreateKeyPairResponse, Sign, SignResponse, SignatureVerify, SignatureVerifyResponse,
    },
    kmip_types::ValidityIndicator,
    requests::{create_ec_key_pair_request, create_rsa_key_pair_request},
};
use cosmian_logger::log_init;
use tracing::debug;
use zeroize::Zeroizing;

use crate::{
    config::ServerParams, core::KMS, result::KResult, tests::test_utils::https_clap_config,
};

const TEST_DATA: &[u8] = b"Hello, world! This is a test message for signing.";

/// Generic signing test function that works with any key pair creation response
///
/// # Arguments
/// * `test_streaming` - If true, tests streaming signature with multiple sign calls
async fn test_sign_verify(
    kms: Arc<KMS>,
    owner: &str,
    key_pair_response: CreateKeyPairResponse,
    expected_signature_length_range: (usize, usize),
    test_name: &str,
    test_streaming: bool,
) -> KResult<()> {
    let private_key_id = key_pair_response.private_key_unique_identifier;
    let public_key_id = key_pair_response.public_key_unique_identifier;

    let signature = if test_streaming {
        // Test streaming signature with multiple calls
        test_streaming_signature(kms.clone(), owner, &private_key_id).await?
    } else {
        // Test single-call signature
        test_single_signature(kms.clone(), owner, &private_key_id).await?
    };

    // Check signature length is within expected range
    let (min_len, max_len) = expected_signature_length_range;
    if min_len == max_len {
        assert_eq!(
            signature.len(),
            min_len,
            "{test_name} signature should be {min_len} bytes",
        );
    } else {
        assert!(
            signature.len() >= min_len && signature.len() <= max_len,
            "Expected {test_name} signature length between {min_len}-{max_len} bytes, got {}",
            signature.len()
        );
    }

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

/// Test single-call signature
async fn test_single_signature(
    kms: Arc<KMS>,
    owner: &str,
    private_key_id: &UniqueIdentifier,
) -> KResult<Vec<u8>> {
    let sign_request = Sign {
        unique_identifier: Some(private_key_id.clone()),
        data: Some(Zeroizing::new(TEST_DATA.to_vec())),
        ..Default::default()
    };

    let sign_response: SignResponse = kms.sign(sign_request, owner, None).await?;

    assert_eq!(sign_response.unique_identifier, *private_key_id);
    assert!(sign_response.signature_data.is_some());

    Ok(sign_response.signature_data.unwrap())
}

/// Test streaming signature with multiple calls
async fn test_streaming_signature(
    kms: Arc<KMS>,
    owner: &str,
    private_key_id: &UniqueIdentifier,
) -> KResult<Vec<u8>> {
    // Split test data into chunks for streaming
    let chunk_size = TEST_DATA.len() / 3;
    let chunks: Vec<&[u8]> = TEST_DATA.chunks(chunk_size).collect();

    // First call - init with first chunk
    let init_request = Sign {
        unique_identifier: Some(private_key_id.clone()),
        data: Some(Zeroizing::new(chunks[0].to_vec())),
        init_indicator: Some(true),
        final_indicator: Some(false),
        ..Default::default()
    };

    let init_response: SignResponse = kms.sign(init_request, owner, None).await?;
    assert_eq!(init_response.unique_identifier, *private_key_id);
    let mut correlation_value = init_response.correlation_value;

    // Middle calls - continue with remaining chunks except the last
    for chunk in chunks.iter().skip(1).take(chunks.len() - 2) {
        let continue_request = Sign {
            unique_identifier: Some(private_key_id.clone()),
            data: Some(Zeroizing::new(chunk.to_vec())),
            correlation_value: correlation_value.clone(),
            init_indicator: Some(false),
            final_indicator: Some(false),
            ..Default::default()
        };

        let continue_response: SignResponse = kms.sign(continue_request, owner, None).await?;
        assert_eq!(continue_response.unique_identifier, *private_key_id);
        correlation_value = continue_response.signature_data;
        debug!("Second correlation value: {correlation_value:?}");
    }

    // Final call - finalize with last chunk
    let final_request = Sign {
        unique_identifier: Some(private_key_id.clone()),
        data: Some(Zeroizing::new(chunks.last().unwrap().to_vec())),
        correlation_value: correlation_value.clone(),
        init_indicator: Some(false),
        final_indicator: Some(true),
        ..Default::default()
    };
    let final_response: SignResponse = kms.sign(final_request, owner, None).await?;
    debug!("Last correlation value: {correlation_value:?}");

    assert_eq!(final_response.unique_identifier, *private_key_id);
    assert!(final_response.signature_data.is_some());

    Ok(final_response.signature_data.unwrap())
}

#[tokio::test]
async fn test_sign_rsa() -> KResult<()> {
    log_init(None);

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

    // Test single-call signature
    test_sign_verify(
        kms.clone(),
        owner,
        response.clone(),
        (256, 256),
        "RSA 2048",
        false,
    )
    .await
}

#[tokio::test]
async fn test_sign_ecdsa() -> KResult<()> {
    log_init(None);

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

    // Test single-call signature
    test_sign_verify(
        kms.clone(),
        owner,
        response.clone(),
        (64, 72),
        "ECDSA P-256",
        false,
    )
    .await
}
