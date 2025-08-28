use std::sync::Arc;

use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::kmip_types::{
    RecommendedCurve, UniqueIdentifier,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::EMPTY_TAGS,
    kmip_operations::{Sign, SignResponse, SignatureVerify},
    kmip_types::ValidityIndicator,
    requests::{create_ec_key_pair_request, create_rsa_key_pair_request},
};
use cosmian_logger::log_init;
use zeroize::Zeroizing;

use crate::{
    config::ServerParams, core::KMS, result::KResult, tests::test_utils::https_clap_config,
};

const TEST_DATA: &[u8] = b"Hello, world! This is a test message for signing.";
const TEST_DATA_DIGESTED: &[u8] =
    b"b93c92a057b6d5d9fc506c6cccb41d4a944ce1f8954d7e051aa5813e2aa75261";

/// Test signing and verification (with and without digested data)
async fn test_single_signature(
    kms: Arc<KMS>,
    owner: &str,
    private_key_id: &UniqueIdentifier,
    public_key_id: &UniqueIdentifier,
) -> KResult<()> {
    // Sign using the raw data
    let sign_request = Sign {
        unique_identifier: Some(private_key_id.clone()),
        data: Some(Zeroizing::new(TEST_DATA.to_vec())),
        ..Default::default()
    };
    let sign_response: SignResponse = kms.sign(sign_request, owner, None).await?;
    assert_eq!(sign_response.unique_identifier, *private_key_id);
    assert!(sign_response.signature_data.is_some());

    // Verify signature using raw data
    let signature = sign_response.signature_data.clone().unwrap();
    // Test signature verification using the public key and raw data
    let verify_request = SignatureVerify {
        unique_identifier: Some(public_key_id.clone()),
        data: Some(TEST_DATA.to_vec()),
        signature_data: Some(signature.clone()),
        ..Default::default()
    };
    let verify_response = kms.signature_verify(verify_request, owner, None).await?;
    // Verify the signature verification response
    assert_eq!(verify_response.unique_identifier, public_key_id.clone());
    assert_eq!(
        verify_response.validity_indicator,
        Some(ValidityIndicator::Valid)
    );

    // Now test signing with digested data
    let sign_request = Sign {
        unique_identifier: Some(private_key_id.clone()),
        digested_data: Some(hex::decode(TEST_DATA_DIGESTED).unwrap()),
        ..Default::default()
    };
    let sign_response: SignResponse = kms.sign(sign_request, owner, None).await?;
    assert_eq!(sign_response.unique_identifier, *private_key_id);
    assert!(sign_response.signature_data.is_some());

    // Verify signature
    let signature = sign_response.signature_data.unwrap();
    // Test signature verification using the public key and digested data
    let verify_request = SignatureVerify {
        unique_identifier: Some(public_key_id.clone()),
        digested_data: Some(hex::decode(TEST_DATA_DIGESTED).unwrap()),
        signature_data: Some(signature.clone()),
        ..Default::default()
    };
    let verify_response = kms.signature_verify(verify_request, owner, None).await?;
    // Verify the signature verification response
    assert_eq!(verify_response.unique_identifier, public_key_id.clone());
    assert_eq!(
        verify_response.validity_indicator,
        Some(ValidityIndicator::Valid)
    );

    Ok(())
}

/// Test streaming signature with multiple calls
async fn _test_streaming_signature(
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

    assert_eq!(final_response.unique_identifier, *private_key_id);
    assert!(final_response.signature_data.is_some());

    Ok(final_response.signature_data.unwrap())
}

/// Test streaming signature verification with multiple calls
async fn test_streaming_signature_verification(
    kms: Arc<KMS>,
    owner: &str,
    private_key_id: &UniqueIdentifier,
    public_key_id: &UniqueIdentifier,
) -> KResult<()> {
    // First, create a signature using regular (non-streaming) sign
    let sign_request = Sign {
        unique_identifier: Some(private_key_id.clone()),
        data: Some(Zeroizing::new(TEST_DATA.to_vec())),
        ..Default::default()
    };
    let sign_response: SignResponse = kms.sign(sign_request, owner, None).await?;
    let signature = sign_response.signature_data.unwrap();

    // Now test streaming verification
    // Split test data into chunks for streaming verification
    let chunk_size = TEST_DATA.len() / 3;
    let chunks: Vec<&[u8]> = TEST_DATA.chunks(chunk_size).collect();

    // First call - init with first chunk
    let init_request = SignatureVerify {
        unique_identifier: Some(public_key_id.clone()),
        data: Some(chunks[0].to_vec()),
        signature_data: None, // No signature data in init call
        init_indicator: Some(true),
        final_indicator: Some(false),
        ..Default::default()
    };

    let init_response = kms.signature_verify(init_request, owner, None).await?;
    assert_eq!(init_response.unique_identifier, public_key_id.clone());
    assert!(init_response.validity_indicator.is_none()); // No result yet
    let mut correlation_value = init_response.correlation_value;
    assert!(correlation_value.is_some());

    // Middle calls - continue with remaining chunks except the last
    for chunk in chunks.iter().skip(1).take(chunks.len() - 2) {
        let continue_request = SignatureVerify {
            unique_identifier: Some(public_key_id.clone()),
            data: Some(chunk.to_vec()),
            signature_data: None,
            correlation_value: correlation_value.clone(),
            init_indicator: Some(false),
            final_indicator: Some(false),
            ..Default::default()
        };

        let continue_response = kms.signature_verify(continue_request, owner, None).await?;
        assert_eq!(continue_response.unique_identifier, public_key_id.clone());
        assert!(continue_response.validity_indicator.is_none()); // No result yet
        correlation_value = continue_response.correlation_value;
        assert!(correlation_value.is_some());
    }

    // Final call - finalize with last chunk and signature
    let final_request = SignatureVerify {
        unique_identifier: Some(public_key_id.clone()),
        data: Some(chunks.last().unwrap().to_vec()),
        signature_data: Some(signature),
        correlation_value: correlation_value.clone(),
        init_indicator: Some(false),
        final_indicator: Some(true),
        ..Default::default()
    };
    let final_response = kms.signature_verify(final_request, owner, None).await?;

    assert_eq!(final_response.unique_identifier, public_key_id.clone());
    assert_eq!(
        final_response.validity_indicator,
        Some(ValidityIndicator::Valid)
    );
    assert!(final_response.correlation_value.is_none()); // No correlation value in final response

    Ok(())
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
    test_single_signature(
        kms.clone(),
        owner,
        &response.private_key_unique_identifier,
        &response.public_key_unique_identifier,
    )
    .await?;

    // Test streaming signature verification
    test_streaming_signature_verification(
        kms.clone(),
        owner,
        &response.private_key_unique_identifier,
        &response.public_key_unique_identifier,
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
    test_single_signature(
        kms.clone(),
        owner,
        &response.private_key_unique_identifier,
        &response.public_key_unique_identifier,
    )
    .await?;

    // Test streaming signature verification
    test_streaming_signature_verification(
        kms.clone(),
        owner,
        &response.private_key_unique_identifier,
        &response.public_key_unique_identifier,
    )
    .await
}

#[tokio::test]
async fn test_sign_eddsa() -> KResult<()> {
    log_init(None);

    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_user_eddsa_sign";

    // Create EdDSA key pair (Ed25519)
    let request = create_ec_key_pair_request(
        None,                           // private_key_id
        EMPTY_TAGS,                     // tags
        RecommendedCurve::CURVEED25519, // curve
        false,                          // sensitive
        None,                           // wrapping_key_id
    )?;
    let response = kms.create_key_pair(request, owner, None, None).await?;

    // Test single-call signature
    test_single_signature(
        kms.clone(),
        owner,
        &response.private_key_unique_identifier,
        &response.public_key_unique_identifier,
    )
    .await?;

    // Test streaming signature verification
    test_streaming_signature_verification(
        kms.clone(),
        owner,
        &response.private_key_unique_identifier,
        &response.public_key_unique_identifier,
    )
    .await
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_sign_secp256k1() -> KResult<()> {
    log_init(None);

    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_user_secp256k1_sign";

    // Create secp256k1 key pair
    let request = create_ec_key_pair_request(
        None,                        // private_key_id
        EMPTY_TAGS,                  // tags
        RecommendedCurve::SECP256K1, // curve
        false,                       // sensitive
        None,                        // wrapping_key_id
    )?;
    let response = kms.create_key_pair(request, owner, None, None).await?;

    // Test single-call signature
    test_single_signature(
        kms.clone(),
        owner,
        &response.private_key_unique_identifier,
        &response.public_key_unique_identifier,
    )
    .await?;

    // Test streaming signature verification
    test_streaming_signature_verification(
        kms.clone(),
        owner,
        &response.private_key_unique_identifier,
        &response.public_key_unique_identifier,
    )
    .await
}
