#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        extra::VENDOR_ID_COSMIAN,
        kmip_operations::{Export, ExportResponse},
        kmip_types::{CryptographicAlgorithm, KeyFormatType, UniqueIdentifier},
        requests::create_pqc_key_pair_request,
    },
};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::pqc::{
    pqc_private_key_pkcs8_to_raw, pqc_public_key_spki_to_raw,
};

use crate::{init_test_logging, start_default_test_kms_server};

/// Helper: export a key with a specific format.
async fn export_key(client: &KmsClient, key_id: &str, format: KeyFormatType) -> ExportResponse {
    let export_req = Export::new(
        UniqueIdentifier::TextString(key_id.to_owned()),
        false,
        None,
        Some(format),
    );
    client.export(export_req).await.unwrap()
}

/// Helper: export a key in its default (stored) format.
async fn export_key_default(client: &KmsClient, key_id: &str) -> ExportResponse {
    let export_req = Export::new(
        UniqueIdentifier::TextString(key_id.to_owned()),
        false,
        None,
        None,
    );
    client.export(export_req).await.unwrap()
}

/// Generate a PQC key pair, export the private and public keys as Raw bytes,
/// then export them again in default (PKCS#8) format and locally convert to Raw.
/// Assert that both approaches yield identical raw bytes.
async fn assert_pqc_export_raw_roundtrip(client: &KmsClient, algorithm: CryptographicAlgorithm) {
    // Create key pair
    let create_req =
        create_pqc_key_pair_request(VENDOR_ID_COSMIAN, Vec::<String>::new(), algorithm, false)
            .unwrap();
    let create_resp = client.create_key_pair(create_req).await.unwrap();
    let priv_id = create_resp.private_key_unique_identifier.to_string();
    let pub_id = create_resp.public_key_unique_identifier.to_string();

    // ── Private key: export as Raw ──
    let priv_raw_resp = export_key(client, &priv_id, KeyFormatType::Raw).await;
    let priv_raw_block = priv_raw_resp.object.key_block().unwrap();
    assert_eq!(
        priv_raw_block.key_format_type,
        KeyFormatType::Raw,
        "exported private key format must be Raw"
    );
    let priv_raw_bytes = priv_raw_block.key_bytes().unwrap();

    // ── Private key: export as PKCS#8 (default) and locally convert to Raw ──
    let priv_pkcs8_resp = export_key_default(client, &priv_id).await;
    let priv_pkcs8_block = priv_pkcs8_resp.object.key_block().unwrap();
    assert_eq!(
        priv_pkcs8_block.key_format_type,
        KeyFormatType::PKCS8,
        "default exported private key format must be PKCS8"
    );
    let priv_pkcs8_bytes = priv_pkcs8_block.key_bytes().unwrap();
    let priv_local_raw =
        pqc_private_key_pkcs8_to_raw(&priv_pkcs8_bytes).expect("local PKCS8→Raw conversion");

    assert_eq!(
        &priv_raw_bytes[..],
        priv_local_raw.as_slice(),
        "Private key: export-as-Raw must equal local PKCS8→Raw conversion for {algorithm:?}"
    );

    // ── Public key: export as Raw ──
    let pub_raw_resp = export_key(client, &pub_id, KeyFormatType::Raw).await;
    let pub_raw_block = pub_raw_resp.object.key_block().unwrap();
    assert_eq!(
        pub_raw_block.key_format_type,
        KeyFormatType::Raw,
        "exported public key format must be Raw"
    );
    let pub_raw_bytes = pub_raw_block.key_bytes().unwrap();

    // ── Public key: export as PKCS#8 (default) and locally convert to Raw ──
    let pub_pkcs8_resp = export_key_default(client, &pub_id).await;
    let pub_pkcs8_block = pub_pkcs8_resp.object.key_block().unwrap();
    assert_eq!(
        pub_pkcs8_block.key_format_type,
        KeyFormatType::PKCS8,
        "default exported public key format must be PKCS8"
    );
    let pub_pkcs8_bytes = pub_pkcs8_block.key_bytes().unwrap();
    let pub_local_raw =
        pqc_public_key_spki_to_raw(&pub_pkcs8_bytes).expect("local SPKI→Raw conversion");

    assert_eq!(
        &pub_raw_bytes[..],
        pub_local_raw.as_slice(),
        "Public key: export-as-Raw must equal local SPKI→Raw conversion for {algorithm:?}"
    );
}

/// ML-DSA-44: generate, export as Raw, and verify consistency.
#[tokio::test]
async fn test_pqc_export_raw_ml_dsa_44() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    Box::pin(assert_pqc_export_raw_roundtrip(
        &client,
        CryptographicAlgorithm::MLDSA_44,
    ))
    .await;
}

/// ML-KEM-768: generate, export as Raw, and verify consistency.
#[tokio::test]
async fn test_pqc_export_raw_ml_kem_768() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    Box::pin(assert_pqc_export_raw_roundtrip(
        &client,
        CryptographicAlgorithm::MLKEM_768,
    ))
    .await;
}

/// SLH-DSA-SHA2-128s: generate, export as Raw, and verify consistency.
#[tokio::test]
async fn test_pqc_export_raw_slh_dsa_sha2_128s() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    Box::pin(assert_pqc_export_raw_roundtrip(
        &client,
        CryptographicAlgorithm::SLHDSA_SHA2_128s,
    ))
    .await;
}
