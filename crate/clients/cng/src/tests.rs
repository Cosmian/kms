/// Integration tests for the CNG KSP.
///
/// These tests start an in-process KMS server and exercise the KSP through
/// the `backend` module (no Windows CNG infrastructure needed).
///
/// Tests are intentionally non-async (`#[test]` not `#[tokio::test]`):
/// `backend` functions call `RUNTIME.block_on(...)` internally, which panics
/// when called from inside an async Tokio context. We therefore start the
/// in-process KMS server with a short-lived local runtime, then drop it before
/// calling any backend function (which uses the separate static `RUNTIME`).
use serial_test::serial;
use test_kms_server::start_default_test_kms_server;

use crate::backend;

type KmsClient = ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kms_client::KmsClient;

/// Start (or reuse) the shared in-process KMS test server and return an owner
/// `KmsClient`.  A temporary Tokio runtime is used only for the async setup;
/// it is dropped before any `backend::*` function is called so that the
/// static `RUNTIME` inside `backend` can call `block_on` without conflict.
fn test_client() -> KmsClient {
    let rt = tokio::runtime::Runtime::new().expect("failed to create setup runtime");
    let ctx = rt.block_on(async { start_default_test_kms_server().await });
    // `ctx` is `&'static TestsContext` — server lives for the whole process.
    // Drop `rt` now so we are outside any runtime when backend functions run.
    drop(rt);
    ctx.get_owner_client()
}

/// Cleanup helper: revoke + destroy a key pair (best-effort).
fn cleanup_key_pair(client: &KmsClient, priv_id: &str, pub_id: &str) {
    drop(backend::revoke_key(client, priv_id));
    drop(backend::revoke_key(client, pub_id));
    drop(backend::destroy_key(client, priv_id));
    drop(backend::destroy_key(client, pub_id));
}

// ─── RSA key pair ─────────────────────────────────────────────────────────────

#[test]
#[serial]
fn test_create_rsa_key_pair() {
    let client = test_client();
    let (priv_id, pub_id) =
        backend::create_rsa_key_pair(&client, "test-rsa-2048", 2048, true)
            .expect("create_rsa_key_pair failed");
    assert!(!priv_id.is_empty(), "private key UUID must not be empty");
    assert!(!pub_id.is_empty(), "public key UUID must not be empty");

    // Cleanup
    cleanup_key_pair(&client, &priv_id, &pub_id);
}

#[test]
#[serial]
fn test_sign_with_rsa_key() {
    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::{
        HashingAlgorithm, PaddingMethod,
    };

    let client = test_client();
    let (priv_id, pub_id) =
        backend::create_rsa_key_pair(&client, "test-rsa-sign", 2048, true)
            .expect("create_rsa_key_pair failed");

    // SHA-256 of "hello"
    let hash = [
        0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9,
        0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62,
        0x93, 0x8b, 0x98, 0x24,
    ];
    let sig = backend::sign_hash(
        &client,
        &priv_id,
        &hash,
        HashingAlgorithm::SHA256,
        Some(PaddingMethod::PKCS1v15),
        None,
    )
    .expect("sign_hash failed");
    assert!(!sig.is_empty(), "signature must not be empty");

    // Cleanup
    cleanup_key_pair(&client, &priv_id, &pub_id);
}

// ─── EC key pair ──────────────────────────────────────────────────────────────

#[test]
#[serial]
fn test_create_ec_key_pair() {
    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_2_1::kmip_types::RecommendedCurve;

    let client = test_client();
    let (priv_id, pub_id) =
        backend::create_ec_key_pair(&client, "test-ec-p256", RecommendedCurve::P256)
            .expect("create_ec_key_pair failed");
    assert!(!priv_id.is_empty(), "private key UUID must not be empty");
    assert!(!pub_id.is_empty(), "public key UUID must not be empty");

    // Cleanup
    cleanup_key_pair(&client, &priv_id, &pub_id);
}

// ─── Key locate & tag ─────────────────────────────────────────────────────────

#[test]
#[serial]
fn test_locate_key_by_name() {
    let client = test_client();
    let (priv_id, pub_id) =
        backend::create_rsa_key_pair(&client, "test-locate", 2048, true)
            .expect("create_rsa_key_pair failed");

    let found_id = backend::locate_key_by_name(&client, "test-locate")
        .expect("locate_key_by_name failed");
    assert_eq!(
        found_id, priv_id,
        "locate must return the private key UUID"
    );

    // Cleanup
    cleanup_key_pair(&client, &priv_id, &pub_id);
}

// ─── List CNG keys ────────────────────────────────────────────────────────────

#[test]
#[serial]
fn test_list_cng_keys() {
    let client = test_client();

    // Create two keys
    let (priv1, pub1) =
        backend::create_rsa_key_pair(&client, "list-test-key-1", 2048, true)
            .expect("create key 1 failed");
    let (priv2, pub2) =
        backend::create_rsa_key_pair(&client, "list-test-key-2", 2048, false)
            .expect("create key 2 failed");

    let keys = backend::list_cng_keys(&client).expect("list_cng_keys failed");
    let names: Vec<&str> = keys.iter().map(|(n, _)| n.as_str()).collect();
    assert!(
        names.contains(&"list-test-key-1"),
        "key 1 not found in list"
    );
    assert!(
        names.contains(&"list-test-key-2"),
        "key 2 not found in list"
    );

    // Cleanup
    cleanup_key_pair(&client, &priv1, &pub1);
    cleanup_key_pair(&client, &priv2, &pub2);
}

// ─── Export public key ────────────────────────────────────────────────────────

#[test]
#[serial]
fn test_export_public_key_spki() {
    let client = test_client();
    let (priv_id, pub_id) =
        backend::create_rsa_key_pair(&client, "test-export-pub", 2048, true)
            .expect("create_rsa_key_pair failed");

    let spki = backend::export_public_key_spki(&client, &pub_id)
        .expect("export_public_key_spki failed");
    // SPKI DER starts with 0x30 (SEQUENCE tag)
    assert_eq!(spki[0], 0x30, "exported data must start with DER SEQUENCE tag");

    // Cleanup
    cleanup_key_pair(&client, &priv_id, &pub_id);
}

// ─── EC P-384 and P-521 key pairs ────────────────────────────────────────────

#[test]
#[serial]
fn test_create_ec_key_pair_p384() {
    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_2_1::kmip_types::RecommendedCurve;

    let client = test_client();
    let (priv_id, pub_id) =
        backend::create_ec_key_pair(&client, "test-ec-p384", RecommendedCurve::P384)
            .expect("create_ec_key_pair P-384 failed");
    assert!(!priv_id.is_empty());

    // Sign with ECDSA + SHA-384
    let hash: [u8; 48] = [0xAB; 48];
    let sig = backend::sign_hash(
        &client,
        &priv_id,
        &hash,
        ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm::SHA384,
        None,
        None,
    )
    .expect("sign_hash ECDSA P-384 failed");
    assert!(!sig.is_empty(), "P-384 ECDSA signature must not be empty");

    cleanup_key_pair(&client, &priv_id, &pub_id);
}

#[test]
#[serial]
fn test_create_ec_key_pair_p521() {
    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_2_1::kmip_types::RecommendedCurve;

    let client = test_client();
    let (priv_id, pub_id) =
        backend::create_ec_key_pair(&client, "test-ec-p521", RecommendedCurve::P521)
            .expect("create_ec_key_pair P-521 failed");
    assert!(!priv_id.is_empty());

    // Export public key
    let spki = backend::export_public_key_spki(&client, &pub_id)
        .expect("export P-521 SPKI failed");
    assert_eq!(spki[0], 0x30, "P-521 SPKI must start with SEQUENCE tag");

    cleanup_key_pair(&client, &priv_id, &pub_id);
}

// ─── RSA-PSS sign ─────────────────────────────────────────────────────────────

#[test]
#[serial]
fn test_sign_rsa_pss() {
    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::{
        HashingAlgorithm, PaddingMethod,
    };

    let client = test_client();
    let (priv_id, pub_id) =
        backend::create_rsa_key_pair(&client, "test-rsa-pss", 2048, true)
            .expect("create_rsa_key_pair failed");

    let hash: [u8; 32] = [0x42; 32];
    let sig = backend::sign_hash(
        &client,
        &priv_id,
        &hash,
        HashingAlgorithm::SHA256,
        Some(PaddingMethod::PSS),
        Some(32),
    )
    .expect("sign_hash RSA-PSS failed");
    assert!(!sig.is_empty(), "RSA-PSS signature must not be empty");
    assert_eq!(sig.len(), 256, "RSA-2048 PSS signature must be 256 bytes");

    cleanup_key_pair(&client, &priv_id, &pub_id);
}

// ─── Signature verification ──────────────────────────────────────────────────

#[test]
#[serial]
fn test_verify_rsa_pkcs1v15() {
    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::{
        HashingAlgorithm, PaddingMethod,
    };

    let client = test_client();
    let (priv_id, pub_id) =
        backend::create_rsa_key_pair(&client, "test-verify-rsa", 2048, true)
            .expect("create_rsa_key_pair failed");

    let hash: [u8; 32] = [0x55; 32];
    let sig = backend::sign_hash(
        &client,
        &priv_id,
        &hash,
        HashingAlgorithm::SHA256,
        Some(PaddingMethod::PKCS1v15),
        None,
    )
    .expect("sign_hash failed");

    // Verify with correct hash
    let valid = backend::verify_signature(
        &client,
        &pub_id,
        &hash,
        &sig,
        HashingAlgorithm::SHA256,
        Some(PaddingMethod::PKCS1v15),
        None,
    )
    .expect("verify_signature failed");
    assert!(valid, "RSA PKCS1v15 signature must be valid");

    // Verify with wrong hash must fail
    let wrong_hash: [u8; 32] = [0xAA; 32];
    let invalid = backend::verify_signature(
        &client,
        &pub_id,
        &wrong_hash,
        &sig,
        HashingAlgorithm::SHA256,
        Some(PaddingMethod::PKCS1v15),
        None,
    )
    .expect("verify_signature failed");
    assert!(!invalid, "RSA PKCS1v15 signature must be invalid for wrong hash");

    cleanup_key_pair(&client, &priv_id, &pub_id);
}

#[test]
#[serial]
fn test_verify_ecdsa_p256() {
    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::{
        kmip_0::kmip_types::HashingAlgorithm,
        kmip_2_1::kmip_types::RecommendedCurve,
    };

    let client = test_client();
    let (priv_id, pub_id) =
        backend::create_ec_key_pair(&client, "test-verify-ec", RecommendedCurve::P256)
            .expect("create_ec_key_pair failed");

    let hash: [u8; 32] = [0x77; 32];
    let sig = backend::sign_hash(
        &client,
        &priv_id,
        &hash,
        HashingAlgorithm::SHA256,
        None,
        None,
    )
    .expect("sign_hash ECDSA failed");

    let valid = backend::verify_signature(
        &client,
        &pub_id,
        &hash,
        &sig,
        HashingAlgorithm::SHA256,
        None,
        None,
    )
    .expect("verify_signature failed");
    assert!(valid, "ECDSA P-256 signature must be valid");

    cleanup_key_pair(&client, &priv_id, &pub_id);
}

// ─── RSA OAEP encrypt/decrypt ────────────────────────────────────────────────

#[test]
#[serial]
fn test_rsa_encrypt_decrypt_oaep() {
    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::{
        HashingAlgorithm, PaddingMethod,
    };

    let client = test_client();
    let (priv_id, pub_id) =
        backend::create_rsa_key_pair(&client, "test-enc-oaep", 2048, false)
            .expect("create_rsa_key_pair failed");

    let plaintext = b"CNG KSP OAEP round-trip test";
    let ct = backend::encrypt_data(
        &client,
        &pub_id,
        plaintext,
        PaddingMethod::OAEP,
        Some(HashingAlgorithm::SHA256),
    )
    .expect("encrypt_data OAEP failed");
    assert!(!ct.is_empty());

    let pt = backend::decrypt_data(
        &client,
        &priv_id,
        &ct,
        PaddingMethod::OAEP,
        Some(HashingAlgorithm::SHA256),
    )
    .expect("decrypt_data OAEP failed");
    assert_eq!(&*pt, plaintext, "OAEP round-trip must recover plaintext");

    cleanup_key_pair(&client, &priv_id, &pub_id);
}
