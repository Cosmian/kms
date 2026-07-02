//! RFC 7515 / RFC 7516 test vectors — known-answer and known-key round-trip tests.
//!
//! # Coverage
//!
//! ## Implemented
//!
//! | RFC appendix | Algorithm | Test |
//! |---|---|---|
//! | RFC 7515 §A.1 | HMAC-SHA256 (HS256) | [`test_rfc7515_a1_hs256_known_answer`] |
//! | RFC 7515 §A.2 | RS256 (RSA-2048) | [`test_rfc7515_a2_rs256_known_key_round_trip`] |
//! | RFC 7515 §A.3 | ES256 (ECDSA P-256) | [`test_rfc7515_a3_es256_known_key_round_trip`] |
//! | RFC 7515 §A.4 | ES512 (ECDSA P-521) | [`test_rfc7515_a4_es512_known_key_round_trip`] |
//! | RFC 7516 §A.1 | RSAES-OAEP + A256GCM | [`test_rfc7516_a1_rsa_oaep_a256gcm_known_key`] |
//!
//! ## Not yet implemented (blocked — to be added in future versions)
//!
//! | RFC appendix | Blocked by |
//! |---|---|
//! | RFC 7516 §A.2 — RSAES-PKCS1-v1_5 + A128CBC-HS256 | RSA-PKCS1v1.5 + AES-CBC not implemented |
//! | RFC 7516 §A.3 — AES Key Wrap + A128CBC-HS256 | AES key-wrap + AES-CBC not implemented |
//! | RFC 7516 §A.5 — dir + A128CBC-HS256 | AES-CBC not implemented; no normative GCM vector |
//! | RFC 7518 §B — AES_CBC_HMAC_SHA2 KAT | AES-CBC not implemented |
//! | RFC 7518 §C — ECDH-ES key agreement | ECDH-ES not implemented |

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, PrivateKey},
        kmip_operations::{CreateKeyPairResponse, ImportResponse},
        kmip_types::{CryptographicAlgorithm, KeyFormatType, RecommendedCurve},
        requests::{
            create_ec_key_pair_request, create_rsa_key_pair_request, import_object_request,
        },
    },
};
use cosmian_logger::log_init;
use openssl::{
    bn::BigNum,
    pkey::PKey,
    rsa::Rsa,
    symm::{Cipher, encrypt_aead},
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{result::KResult, tests::test_utils};

/// RFC 7515 §Appendix A.1 — HMAC-SHA256 known-answer test.
///
/// Source: <https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1>
///
/// Key, signing input, and expected MAC (`dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`)
/// are taken verbatim from the RFC. Any regression in the HS256 code path will
/// produce a different MAC and fail with a clear message.
#[tokio::test]
async fn test_rfc7515_a1_hs256_known_answer() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    // RFC 7515 §A.1 — 512-bit key (base64url):
    //   AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow
    let key_bytes = URL_SAFE_NO_PAD
        .decode(
            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        )
        .expect("RFC 7515 A.1 key is valid base64url");
    let kid = super::common::import_hmac_key(&app, key_bytes).await?;

    // RFC 7515 §A.1 — JWS Signing Input:
    //   ASCII(BASE64URL(UTF8(Protected Header)) || '.' || BASE64URL(Payload))
    //   Embedded CR+LF sequences are part of the RFC test data.
    let signing_input: &[u8] =
        b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9\
          .eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    let data_b64 = URL_SAFE_NO_PAD.encode(signing_input);

    let compute_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "HS256", "data": data_b64}),
        "/v1/crypto/mac",
    )
    .await?;

    // RFC 7515 §A.1 — expected MAC (base64url):
    let got_mac = compute_resp["mac"].as_str().expect("missing mac field");
    assert_eq!(
        got_mac, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        "RFC 7515 §A.1 (https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1): \
         HS256 HMAC-SHA256 over JWS signing input must match the known-answer vector"
    );

    // Verify the correct MAC is accepted
    let verify_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "HS256", "data": data_b64, "mac": got_mac}),
        "/v1/crypto/mac",
    )
    .await?;
    assert_eq!(
        verify_resp["valid"].as_bool(),
        Some(true),
        "RFC 7515 §A.1: correct MAC must verify as valid=true"
    );

    Ok(())
}

/// RFC 7515 §Appendix A.2 — RS256 (RSA-2048) known-key round-trip.
///
/// Source: <https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2>
///
/// The RFC JWK uses a 2048-bit RSA key. We generate a fresh 2048-bit key pair
/// and confirm sign → verify succeeds end-to-end.
///
/// **Not a known-answer test** because our `/v1/crypto/verify` requires a `kid`
/// field in the JWS protected header; the RFC compact JWS header is
/// `{"alg":"RS256"}` (no `kid`). When kid-less verification is supported,
/// replace this with a full known-answer test using the exact RFC signing input
/// and signature from Appendix A.2.
#[tokio::test]
async fn test_rfc7515_a2_rs256_known_key_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kp_req =
        create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, EMPTY_TAGS, 2048, false, None)?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let private_kid = kp_resp.private_key_unique_identifier.to_string();
    let public_kid = kp_resp.public_key_unique_identifier.to_string();

    super::common::sign_verify_round_trip(&app, "RS256", &private_kid, &public_kid).await
}

/// RFC 7515 §Appendix A.3 — ES256 (ECDSA P-256) known-key round-trip.
///
/// Source: <https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3>
///
/// RFC JWK: `kty=EC, crv=P-256`, private scalar `d`.
/// The RFC signature is non-deterministic (random nonce); we confirm
/// sign → verify succeeds for a freshly generated P-256 key pair.
///
/// Full known-answer test deferred — same `kid` constraint as A.2.
#[tokio::test]
async fn test_rfc7515_a3_es256_known_key_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kp_req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P256,
        false,
        None,
    )?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let private_kid = kp_resp.private_key_unique_identifier.to_string();
    let public_kid = kp_resp.public_key_unique_identifier.to_string();

    super::common::sign_verify_round_trip(&app, "ES256", &private_kid, &public_kid).await
}

/// RFC 7515 §Appendix A.4 — ES512 (ECDSA P-521) known-key round-trip.
///
/// Source: <https://www.rfc-editor.org/rfc/rfc7515#appendix-A.4>
///
/// RFC JWK: `kty=EC, crv=P-521`.
/// Same constraints as A.3 (non-deterministic signature + `kid` requirement).
/// Full known-answer test deferred until kid-less verify is supported.
#[tokio::test]
async fn test_rfc7515_a4_es512_known_key_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kp_req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P521,
        false,
        None,
    )?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let private_kid = kp_resp.private_key_unique_identifier.to_string();
    let public_kid = kp_resp.public_key_unique_identifier.to_string();

    super::common::sign_verify_round_trip(&app, "ES512", &private_kid, &public_kid).await
}

/// RFC 7516 §Appendix A.1 — RSAES-OAEP + A256GCM known-key decrypt.
///
/// Source: <https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1>
///
/// The RFC private key (JWK) and `encrypted_key` (RSA-OAEP ciphertext of the
/// known CEK) are taken verbatim from the RFC. Because the RFC protected header
/// lacks a `kid` field (required by the KMS `/v1/crypto/decrypt` endpoint), a
/// modified header is assembled and the AES-GCM ciphertext recomputed with the
/// matching AAD.
///
/// What this verifies:
/// - The KMS correctly imports the RFC 2048-bit RSA private key
/// - RSA-OAEP unwrap of the RFC `encrypted_key` recovers the exact RFC CEK
/// - AES-256-GCM decrypt with the recovered CEK produces the RFC plaintext
///
/// Note: RSA-OAEP is non-deterministic, so `encrypted_key` cannot be reproduced;
/// AES-GCM is deterministic — the RFC plaintext is the fixed assertion.
#[tokio::test]
#[allow(clippy::many_single_char_names)]
async fn test_rfc7516_a1_rsa_oaep_a256gcm_known_key() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None, None).await;

    // ── RFC 7516 §A.1.3 — RSA-2048 private key (JWK, verbatim) ──────────────
    // Source: https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1
    let decode_b64 = |s: &str| URL_SAFE_NO_PAD.decode(s).expect("RFC base64url is valid");

    let n = BigNum::from_slice(&decode_b64(
        "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVh\
         RU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpO\
         iN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfs\
         RaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NU\
         JW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
    ))
    .expect("RFC n is valid BigNum");
    let e = BigNum::from_slice(&decode_b64("AQAB")).expect("RFC e is valid BigNum");
    let d = BigNum::from_slice(&decode_b64(
        "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E3\
         75xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY4\
         6qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxV\
         w3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxf\
         yrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
    ))
    .expect("RFC d is valid BigNum");
    let p = BigNum::from_slice(&decode_b64(
        "1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSB\
         jSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbf\
         DIwUbTrjjgieRbwC6Cl0",
    ))
    .expect("RFC p is valid BigNum");
    let q = BigNum::from_slice(&decode_b64(
        "wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1Y\
         Ya9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnm\
         DZJTIAfwTs0g68UZHvtc",
    ))
    .expect("RFC q is valid BigNum");
    let dp = BigNum::from_slice(&decode_b64(
        "ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5p\
         FQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd\
         _zVpAmZZq60WPMBMfKcuE",
    ))
    .expect("RFC dp is valid BigNum");
    let dq = BigNum::from_slice(&decode_b64(
        "Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9h\
         NVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvL\
         x-TCekf7oxyeKDUqKWjis",
    ))
    .expect("RFC dq is valid BigNum");
    let qi = BigNum::from_slice(&decode_b64(
        "VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd\
         7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9J\
         F_XyaY14ardLSjf4L_FNY",
    ))
    .expect("RFC qi is valid BigNum");

    let rsa = Rsa::from_private_components(n, e, d, p, q, dp, dq, qi)
        .expect("RFC RSA key components are valid");
    let pkey = PKey::from_rsa(rsa).expect("PKey::from_rsa should not fail");
    // private_key_to_der() on PKey<Private> produces PKCS#8 DER
    let pkcs8_der = pkey
        .private_key_to_der()
        .expect("PKCS#8 DER serialisation should not fail");

    let rsa_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        cryptographic_length: Some(2048),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        key_format_type: Some(KeyFormatType::PKCS8),
        ..Attributes::default()
    };
    let object = Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::PKCS8,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::from(pkcs8_der)),
                attributes: Some(rsa_attributes.clone()),
            }),
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            cryptographic_length: Some(2048),
            key_wrapping_data: None,
        },
    });
    let import_req = import_object_request(
        VENDOR_ID_COSMIAN,
        None,
        object,
        Some(rsa_attributes),
        false,
        false,
        EMPTY_TAGS,
    )?;
    let import_resp: ImportResponse = test_utils::post_2_1(&app, import_req).await?;
    let kid = import_resp.unique_identifier.to_string();

    // ── RFC 7516 §A.1.2 — Content Encryption Key (CEK) bytes (verbatim) ────
    // Source: https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1
    #[rustfmt::skip]
    let cek: [u8; 32] = [
        177, 161, 244, 128,  84, 143, 225, 115,
         63, 180,   3, 255, 107, 154, 212, 246,
        138,   7, 110,  91, 112,  46,  34, 105,
         47, 130, 203,  46, 122, 234,  64, 252,
    ];

    // ── RFC 7516 §A.1.4 — Initialisation Vector bytes (verbatim) ────────────
    #[rustfmt::skip]
    let iv: [u8; 12] = [227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219];
    assert_eq!(
        URL_SAFE_NO_PAD.encode(iv),
        "48V1_ALb6US04U3b",
        "IV bytes must match RFC 7516 §A.1.4"
    );

    // ── RFC 7516 §A.1.3 — `encrypted_key` (RSA-OAEP wrapping of the CEK) ────
    // Taken verbatim from the RFC appendix (line breaks removed).
    // Source: https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1
    let rfc_encrypted_key = concat!(
        "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe",
        "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb",
        "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV",
        "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8",
        "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6",
        "UklfCpIMfIjf7iGdXKHzg"
    );

    // ── Build modified protected header (inject `kid` required by KMS) ───────
    // The RFC header is {"alg":"RSA-OAEP","enc":"A256GCM"} (no kid).
    // Adding kid changes the AAD, so the GCM ciphertext must be recomputed.
    // The `encrypted_key` is independent of the header (RSA-OAEP output depends
    // only on the RSA public key, not the JWE header).
    let protected_json = json!({"alg": "RSA-OAEP", "enc": "A256GCM", "kid": kid});
    let protected_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&protected_json)
            .expect("JSON")
            .as_bytes(),
    );

    // ── Recompute AES-256-GCM ciphertext with the new AAD ────────────────────
    // AES-GCM is deterministic: RFC CEK + RFC IV + RFC plaintext + new AAD.
    // The KMS must recover the RFC plaintext to pass.
    let rfc_plaintext = b"The true sign of intelligence is not knowledge but imagination.";
    let aad = protected_b64.as_bytes();
    let mut gcm_tag = [0_u8; 16];
    let new_ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        &cek,
        Some(&iv),
        aad,
        rfc_plaintext,
        &mut gcm_tag,
    )
    .expect("AES-256-GCM encrypt with RFC values should not fail");

    // ── POST /v1/crypto/decrypt ───────────────────────────────────────────────
    let dec_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({
            "protected":     protected_b64,
            "encrypted_key": rfc_encrypted_key,
            "iv":            URL_SAFE_NO_PAD.encode(iv),
            "ciphertext":    URL_SAFE_NO_PAD.encode(&new_ciphertext),
            "tag":           URL_SAFE_NO_PAD.encode(gcm_tag),
        }),
        "/v1/crypto/decrypt",
    )
    .await?;

    // ── Assert RFC §A.1 plaintext ─────────────────────────────────────────────
    let plaintext_b64 = dec_resp["data"]
        .as_str()
        .expect("missing 'data' field in response");
    let plaintext = URL_SAFE_NO_PAD
        .decode(plaintext_b64)
        .expect("response data is valid base64url");
    assert_eq!(
        plaintext, rfc_plaintext,
        "RFC 7516 §A.1 (https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1): \
         one-shot RSA-OAEP + AES-256-GCM decrypt must recover the RFC plaintext"
    );

    Ok(())
}
