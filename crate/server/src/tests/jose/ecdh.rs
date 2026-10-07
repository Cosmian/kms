//! ECDH-ES / ECDH-ES+A128KW / ECDH-ES+A256KW decrypt round-trip tests (RFC 7518 §4.6).
//!
//! `/v1/crypto/encrypt` intentionally does **not** implement an ECDH-ES sender path
//! (the KMS stays a decryption oracle only — see plan §2). Every test therefore plays
//! the sender role itself: it generates an ephemeral key, performs the ECDH-ES key
//! agreement and Concat KDF using the same `cosmian_kms_crypto` primitives the server
//! uses (already independently verified against RFC 7518 Appendix C test vectors in
//! `crate/crypto`), AES-GCM encrypts, and only then calls the real `/v1/crypto/decrypt`
//! endpoint under test.

use actix_web::{http::StatusCode, test};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::elliptic_curves::operation::x25519_key_agreement;
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::{
    elliptic_curves::operation::ecdh_key_agreement, kdf::concat_kdf::concat_kdf,
    symmetric::rfc3394::rfc3394_wrap,
};
use cosmian_logger::log_init;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    nid::Nid,
    rand::rand_bytes,
    symm::{Cipher, encrypt_aead},
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{result::KResult, tests::test_utils};

/// AES-GCM key size in bytes for a given `enc` value.
fn cek_len(enc: &str) -> usize {
    match enc {
        "A128GCM" => 16,
        "A192GCM" => 24,
        "A256GCM" => 32,
        other => panic!("unsupported enc {other}"),
    }
}

fn cipher_for(enc: &str) -> Cipher {
    match enc {
        "A128GCM" => Cipher::aes_128_gcm(),
        "A192GCM" => Cipher::aes_192_gcm(),
        "A256GCM" => Cipher::aes_256_gcm(),
        other => panic!("unsupported enc {other}"),
    }
}

/// Generate a fresh ephemeral EC key pair on `nid` and return
/// `(private_scalar_bytes, x_b64, y_b64)`.
fn generate_ephemeral_ec(nid: Nid) -> (Vec<u8>, String, String) {
    let group = EcGroup::from_curve_name(nid).expect("curve group");
    let ephemeral = EcKey::generate(&group).expect("EC key generation");
    let mut ctx = BigNumContext::new().expect("BigNumContext");
    let mut x = BigNum::new().expect("BigNum");
    let mut y = BigNum::new().expect("BigNum");
    ephemeral
        .public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
        .expect("affine coordinates");

    let coord_len = match nid {
        Nid::X9_62_PRIME256V1 => 32,
        Nid::SECP384R1 => 48,
        Nid::SECP521R1 => 66,
        _ => panic!("unsupported nid"),
    };
    let x_bytes = x.to_vec_padded(coord_len).expect("pad x");
    let y_bytes = y.to_vec_padded(coord_len).expect("pad y");
    let scalar_bytes = ephemeral.private_key().to_vec();

    (
        scalar_bytes,
        URL_SAFE_NO_PAD.encode(&x_bytes),
        URL_SAFE_NO_PAD.encode(&y_bytes),
    )
}

fn nid_for_crv(crv: &str) -> Nid {
    match crv {
        "P-256" => Nid::X9_62_PRIME256V1,
        "P-384" => Nid::SECP384R1,
        "P-521" => Nid::SECP521R1,
        other => panic!("unsupported crv {other}"),
    }
}

/// The receiver's static EC key material used to build an ECDH-ES sender
/// simulation (bundles what would otherwise be four separate arguments).
struct StaticEcKey<'a> {
    kid: &'a str,
    crv: &'a str,
    x_b64: &'a str,
    y_b64: &'a str,
}

/// Build the JWE flattened-JSON decrypt request body (as `serde_json::Value`) for an
/// EC ECDH-ES sender simulation, and return it alongside the plaintext for assertion.
fn build_ec_ecdh_es_request(
    static_key: &StaticEcKey<'_>,
    alg: &str,
    enc: &str,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Value {
    let StaticEcKey {
        kid,
        crv,
        x_b64: static_x_b64,
        y_b64: static_y_b64,
    } = *static_key;
    let nid = nid_for_crv(crv);
    let (ephemeral_scalar, epk_x, epk_y) = generate_ephemeral_ec(nid);

    let static_x = URL_SAFE_NO_PAD.decode(static_x_b64).expect("valid x");
    let static_y = URL_SAFE_NO_PAD.decode(static_y_b64).expect("valid y");
    let mut static_point = vec![0x04_u8];
    static_point.extend_from_slice(&static_x);
    static_point.extend_from_slice(&static_y);

    let z = ecdh_key_agreement(nid, &ephemeral_scalar, &static_point).expect("ECDH agreement");

    let protected = json!({
        "alg": alg,
        "enc": enc,
        "kid": kid,
        "epk": {"kty": "EC", "crv": crv, "x": epk_x, "y": epk_y},
    });
    let protected_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).expect("serialize protected"));

    let aad_bytes: Vec<u8> = aad.map_or_else(
        || protected_b64.as_bytes().to_vec(),
        |a| format!("{protected_b64}.{}", URL_SAFE_NO_PAD.encode(a)).into_bytes(),
    );

    let (cek, encrypted_key_b64): (Zeroizing<Vec<u8>>, Option<String>) = if alg == "ECDH-ES" {
        let key_len_bits = u32::try_from(cek_len(enc) * 8).expect("fits u32");
        let cek = concat_kdf(&z, key_len_bits, enc.as_bytes(), &[], &[]).expect("concat kdf");
        (cek, None)
    } else {
        let kek_bits: u32 = if alg == "ECDH-ES+A128KW" { 128 } else { 256 };
        let kek = concat_kdf(&z, kek_bits, alg.as_bytes(), &[], &[]).expect("concat kdf");
        let mut cek = Zeroizing::new(vec![0_u8; cek_len(enc)]);
        rand_bytes(&mut cek).expect("random cek");
        let wrapped = rfc3394_wrap(&cek, &kek).expect("rfc3394 wrap");
        (cek, Some(URL_SAFE_NO_PAD.encode(&wrapped)))
    };

    let mut iv = vec![0_u8; 12];
    rand_bytes(&mut iv).expect("random iv");
    let mut tag = vec![0_u8; 16];
    let ciphertext = encrypt_aead(
        cipher_for(enc),
        &cek,
        Some(&iv),
        &aad_bytes,
        plaintext,
        &mut tag,
    )
    .expect("AES-GCM encrypt");

    let mut body = json!({
        "protected": protected_b64,
        "iv": URL_SAFE_NO_PAD.encode(&iv),
        "ciphertext": URL_SAFE_NO_PAD.encode(&ciphertext),
        "tag": URL_SAFE_NO_PAD.encode(&tag),
    });
    if let Some(ek) = encrypted_key_b64 {
        body["encrypted_key"] = json!(ek);
    }
    if let Some(a) = aad {
        body["aad"] = json!(URL_SAFE_NO_PAD.encode(a));
    }
    body
}

async fn ecdh_es_round_trip(crv: &str, alg: &str, enc: &str) -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (kid_priv, _kid_pub, x_b64, y_b64) =
        super::common::create_ecdh_ec_key_pair_rest(&app, crv, alg).await?;

    let plaintext = format!("ECDH-ES round trip: crv={crv} alg={alg} enc={enc}");
    let req_body = build_ec_ecdh_es_request(
        &StaticEcKey {
            kid: &kid_priv,
            crv,
            x_b64: &x_b64,
            y_b64: &y_b64,
        },
        alg,
        enc,
        plaintext.as_bytes(),
        None,
    );

    let dec_resp: Value =
        test_utils::post_json_with_uri(&app, req_body, "/v1/crypto/decrypt").await?;
    let recovered = URL_SAFE_NO_PAD
        .decode(dec_resp["data"].as_str().expect("missing data"))
        .expect("base64url decode");
    assert_eq!(recovered, plaintext.as_bytes());

    Ok(())
}

// ---------------------------------------------------------------------------
// Bare ECDH-ES (direct key agreement, no key wrap) — P-256 / P-384 / P-521
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ecdh_es_p256_a128gcm_round_trip() -> KResult<()> {
    ecdh_es_round_trip("P-256", "ECDH-ES", "A128GCM").await
}

#[tokio::test]
async fn test_ecdh_es_p384_a256gcm_round_trip() -> KResult<()> {
    ecdh_es_round_trip("P-384", "ECDH-ES", "A256GCM").await
}

#[tokio::test]
async fn test_ecdh_es_p521_a256gcm_round_trip() -> KResult<()> {
    ecdh_es_round_trip("P-521", "ECDH-ES", "A256GCM").await
}

// ---------------------------------------------------------------------------
// ECDH-ES+A128KW / +A256KW (key-wrapped CEK) — P-256 / P-384 / P-521
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ecdh_es_a128kw_p256_round_trip() -> KResult<()> {
    ecdh_es_round_trip("P-256", "ECDH-ES+A128KW", "A128GCM").await
}

#[tokio::test]
async fn test_ecdh_es_a256kw_p384_round_trip() -> KResult<()> {
    ecdh_es_round_trip("P-384", "ECDH-ES+A256KW", "A256GCM").await
}

#[tokio::test]
async fn test_ecdh_es_a256kw_p521_round_trip() -> KResult<()> {
    ecdh_es_round_trip("P-521", "ECDH-ES+A256KW", "A256GCM").await
}

/// Decrypt must also work when `kid` in the protected header is the **public**
/// key's UID (the KMS follows the `PrivateKeyLink` to find the static private key) —
/// this is the realistic case since only public keys are ever published (JWKS).
#[tokio::test]
async fn test_ecdh_es_decrypt_via_public_kid() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (_kid_priv, kid_pub, x_b64, y_b64) =
        super::common::create_ecdh_ec_key_pair_rest(&app, "P-256", "ECDH-ES").await?;

    let plaintext = b"decrypt resolved via public key kid";
    let req_body = build_ec_ecdh_es_request(
        &StaticEcKey {
            kid: &kid_pub,
            crv: "P-256",
            x_b64: &x_b64,
            y_b64: &y_b64,
        },
        "ECDH-ES",
        "A128GCM",
        plaintext,
        None,
    );

    let dec_resp: Value =
        test_utils::post_json_with_uri(&app, req_body, "/v1/crypto/decrypt").await?;
    let recovered = URL_SAFE_NO_PAD
        .decode(dec_resp["data"].as_str().expect("missing data"))
        .expect("base64url decode");
    assert_eq!(recovered, plaintext);

    Ok(())
}

/// AAD is bound to the ciphertext: correct AAD decrypts; tampered AAD must fail.
#[tokio::test]
async fn test_ecdh_es_aad_binding() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (kid_priv, _kid_pub, x_b64, y_b64) =
        super::common::create_ecdh_ec_key_pair_rest(&app, "P-256", "ECDH-ES").await?;

    let mut req_body = build_ec_ecdh_es_request(
        &StaticEcKey {
            kid: &kid_priv,
            crv: "P-256",
            x_b64: &x_b64,
            y_b64: &y_b64,
        },
        "ECDH-ES",
        "A128GCM",
        b"secret payload",
        Some(b"associated-data"),
    );

    // Correct AAD → success
    test_utils::post_json_with_uri::<_, _, Value, _>(&app, req_body.clone(), "/v1/crypto/decrypt")
        .await
        .expect("decrypt with correct AAD should succeed");

    // Tampered AAD → must fail
    req_body["aad"] = json!(URL_SAFE_NO_PAD.encode(b"tampered-aad"));
    let http_req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&req_body)
        .to_request();
    let resp = test::call_service(&app, http_req).await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "decrypt with tampered AAD must fail"
    );

    Ok(())
}

/// `ECDH-ES+A128KW` requires a non-empty `encrypted_key`; omitting it must fail.
#[tokio::test]
async fn test_ecdh_es_a128kw_missing_encrypted_key_rejected() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (kid_priv, _kid_pub, x_b64, y_b64) =
        super::common::create_ecdh_ec_key_pair_rest(&app, "P-256", "ECDH-ES+A128KW").await?;

    let mut req_body = build_ec_ecdh_es_request(
        &StaticEcKey {
            kid: &kid_priv,
            crv: "P-256",
            x_b64: &x_b64,
            y_b64: &y_b64,
        },
        "ECDH-ES+A128KW",
        "A128GCM",
        b"payload",
        None,
    );
    req_body
        .as_object_mut()
        .expect("object")
        .remove("encrypted_key");

    let http_req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&req_body)
        .to_request();
    let resp = test::call_service(&app, http_req).await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "ECDH-ES+A128KW decrypt without encrypted_key must fail"
    );

    Ok(())
}

/// Bare `ECDH-ES` must reject a request that carries a non-empty `encrypted_key`
/// (RFC 7518 §4.6.2 — direct agreement never uses key wrapping).
#[tokio::test]
async fn test_ecdh_es_direct_rejects_encrypted_key() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (kid_priv, _kid_pub, x_b64, y_b64) =
        super::common::create_ecdh_ec_key_pair_rest(&app, "P-256", "ECDH-ES").await?;

    let mut req_body = build_ec_ecdh_es_request(
        &StaticEcKey {
            kid: &kid_priv,
            crv: "P-256",
            x_b64: &x_b64,
            y_b64: &y_b64,
        },
        "ECDH-ES",
        "A128GCM",
        b"payload",
        None,
    );
    req_body["encrypted_key"] = json!(URL_SAFE_NO_PAD.encode(b"unexpected-wrapped-key-bytes!!"));

    let http_req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&req_body)
        .to_request();
    let resp = test::call_service(&app, http_req).await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "bare ECDH-ES decrypt with a non-empty encrypted_key must fail"
    );

    Ok(())
}

/// A mismatched `epk.crv` (relative to the static key's curve) must be rejected.
#[tokio::test]
async fn test_ecdh_es_mismatched_epk_curve_rejected() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (kid_priv, _kid_pub, _x_b64, _y_b64) =
        super::common::create_ecdh_ec_key_pair_rest(&app, "P-256", "ECDH-ES").await?;

    // Generate an ephemeral key on the *wrong* curve (P-384) and pair it with a P-256
    // static key — the server must detect the `epk.crv` / static-key-curve mismatch.
    let (_scalar, epk_x, epk_y) = generate_ephemeral_ec(Nid::SECP384R1);
    let protected = json!({
        "alg": "ECDH-ES",
        "enc": "A128GCM",
        "kid": kid_priv,
        "epk": {"kty": "EC", "crv": "P-384", "x": epk_x, "y": epk_y},
    });
    let protected_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).expect("serialize"));

    let req_body = json!({
        "protected": protected_b64,
        "iv": URL_SAFE_NO_PAD.encode([0_u8; 12]),
        "ciphertext": URL_SAFE_NO_PAD.encode(b"irrelevant-ciphertext"),
        "tag": URL_SAFE_NO_PAD.encode([0_u8; 16]),
    });

    let http_req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&req_body)
        .to_request();
    let resp = test::call_service(&app, http_req).await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "mismatched epk.crv vs. static key curve must be rejected"
    );

    Ok(())
}

/// A `Sign`-only EC key (created for `ES256`) must be rejected by ECDH-ES decrypt
/// (usage-mask enforcement — prevents key confusion between signing and key-agreement).
#[tokio::test]
async fn test_ecdh_es_rejects_sign_only_key() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    // Created for ES256 → Sign/Verify usage only, not KeyAgreement.
    let resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kty": "EC", "crv": "P-256", "alg": "ES256"}),
        "/v1/crypto/keys",
    )
    .await?;
    let kid_priv = resp["kid"].as_str().expect("missing kid").to_owned();

    // Fabricate a plausible-looking ECDH-ES request; it must be rejected before
    // any cryptographic material is meaningfully used, due to the usage-mask check.
    let (_scalar, epk_x, epk_y) = generate_ephemeral_ec(Nid::X9_62_PRIME256V1);
    let protected = json!({
        "alg": "ECDH-ES",
        "enc": "A128GCM",
        "kid": kid_priv,
        "epk": {"kty": "EC", "crv": "P-256", "x": epk_x, "y": epk_y},
    });
    let protected_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).expect("serialize"));

    let req_body = json!({
        "protected": protected_b64,
        "iv": URL_SAFE_NO_PAD.encode([0_u8; 12]),
        "ciphertext": URL_SAFE_NO_PAD.encode(b"irrelevant-ciphertext"),
        "tag": URL_SAFE_NO_PAD.encode([0_u8; 16]),
    });

    let http_req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&req_body)
        .to_request();
    let resp = test::call_service(&app, http_req).await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "a Sign-only EC key must be rejected by ECDH-ES decrypt"
    );

    Ok(())
}

/// Requesting an X25519 OKP key pair (`crv=X25519`) must fail in FIPS builds — the
/// curve is not FIPS 140-3 approved and the primitive does not exist in this build.
#[cfg(not(feature = "non-fips"))]
#[tokio::test]
async fn test_x25519_key_creation_rejected_in_fips_build() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let http_req = test::TestRequest::post()
        .uri("/v1/crypto/keys")
        .set_json(&json!({"kty": "OKP", "crv": "X25519", "alg": "ECDH-ES"}))
        .to_request();
    let resp = test::call_service(&app, http_req).await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "X25519 OKP key creation must be rejected in a FIPS build"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// X25519 (non-FIPS only)
// ---------------------------------------------------------------------------

#[cfg(feature = "non-fips")]
mod non_fips {
    use base64::Engine as _;
    use openssl::pkey::PKey;

    use super::{
        KResult, StatusCode, URL_SAFE_NO_PAD, Value, Zeroizing, cek_len, cipher_for, concat_kdf,
        encrypt_aead, json, log_init, rand_bytes, rfc3394_wrap, test, test_utils,
        x25519_key_agreement,
    };

    /// Generate a fresh ephemeral X25519 key pair and return `(private_raw, x_b64)`.
    fn generate_ephemeral_x25519() -> (Vec<u8>, String) {
        let ephemeral = PKey::generate_x25519().expect("X25519 key generation");
        let priv_raw = ephemeral.raw_private_key().expect("raw private key");
        let pub_raw = ephemeral.raw_public_key().expect("raw public key");
        (priv_raw, URL_SAFE_NO_PAD.encode(&pub_raw))
    }

    fn build_x25519_ecdh_es_request(
        kid: &str,
        alg: &str,
        enc: &str,
        static_x_b64: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Value {
        let (ephemeral_priv, epk_x) = generate_ephemeral_x25519();
        let static_pub = URL_SAFE_NO_PAD.decode(static_x_b64).expect("valid x");

        let z = x25519_key_agreement(&ephemeral_priv, &static_pub).expect("X25519 agreement");

        let protected = json!({
            "alg": alg,
            "enc": enc,
            "kid": kid,
            "epk": {"kty": "OKP", "crv": "X25519", "x": epk_x},
        });
        let protected_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).expect("serialize"));

        let aad_bytes: Vec<u8> = aad.map_or_else(
            || protected_b64.as_bytes().to_vec(),
            |a| format!("{protected_b64}.{}", URL_SAFE_NO_PAD.encode(a)).into_bytes(),
        );

        let (cek, encrypted_key_b64): (Zeroizing<Vec<u8>>, Option<String>) = if alg == "ECDH-ES" {
            let key_len_bits = u32::try_from(cek_len(enc) * 8).expect("fits u32");
            let cek = concat_kdf(&z, key_len_bits, enc.as_bytes(), &[], &[]).expect("concat kdf");
            (cek, None)
        } else {
            let kek_bits: u32 = if alg == "ECDH-ES+A128KW" { 128 } else { 256 };
            let kek = concat_kdf(&z, kek_bits, alg.as_bytes(), &[], &[]).expect("concat kdf");
            let mut cek = Zeroizing::new(vec![0_u8; cek_len(enc)]);
            rand_bytes(&mut cek).expect("random cek");
            let wrapped = rfc3394_wrap(&cek, &kek).expect("rfc3394 wrap");
            (cek, Some(URL_SAFE_NO_PAD.encode(&wrapped)))
        };

        let mut iv = vec![0_u8; 12];
        rand_bytes(&mut iv).expect("random iv");
        let mut tag = vec![0_u8; 16];
        let ciphertext = encrypt_aead(
            cipher_for(enc),
            &cek,
            Some(&iv),
            &aad_bytes,
            plaintext,
            &mut tag,
        )
        .expect("AES-GCM encrypt");

        let mut body = json!({
            "protected": protected_b64,
            "iv": URL_SAFE_NO_PAD.encode(&iv),
            "ciphertext": URL_SAFE_NO_PAD.encode(&ciphertext),
            "tag": URL_SAFE_NO_PAD.encode(&tag),
        });
        if let Some(ek) = encrypted_key_b64 {
            body["encrypted_key"] = json!(ek);
        }
        if let Some(a) = aad {
            body["aad"] = json!(URL_SAFE_NO_PAD.encode(a));
        }
        body
    }

    #[tokio::test]
    async fn test_x25519_ecdh_es_a128gcm_round_trip() -> KResult<()> {
        log_init(None);
        let app = test_utils::test_app(None).await;

        let (kid_priv, _kid_pub, x_b64) =
            super::super::common::create_ecdh_x25519_key_pair_rest(&app, "ECDH-ES").await?;

        let plaintext = b"X25519 ECDH-ES round trip";
        let req_body =
            build_x25519_ecdh_es_request(&kid_priv, "ECDH-ES", "A128GCM", &x_b64, plaintext, None);

        let dec_resp: Value =
            test_utils::post_json_with_uri(&app, req_body, "/v1/crypto/decrypt").await?;
        let recovered = URL_SAFE_NO_PAD
            .decode(dec_resp["data"].as_str().expect("missing data"))
            .expect("base64url decode");
        assert_eq!(recovered, plaintext);

        Ok(())
    }

    #[tokio::test]
    async fn test_x25519_ecdh_es_a256kw_round_trip() -> KResult<()> {
        log_init(None);
        let app = test_utils::test_app(None).await;

        let (kid_priv, _kid_pub, x_b64) =
            super::super::common::create_ecdh_x25519_key_pair_rest(&app, "ECDH-ES+A256KW").await?;

        let plaintext = b"X25519 ECDH-ES+A256KW round trip";
        let req_body = build_x25519_ecdh_es_request(
            &kid_priv,
            "ECDH-ES+A256KW",
            "A256GCM",
            &x_b64,
            plaintext,
            None,
        );

        let dec_resp: Value =
            test_utils::post_json_with_uri(&app, req_body, "/v1/crypto/decrypt").await?;
        let recovered = URL_SAFE_NO_PAD
            .decode(dec_resp["data"].as_str().expect("missing data"))
            .expect("base64url decode");
        assert_eq!(recovered, plaintext);

        Ok(())
    }

    /// An EC (P-256) static key must reject an X25519 `epk` (`kty`/`crv` confusion).
    #[tokio::test]
    async fn test_ecdh_es_rejects_okp_epk_for_ec_static_key() -> KResult<()> {
        log_init(None);
        let app = test_utils::test_app(None).await;

        let (kid_priv, _kid_pub, _x_b64, _y_b64) =
            super::super::common::create_ecdh_ec_key_pair_rest(&app, "P-256", "ECDH-ES").await?;

        let (_priv, epk_x) = generate_ephemeral_x25519();
        let protected = json!({
            "alg": "ECDH-ES",
            "enc": "A128GCM",
            "kid": kid_priv,
            "epk": {"kty": "OKP", "crv": "X25519", "x": epk_x},
        });
        let protected_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).expect("serialize"));

        let req_body = json!({
            "protected": protected_b64,
            "iv": URL_SAFE_NO_PAD.encode([0_u8; 12]),
            "ciphertext": URL_SAFE_NO_PAD.encode(b"irrelevant-ciphertext"),
            "tag": URL_SAFE_NO_PAD.encode([0_u8; 16]),
        });

        let http_req = test::TestRequest::post()
            .uri("/v1/crypto/decrypt")
            .set_json(&req_body)
            .to_request();
        let resp = test::call_service(&app, http_req).await;
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "an X25519 epk against an EC static key must be rejected"
        );

        Ok(())
    }
}
