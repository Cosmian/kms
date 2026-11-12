use cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm;
use cosmian_kms_client::{
    KmsClient,
    http_client::Bytes,
    jose::{
        JoseDecryptReq, JoseEncReq, JoseKeyReq, JoseMacReq, JoseSignReq, JoseVerifyReq, b64url,
    },
    kmip_2_1::kmip_objects::Object,
};
use cosmian_kms_crypto::{
    crypto::{
        KmsRng,
        rsa::ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_key_wrap,
        symmetric::symmetric_ciphers::{SymCipher, encrypt, random_key, random_nonce},
    },
    openssl::kmip_public_key_to_openssl,
};
use criterion::{BenchmarkId, Criterion, Throughput};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

use super::{
    transport::{bench_filter_matches, timed_group},
    types::bench_ko,
};
use crate::error::result::{KmsCliResult, KmsCliResultHelper as _};

// =============================================================================
// JOSE BENCHMARKS (REST /v1/crypto/* endpoints)
// =============================================================================

// ─── JOSE key creation helpers ──────────────────────────────────────────────

pub(super) fn jose_create_sym_key(
    rt: &Runtime,
    client: &KmsClient,
    alg: &'static str,
) -> Option<String> {
    let req = JoseKeyReq {
        kty: "oct",
        alg: Some(alg),
        crv: None,
        bits: None,
    };
    rt.block_on(client.jose_create_key(req)).ok().map(|r| r.kid)
}

pub(super) fn jose_try_create_ec_kp(
    rt: &Runtime,
    client: &KmsClient,
    alg: &'static str,
    crv: &'static str,
) -> Option<(String, String)> {
    let req = JoseKeyReq {
        kty: "EC",
        alg: Some(alg),
        crv: Some(crv),
        bits: None,
    };
    let resp = rt.block_on(client.jose_create_key(req)).ok()?;
    Some((resp.kid, resp.kid_public?))
}

pub(super) fn jose_try_create_rsa_kp(
    rt: &Runtime,
    client: &KmsClient,
    alg: &'static str,
    bits: usize,
) -> Option<(String, String)> {
    let req = JoseKeyReq {
        kty: "RSA",
        alg: Some(alg),
        crv: None,
        bits: Some(bits),
    };
    let resp = rt.block_on(client.jose_create_key(req)).ok()?;
    Some((resp.kid, resp.kid_public?))
}

/// Base64url JWE protected header `{"alg":<alg>,"enc":"A256GCM","kid":<kid>}`.
pub(super) fn jose_protected_header(alg: &str, kid: &str) -> KmsCliResult<String> {
    Ok(b64url(
        serde_json::to_string(&serde_json::json!({"alg": alg, "enc": "A256GCM", "kid": kid}))
            .context("JOSE protected header serialization")?
            .as_bytes(),
    ))
}

/// Fresh random A256GCM CEK and its RSA-OAEP wrap under `public_key`, with `hash` for both
/// OAEP and MGF1.
pub(super) fn jose_wrap_new_cek(
    public_key: &Object,
    hash: HashingAlgorithm,
) -> KmsCliResult<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let cek = random_key(&KmsRng::new(), SymCipher::Aes256Gcm)?;
    let encrypted_key = ckm_rsa_pkcs_oaep_key_wrap(
        &kmip_public_key_to_openssl(public_key)?,
        hash,
        hash,
        None,
        &cek,
    )?;
    Ok((cek, encrypted_key))
}

/// `POST /v1/crypto/decrypt` body for an A256GCM JWE under `cek`: fresh IV, AAD = ASCII(`protected`).
pub(super) fn jose_jwe_decrypt_body(
    protected: &str,
    cek: &[u8],
    encrypted_key: &[u8],
    plaintext: &[u8],
) -> KmsCliResult<Bytes> {
    let iv = random_nonce(&KmsRng::new(), SymCipher::Aes256Gcm)?;
    let (ciphertext, tag) = encrypt(
        SymCipher::Aes256Gcm,
        cek,
        &iv,
        protected.as_bytes(),
        plaintext,
        None,
    )?;
    let req = JoseDecryptReq {
        protected: protected.to_owned(),
        encrypted_key: b64url(encrypted_key),
        iv: b64url(&iv),
        ciphertext: b64url(&ciphertext),
        tag: b64url(&tag),
        aad: None,
    };
    Ok(serde_json::to_vec(&req)
        .context("JOSE decrypt JSON serialization")?
        .into())
}

/// Build a `POST /v1/crypto/decrypt` body for a JWE made client-side (like the diagram's
/// Estreem app): fresh CEK + IV, `RSA-OAEP-256` CEK wrap under `public_key`, `A256GCM`
/// content encryption with AAD = ASCII(protected). Every call yields a new `encrypted_key`,
/// so the server's CEK cache never holds it.
pub(super) fn jose_rsa_oaep_decrypt_body(
    public_key: &Object,
    kid: &str,
    plaintext: &[u8],
) -> KmsCliResult<Bytes> {
    let protected = jose_protected_header("RSA-OAEP-256", kid)?;
    let (cek, encrypted_key) = jose_wrap_new_cek(public_key, HashingAlgorithm::SHA256)?;
    jose_jwe_decrypt_body(&protected, &cek, &encrypted_key, plaintext)
}

#[cfg(feature = "non-fips")]
pub(super) fn jose_try_create_okp_kp(rt: &Runtime, client: &KmsClient) -> Option<(String, String)> {
    let req = JoseKeyReq {
        kty: "OKP",
        alg: Some("EdDSA"),
        crv: Some("Ed25519"),
        bits: None,
    };
    let resp = rt.block_on(client.jose_create_key(req)).ok()?;
    Some((resp.kid, resp.kid_public?))
}

// ─── JOSE benchmark dispatcher ──────────────────────────────────────────────

// Individual JOSE bench functions are called directly from the protocol-aware dispatch.

// ─── JOSE encrypt / decrypt (dir + AES-GCM) ────────────────────────────────

pub(super) fn bench_jose_encrypt(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let mut group = timed_group(c, "jose/encrypt");
    let payload = b64url(&[1_u8; 64]);

    for (enc, bits) in [("A128GCM", "128"), ("A192GCM", "192"), ("A256GCM", "256")] {
        // Accept the KMIP vocabulary (`-a aes-gcm -k 256`) as well as the JWA name.
        if !bench_filter_matches("aes-gcm", Some(bits)) && !bench_filter_matches(enc, None) {
            continue;
        }
        let Some(kid) = jose_create_sym_key(rt, client, enc) else {
            eprintln!("[bench] JOSE encrypt {enc} key creation failed, skipping");
            bench_ko("jose/encrypt");
            continue;
        };

        let enc_req = JoseEncReq {
            kid,
            alg: "dir",
            enc,
            data: payload.clone(),
            aad: None,
        };

        let Ok(enc_resp) = rt.block_on(client.jose_encrypt(enc_req.clone())) else {
            eprintln!("[bench] JOSE encrypt {enc} not supported by server, skipping");
            bench_ko("jose/encrypt");
            continue;
        };

        let enc_req_clone = enc_req;
        group.bench_function(BenchmarkId::new("encrypt", enc), |b| {
            b.to_async(rt)
                .iter(|| client.jose_encrypt(enc_req_clone.clone()));
        });

        let dec_req = JoseDecryptReq {
            protected: enc_resp.protected,
            encrypted_key: enc_resp.encrypted_key,
            iv: enc_resp.iv,
            ciphertext: enc_resp.ciphertext,
            tag: enc_resp.tag,
            aad: enc_resp.aad,
        };
        group.bench_function(BenchmarkId::new("decrypt", enc), |b| {
            b.to_async(rt).iter(|| client.jose_decrypt(dec_req.clone()));
        });
    }
    group.finish();

    bench_jose_encrypt_rsa_oaep(c, client, rt);
}

// ─── JOSE RSA-OAEP encrypt / decrypt ────────────────────────────────────────

/// Benchmark `POST /v1/crypto/encrypt` with `alg=RSA-OAEP` / `enc=A256GCM`.
///
/// RSA-OAEP key management: an ephemeral AES-256 CEK is generated, wrapped
/// with the RSA public key via RSA-OAEP, and the plaintext is encrypted with
/// AES-256-GCM.  This benchmark appears in the **Asymmetric Encryption** chart
/// alongside the KMIP RSA benchmarks, allowing a direct protocol comparison.
///
/// Plaintext: 64 bytes (same as other JOSE JWE benchmarks).
fn bench_jose_encrypt_rsa_oaep(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let payload = b64url(&[1_u8; 64]);
    let mut group = timed_group(c, "jose/encrypt/rsa-oaep");
    for bits in [2048_usize, 4096] {
        let bits_str = bits.to_string();
        if !bench_filter_matches("rsa-oaep", Some(&bits_str)) {
            continue;
        }
        // to provision an RSA key — we use RS256 for key-creation only).
        let Some((_priv_kid, pub_kid)) = jose_try_create_rsa_kp(rt, client, "RS256", bits) else {
            eprintln!("[bench] JOSE RSA-OAEP: {bits}-bit key creation failed, skipping");
            bench_ko("jose/encrypt/rsa-oaep");
            continue;
        };

        let enc_req = JoseEncReq {
            kid: pub_kid,
            alg: "RSA-OAEP",
            enc: "A256GCM",
            data: payload.clone(),
            aad: None,
        };

        let Ok(enc_resp) = rt.block_on(client.jose_encrypt(enc_req.clone())) else {
            eprintln!("[bench] JOSE RSA-OAEP encrypt ({bits}-bit) not supported, skipping");
            bench_ko("jose/encrypt/rsa-oaep");
            continue;
        };

        let enc_req_clone = enc_req;
        group.bench_function(BenchmarkId::new("encrypt", bits), |b| {
            b.to_async(rt)
                .iter(|| client.jose_encrypt(enc_req_clone.clone()));
        });

        // The protected header embeds the private key UID so decrypt is self-contained.
        let dec_req = JoseDecryptReq {
            protected: enc_resp.protected,
            encrypted_key: enc_resp.encrypted_key,
            iv: enc_resp.iv,
            ciphertext: enc_resp.ciphertext,
            tag: enc_resp.tag,
            aad: enc_resp.aad,
        };
        group.bench_function(BenchmarkId::new("decrypt", bits), |b| {
            b.to_async(rt).iter(|| client.jose_decrypt(dec_req.clone()));
        });
    }
    group.finish();
}

// ─── JOSE sign / verify ─────────────────────────────────────────────────────

/// Map a JWA signature algorithm to the canonical KMIP label used by ttlv-json
/// benchmarks, so the criterion row-key merges across protocols.
fn jwa_sig_to_kmip_label(alg: &str) -> &'static str {
    match alg {
        "ES256" => "ecdsa-p256",
        "ES384" => "ecdsa-p384",
        "RS256" => "rsa-pkcs1v15",
        "PS256" => "rsa-pss",
        "EdDSA" => "eddsa-ed25519",
        other => {
            // Leak the string so we can return &'static str for unknown algs;
            // this only happens in tests / unexpected configs.
            Box::leak(other.to_lowercase().into_boxed_str())
        }
    }
}

pub(super) fn bench_jose_sign_verify(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let payload = b64url(&[0x42_u8; 32]);

    // (jwa_alg, kty/crv) — FIPS algorithms
    for &(alg, crv) in &[("ES256", "P-256"), ("ES384", "P-384")] {
        let Some((priv_kid, _pub_kid)) = jose_try_create_ec_kp(rt, client, alg, crv) else {
            eprintln!("[bench] JOSE sign {alg} key creation failed, skipping");
            bench_ko(format!("jose/sign-verify/{}", jwa_sig_to_kmip_label(alg)));
            continue;
        };
        bench_jose_sign_verify_one(c, client, rt, alg, &priv_kid, &payload);
    }

    for &(alg, bits) in &[("RS256", 2048_usize), ("PS256", 2048_usize)] {
        let Some((priv_kid, _pub_kid)) = jose_try_create_rsa_kp(rt, client, alg, bits) else {
            eprintln!("[bench] JOSE sign {alg} key creation failed, skipping");
            bench_ko(format!("jose/sign-verify/{}", jwa_sig_to_kmip_label(alg)));
            continue;
        };
        bench_jose_sign_verify_one(c, client, rt, alg, &priv_kid, &payload);
    }

    #[cfg(feature = "non-fips")]
    {
        if let Some((priv_kid, _pub_kid)) = jose_try_create_okp_kp(rt, client) {
            bench_jose_sign_verify_one(c, client, rt, "EdDSA", &priv_kid, &payload);
        } else {
            eprintln!("[bench] JOSE sign EdDSA key creation failed, skipping");
            bench_ko("jose/sign-verify/eddsa-ed25519");
        }
    }
}

/// Benchmark a single JOSE sign/verify algorithm.
///
/// Uses group name `"jose/sign-verify/{kmip_label}"` and bench-function names
/// `"sign"` / `"verify"` — matching ttlv-json so criterion row-keys merge.
pub(super) fn bench_jose_sign_verify_one(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    alg: &'static str,
    priv_kid: &str,
    payload: &str,
) {
    let label = jwa_sig_to_kmip_label(alg);
    if !bench_filter_matches(label, None) && !bench_filter_matches(alg, None) {
        return;
    }
    let sign_req = JoseSignReq {
        kid: priv_kid.to_owned(),
        alg,
        data: payload.to_owned(),
    };

    let Ok(sign_resp) = rt.block_on(client.jose_sign(sign_req.clone())) else {
        eprintln!("[bench] JOSE sign {alg} not supported by server, skipping");
        bench_ko(format!("jose/sign-verify/{label}"));
        return;
    };

    let mut group = timed_group(c, format!("jose/sign-verify/{label}"));
    group.bench_function("sign", |b| {
        b.to_async(rt).iter(|| client.jose_sign(sign_req.clone()));
    });

    let verify_req = JoseVerifyReq {
        protected: sign_resp.protected,
        data: payload.to_owned(),
        signature: sign_resp.signature,
    };
    group.bench_function("verify", |b| {
        b.to_async(rt)
            .iter(|| client.jose_verify(verify_req.clone()));
    });
    group.finish();
}

// ─── JOSE MAC (HMAC) ────────────────────────────────────────────────────────

pub(super) fn bench_jose_mac(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let mut group = timed_group(c, "jose/mac");
    let payload = b64url(&[0xAB_u8; 64]);

    for alg in ["HS256", "HS384", "HS512"] {
        if !bench_filter_matches(alg, None) {
            continue;
        }
        let Some(kid) = jose_create_sym_key(rt, client, alg) else {
            eprintln!("[bench] JOSE MAC {alg} key creation failed, skipping");
            bench_ko("jose/mac");
            continue;
        };

        let mac_req = JoseMacReq {
            kid: kid.clone(),
            alg,
            data: payload.clone(),
            mac: None,
        };

        let Ok(mac_resp) = rt.block_on(client.jose_mac_compute(mac_req.clone())) else {
            eprintln!("[bench] JOSE MAC {alg} not supported by server, skipping");
            bench_ko("jose/mac");
            continue;
        };

        let mac_req_clone = mac_req;
        group.bench_function(BenchmarkId::new("compute", alg), |b| {
            b.to_async(rt)
                .iter(|| client.jose_mac_compute(mac_req_clone.clone()));
        });

        let verify_req = JoseMacReq {
            kid,
            alg,
            data: payload.clone(),
            mac: Some(mac_resp.mac),
        };
        group.bench_function(BenchmarkId::new("verify", alg), |b| {
            b.to_async(rt)
                .iter(|| client.jose_mac_verify(verify_req.clone()));
        });
    }
    group.finish();
}

// ─── JOSE key creation ──────────────────────────────────────────────────────

pub(super) fn bench_jose_key_creation(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let mut group = timed_group(c, "jose/key-creation");

    // Symmetric keys
    for alg in ["A128GCM", "A256GCM"] {
        if !bench_filter_matches(alg, None) {
            continue;
        }
        let req = JoseKeyReq {
            kty: "oct",
            alg: Some(alg),
            crv: None,
            bits: None,
        };
        if rt.block_on(client.jose_create_key(req)).is_err() {
            eprintln!("[bench] JOSE key-creation oct/{alg} not supported, skipping");
            bench_ko("jose/key-creation");
            continue;
        }
        group.bench_function(BenchmarkId::new("oct", alg), |b| {
            b.to_async(rt).iter(|| client.jose_create_key(req));
        });
    }

    // EC keys
    for (alg, crv) in [("ES256", "P-256"), ("ES384", "P-384")] {
        if !bench_filter_matches(alg, Some(crv)) {
            continue;
        }
        let req = JoseKeyReq {
            kty: "EC",
            alg: Some(alg),
            crv: Some(crv),
            bits: None,
        };
        if rt.block_on(client.jose_create_key(req)).is_err() {
            eprintln!("[bench] JOSE key-creation EC/{alg} not supported, skipping");
            bench_ko("jose/key-creation");
            continue;
        }
        group.bench_function(BenchmarkId::new("EC", alg), |b| {
            b.to_async(rt).iter(|| client.jose_create_key(req));
        });
    }

    // RSA keys
    let rsa_req = JoseKeyReq {
        kty: "RSA",
        alg: Some("RS256"),
        crv: None,
        bits: Some(2048),
    };
    if bench_filter_matches("rsa", Some("2048")) {
        if rt.block_on(client.jose_create_key(rsa_req)).is_ok() {
            group.bench_function(BenchmarkId::new("RSA", "2048"), |b| {
                b.to_async(rt).iter(|| client.jose_create_key(rsa_req));
            });
        } else {
            eprintln!("[bench] JOSE key-creation RSA/2048 not supported, skipping");
            bench_ko("jose/key-creation");
        }
    }

    group.finish();
}

// =============================================================================
// JOSE BATCH BENCHMARK
// =============================================================================

pub(super) fn bench_jose_batch(c: &mut Criterion, client: &KmsClient, rt: &Runtime, sanity: bool) {
    if !bench_filter_matches("batch", None) {
        return;
    }
    let mut group = timed_group(c, "jose/batch");
    let Some(kid) = jose_create_sym_key(rt, client, "A256GCM") else {
        eprintln!("[bench] JOSE batch key creation failed, skipping");
        bench_ko("jose/batch");
        return;
    };

    let payload = b64url(&[1_u8; 64]);
    let enc_req = JoseEncReq {
        kid,
        alg: "dir",
        enc: "A256GCM",
        data: payload,
        aad: None,
    };

    // Test that the endpoint works
    if rt.block_on(client.jose_encrypt(enc_req.clone())).is_err() {
        eprintln!("[bench] JOSE batch encrypt not supported, skipping");
        bench_ko("jose/batch");
        return;
    }

    let batch_sizes: &[usize] = if sanity { &[1] } else { &[1, 10, 50, 100] };
    for &n in batch_sizes {
        let parameter_name = if n == 1 {
            format!("{n} request")
        } else {
            format!("{n} requests")
        };

        group.throughput(Throughput::Elements(u64::try_from(n).unwrap_or(u64::MAX)));
        group.bench_with_input(
            BenchmarkId::new("encrypt", &parameter_name),
            &n,
            |b, &count| {
                b.to_async(rt).iter(|| async {
                    for _ in 0..count {
                        drop(client.jose_encrypt(enc_req.clone()).await);
                    }
                });
            },
        );
    }
    group.finish();
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use cosmian_kmip::{
        kmip_0::kmip_types::HashingAlgorithm,
        kmip_2_1::{
            extra::{
                VENDOR_ID_COSMIAN,
                fips::{FIPS_PRIVATE_RSA_MASK, FIPS_PUBLIC_RSA_MASK},
            },
            kmip_attributes::Attributes,
            kmip_types::CryptographicAlgorithm,
        },
    };
    use cosmian_kms_crypto::{
        crypto::{
            rsa::{
                ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_key_unwrap, operation::create_rsa_key_pair,
            },
            symmetric::symmetric_ciphers::{SymCipher, decrypt},
        },
        openssl::kmip_private_key_to_openssl,
    };
    use serde_json::Value;

    use super::jose_rsa_oaep_decrypt_body;
    use crate::error::result::KmsCliResult;

    fn field(body: &Value, name: &str) -> KmsCliResult<Vec<u8>> {
        Ok(URL_SAFE_NO_PAD.decode(body[name].as_str().unwrap_or_default())?)
    }

    #[test]
    #[expect(clippy::panic_in_result_fn, reason = "assertions in a test")]
    fn jose_rsa_oaep_decrypt_body_round_trips_and_is_fresh() -> KmsCliResult<()> {
        let kp = create_rsa_key_pair(
            VENDOR_ID_COSMIAN,
            "sk",
            "pk",
            Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: Some(2048),
                ..Default::default()
            },
            Some(Attributes {
                cryptographic_usage_mask: Some(FIPS_PRIVATE_RSA_MASK),
                ..Default::default()
            }),
            Some(Attributes {
                cryptographic_usage_mask: Some(FIPS_PUBLIC_RSA_MASK),
                ..Default::default()
            }),
        )?;
        let body1: Value = serde_json::from_slice(&jose_rsa_oaep_decrypt_body(
            kp.public_key(),
            "pk",
            b"diagram",
        )?)?;
        let body2: Value = serde_json::from_slice(&jose_rsa_oaep_decrypt_body(
            kp.public_key(),
            "pk",
            b"diagram",
        )?)?;

        let protected = body1["protected"].as_str().unwrap_or_default();
        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected)?)?;
        assert_eq!(header["alg"], "RSA-OAEP-256");
        assert_eq!(header["enc"], "A256GCM");
        assert_eq!(header["kid"], "pk");

        let cek = ckm_rsa_pkcs_oaep_key_unwrap(
            &kmip_private_key_to_openssl(kp.private_key())?,
            HashingAlgorithm::SHA256,
            HashingAlgorithm::SHA256,
            None,
            &field(&body1, "encrypted_key")?,
        )?;
        let plaintext = decrypt(
            SymCipher::Aes256Gcm,
            &cek,
            &field(&body1, "iv")?,
            protected.as_bytes(),
            &field(&body1, "ciphertext")?,
            &field(&body1, "tag")?,
            None,
        )?;
        assert_eq!(plaintext.as_slice(), b"diagram");
        assert_ne!(body1["encrypted_key"], body2["encrypted_key"]);
        Ok(())
    }
}
