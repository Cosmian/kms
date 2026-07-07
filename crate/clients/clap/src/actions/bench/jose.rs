use cosmian_kms_client::{
    KmsClient,
    jose::{
        JoseDecryptReq, JoseEncReq, JoseKeyReq, JoseMacReq, JoseSignReq, JoseVerifyReq, b64url,
    },
};
use criterion::{BenchmarkId, Criterion, Throughput};
use tokio::runtime::Runtime;

use super::types::bench_ko;

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

fn jose_try_create_rsa_kp(
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

#[cfg(feature = "non-fips")]
fn jose_try_create_okp_kp(rt: &Runtime, client: &KmsClient) -> Option<(String, String)> {
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
    let mut group = c.benchmark_group("jose/encrypt");
    let payload = b64url(&[1_u8; 64]);

    for enc in ["A128GCM", "A192GCM", "A256GCM"] {
        let Some(kid) = jose_create_sym_key(rt, client, enc) else {
            eprintln!("[bench] JOSE encrypt {enc} key creation failed, skipping");
            bench_ko("jose/encrypt");
            continue;
        };

        let enc_req = JoseEncReq {
            kid: kid.clone(),
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

        let enc_req_clone = enc_req.clone();
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
    let mut group = c.benchmark_group("jose/encrypt/rsa-oaep");

    for bits in [2048_usize, 4096] {
        // Create an RSA key pair; re-use the existing helper (any JWS alg works
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

        let enc_req_clone = enc_req.clone();
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

    let mut group = c.benchmark_group(format!("jose/sign-verify/{label}"));
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
    let mut group = c.benchmark_group("jose/mac");
    let payload = b64url(&[0xAB_u8; 64]);

    for alg in ["HS256", "HS384", "HS512"] {
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

        let mac_req_clone = mac_req.clone();
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
    let mut group = c.benchmark_group("jose/key-creation");

    // Symmetric keys
    for alg in ["A128GCM", "A256GCM"] {
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
    if rt.block_on(client.jose_create_key(rsa_req)).is_ok() {
        group.bench_function(BenchmarkId::new("RSA", "2048"), |b| {
            b.to_async(rt).iter(|| client.jose_create_key(rsa_req));
        });
    } else {
        eprintln!("[bench] JOSE key-creation RSA/2048 not supported, skipping");
        bench_ko("jose/key-creation");
    }

    group.finish();
}

// =============================================================================
// JOSE BATCH BENCHMARK
// =============================================================================

pub(super) fn bench_jose_batch(c: &mut Criterion, client: &KmsClient, rt: &Runtime, sanity: bool) {
    let mut group = c.benchmark_group("jose/batch");

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

        group.throughput(Throughput::Elements(n as u64));
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
