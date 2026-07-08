#[cfg(feature = "non-fips")]
use cosmian_kms_client::kmip_2_1::requests::create_pqc_key_pair_request;
#[cfg(feature = "non-fips")]
use cosmian_kms_client::reexport::cosmian_kms_client_utils::configurable_kem_utils::{
    KemAlgorithm, build_create_configurable_kem_keypair_request,
};
#[cfg(feature = "non-fips")]
use cosmian_kms_client::reexport::cosmian_kms_client_utils::cover_crypt_utils::{
    build_create_covercrypt_master_keypair_request, build_create_covercrypt_usk_request,
};
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_0::{
        kmip_messages::{RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader},
        kmip_types::ProtocolVersion,
    },
    kmip_2_1::{
        extra::BulkData,
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Decrypt, Encrypt, Operation, Sign, SignatureVerify},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
            RecommendedCurve,
        },
        requests::{
            create_ec_key_pair_request, create_rsa_key_pair_request, decrypt_request,
            encrypt_request, symmetric_key_create_request,
        },
    },
};
use criterion::{BenchmarkId, Criterion, Throughput};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

#[cfg(feature = "non-fips")]
use super::helpers::{
    aes_gcm_siv_params, chacha20_params, kem_params, rsa_pkcs15_params, try_create_ec_kp_no_fips,
    try_create_pqc_kp, try_create_sym_key,
};
use super::{
    helpers::{
        aes_gcm_params, aes_xts_params, create_rsa_kp, create_sym_key, rsa_kwp_params,
        rsa_oaep_params, try_create_ec_kp, with_fips_ec_masks, with_fips_rsa_masks,
    },
    types::bench_ko,
};

pub(super) fn bench_encrypt(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    bench_encrypt_aes_gcm(c, client, rt);
    bench_encrypt_aes_xts(c, client, rt);

    #[cfg(feature = "non-fips")]
    bench_encrypt_aes_gcm_siv(c, client, rt);

    #[cfg(feature = "non-fips")]
    bench_encrypt_chacha20(c, client, rt);

    bench_rsa_encrypt_family(
        c,
        client,
        rt,
        "rsa-oaep",
        &rsa_oaep_params(),
        &[2048, 3072, 4096],
    );

    bench_rsa_encrypt_family(
        c,
        client,
        rt,
        "rsa-aes-kwp",
        &rsa_kwp_params(),
        &[2048, 3072, 4096],
    );

    #[cfg(feature = "non-fips")]
    bench_rsa_encrypt_family(
        c,
        client,
        rt,
        "rsa-pkcs1v15",
        &rsa_pkcs15_params(),
        &[2048, 3072, 4096],
    );

    #[cfg(feature = "non-fips")]
    bench_encrypt_ecies(c, client, rt);

    #[cfg(feature = "non-fips")]
    bench_encrypt_salsa(c, client, rt);

    #[cfg(feature = "non-fips")]
    bench_encrypt_covercrypt(c, client, rt);

    #[cfg(feature = "non-fips")]
    bench_kem(c, client, rt);

    #[cfg(feature = "non-fips")]
    bench_pqc_kem(c, client, rt);
}

pub(super) fn bench_encrypt_aes_gcm(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let mut group = c.benchmark_group("encrypt/aes-gcm");
    let params = aes_gcm_params();

    for bits in [128, 192, 256] {
        let key_id = create_sym_key(rt, client, bits, CryptographicAlgorithm::AES);

        let enc_req = Encrypt {
            unique_identifier: Some(key_id.clone()),
            cryptographic_parameters: Some(params.clone()),
            data: Some(Zeroizing::new(vec![1_u8; 64])),
            ..Default::default()
        };

        let Ok(enc_resp) = rt.block_on(client.encrypt(enc_req.clone())) else {
            eprintln!("[bench] AES-GCM-{bits} not supported by server, skipping");
            bench_ko("encrypt/aes-gcm");
            continue;
        };

        group.bench_function(BenchmarkId::new("encrypt", bits), |b| {
            b.to_async(rt).iter(|| client.encrypt(enc_req.clone()));
        });

        let dec_req = Decrypt {
            unique_identifier: Some(key_id),
            cryptographic_parameters: Some(params.clone()),
            data: Some(enc_resp.data.map_or_else(Vec::new, |z| z.to_vec())),
            i_v_counter_nonce: enc_resp.i_v_counter_nonce,
            authenticated_encryption_tag: enc_resp.authenticated_encryption_tag,
            ..Default::default()
        };
        group.bench_function(BenchmarkId::new("decrypt", bits), |b| {
            b.to_async(rt).iter(|| client.decrypt(dec_req.clone()));
        });
    }
    group.finish();
}

#[cfg(feature = "non-fips")]
pub(super) fn bench_encrypt_chacha20(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let Some(key_id) = try_create_sym_key(rt, client, 256, CryptographicAlgorithm::ChaCha20) else {
        eprintln!("[bench] ChaCha20 not supported by server, skipping");
        bench_ko("encrypt/chacha20-poly1305");
        return;
    };

    let mut group = c.benchmark_group("encrypt/chacha20-poly1305");
    let params = chacha20_params();

    let enc_req = Encrypt {
        unique_identifier: Some(key_id.clone()),
        cryptographic_parameters: Some(params.clone()),
        data: Some(Zeroizing::new(vec![1_u8; 64])),
        ..Default::default()
    };
    group.bench_function("encrypt/256", |b| {
        b.to_async(rt).iter(|| client.encrypt(enc_req.clone()));
    });

    let enc_resp = rt
        .block_on(client.encrypt(enc_req))
        .expect("pre-encrypt for decrypt setup");
    let dec_req = Decrypt {
        unique_identifier: Some(key_id),
        cryptographic_parameters: Some(params),
        data: Some(enc_resp.data.map_or_else(Vec::new, |z| z.to_vec())),
        i_v_counter_nonce: enc_resp.i_v_counter_nonce,
        authenticated_encryption_tag: enc_resp.authenticated_encryption_tag,
        ..Default::default()
    };
    group.bench_function("decrypt/256", |b| {
        b.to_async(rt).iter(|| client.decrypt(dec_req.clone()));
    });
    group.finish();
}

fn bench_rsa_encrypt_family(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    label: &str,
    params: &CryptographicParameters,
    key_sizes: &[usize],
) {
    let mut group = c.benchmark_group(format!("encrypt/{label}"));
    for &bits in key_sizes {
        let (pub_id, priv_id) = create_rsa_kp(rt, client, bits);
        let pub_str = pub_id.to_string();

        // Test that the algorithm is actually supported by the server
        let test_req = encrypt_request(
            &pub_str,
            None,
            vec![0x42_u8; 32],
            None,
            None,
            Some(params.clone()),
        )
        .expect("encrypt request");
        if rt.block_on(client.encrypt(test_req)).is_err() {
            eprintln!("[bench] {label}-{bits} not supported by server, skipping");
            bench_ko(format!("encrypt/{label}"));
            continue;
        }

        let enc_req = encrypt_request(
            &pub_str,
            None,
            vec![0x42_u8; 32],
            None,
            None,
            Some(params.clone()),
        )
        .expect("encrypt request");
        group.bench_function(BenchmarkId::new("encrypt", bits), |b| {
            b.to_async(rt).iter(|| client.encrypt(enc_req.clone()));
        });

        let enc_resp = rt
            .block_on(client.encrypt(enc_req))
            .expect("pre-encrypt for decrypt");
        let ct = enc_resp.data.map_or_else(Vec::new, |z| z.to_vec());
        let dec_req = Decrypt {
            unique_identifier: Some(priv_id),
            cryptographic_parameters: Some(params.clone()),
            data: Some(ct),
            ..Default::default()
        };
        group.bench_function(BenchmarkId::new("decrypt", bits), |b| {
            b.to_async(rt).iter(|| client.decrypt(dec_req.clone()));
        });
    }
    group.finish();
}

pub(super) fn bench_encrypt_aes_xts(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let mut group = c.benchmark_group("encrypt/aes-xts");
    let params = aes_xts_params();

    // AES-XTS requires double-sized keys: 256-bit key = AES-128-XTS, 512-bit = AES-256-XTS
    for (label, bits) in [("128", 256), ("256", 512)] {
        let key_id = create_sym_key(rt, client, bits, CryptographicAlgorithm::AES);

        // AES-XTS needs a 16-byte tweak as IV
        let enc_req = Encrypt {
            unique_identifier: Some(key_id.clone()),
            cryptographic_parameters: Some(params.clone()),
            data: Some(Zeroizing::new(vec![1_u8; 64])),
            i_v_counter_nonce: Some(vec![0_u8; 16]),
            ..Default::default()
        };

        // Test support before benchmarking
        if rt.block_on(client.encrypt(enc_req.clone())).is_err() {
            eprintln!("[bench] AES-XTS-{label} not supported by server, skipping");
            bench_ko("encrypt/aes-xts");
            continue;
        }

        group.bench_function(BenchmarkId::new("encrypt", label), |b| {
            b.to_async(rt).iter(|| client.encrypt(enc_req.clone()));
        });

        let enc_resp = rt
            .block_on(client.encrypt(enc_req))
            .expect("pre-encrypt for decrypt setup");
        let dec_req = Decrypt {
            unique_identifier: Some(key_id),
            cryptographic_parameters: Some(params.clone()),
            data: Some(enc_resp.data.map_or_else(Vec::new, |z| z.to_vec())),
            i_v_counter_nonce: enc_resp.i_v_counter_nonce,
            ..Default::default()
        };
        group.bench_function(BenchmarkId::new("decrypt", label), |b| {
            b.to_async(rt).iter(|| client.decrypt(dec_req.clone()));
        });
    }
    group.finish();
}

#[cfg(feature = "non-fips")]
pub(super) fn bench_encrypt_aes_gcm_siv(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let mut group = c.benchmark_group("encrypt/aes-gcm-siv");
    let params = aes_gcm_siv_params();

    for bits in [128, 256] {
        let key_id = create_sym_key(rt, client, bits, CryptographicAlgorithm::AES);

        let enc_req = Encrypt {
            unique_identifier: Some(key_id.clone()),
            cryptographic_parameters: Some(params.clone()),
            data: Some(Zeroizing::new(vec![1_u8; 64])),
            ..Default::default()
        };

        if rt.block_on(client.encrypt(enc_req.clone())).is_err() {
            eprintln!("[bench] AES-GCM-SIV-{bits} not supported by server, skipping");
            bench_ko("encrypt/aes-gcm-siv");
            continue;
        }

        group.bench_function(BenchmarkId::new("encrypt", bits), |b| {
            b.to_async(rt).iter(|| client.encrypt(enc_req.clone()));
        });

        let enc_resp = rt
            .block_on(client.encrypt(enc_req))
            .expect("pre-encrypt for decrypt setup");
        let dec_req = Decrypt {
            unique_identifier: Some(key_id),
            cryptographic_parameters: Some(params.clone()),
            data: Some(enc_resp.data.map_or_else(Vec::new, |z| z.to_vec())),
            i_v_counter_nonce: enc_resp.i_v_counter_nonce,
            authenticated_encryption_tag: enc_resp.authenticated_encryption_tag,
            ..Default::default()
        };
        group.bench_function(BenchmarkId::new("decrypt", bits), |b| {
            b.to_async(rt).iter(|| client.decrypt(dec_req.clone()));
        });
    }
    group.finish();
}

#[cfg(feature = "non-fips")]
pub(super) fn bench_encrypt_ecies(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let mut group = c.benchmark_group("encrypt/ecies");

    for (label, curve) in [
        ("P-256", RecommendedCurve::P256),
        ("P-384", RecommendedCurve::P384),
        ("P-521", RecommendedCurve::P521),
    ] {
        let Some((pub_id, priv_id)) = try_create_ec_kp_no_fips(rt, client, curve) else {
            eprintln!("[bench] ECIES {label} not supported by server, skipping");
            bench_ko("encrypt/ecies");
            continue;
        };
        let pub_str = pub_id.to_string();

        let enc_req = encrypt_request(&pub_str, None, vec![0x42_u8; 64], None, None, None)
            .expect("encrypt request");

        if rt.block_on(client.encrypt(enc_req.clone())).is_err() {
            eprintln!("[bench] ECIES {label} encrypt failed, skipping");
            bench_ko("encrypt/ecies");
            continue;
        }

        group.bench_function(BenchmarkId::new("encrypt", label), |b| {
            b.to_async(rt).iter(|| client.encrypt(enc_req.clone()));
        });

        let enc_resp = rt
            .block_on(client.encrypt(enc_req))
            .expect("pre-encrypt for decrypt");
        let ct = enc_resp.data.map_or_else(Vec::new, |z| z.to_vec());
        let dec_req = decrypt_request(&priv_id.to_string(), None, ct, None, None, None);
        group.bench_function(BenchmarkId::new("decrypt", label), |b| {
            b.to_async(rt).iter(|| client.decrypt(dec_req.clone()));
        });
    }
    group.finish();
}

#[cfg(feature = "non-fips")]
pub(super) fn bench_encrypt_salsa(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let Some((pub_id, priv_id)) =
        try_create_ec_kp_no_fips(rt, client, RecommendedCurve::CURVE25519)
    else {
        eprintln!("[bench] Salsa Sealed Box (X25519) not supported by server, skipping");
        bench_ko("encrypt/salsa-sealed-box");
        return;
    };
    let pub_str = pub_id.to_string();

    let enc_req = encrypt_request(&pub_str, None, vec![0x42_u8; 64], None, None, None)
        .expect("encrypt request");

    if rt.block_on(client.encrypt(enc_req.clone())).is_err() {
        eprintln!("[bench] Salsa Sealed Box encrypt failed, skipping");
        bench_ko("encrypt/salsa-sealed-box");
        return;
    }

    let mut group = c.benchmark_group("encrypt/salsa-sealed-box");
    group.bench_function("encrypt", |b| {
        b.to_async(rt).iter(|| client.encrypt(enc_req.clone()));
    });

    let enc_resp = rt
        .block_on(client.encrypt(enc_req))
        .expect("pre-encrypt for decrypt");
    let ct = enc_resp.data.map_or_else(Vec::new, |z| z.to_vec());
    let dec_req = decrypt_request(&priv_id.to_string(), None, ct, None, None, None);
    group.bench_function("decrypt", |b| {
        b.to_async(rt).iter(|| client.decrypt(dec_req.clone()));
    });
    group.finish();
}

#[cfg(feature = "non-fips")]
pub(super) fn bench_encrypt_covercrypt(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let access_structure =
        r#"{"Department": ["RnD", "HR"], "Security Level::<": ["Protected", "Confidential"]}"#;
    let encryption_policy = "Department::RnD && Security Level::Confidential";
    let decryption_policy = "Department::RnD && Security Level::Confidential";

    let vid = client.config.vendor_id.clone();
    let result = rt.block_on(async {
        let kp_req = build_create_covercrypt_master_keypair_request(
            &vid,
            access_structure,
            ["bench"],
            false,
            None,
        )
        .map_err(|e| format!("CC key pair request: {e}"))?;
        let kp_resp = client
            .create_key_pair(kp_req)
            .await
            .map_err(|e| format!("CC key pair creation: {e}"))?;

        let usk_req = build_create_covercrypt_usk_request(
            &vid,
            decryption_policy,
            &kp_resp.private_key_unique_identifier.to_string(),
            Vec::<String>::new(),
            false,
            None,
        )
        .map_err(|e| format!("CC USK request: {e}"))?;
        let usk_resp = client
            .create(usk_req)
            .await
            .map_err(|e| format!("CC USK creation: {e}"))?;

        Ok::<_, String>((
            kp_resp.public_key_unique_identifier,
            usk_resp.unique_identifier,
        ))
    });

    let (pub_id, usk_id) = match result {
        Ok(ids) => ids,
        Err(e) => {
            eprintln!("[bench] Covercrypt not supported by server: {e}, skipping");
            bench_ko("encrypt/covercrypt");
            return;
        }
    };

    let pub_str = pub_id.to_string();
    let usk_str = usk_id.to_string();

    let enc_req = encrypt_request(
        &pub_str,
        Some(encryption_policy.to_owned()),
        vec![0x42_u8; 64],
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    )
    .expect("CC encrypt request");

    if rt.block_on(client.encrypt(enc_req.clone())).is_err() {
        eprintln!("[bench] Covercrypt encrypt failed, skipping");
        bench_ko("encrypt/covercrypt");
        return;
    }

    let mut group = c.benchmark_group("encrypt/covercrypt");
    group.bench_function("encrypt", |b| {
        b.to_async(rt).iter(|| client.encrypt(enc_req.clone()));
    });

    let enc_resp = rt
        .block_on(client.encrypt(enc_req))
        .expect("pre-encrypt for decrypt");
    let ct = enc_resp.data.map_or_else(Vec::new, |z| z.to_vec());
    let dec_req = decrypt_request(
        &usk_str,
        None,
        ct,
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
    );
    group.bench_function("decrypt", |b| {
        b.to_async(rt).iter(|| client.decrypt(dec_req.clone()));
    });
    group.finish();
}

#[cfg(feature = "non-fips")]
fn bench_kem(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let vid = client.config.vendor_id.clone();
    let params = kem_params();

    let algorithms = [
        ("ML-KEM-512", KemAlgorithm::MlKem512),
        ("ML-KEM-768", KemAlgorithm::MlKem768),
        ("ML-KEM-512/P-256", KemAlgorithm::MlKem512P256),
        ("ML-KEM-768/P-256", KemAlgorithm::MlKem768P256),
        ("ML-KEM-512/X25519", KemAlgorithm::MlKem512Curve25519),
        ("ML-KEM-768/X25519", KemAlgorithm::MlKem768Curve25519),
    ];

    let mut group = c.benchmark_group("kem/configurable");
    for (label, algo) in algorithms {
        let result = rt.block_on(async {
            let kp_req = build_create_configurable_kem_keypair_request(
                &vid,
                None,
                ["bench"],
                algo,
                false,
                None,
            )
            .map_err(|e| format!("KEM key pair request ({label}): {e}"))?;
            let kp_resp = client
                .create_key_pair(kp_req)
                .await
                .map_err(|e| format!("KEM key pair creation ({label}): {e}"))?;
            Ok::<_, String>((
                kp_resp.public_key_unique_identifier,
                kp_resp.private_key_unique_identifier,
            ))
        });

        let (pub_id, priv_id) = match result {
            Ok(ids) => ids,
            Err(e) => {
                eprintln!("[bench] KEM {label} not supported: {e}, skipping");
                bench_ko("kem/configurable");
                continue;
            }
        };

        let pub_str = pub_id.to_string();
        let enc_req = encrypt_request(&pub_str, None, Vec::new(), None, None, Some(params.clone()))
            .expect("KEM encapsulate request");

        if rt.block_on(client.encrypt(enc_req.clone())).is_err() {
            eprintln!("[bench] KEM {label} encapsulate failed, skipping");
            bench_ko("kem/configurable");
            continue;
        }

        group.bench_function(BenchmarkId::new("encapsulate", label), |b| {
            b.to_async(rt).iter(|| client.encrypt(enc_req.clone()));
        });

        let enc_resp = rt
            .block_on(client.encrypt(enc_req))
            .expect("pre-encapsulate for decapsulate");
        let ct = enc_resp.data.map_or_else(Vec::new, |z| z.to_vec());
        let dec_req = decrypt_request(
            &priv_id.to_string(),
            None,
            ct,
            None,
            None,
            Some(params.clone()),
        );
        group.bench_function(BenchmarkId::new("decapsulate", label), |b| {
            b.to_async(rt).iter(|| client.decrypt(dec_req.clone()));
        });
    }
    group.finish();
}

#[cfg(feature = "non-fips")]
fn bench_pqc_kem(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let algorithms: &[(&str, CryptographicAlgorithm)] = &[
        ("ML-KEM-512", CryptographicAlgorithm::MLKEM_512),
        ("ML-KEM-768", CryptographicAlgorithm::MLKEM_768),
        ("ML-KEM-1024", CryptographicAlgorithm::MLKEM_1024),
        ("X25519MLKEM768", CryptographicAlgorithm::X25519MLKEM768),
        ("X448MLKEM1024", CryptographicAlgorithm::X448MLKEM1024),
    ];

    let mut group = c.benchmark_group("kem/pqc");
    for &(label, algo) in algorithms {
        let Some((pub_id, priv_id)) = try_create_pqc_kp(rt, client, algo) else {
            eprintln!("[bench] PQC KEM {label} not supported by server, skipping");
            bench_ko("kem/pqc");
            continue;
        };

        let pub_str = pub_id.to_string();
        let enc_req =
            encrypt_request(&pub_str, None, Vec::new(), None, None, None).expect("KEM request");

        let Ok(enc_resp) = rt.block_on(client.encrypt(enc_req.clone())) else {
            eprintln!("[bench] PQC KEM {label} encapsulate failed, skipping");
            bench_ko("kem/pqc");
            continue;
        };

        group.bench_function(BenchmarkId::new("encapsulate", label), |b| {
            b.to_async(rt).iter(|| client.encrypt(enc_req.clone()));
        });

        // Standard PQC KEM: ciphertext is in i_v_counter_nonce
        let ct = enc_resp
            .i_v_counter_nonce
            .unwrap_or_else(|| enc_resp.data.map_or_else(Vec::new, |z| z.to_vec()));
        let dec_req = decrypt_request(&priv_id.to_string(), None, ct, None, None, None);
        group.bench_function(BenchmarkId::new("decapsulate", label), |b| {
            b.to_async(rt).iter(|| client.decrypt(dec_req.clone()));
        });
    }
    group.finish();
}

// =============================================================================
// KEY CREATION BENCHMARKS
// =============================================================================

pub(super) fn bench_key_creation(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let vid = client.config.vendor_id.clone();

    // ── Symmetric keys ───────────────────────────────────────────────────
    {
        let mut group = c.benchmark_group("key-creation/symmetric");
        for (label, bits, algo) in [
            ("aes-128", 128, CryptographicAlgorithm::AES),
            ("aes-192", 192, CryptographicAlgorithm::AES),
            ("aes-256", 256, CryptographicAlgorithm::AES),
        ] {
            let vid = vid.clone();
            group.bench_function(label, |b| {
                b.to_async(rt).iter(|| {
                    let vid = vid.clone();
                    async move {
                        let req = symmetric_key_create_request(
                            &vid,
                            None,
                            bits,
                            algo,
                            Vec::<String>::new(),
                            false,
                            None,
                        )
                        .unwrap();
                        client.create(req).await.unwrap();
                    }
                });
            });
        }
        #[cfg(feature = "non-fips")]
        if try_create_sym_key(rt, client, 256, CryptographicAlgorithm::ChaCha20).is_some() {
            group.bench_function("chacha20-256", |b| {
                b.to_async(rt).iter(|| {
                    let vid = vid.clone();
                    async move {
                        let req = symmetric_key_create_request(
                            &vid,
                            None,
                            256,
                            CryptographicAlgorithm::ChaCha20,
                            Vec::<String>::new(),
                            false,
                            None,
                        )
                        .unwrap();
                        client.create(req).await.unwrap();
                    }
                });
            });
        } else {
            bench_ko("key-creation/symmetric");
        }
        group.finish();
    }

    // ── RSA key pairs ────────────────────────────────────────────────────
    {
        let mut group = c.benchmark_group("key-creation/rsa");
        for bits in [2048, 3072, 4096] {
            let vid = vid.clone();
            group.bench_function(format!("rsa-{bits}"), |b| {
                b.to_async(rt).iter(|| {
                    let vid = vid.clone();
                    async move {
                        let req = with_fips_rsa_masks(
                            create_rsa_key_pair_request(
                                &vid,
                                None,
                                Vec::<String>::new(),
                                bits,
                                false,
                                None,
                            )
                            .unwrap(),
                        );
                        client.create_key_pair(req).await.unwrap();
                    }
                });
            });
        }
        group.finish();
    }

    // ── EC key pairs ─────────────────────────────────────────────────────
    {
        let mut group = c.benchmark_group("key-creation/ec");
        for (label, curve) in [
            ("p256", RecommendedCurve::P256),
            ("p384", RecommendedCurve::P384),
            ("p521", RecommendedCurve::P521),
        ] {
            let vid = vid.clone();
            group.bench_function(label, |b| {
                b.to_async(rt).iter(|| {
                    let vid = vid.clone();
                    async move {
                        let req = with_fips_ec_masks(
                            create_ec_key_pair_request(
                                &vid,
                                None,
                                Vec::<String>::new(),
                                curve,
                                false,
                                None,
                            )
                            .unwrap(),
                        );
                        client.create_key_pair(req).await.unwrap();
                    }
                });
            });
        }
        #[cfg(feature = "non-fips")]
        for (label, curve) in [
            ("ed25519", RecommendedCurve::CURVEED25519),
            ("ed448", RecommendedCurve::CURVEED448),
            ("secp256k1", RecommendedCurve::SECP256K1),
        ] {
            if try_create_ec_kp(rt, client, curve).is_some() {
                let vid = vid.clone();
                group.bench_function(label, |b| {
                    b.to_async(rt).iter(|| {
                        let vid = vid.clone();
                        async move {
                            let req = with_fips_ec_masks(
                                create_ec_key_pair_request(
                                    &vid,
                                    None,
                                    Vec::<String>::new(),
                                    curve,
                                    false,
                                    None,
                                )
                                .unwrap(),
                            );
                            client.create_key_pair(req).await.unwrap();
                        }
                    });
                });
            } else {
                bench_ko("key-creation/ec");
            }
        }
        group.finish();
    }

    // ── Covercrypt key pairs (non-FIPS) ──────────────────────────────────
    #[cfg(feature = "non-fips")]
    {
        let access_structure =
            r#"{"Department": ["RnD", "HR"], "Security Level::<": ["Protected", "Confidential"]}"#;
        let vid2 = vid.clone();
        let result = rt.block_on(async {
            let req = build_create_covercrypt_master_keypair_request(
                &vid2,
                access_structure,
                ["bench"],
                false,
                None,
            )
            .ok();
            match req {
                Some(r) => client.create_key_pair(r).await.ok(),
                None => None,
            }
        });
        if result.is_some() {
            let mut group = c.benchmark_group("key-creation/covercrypt");
            group.bench_function("master-keypair", |b| {
                b.to_async(rt).iter(|| {
                    let vid2 = vid.clone();
                    async move {
                        let req = build_create_covercrypt_master_keypair_request(
                            &vid2,
                            access_structure,
                            Vec::<String>::new(),
                            false,
                            None,
                        )
                        .unwrap();
                        client.create_key_pair(req).await.unwrap();
                    }
                });
            });
            group.finish();
        } else {
            bench_ko("key-creation/covercrypt");
        }
    }

    // ── Configurable KEM key pairs (non-FIPS) ───────────────────────────
    #[cfg(feature = "non-fips")]
    {
        let kem_algos = [
            ("ML-KEM-512", KemAlgorithm::MlKem512),
            ("ML-KEM-768", KemAlgorithm::MlKem768),
            ("ML-KEM-512/P-256", KemAlgorithm::MlKem512P256),
            ("ML-KEM-768/P-256", KemAlgorithm::MlKem768P256),
            ("ML-KEM-512/X25519", KemAlgorithm::MlKem512Curve25519),
            ("ML-KEM-768/X25519", KemAlgorithm::MlKem768Curve25519),
        ];

        let mut group = c.benchmark_group("key-creation/kem");
        for (label, algo) in kem_algos {
            let vid2 = vid.clone();
            let result = rt.block_on(async {
                let req = build_create_configurable_kem_keypair_request(
                    &vid2,
                    None,
                    ["bench"],
                    algo,
                    false,
                    None,
                )
                .ok()?;
                client.create_key_pair(req).await.ok()
            });
            if result.is_some() {
                let vid2 = vid.clone();
                group.bench_function(label, |b| {
                    b.to_async(rt).iter(|| {
                        let vid2 = vid2.clone();
                        async move {
                            let req = build_create_configurable_kem_keypair_request(
                                &vid2,
                                None,
                                Vec::<String>::new(),
                                algo,
                                false,
                                None,
                            )
                            .unwrap();
                            client.create_key_pair(req).await.unwrap();
                        }
                    });
                });
            } else {
                bench_ko("key-creation/kem");
            }
        }
        group.finish();
    }

    // ── PQC key pairs (non-FIPS) ────────────────────────────────────────
    #[cfg(feature = "non-fips")]
    {
        let pqc_algos: &[(&str, CryptographicAlgorithm)] = &[
            ("ML-KEM-512", CryptographicAlgorithm::MLKEM_512),
            ("ML-KEM-768", CryptographicAlgorithm::MLKEM_768),
            ("ML-KEM-1024", CryptographicAlgorithm::MLKEM_1024),
            ("X25519MLKEM768", CryptographicAlgorithm::X25519MLKEM768),
            ("X448MLKEM1024", CryptographicAlgorithm::X448MLKEM1024),
            ("ML-DSA-44", CryptographicAlgorithm::MLDSA_44),
            ("ML-DSA-65", CryptographicAlgorithm::MLDSA_65),
            ("ML-DSA-87", CryptographicAlgorithm::MLDSA_87),
            (
                "SLH-DSA-SHA2-128s",
                CryptographicAlgorithm::SLHDSA_SHA2_128s,
            ),
            (
                "SLH-DSA-SHA2-128f",
                CryptographicAlgorithm::SLHDSA_SHA2_128f,
            ),
            (
                "SLH-DSA-SHA2-192s",
                CryptographicAlgorithm::SLHDSA_SHA2_192s,
            ),
            (
                "SLH-DSA-SHA2-192f",
                CryptographicAlgorithm::SLHDSA_SHA2_192f,
            ),
            (
                "SLH-DSA-SHA2-256s",
                CryptographicAlgorithm::SLHDSA_SHA2_256s,
            ),
            (
                "SLH-DSA-SHA2-256f",
                CryptographicAlgorithm::SLHDSA_SHA2_256f,
            ),
            (
                "SLH-DSA-SHAKE-128s",
                CryptographicAlgorithm::SLHDSA_SHAKE_128s,
            ),
            (
                "SLH-DSA-SHAKE-128f",
                CryptographicAlgorithm::SLHDSA_SHAKE_128f,
            ),
            (
                "SLH-DSA-SHAKE-192s",
                CryptographicAlgorithm::SLHDSA_SHAKE_192s,
            ),
            (
                "SLH-DSA-SHAKE-192f",
                CryptographicAlgorithm::SLHDSA_SHAKE_192f,
            ),
            (
                "SLH-DSA-SHAKE-256s",
                CryptographicAlgorithm::SLHDSA_SHAKE_256s,
            ),
            (
                "SLH-DSA-SHAKE-256f",
                CryptographicAlgorithm::SLHDSA_SHAKE_256f,
            ),
        ];

        let mut group = c.benchmark_group("key-creation/pqc");
        for &(label, algo) in pqc_algos {
            let vid2 = vid.clone();
            let result = rt.block_on(async {
                let req = create_pqc_key_pair_request(&vid2, ["bench"], algo, false).ok()?;
                client.create_key_pair(req).await.ok()
            });
            if result.is_some() {
                let vid2 = vid.clone();
                group.bench_function(label, |b| {
                    b.to_async(rt).iter(|| {
                        let vid2 = vid2.clone();
                        async move {
                            let req = create_pqc_key_pair_request(
                                &vid2,
                                Vec::<String>::new(),
                                algo,
                                false,
                            )
                            .unwrap();
                            client.create_key_pair(req).await.unwrap();
                        }
                    });
                });
            } else {
                bench_ko("key-creation/pqc");
            }
        }
        group.finish();
    }
}

// =============================================================================
// SIGN / VERIFY BENCHMARKS
// =============================================================================

pub(super) fn bench_sign_verify(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    // ECDSA — FIPS curves
    for (label, curve, algo) in [
        (
            "ecdsa-p256",
            RecommendedCurve::P256,
            DigitalSignatureAlgorithm::ECDSAWithSHA256,
        ),
        (
            "ecdsa-p384",
            RecommendedCurve::P384,
            DigitalSignatureAlgorithm::ECDSAWithSHA384,
        ),
        (
            "ecdsa-p521",
            RecommendedCurve::P521,
            DigitalSignatureAlgorithm::ECDSAWithSHA512,
        ),
    ] {
        bench_ec_sign(c, client, rt, label, curve, Some(algo));
    }

    // Non-FIPS EC signature algorithms
    #[cfg(feature = "non-fips")]
    {
        bench_ec_sign(
            c,
            client,
            rt,
            "ecdsa-secp256k1",
            RecommendedCurve::SECP256K1,
            Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
        );

        bench_ec_sign(
            c,
            client,
            rt,
            "eddsa-ed25519",
            RecommendedCurve::CURVEED25519,
            None,
        );

        bench_ec_sign(
            c,
            client,
            rt,
            "eddsa-ed448",
            RecommendedCurve::CURVEED448,
            None,
        );
    }

    // RSA-PSS
    bench_rsa_pss_sign(c, client, rt);

    // PQC signature algorithms (non-FIPS)
    #[cfg(feature = "non-fips")]
    bench_pqc_sign(
        c,
        client,
        rt,
        "sign-verify/ml-dsa",
        &[
            ("44", CryptographicAlgorithm::MLDSA_44),
            ("65", CryptographicAlgorithm::MLDSA_65),
            ("87", CryptographicAlgorithm::MLDSA_87),
        ],
    );

    #[cfg(feature = "non-fips")]
    bench_pqc_sign(
        c,
        client,
        rt,
        "sign-verify/slh-dsa",
        &[
            ("SHA2-128s", CryptographicAlgorithm::SLHDSA_SHA2_128s),
            ("SHA2-128f", CryptographicAlgorithm::SLHDSA_SHA2_128f),
            ("SHA2-192s", CryptographicAlgorithm::SLHDSA_SHA2_192s),
            ("SHA2-192f", CryptographicAlgorithm::SLHDSA_SHA2_192f),
            ("SHA2-256s", CryptographicAlgorithm::SLHDSA_SHA2_256s),
            ("SHA2-256f", CryptographicAlgorithm::SLHDSA_SHA2_256f),
            ("SHAKE-128s", CryptographicAlgorithm::SLHDSA_SHAKE_128s),
            ("SHAKE-128f", CryptographicAlgorithm::SLHDSA_SHAKE_128f),
            ("SHAKE-192s", CryptographicAlgorithm::SLHDSA_SHAKE_192s),
            ("SHAKE-192f", CryptographicAlgorithm::SLHDSA_SHAKE_192f),
            ("SHAKE-256s", CryptographicAlgorithm::SLHDSA_SHAKE_256s),
            ("SHAKE-256f", CryptographicAlgorithm::SLHDSA_SHAKE_256f),
        ],
    );
}

fn bench_ec_sign(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    label: &str,
    curve: RecommendedCurve,
    sign_algo: Option<DigitalSignatureAlgorithm>,
) {
    let Some((pub_id, priv_id)) = try_create_ec_kp(rt, client, curve) else {
        eprintln!("[bench] {label} not supported by server, skipping");
        bench_ko(format!("sign-verify/{label}"));
        return;
    };

    let sign_params = sign_algo.map(|a| CryptographicParameters {
        digital_signature_algorithm: Some(a),
        ..Default::default()
    });
    let message = Zeroizing::new(vec![0x42_u8; 32]);

    let sign_req = Sign {
        unique_identifier: Some(priv_id),
        cryptographic_parameters: sign_params.clone(),
        data: Some(message.clone()),
        ..Default::default()
    };
    let Ok(sign_resp) = rt.block_on(client.sign(sign_req.clone())) else {
        eprintln!("[bench] {label} sign not supported by server, skipping");
        bench_ko(format!("sign-verify/{label}"));
        return;
    };
    let sample_sig = sign_resp.signature_data.unwrap_or_default();

    let verify_req = SignatureVerify {
        unique_identifier: Some(pub_id),
        cryptographic_parameters: sign_params,
        data: Some(message.to_vec()),
        signature_data: Some(sample_sig),
        ..Default::default()
    };

    let mut group = c.benchmark_group(format!("sign-verify/{label}"));
    group.bench_function("sign", |b| {
        b.to_async(rt).iter(|| client.sign(sign_req.clone()));
    });
    group.bench_function("verify", |b| {
        b.to_async(rt)
            .iter(|| client.signature_verify(verify_req.clone()));
    });
    group.finish();
}

fn bench_rsa_pss_sign(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let sign_params = Some(CryptographicParameters {
        digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
        ..Default::default()
    });
    let message = Zeroizing::new(vec![0x42_u8; 32]);

    let mut group = c.benchmark_group("sign-verify/rsa-pss");
    for bits in [2048, 3072, 4096] {
        let (pub_id, priv_id) = create_rsa_kp(rt, client, bits);

        let sign_req = Sign {
            unique_identifier: Some(priv_id),
            cryptographic_parameters: sign_params.clone(),
            data: Some(message.clone()),
            ..Default::default()
        };
        let Ok(sign_resp) = rt.block_on(client.sign(sign_req.clone())) else {
            eprintln!("[bench] rsa-pss-{bits} sign not supported by server, skipping");
            bench_ko("sign-verify/rsa-pss");
            continue;
        };
        let sample_sig = sign_resp.signature_data.unwrap_or_default();

        let verify_req = SignatureVerify {
            unique_identifier: Some(pub_id),
            cryptographic_parameters: sign_params.clone(),
            data: Some(message.to_vec()),
            signature_data: Some(sample_sig),
            ..Default::default()
        };

        group.bench_function(BenchmarkId::new("sign", bits), |b| {
            b.to_async(rt).iter(|| client.sign(sign_req.clone()));
        });
        group.bench_function(BenchmarkId::new("verify", bits), |b| {
            b.to_async(rt)
                .iter(|| client.signature_verify(verify_req.clone()));
        });
    }
    group.finish();
}

#[cfg(feature = "non-fips")]
fn bench_pqc_sign(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    group_name: &str,
    algorithms: &[(&str, CryptographicAlgorithm)],
) {
    let message = Zeroizing::new(vec![0x42_u8; 32]);
    let mut group = c.benchmark_group(group_name);

    for &(label, algo) in algorithms {
        let Some((pub_id, priv_id)) = try_create_pqc_kp(rt, client, algo) else {
            eprintln!("[bench] {label} not supported by server, skipping");
            bench_ko(group_name);
            continue;
        };

        let sign_req = Sign {
            unique_identifier: Some(priv_id),
            cryptographic_parameters: None,
            data: Some(message.clone()),
            ..Default::default()
        };
        let Ok(sign_resp) = rt.block_on(client.sign(sign_req.clone())) else {
            eprintln!("[bench] {label} sign failed, skipping");
            bench_ko(group_name);
            continue;
        };
        let sample_sig = sign_resp.signature_data.unwrap_or_default();

        let verify_req = SignatureVerify {
            unique_identifier: Some(pub_id),
            cryptographic_parameters: None,
            data: Some(message.to_vec()),
            signature_data: Some(sample_sig),
            ..Default::default()
        };

        group.bench_function(BenchmarkId::new("sign", label), |b| {
            b.to_async(rt).iter(|| client.sign(sign_req.clone()));
        });
        group.bench_function(BenchmarkId::new("verify", label), |b| {
            b.to_async(rt)
                .iter(|| client.signature_verify(verify_req.clone()));
        });
    }
    group.finish();
}

// =============================================================================
// BATCH BENCHMARKS
// =============================================================================

pub(super) fn bench_batch(c: &mut Criterion, client: &KmsClient, rt: &Runtime, sanity: bool) {
    bench_batch_aes_bulk(c, client, rt, sanity);

    bench_batch_rsa_message(c, client, rt, "batch/rsa-oaep", &rsa_oaep_params(), sanity);

    bench_batch_rsa_message(
        c,
        client,
        rt,
        "batch/rsa-aes-kwp",
        &rsa_kwp_params(),
        sanity,
    );

    #[cfg(feature = "non-fips")]
    bench_batch_rsa_message(
        c,
        client,
        rt,
        "batch/rsa-pkcs1v15",
        &rsa_pkcs15_params(),
        sanity,
    );
}

pub(super) fn bench_batch_aes_bulk(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    sanity: bool,
) {
    let mut group = c.benchmark_group("batch/aes-gcm");
    let params = aes_gcm_params();

    let batch_sizes: &[usize] = if sanity {
        &[1]
    } else {
        &[1, 10, 50, 100, 500, 1000]
    };

    for bits in [128, 256] {
        let key_id = create_sym_key(rt, client, bits, CryptographicAlgorithm::AES);
        let key_str = key_id.to_string();

        for n in batch_sizes.iter().copied() {
            let parameter_name = if n == 1 {
                format!("{n} request")
            } else {
                format!("{n} requests")
            };

            let data = if n == 1 {
                Zeroizing::new(vec![1_u8; 64])
            } else {
                BulkData::new(vec![Zeroizing::new(vec![1_u8; 64]); n])
                    .serialize()
                    .expect("BulkData serialize")
            };
            let req = encrypt_request(
                &key_str,
                None,
                data.to_vec(),
                None,
                None,
                Some(params.clone()),
            )
            .expect("encrypt request");

            let pre_resp = rt
                .block_on(client.encrypt(req.clone()))
                .expect("pre-encrypt bulk request");
            let ciphertext = pre_resp.data.map_or_else(Vec::new, |z| z.to_vec());
            let dec_req =
                decrypt_request(&key_str, None, ciphertext, None, None, Some(params.clone()));

            group.throughput(Throughput::Elements(n as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("{bits}-bit key encrypt"), &parameter_name),
                &n,
                |b, _| {
                    b.to_async(rt).iter(|| client.encrypt(req.clone()));
                },
            );
            group.bench_with_input(
                BenchmarkId::new(format!("{bits}-bit key decrypt"), &parameter_name),
                &n,
                |b, _| {
                    b.to_async(rt).iter(|| client.decrypt(dec_req.clone()));
                },
            );
        }
    }
    group.finish();
}

pub(super) fn bench_batch_rsa_message(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    group_name: &str,
    params: &CryptographicParameters,
    sanity: bool,
) {
    let mut group = c.benchmark_group(group_name);

    for bits in [2048, 3072, 4096] {
        let (pub_id, priv_id) = create_rsa_kp(rt, client, bits);
        let pub_str = pub_id.to_string();
        let priv_str = priv_id.to_string();

        // Test support
        let test_req = encrypt_request(
            &pub_str,
            None,
            vec![0_u8; 32],
            None,
            None,
            Some(params.clone()),
        )
        .expect("test encrypt request");
        if rt.block_on(client.encrypt(test_req)).is_err() {
            eprintln!("[bench] {group_name}-{bits} not supported by server, skipping");
            bench_ko(group_name);
            continue;
        }

        // Pre-encrypt for decrypt batches
        let pre_req = encrypt_request(
            &pub_str,
            None,
            vec![0_u8; 32],
            None,
            None,
            Some(params.clone()),
        )
        .expect("pre-encrypt request");
        let pre_resp = rt.block_on(client.encrypt(pre_req)).expect("pre-encrypt");
        let ciphertext = pre_resp.data.map_or_else(Vec::new, |z| z.to_vec());

        let rsa_batch_sizes: &[usize] = if sanity { &[1] } else { &[1, 10, 50, 100] };
        for n in rsa_batch_sizes.iter().copied() {
            let parameter_name = if n == 1 {
                format!("{n} request")
            } else {
                format!("{n} requests")
            };

            // Encrypt batch
            let enc_item = encrypt_request(
                &pub_str,
                None,
                vec![0_u8; 32],
                None,
                None,
                Some(params.clone()),
            )
            .expect("encrypt request");
            let enc_msg = RequestMessage {
                request_header: RequestMessageHeader {
                    protocol_version: ProtocolVersion {
                        protocol_version_major: 2,
                        protocol_version_minor: 1,
                    },
                    batch_count: i32::try_from(n).expect("batch_count fits i32"),
                    ..Default::default()
                },
                batch_item: (0..n)
                    .map(|_| {
                        RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                            Operation::Encrypt(Box::new(enc_item.clone())),
                        ))
                    })
                    .collect(),
            };

            group.throughput(Throughput::Elements(n as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("{bits}-bit key encrypt"), &parameter_name),
                &n,
                |b, _| {
                    b.to_async(rt).iter(|| client.message(enc_msg.clone()));
                },
            );

            // Decrypt batch
            let dec_item = decrypt_request(
                &priv_str,
                None,
                ciphertext.clone(),
                None,
                None,
                Some(params.clone()),
            );
            let dec_msg = RequestMessage {
                request_header: RequestMessageHeader {
                    protocol_version: ProtocolVersion {
                        protocol_version_major: 2,
                        protocol_version_minor: 1,
                    },
                    batch_count: i32::try_from(n).expect("batch_count fits i32"),
                    ..Default::default()
                },
                batch_item: (0..n)
                    .map(|_| {
                        RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                            Operation::Decrypt(Box::new(dec_item.clone())),
                        ))
                    })
                    .collect(),
            };

            group.bench_with_input(
                BenchmarkId::new(format!("{bits}-bit key decrypt"), &parameter_name),
                &n,
                |b, _| {
                    b.to_async(rt).iter(|| client.message(dec_msg.clone()));
                },
            );
        }
    }
    group.finish();
}
