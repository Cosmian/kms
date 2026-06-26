#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::as_conversions,
    let_underscore_drop
)]
//! HTTP throughput benchmark: proves that the KMS scales on multiple CPUs.
//!
//! For each worker count in {1, 2, 4, 8} the bench:
//!   1. Starts a fresh in-process KMS server with `server_workers = N`.
//!   2. Pre-creates the cryptographic keys used as bench fixtures.
//!   3. Drives `CONCURRENCY` concurrent HTTP requests per Criterion iteration
//!      for three representative KMIP operations:
//!        - AES-256-GCM symmetric encrypt  (lightweight, high-frequency)
//!        - RSA-2048 OAEP decrypt           (CPU-heavy asymmetric)
//!        - ECDSA P-256 sign                (CPU-heavy, short messages)
//!   4. Reports throughput in req/s so the scaling curve is visible.
//!
//! Run:
//!   `cargo bench --bench http_throughput -p test_kms_server`
//!
//! Generate a flamegraph (Linux, requires `cargo install flamegraph`):
//!   `CARGO_PROFILE_BENCH_DEBUG=true`
//!   `cargo flamegraph --bench http_throughput -p test_kms_server -- --bench`

use std::time::Instant;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures::future::join_all;
use test_kms_server::{
    TestClientOptions, init_test_logging, start_test_server_with_patch, test_config_path,
};
use zeroize::Zeroizing;

use cosmian_kms_client::{
    KmsClient, KmsClientError,
    kmip_0::kmip_types::{CryptographicUsageMask, HashingAlgorithm, PaddingMethod},
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, Sign},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
            KeyFormatType, RecommendedCurve, UniqueIdentifier,
        },
        requests::{
            create_ec_key_pair_request, create_rsa_key_pair_request, decrypt_request,
            encrypt_request,
        },
    },
};

/// Number of concurrent HTTP tasks dispatched per Criterion iteration.
/// High enough to saturate the server workers; low enough to avoid OS thread exhaustion.
const CONCURRENCY: usize = 16;

/// Worker counts to sweep (actix-web threads per server instance).
const WORKER_COUNTS: &[usize] = &[1, 2, 4, 8];

// ── Key creation helpers ──────────────────────────────────────────────────────

async fn create_aes_key(client: &KmsClient) -> String {
    let attrs = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        }),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    };
    let req = Create {
        object_type: ObjectType::SymmetricKey,
        attributes: attrs,
        protection_storage_masks: None,
    };
    client
        .create(req)
        .await
        .unwrap()
        .unique_identifier
        .to_string()
}

async fn create_rsa_keypair(client: &KmsClient) -> (String, String) {
    let req =
        create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, ["bench"], 2048, false, None).unwrap();
    let resp = client.create_key_pair(req).await.unwrap();
    (
        resp.private_key_unique_identifier.to_string(),
        resp.public_key_unique_identifier.to_string(),
    )
}

async fn create_ec_keypair(client: &KmsClient) -> (String, String) {
    let req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        ["bench"],
        RecommendedCurve::P256,
        false,
        None,
    )
    .unwrap();
    let resp = client.create_key_pair(req).await.unwrap();
    (
        resp.private_key_unique_identifier.to_string(),
        resp.public_key_unique_identifier.to_string(),
    )
}

// ── Operation helpers ─────────────────────────────────────────────────────────

async fn aes_encrypt(client: &KmsClient, key_id: &str) -> Result<(), KmsClientError> {
    let params = CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        ..Default::default()
    };
    let req = encrypt_request(key_id, None, vec![0x42_u8; 64], None, None, Some(params))?;
    client.encrypt(req).await.map(|_| ())
}

async fn rsa_decrypt(
    client: &KmsClient,
    sk_id: &str,
    ciphertext: &[u8],
) -> Result<(), KmsClientError> {
    let params = CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        padding_method: Some(PaddingMethod::OAEP),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        ..Default::default()
    };
    let req = decrypt_request(sk_id, None, ciphertext.to_vec(), None, None, Some(params));
    client.decrypt(req).await.map(|_| ())
}

async fn ec_sign(client: &KmsClient, sk_id: &str) -> Result<(), KmsClientError> {
    let req = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(sk_id.to_owned())),
        cryptographic_parameters: Some(CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
            ..Default::default()
        }),
        data: Some(Zeroizing::new(vec![0x42_u8; 32])),
        ..Sign::default()
    };
    client.sign(req).await.map(|_| ())
}

// ── RSA ciphertext pre-computation ───────────────────────────────────────────

async fn rsa_encrypt_sample(client: &KmsClient, pk_id: &str) -> Vec<u8> {
    let params = CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        padding_method: Some(PaddingMethod::OAEP),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        ..Default::default()
    };
    let req = encrypt_request(pk_id, None, vec![0x42_u8; 32], None, None, Some(params)).unwrap();
    client
        .encrypt(req)
        .await
        .expect("RSA OAEP encrypt (setup)")
        .data
        .unwrap()
}

// ── Bench entry point ─────────────────────────────────────────────────────────

fn bench_http_throughput(c: &mut Criterion) {
    init_test_logging();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime for bench");

    let config_path = test_config_path("auth_plain.toml");

    let mut group = c.benchmark_group("KMS CPU Scaling");
    group.throughput(Throughput::Elements(CONCURRENCY as u64));
    // Reduce sample count to keep total bench time reasonable; each sample
    // already exercises many concurrent requests.
    group.sample_size(20);
    // RSA-2048 OAEP decrypt takes ~450ms/iter; the default 5s measurement
    // window is too short for 20 samples. 10s avoids the Criterion warning.
    group.measurement_time(std::time::Duration::from_secs(10));

    for &workers in WORKER_COUNTS {
        // ── Start a fresh server with the requested worker count ──────────
        let ctx = runtime
            .block_on(start_test_server_with_patch(
                &config_path,
                |cfg| {
                    cfg.http.server_workers = Some(workers);
                    // Keep SQLite on tmpfs to keep I/O out of the critical path.
                    let shm = std::path::PathBuf::from("/dev/shm");
                    let base = if shm.exists() {
                        shm
                    } else {
                        std::env::temp_dir()
                    };
                    cfg.db.sqlite_path =
                        base.join(format!("kms_bench_w{workers}_{}", std::process::id()));
                    cfg.db.clear_database = true;
                },
                TestClientOptions::default(),
            ))
            .expect("failed to start KMS server");

        let client = ctx.get_owner_client();

        // ── Pre-create keys (not timed) ───────────────────────────────────
        let (aes_key_id, rsa_sk_id, ciphertext, ec_sk_id) = runtime.block_on(async {
            let aes_key_id = create_aes_key(&client).await;
            let (rsa_sk, rsa_pk) = create_rsa_keypair(&client).await;
            let ciphertext = rsa_encrypt_sample(&client, &rsa_pk).await;
            let (ec_sk, _) = create_ec_keypair(&client).await;
            (aes_key_id, rsa_sk, ciphertext, ec_sk)
        });

        // ── AES-256-GCM encrypt ───────────────────────────────────────────
        group.bench_with_input(
            BenchmarkId::new("AES-256-GCM encrypt", format!("{workers} workers")),
            &workers,
            |b, _| {
                let client = client.clone();
                let key_id = aes_key_id.clone();
                b.to_async(&runtime).iter_custom(|iters| {
                    let client = client.clone();
                    let key_id = key_id.clone();
                    async move {
                        let start = Instant::now();
                        for _ in 0..iters {
                            let tasks: Vec<_> = (0..CONCURRENCY)
                                .map(|_| {
                                    let c = client.clone();
                                    let k = key_id.clone();
                                    tokio::spawn(async move { aes_encrypt(&c, &k).await })
                                })
                                .collect();
                            join_all(tasks).await;
                        }
                        start.elapsed()
                    }
                });
            },
        );

        // ── RSA-2048 OAEP decrypt ─────────────────────────────────────────
        group.bench_with_input(
            BenchmarkId::new("RSA-2048 OAEP decrypt", format!("{workers} workers")),
            &workers,
            |b, _| {
                let client = client.clone();
                let sk_id = rsa_sk_id.clone();
                let ct = ciphertext.clone();
                b.to_async(&runtime).iter_custom(|iters| {
                    let client = client.clone();
                    let sk_id = sk_id.clone();
                    let ct = ct.clone();
                    async move {
                        let start = Instant::now();
                        for _ in 0..iters {
                            let tasks: Vec<_> = (0..CONCURRENCY)
                                .map(|_| {
                                    let c = client.clone();
                                    let s = sk_id.clone();
                                    let ciphertext = ct.clone();
                                    tokio::spawn(
                                        async move { rsa_decrypt(&c, &s, &ciphertext).await },
                                    )
                                })
                                .collect();
                            for res in join_all(tasks).await {
                                res.expect("task panicked").expect("request failed");
                            }
                        }
                        start.elapsed()
                    }
                });
            },
        );

        // ── ECDSA P-256 sign ──────────────────────────────────────────────
        group.bench_with_input(
            BenchmarkId::new("ECDSA P-256 sign", format!("{workers} workers")),
            &workers,
            |b, _| {
                let client = client.clone();
                let sk_id = ec_sk_id.clone();
                b.to_async(&runtime).iter_custom(|iters| {
                    let client = client.clone();
                    let sk_id = sk_id.clone();
                    async move {
                        let start = Instant::now();
                        for _ in 0..iters {
                            let tasks: Vec<_> = (0..CONCURRENCY)
                                .map(|_| {
                                    let c = client.clone();
                                    let k = sk_id.clone();
                                    tokio::spawn(async move { ec_sign(&c, &k).await })
                                })
                                .collect();
                            for res in join_all(tasks).await {
                                res.expect("task panicked").expect("request failed");
                            }
                        }
                        start.elapsed()
                    }
                });
            },
        );

        // ── Shut down the server before starting the next worker count ────
        runtime.block_on(ctx.stop_server()).ok();
    }

    group.finish();
}

// ── Criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(http_throughput_benches, bench_http_throughput);
criterion_main!(http_throughput_benches);
