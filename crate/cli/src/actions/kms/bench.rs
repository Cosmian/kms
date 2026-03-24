#![allow(
    clippy::as_conversions,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::implicit_clone,
    clippy::format_push_string,
    clippy::branches_sharing_code,
    clippy::only_used_in_recursion,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]

// =============================================================================
// COMPACT OUTPUT TRACKING
// =============================================================================
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{Parser, ValueEnum};
#[cfg(feature = "non-fips")]
use cosmian_kms_client::kmip_2_1::requests::create_pqc_key_pair_request;
#[cfg(feature = "non-fips")]
use cosmian_kms_client::reexport::cosmian_kms_client_utils::{
    configurable_kem_utils::{KemAlgorithm, build_create_configurable_kem_keypair_request},
    cover_crypt_utils::{
        build_create_covercrypt_master_keypair_request, build_create_covercrypt_usk_request,
    },
};
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_0::{
        kmip_messages::{RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader},
        kmip_types::{BlockCipherMode, HashingAlgorithm, PaddingMethod, ProtocolVersion},
    },
    kmip_2_1::{
        extra::{
            BulkData,
            fips::{
                FIPS_PRIVATE_ECC_MASK_SIGN_ECDH, FIPS_PRIVATE_RSA_MASK,
                FIPS_PUBLIC_ECC_MASK_SIGN_ECDH, FIPS_PUBLIC_RSA_MASK,
            },
        },
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{CreateKeyPair, Decrypt, Encrypt, Operation, Sign, SignatureVerify},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
            RecommendedCurve, UniqueIdentifier,
        },
        requests::{
            create_ec_key_pair_request, create_rsa_key_pair_request, decrypt_request,
            encrypt_request, symmetric_key_create_request,
        },
    },
};
use criterion::{BenchmarkId, Criterion, Throughput};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

use crate::error::{KmsCliError, result::KmsCliResult};

thread_local! {
    /// Benchmarks that were skipped (server does not support the algorithm).
    /// Only KO events need explicit tracking; OKs are read from criterion output.
    static BENCH_KO: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Record a benchmark name as skipped/unsupported (for compact output).
fn bench_ko(name: impl Into<String>) {
    BENCH_KO.with(|r| r.borrow_mut().push(name.into()));
}

/// Reset the KO accumulator before a new benchmark run.
fn bench_ko_reset() {
    BENCH_KO.with(|r| r.borrow_mut().clear());
}

// =============================================================================
// CLI TYPES
// =============================================================================

/// Output format for benchmark results (aligned with cargo-criterion).
#[derive(Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum BenchFormat {
    /// Criterion console output with HTML reports in target/criterion/
    #[default]
    Text,
    /// Collect criterion estimates and write JSON to target/criterion/benchmarks.json
    Json,
    /// Generate markdown tables from criterion estimates (embedded criterion-table)
    Markdown,
    /// One line per benchmark: name + OK/KO. Criterion output is suppressed.
    /// Automatically selected when --sanity is used without an explicit --format.
    Compact,
}

/// Benchmark speed / sampling mode.
#[derive(Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum BenchSpeed {
    /// 100 samples, configurable measurement time (--time), 3 s warmup.
    #[default]
    Normal,
    /// 10 samples, 1 s measurement, 0.5 s warmup.
    Quick,
    /// Smoke-test: 10 samples (criterion minimum), 1 ms measurement, 1 ms warmup.
    /// Automatically selects --format compact when no explicit format is given.
    Sanity,
}

/// Benchmark mode selection.
#[derive(Clone, Debug, Default, ValueEnum)]
pub enum BenchMode {
    /// Run ALL benchmark categories in order
    #[default]
    All,
    /// Encrypt/decrypt: AES-GCM, `ChaCha20` (non-FIPS), RSA-OAEP, RSA-AES-KWP, RSA-PKCS1v15 (non-FIPS)
    Encrypt,
    /// Key creation: symmetric, RSA, EC key pairs
    KeyCreation,
    /// Sign/verify: ECDSA, `EdDSA` (non-FIPS), RSA-PSS, ML-DSA, SLH-DSA (non-FIPS)
    SignVerify,
    /// KMIP Message batch: AES `BulkData`, RSA KMIP Message
    Batch,
}

/// Run benchmarks using criterion for statistical analysis.
///
/// Connects to an external KMS server and runs criterion benchmarks.
/// Results include mean, median, standard deviation, and confidence intervals.
/// HTML reports are generated in `target/criterion/`.
///
/// Examples:
///   ckms bench                                   # all modes, default config
///   ckms bench --mode encrypt                    # encrypt mode only
///   ckms bench --speed sanity                    # smoke-test: 1 pass per bench, compact output
///   ckms bench --mode key-creation --speed quick # quick run
///   ckms bench --format json                     # also write JSON results
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct BenchAction {
    /// Benchmark category (default: all)
    #[clap(long = "mode", short = 'm', default_value = "all")]
    mode: BenchMode,

    /// Output format
    #[clap(long = "format", short = 'f', default_value = "text")]
    format: BenchFormat,

    /// Benchmark speed mode: normal (default), quick, or sanity.
    /// Sanity auto-selects --format compact when no explicit format is given.
    #[clap(long = "speed", short = 's', default_value = "normal")]
    speed: BenchSpeed,

    /// Maximum measurement time per benchmark in seconds (default: 10).
    /// Caps how long criterion spends on each benchmark function.
    /// Ignored in quick and sanity speed modes.
    #[clap(long = "time", short = 't', default_value = "10")]
    time: u64,

    /// Save results under a named baseline in target/criterion/<bench>/<name>/.
    /// Use this to snapshot a run before a change. To compare, run again with
    /// --load-baseline <name> (or without any flag to diff against "base").
    /// Example: --save-baseline before-my-change
    #[clap(long = "save-baseline")]
    save_baseline: Option<String>,

    /// Compare results against a previously saved baseline.
    /// Prints change% in console output for each benchmark.
    /// Example: --load-baseline before-my-change
    #[clap(long = "load-baseline")]
    load_baseline: Option<String>,

    /// When emitting --format json, insert this label as the version column so
    /// that criterion-table renders versions as columns for proper comparison.
    /// Run baseline first, compare second, then combine:
    ///   cat v5.12.json v5.17.json | criterion-table > diff.md
    #[clap(long = "version-label")]
    version_label: Option<String>,
}

// =============================================================================
// FIPS MASK HELPERS
// =============================================================================

fn with_fips_rsa_masks(mut req: CreateKeyPair) -> CreateKeyPair {
    if let Some(a) = req.common_attributes.as_mut() {
        a.cryptographic_usage_mask = Some(FIPS_PRIVATE_RSA_MASK | FIPS_PUBLIC_RSA_MASK);
    }
    if let Some(a) = req.private_key_attributes.as_mut() {
        a.cryptographic_usage_mask = Some(FIPS_PRIVATE_RSA_MASK);
    }
    if let Some(a) = req.public_key_attributes.as_mut() {
        a.cryptographic_usage_mask = Some(FIPS_PUBLIC_RSA_MASK);
    }
    req
}

fn with_fips_ec_masks(mut req: CreateKeyPair) -> CreateKeyPair {
    if let Some(a) = req.common_attributes.as_mut() {
        a.cryptographic_usage_mask =
            Some(FIPS_PRIVATE_ECC_MASK_SIGN_ECDH | FIPS_PUBLIC_ECC_MASK_SIGN_ECDH);
    }
    if let Some(a) = req.private_key_attributes.as_mut() {
        a.cryptographic_usage_mask = Some(FIPS_PRIVATE_ECC_MASK_SIGN_ECDH);
    }
    if let Some(a) = req.public_key_attributes.as_mut() {
        a.cryptographic_usage_mask = Some(FIPS_PUBLIC_ECC_MASK_SIGN_ECDH);
    }
    req
}

// =============================================================================
// CRYPTOGRAPHIC PARAMETER HELPERS
// =============================================================================

fn aes_gcm_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(BlockCipherMode::GCM),
        ..Default::default()
    }
}

#[cfg(feature = "non-fips")]
fn chacha20_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::ChaCha20),
        ..Default::default()
    }
}

fn rsa_oaep_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        padding_method: Some(PaddingMethod::OAEP),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        ..Default::default()
    }
}

fn rsa_kwp_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        ..Default::default()
    }
}

#[cfg(feature = "non-fips")]
fn rsa_pkcs15_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        padding_method: Some(PaddingMethod::PKCS1v15),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        ..Default::default()
    }
}

fn aes_xts_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(BlockCipherMode::XTS),
        ..Default::default()
    }
}

#[cfg(feature = "non-fips")]
fn aes_gcm_siv_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(BlockCipherMode::GCMSIV),
        ..Default::default()
    }
}

#[cfg(feature = "non-fips")]
fn kem_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::ConfigurableKEM),
        ..Default::default()
    }
}

// =============================================================================
// KEY CREATION HELPERS
// =============================================================================

fn create_sym_key(
    rt: &Runtime,
    client: &KmsClient,
    bits: usize,
    algo: CryptographicAlgorithm,
) -> UniqueIdentifier {
    rt.block_on(async {
        let req = symmetric_key_create_request(
            &client.config.vendor_id,
            None,
            bits,
            algo,
            ["bench"],
            false,
            None,
        )
        .expect("symmetric key request");
        client
            .create(req)
            .await
            .expect("create symmetric key")
            .unique_identifier
    })
}

#[cfg(feature = "non-fips")]
fn try_create_sym_key(
    rt: &Runtime,
    client: &KmsClient,
    bits: usize,
    algo: CryptographicAlgorithm,
) -> Option<UniqueIdentifier> {
    rt.block_on(async {
        let req = symmetric_key_create_request(
            &client.config.vendor_id,
            None,
            bits,
            algo,
            ["bench"],
            false,
            None,
        )
        .ok()?;
        client.create(req).await.ok().map(|r| r.unique_identifier)
    })
}

fn create_rsa_kp(
    rt: &Runtime,
    client: &KmsClient,
    bits: usize,
) -> (UniqueIdentifier, UniqueIdentifier) {
    rt.block_on(async {
        let req = with_fips_rsa_masks(
            create_rsa_key_pair_request(
                &client.config.vendor_id,
                None,
                ["bench"],
                bits,
                false,
                None,
            )
            .expect("RSA key pair request"),
        );
        let resp = client
            .create_key_pair(req)
            .await
            .expect("create RSA key pair");
        (
            resp.public_key_unique_identifier,
            resp.private_key_unique_identifier,
        )
    })
}

fn try_create_ec_kp(
    rt: &Runtime,
    client: &KmsClient,
    curve: RecommendedCurve,
) -> Option<(UniqueIdentifier, UniqueIdentifier)> {
    rt.block_on(async {
        let req = with_fips_ec_masks(
            create_ec_key_pair_request(
                &client.config.vendor_id,
                None,
                ["bench"],
                curve,
                false,
                None,
            )
            .ok()?,
        );
        let resp = client.create_key_pair(req).await.ok()?;
        Some((
            resp.public_key_unique_identifier,
            resp.private_key_unique_identifier,
        ))
    })
}

/// Create EC key pair *without* FIPS usage masks — needed for ECIES/Salsa
/// because those operations require Encrypt/Decrypt usage, not Sign/ECDH.
#[cfg(feature = "non-fips")]
fn try_create_ec_kp_no_fips(
    rt: &Runtime,
    client: &KmsClient,
    curve: RecommendedCurve,
) -> Option<(UniqueIdentifier, UniqueIdentifier)> {
    rt.block_on(async {
        let req = create_ec_key_pair_request(
            &client.config.vendor_id,
            None,
            ["bench"],
            curve,
            false,
            None,
        )
        .ok()?;
        let resp = client.create_key_pair(req).await.ok()?;
        Some((
            resp.public_key_unique_identifier,
            resp.private_key_unique_identifier,
        ))
    })
}

#[cfg(feature = "non-fips")]
fn try_create_pqc_kp(
    rt: &Runtime,
    client: &KmsClient,
    algorithm: CryptographicAlgorithm,
) -> Option<(UniqueIdentifier, UniqueIdentifier)> {
    rt.block_on(async {
        let req =
            create_pqc_key_pair_request(&client.config.vendor_id, ["bench"], algorithm, false)
                .ok()?;
        let resp = client.create_key_pair(req).await.ok()?;
        Some((
            resp.public_key_unique_identifier,
            resp.private_key_unique_identifier,
        ))
    })
}

// =============================================================================
// ENCRYPT BENCHMARKS
// =============================================================================

fn bench_encrypt(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
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

fn bench_encrypt_aes_gcm(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
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
fn bench_encrypt_chacha20(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
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

fn bench_encrypt_aes_xts(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
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
fn bench_encrypt_aes_gcm_siv(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
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
fn bench_encrypt_ecies(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
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
fn bench_encrypt_salsa(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
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
fn bench_encrypt_covercrypt(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
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

fn bench_key_creation(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
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

fn bench_sign_verify(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
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

fn bench_batch(c: &mut Criterion, client: &KmsClient, rt: &Runtime, sanity: bool) {
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

fn bench_batch_aes_bulk(c: &mut Criterion, client: &KmsClient, rt: &Runtime, sanity: bool) {
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

fn bench_batch_rsa_message(
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

// =============================================================================
// JSON OUTPUT  (criterion-table-compatible newline-delimited JSON)
// =============================================================================

// --- Criterion internal deserialization structs ---

#[derive(Deserialize)]
struct CriterionEstimates {
    mean: CriterionEstimate,
    median: CriterionEstimate,
    #[allow(dead_code)]
    std_dev: CriterionEstimate,
    median_abs_dev: Option<CriterionEstimate>,
}

#[derive(Deserialize)]
struct CriterionEstimate {
    point_estimate: f64,
    #[allow(dead_code)]
    standard_error: f64,
    confidence_interval: CriterionCI,
}

#[derive(Deserialize)]
struct CriterionCI {
    #[allow(dead_code)]
    confidence_level: f64,
    lower_bound: f64,
    upper_bound: f64,
}

// --- criterion-table output format (cargo-criterion --message-format=json schema) ---

#[derive(Serialize)]
struct CtEst {
    estimate: f64,
    lower_bound: f64,
    upper_bound: f64,
    unit: &'static str, // "ns"
}

#[derive(Serialize)]
struct CtBenchmarkComplete {
    reason: &'static str, /* "benchmark-complete" (cargo-criterion compat; ignored by criterion-table) */
    id: String,
    report_directory: &'static str, // "" — criterion-table requires a string, not null
    iteration_count: Vec<u64>,      // [] — required non-null array
    measured_values: Vec<f64>,      // [] — required non-null array
    unit: &'static str,             // "ns" — required top-level time unit
    throughput: Vec<serde_json::Value>, // [] — required non-null array
    typical: CtEst,
    mean: CtEst,
    median: CtEst,
    median_abs_dev: CtEst,
    slope: Option<CtEst>,
    change: Option<serde_json::Value>, // always null; version comparison done via ID structure
}

fn count_baseline_files(home: &Path, baseline: &str) -> usize {
    let mut count = 0;
    if let Ok(walker) = fs::read_dir(home) {
        count_baseline_recursive(walker, baseline, &mut count);
    }
    count
}

fn count_baseline_recursive(dir: fs::ReadDir, baseline: &str, count: &mut usize) {
    for entry in dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some(baseline) {
                let estimates = path.join("estimates.json");
                if estimates.exists() {
                    *count += 1;
                }
            } else if let Ok(sub) = fs::read_dir(&path) {
                count_baseline_recursive(sub, baseline, count);
            }
        }
    }
}

fn criterion_home() -> PathBuf {
    std::env::var("CRITERION_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("CARGO_TARGET_DIR").map(|p| PathBuf::from(p).join("criterion")))
        .unwrap_or_else(|_| PathBuf::from("target/criterion"))
}

fn collect_json_output(version_label: Option<&str>) -> KmsCliResult<()> {
    let home = criterion_home();
    let mut entries: Vec<CtBenchmarkComplete> = Vec::new();
    if home.exists() {
        collect_estimates_recursive(&home, &home, version_label, &mut entries)?;
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));

    // Emit one JSON line per benchmark to stdout (criterion-table format).
    for entry in &entries {
        let line = serde_json::to_string(entry)
            .map_err(|e| KmsCliError::Default(format!("JSON serialization: {e}")))?;
        #[allow(clippy::print_stdout)]
        {
            println!("{line}");
        }
    }

    // Keep writing benchmarks.json for backward compatibility.
    let json_path = home.join("benchmarks.json");
    let compat = serde_json::json!({ "benchmarks": entries });
    let content = serde_json::to_string_pretty(&compat)
        .map_err(|e| KmsCliError::Default(format!("JSON serialization: {e}")))?;
    fs::write(&json_path, &content)
        .map_err(|e| KmsCliError::Default(format!("Write {}: {e}", json_path.display())))?;
    eprintln!("[bench] JSON results written to {}", json_path.display());
    Ok(())
}

const fn make_ct_est(est: &CriterionEstimate) -> CtEst {
    CtEst {
        estimate: est.point_estimate,
        lower_bound: est.confidence_interval.lower_bound,
        upper_bound: est.confidence_interval.upper_bound,
        unit: "ns",
    }
}

/// Transform a raw criterion path ID for version comparison.
///
/// When `version_label` is set, inserts the label as the second-to-last
/// segment so criterion-table renders versions as columns:
/// - `"A/B/C"` → `"A/{label}/B - C"` (section=A, col=label, row="B - C")
/// - `"A/B"`   → `"A/{label}/B"`      (section=A, col=label, row=B)
/// - `"A"`     → `"A/{label}"`        (section=A, col=label, no row)
fn apply_version_label(raw_id: &str, label: &str) -> String {
    if let Some((section, rest)) = raw_id.split_once('/') {
        let row = rest.replace('/', " - ");
        format!("{section}/{label}/{row}")
    } else {
        format!("{raw_id}/{label}")
    }
}

fn collect_estimates_recursive(
    base: &Path,
    dir: &Path,
    version_label: Option<&str>,
    results: &mut Vec<CtBenchmarkComplete>,
) -> KmsCliResult<()> {
    let estimates_path = dir.join("new").join("estimates.json");
    if estimates_path.exists() {
        let content = fs::read_to_string(&estimates_path)
            .map_err(|e| KmsCliError::Default(format!("Read {}: {e}", estimates_path.display())))?;
        if let Ok(estimates) = serde_json::from_str::<CriterionEstimates>(&content) {
            let raw_id = dir
                .strip_prefix(base)
                .unwrap_or(dir)
                .to_string_lossy()
                .to_string();
            let id = version_label.map_or_else(
                || raw_id.clone(),
                |label| apply_version_label(&raw_id, label),
            );
            let mean = make_ct_est(&estimates.mean);
            let median = make_ct_est(&estimates.median);
            let median_abs_dev = estimates.median_abs_dev.as_ref().map_or(
                CtEst {
                    estimate: 0.0,
                    lower_bound: 0.0,
                    upper_bound: 0.0,
                    unit: "ns",
                },
                make_ct_est,
            );
            results.push(CtBenchmarkComplete {
                reason: "benchmark-complete",
                id,
                report_directory: "",
                iteration_count: vec![],
                measured_values: vec![],
                unit: "ns",
                throughput: vec![],
                typical: make_ct_est(&estimates.mean),
                mean,
                median,
                median_abs_dev,
                slope: None,
                change: None,
            });
        }
    }
    if let Ok(dir_entries) = fs::read_dir(dir) {
        for entry in dir_entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir())
                && entry.file_name() != "new"
                && entry.file_name() != "base"
                && entry.file_name() != "change"
            {
                collect_estimates_recursive(base, &entry.path(), version_label, results)?;
            }
        }
    }
    Ok(())
}

// =============================================================================
// MARKDOWN TABLE GENERATION (embedded criterion-table)
// =============================================================================

/// Metadata from criterion's `benchmark.json`.
#[derive(Deserialize)]
struct BenchmarkMeta {
    group_id: String,
    function_id: Option<String>,
    value_str: Option<String>,
    #[allow(dead_code)]
    full_id: String,
    #[allow(dead_code)]
    directory_name: String,
}

/// Slope estimate from criterion's `estimates.json`.
#[derive(Deserialize)]
struct SlopeEstimates {
    slope: Option<SlopeEstimate>,
    mean: CriterionEstimate,
}

#[derive(Deserialize)]
struct SlopeEstimate {
    point_estimate: f64,
}

/// One benchmark data point for table rendering.
struct BenchPoint {
    function_id: String,
    value_str: String,
    time_ns: f64,
}

/// Format nanoseconds as human-readable time.
fn format_time(ns: f64) -> String {
    if ns < 1_000.0 {
        format!("{ns:.2} ns")
    } else if ns < 1_000_000.0 {
        format!("{:.2} µs", ns / 1_000.0)
    } else if ns < 1_000_000_000.0 {
        format!("{:.2} ms", ns / 1_000_000.0)
    } else {
        format!("{:.2} s", ns / 1_000_000_000.0)
    }
}

/// Descriptions for groups (matches tables.toml [`top_comments`]).
fn group_description(group_id: &str) -> Option<&'static str> {
    match group_id {
        // Encryption
        "encrypt/aes-gcm" => {
            Some("AES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).")
        }
        "encrypt/aes-xts" => {
            Some("AES-XTS encrypt and decrypt (128/256-bit AES, 64-byte plaintext).")
        }
        "encrypt/aes-gcm-siv" => {
            Some("AES-GCM-SIV encrypt and decrypt (128/256-bit keys, 64-byte plaintext). Non-FIPS.")
        }
        "encrypt/chacha20-poly1305" => Some(
            "ChaCha20-Poly1305 encrypt and decrypt (256-bit key, 64-byte plaintext). Non-FIPS.",
        ),
        "encrypt/rsa-oaep" => {
            Some("RSA-OAEP encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).")
        }
        "encrypt/rsa-pkcs1v15" => Some(
            "RSA PKCS#1 v1.5 encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).",
        ),
        "encrypt/ecies" => {
            Some("ECIES encrypt and decrypt on NIST curves (P-256/P-384/P-521). Non-FIPS.")
        }
        "encrypt/salsa-sealed-box" => {
            Some("Salsa Sealed Box (X25519) encrypt and decrypt. Non-FIPS.")
        }
        "encrypt/covercrypt" => Some("Covercrypt attribute-based encrypt and decrypt. Non-FIPS."),
        // KEM
        "kem/configurable" => Some(
            "Configurable KEM encapsulate and decapsulate (ML-KEM, hybrid variants). Non-FIPS.",
        ),
        "kem/pqc" => Some(
            "Standard PQC KEM encapsulate and decapsulate (ML-KEM, X25519MLKEM768, X448MLKEM1024). Non-FIPS.",
        ),
        // Key creation
        "key-creation/symmetric" => Some("AES (and ChaCha20 in non-FIPS) symmetric key creation."),
        "key-creation/rsa" => Some("RSA key pair generation (2048/3072/4096-bit)."),
        "key-creation/ec" => Some("Elliptic curve key pair generation (NIST and non-FIPS curves)."),
        "key-creation/covercrypt" => Some("Covercrypt master key pair generation. Non-FIPS."),
        "key-creation/kem" => {
            Some("Configurable KEM key pair generation (ML-KEM, hybrid variants). Non-FIPS.")
        }
        "key-creation/pqc" => {
            Some("PQC key pair generation (ML-KEM, ML-DSA, SLH-DSA, hybrid KEM). Non-FIPS.")
        }
        // Sign / verify
        "sign-verify/ecdsa-p256" | "sign-verify/ecdsa-p384" | "sign-verify/ecdsa-p521" => {
            Some("ECDSA sign and verify on NIST curves.")
        }
        "sign-verify/ecdsa-secp256k1" | "sign-verify/eddsa-ed25519" | "sign-verify/eddsa-ed448" => {
            Some("Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).")
        }
        "sign-verify/rsa-pss" => Some("RSA-PSS sign and verify (SHA-256, 2048/3072/4096-bit)."),
        "sign-verify/ml-dsa" => Some("ML-DSA sign and verify (ML-DSA-44/65/87). Non-FIPS."),
        "sign-verify/slh-dsa" => Some(
            "SLH-DSA (stateless hash-based) sign and verify (SHA2/SHAKE, 128/192/256). Non-FIPS.",
        ),
        // Batch
        "batch/aes-gcm" => {
            Some("AES-GCM batch — encrypt/decrypt N items in a single BulkData call.")
        }
        "batch/rsa-pkcs1v15" => {
            Some("RSA PKCS#1 v1.5 batch — encrypt/decrypt N items in a single KMIP message.")
        }
        "batch/rsa-oaep" => {
            Some("RSA-OAEP batch — encrypt/decrypt N items in a single KMIP message.")
        }
        "batch/rsa-aes-kwp" => {
            Some("RSA AES Key Wrap batch — encrypt/decrypt N items in a single KMIP message.")
        }
        _ => None,
    }
}

/// Walk `target/criterion/` and collect all benchmark data points.
fn collect_bench_points(home: &Path) -> KmsCliResult<BTreeMap<String, Vec<BenchPoint>>> {
    let mut groups: BTreeMap<String, Vec<BenchPoint>> = BTreeMap::new();
    collect_bench_points_recursive(home, home, &mut groups)?;
    Ok(groups)
}

fn collect_bench_points_recursive(
    home: &Path,
    dir: &Path,
    groups: &mut BTreeMap<String, Vec<BenchPoint>>,
) -> KmsCliResult<()> {
    let bm_path = dir.join("new").join("benchmark.json");
    let est_path = dir.join("new").join("estimates.json");
    if bm_path.exists() && est_path.exists() {
        let bm_content = fs::read_to_string(&bm_path)
            .map_err(|e| KmsCliError::Default(format!("Read {}: {e}", bm_path.display())))?;
        let est_content = fs::read_to_string(&est_path)
            .map_err(|e| KmsCliError::Default(format!("Read {}: {e}", est_path.display())))?;
        if let (Ok(meta), Ok(est)) = (
            serde_json::from_str::<BenchmarkMeta>(&bm_content),
            serde_json::from_str::<SlopeEstimates>(&est_content),
        ) {
            let time_ns = est
                .slope
                .map_or(est.mean.point_estimate, |s| s.point_estimate);
            let function_id = meta.function_id.unwrap_or_default();
            let value_str = meta.value_str.unwrap_or_default();
            groups.entry(meta.group_id).or_default().push(BenchPoint {
                function_id,
                value_str,
                time_ns,
            });
        }
    }
    if let Ok(entries) = fs::read_dir(dir) {
        let mut sorted: Vec<_> = entries.flatten().collect();
        sorted.sort_by_key(std::fs::DirEntry::file_name);
        for entry in sorted {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if entry.file_type().is_ok_and(|t| t.is_dir())
                && name_str != "new"
                && name_str != "base"
                && name_str != "change"
                && name_str != "report"
            {
                collect_bench_points_recursive(home, &entry.path(), groups)?;
            }
        }
    }
    Ok(())
}

/// Render a single group as a parametrized markdown table (criterion-table style).
///
/// If benchmarks have `value_str` (parameters), renders a pivot table with
/// `function_ids` as columns and parameters as rows. Otherwise renders a flat table.
fn render_group_table(group_id: &str, points: &[BenchPoint]) -> String {
    let mut out = String::new();

    // Group heading
    out.push_str(&format!("### {group_id}\n\n"));
    if let Some(desc) = group_description(group_id) {
        out.push_str(&format!("{desc}\n\n"));
    }

    // Collect unique function_ids and value_strs preserving insertion order
    let mut func_ids: Vec<String> = Vec::new();
    let mut param_strs: Vec<String> = Vec::new();
    for p in points {
        if !func_ids.contains(&p.function_id) {
            func_ids.push(p.function_id.clone());
        }
        if !p.value_str.is_empty() && !param_strs.contains(&p.value_str) {
            param_strs.push(p.value_str.clone());
        }
    }

    // Sort parameters numerically when they have a leading number (e.g. "1 request", "50 requests")
    param_strs.sort_by(|a, b| {
        let num_a = a
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<u64>().ok());
        let num_b = b
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<u64>().ok());
        match (num_a, num_b) {
            (Some(na), Some(nb)) => na.cmp(&nb),
            _ => a.cmp(b),
        }
    });

    if param_strs.is_empty() {
        // Flat table: one column per function_id
        out.push_str("| |");
        for fid in &func_ids {
            out.push_str(&format!(" `{fid}` |"));
        }
        out.push('\n');

        out.push_str("| :--- |");
        for _ in &func_ids {
            out.push_str(" :--- |");
        }
        out.push('\n');

        out.push_str("| |");
        for fid in &func_ids {
            let val = points
                .iter()
                .find(|p| p.function_id == *fid)
                .map_or_else(|| "N/A".to_owned(), |p| format_time(p.time_ns));
            out.push_str(&format!(" `{val}` |"));
        }
        out.push('\n');
    } else {
        // Pivot table: columns = function_ids, rows = parameters
        out.push_str("| |");
        for fid in &func_ids {
            out.push_str(&format!(" `{fid}` |"));
        }
        out.push('\n');

        out.push_str("| :--- |");
        for _ in &func_ids {
            out.push_str(" :--- |");
        }
        out.push('\n');

        for param in &param_strs {
            out.push_str(&format!("| **`{param}`** |"));
            for fid in &func_ids {
                let val = points
                    .iter()
                    .find(|p| p.function_id == *fid && p.value_str == *param)
                    .map_or_else(|| "N/A".to_owned(), |p| format_time(p.time_ns));
                out.push_str(&format!(" `{val}` |"));
            }
            out.push('\n');
        }
    }

    out
}

/// Generate markdown tables for all benchmark groups and write to file.
fn generate_markdown_output() -> KmsCliResult<()> {
    let home = criterion_home();
    if !home.exists() {
        eprintln!("[bench] No criterion data found, skipping markdown generation");
        return Ok(());
    }

    let groups = collect_bench_points(&home)?;
    if groups.is_empty() {
        eprintln!("[bench] No benchmark results found, skipping markdown generation");
        return Ok(());
    }

    let mut md = String::from("## Benchmark Results\n\n");
    for (group_id, points) in &groups {
        md.push_str(&render_group_table(group_id, points));
        md.push('\n');
    }

    let md_path = home.join("benchmarks.md");
    fs::write(&md_path, &md)
        .map_err(|e| KmsCliError::Default(format!("Write {}: {e}", md_path.display())))?;
    eprintln!("[bench] Markdown report written to {}", md_path.display());

    Ok(())
}

/// Return true if any `estimates.json` inside `dir` (recursively) was written
/// at or after `since`. Used to distinguish current-run criterion data from
/// stale data left by previous runs.
fn group_updated_since(dir: &Path, since: std::time::SystemTime) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if group_updated_since(&path, since) {
                return true;
            }
        } else if path.file_name().is_some_and(|n| n == "estimates.json")
            && path
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|t| t >= since)
        {
            return true;
        }
    }
    false
}

fn generate_compact_output(run_start: std::time::SystemTime) -> KmsCliResult<()> {
    let home = criterion_home();
    let mut results: BTreeMap<String, bool> = BTreeMap::new();

    // ── OK: criterion groups updated during the current run ───────────────
    // Filtering by mtime prevents stale data from previous runs (against a
    // different server version) from producing false-positive OKs.
    if home.exists() {
        let points = collect_bench_points(&home)?;
        for group_id in points.keys() {
            // Criterion 0.6 stores group "a/b" as directory target/criterion/a_b/
            // (slashes replaced by underscores, not nested directories).
            let dir_name = group_id.replace('/', "_");
            let group_dir = home.join(&dir_name);
            if group_updated_since(&group_dir, run_start) {
                results.insert(group_id.clone(), true);
            }
        }
    }

    // ── KO: groups that were fully skipped (inserted only if not already OK)
    BENCH_KO.with(|r| {
        for name in r.borrow().iter() {
            results.entry(name.clone()).or_insert(false);
        }
    });

    if results.is_empty() {
        eprintln!("[bench] compact: no results collected");
        return Ok(());
    }

    // ── Print aligned list ────────────────────────────────────────────────
    let width = results.keys().map(String::len).max().unwrap_or(40) + 2;
    for (name, ok) in &results {
        let status = if *ok { "OK" } else { "KO" };
        #[allow(clippy::print_stdout)]
        {
            println!("{name:<width$} {status}");
        }
    }

    let total = results.len();
    let ok_cnt = results.values().filter(|&&v| v).count();
    eprintln!(
        "[bench] compact summary: {ok_cnt}/{total} OK, {} KO",
        total - ok_cnt
    );

    Ok(())
}

// =============================================================================
// BENCH ACTION IMPLEMENTATION
// =============================================================================

impl BenchAction {
    /// Run the benchmark suite using criterion.
    ///
    /// Spawns a blocking task with a fresh tokio runtime (required because
    /// criterion's measurement loop is synchronous) and runs all selected
    /// benchmark groups.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let config = kms_rest_client.config.clone();
        let mode = self.mode.clone();
        let format = self.format.clone();
        let speed = self.speed.clone();
        let time = self.time;
        let save_baseline = self.save_baseline.clone();
        let load_baseline = self.load_baseline.clone();
        let version_label = self.version_label.clone();

        // Drop the existing client (bound to the current runtime)
        drop(kms_rest_client);

        tokio::task::spawn_blocking(move || -> KmsCliResult<()> {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| KmsCliError::Default(format!("Runtime creation failed: {e}")))?;
            let client = KmsClient::new_with_config(config)
                .map_err(|e| KmsCliError::Default(e.to_string()))?;

            // Verify server is reachable
            let version = rt
                .block_on(client.version())
                .map_err(|e| KmsCliError::Default(format!("Server unreachable: {e}")))?;
            eprintln!("[bench] Connected to KMS server version {version}");

            // Reset KO accumulator for this run
            bench_ko_reset();

            // Sanity speed implies compact unless the user explicitly chose another format
            let effective_format = if speed == BenchSpeed::Sanity && format == BenchFormat::Text {
                BenchFormat::Compact
            } else {
                format.clone()
            };

            // Snapshot time just before starting criterion so we can filter
            // stale criterion data from previous runs in generate_compact_output.
            let run_start = std::time::SystemTime::now();

            let mut c = match speed {
                BenchSpeed::Sanity =>
                // Criterion enforces sample_size >= 10; set measurement and warmup to 1ms
                // so each bench function runs as few iterations as possible.
                {
                    Criterion::default()
                        .sample_size(10)
                        .measurement_time(Duration::from_millis(1))
                        .warm_up_time(Duration::from_millis(1))
                }
                BenchSpeed::Quick => Criterion::default()
                    .sample_size(10)
                    .measurement_time(Duration::from_secs(1))
                    .warm_up_time(Duration::from_millis(500)),
                BenchSpeed::Normal => Criterion::default()
                    .sample_size(100)
                    .measurement_time(Duration::from_secs(time))
                    .warm_up_time(Duration::from_secs(3)),
            };

            if let Some(ref name) = save_baseline {
                eprintln!("[bench] Saving baseline '{name}'");
                c = c.save_baseline(name.clone());
            } else if let Some(ref name) = load_baseline {
                eprintln!("[bench] Comparing against baseline '{name}'");
                c = c.retain_baseline(name.clone(), false);
            }

            // Suppress criterion's verbose output during the run.
            //
            // JSON:    fd1 (stdout) → fd2 (stderr)  so JSON isn't mixed with timing text.
            // Compact: fd1 and fd2 both → /dev/null.  Criterion's timing summaries go to
            //          stdout and its "Warming up / Warning" messages go to stderr; both
            //          are noise when the compact report is the only desired output.
            //          Order matters: redirect stderr FIRST, then stdout→stderr so that
            //          the dup2(2,1) copies the already-nulled fd2.
            //          Both fds are restored before generate_compact_output() runs.
            //
            // SAFETY: dup/dup2/open are safe POSIX calls; all fds are restored after drop(c).
            std::io::stdout().flush().ok();
            std::io::stderr().flush().ok();

            let (saved_stdout_fd, saved_stderr_fd): (Option<i32>, Option<i32>) =
                match effective_format {
                    BenchFormat::Json => {
                        #[allow(unsafe_code)]
                        let s = unsafe { libc::dup(1) };
                        #[allow(unsafe_code)]
                        unsafe {
                            libc::dup2(2, 1)
                        };
                        (if s < 0 { None } else { Some(s) }, None)
                    }
                    BenchFormat::Compact => {
                        #[allow(unsafe_code)]
                        let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY) };
                        if devnull >= 0 {
                            #[allow(unsafe_code)]
                            let se = unsafe { libc::dup(2) };
                            #[allow(unsafe_code)]
                            unsafe {
                                libc::dup2(devnull, 2)
                            }; // stderr → /dev/null first
                            #[allow(unsafe_code)]
                            let so = unsafe { libc::dup(1) };
                            #[allow(unsafe_code)]
                            unsafe {
                                libc::dup2(2, 1); // stdout → (already-null) fd2
                                libc::close(devnull);
                            }
                            (
                                if so < 0 { None } else { Some(so) },
                                if se < 0 { None } else { Some(se) },
                            )
                        } else {
                            (None, None)
                        }
                    }
                    _ => (None, None),
                };

            let is_sanity = speed == BenchSpeed::Sanity;
            match mode {
                BenchMode::All => {
                    bench_encrypt(&mut c, &client, &rt);
                    bench_key_creation(&mut c, &client, &rt);
                    bench_sign_verify(&mut c, &client, &rt);
                    bench_batch(&mut c, &client, &rt, is_sanity);
                }
                BenchMode::Encrypt => {
                    bench_encrypt(&mut c, &client, &rt);
                }
                BenchMode::KeyCreation => {
                    bench_key_creation(&mut c, &client, &rt);
                }
                BenchMode::SignVerify => {
                    bench_sign_verify(&mut c, &client, &rt);
                }
                BenchMode::Batch => bench_batch(&mut c, &client, &rt, is_sanity),
            }

            // Drop criterion to finalize reports
            drop(c);

            // Restore stderr (compact mode silenced criterion's warnings).
            if let Some(saved) = saved_stderr_fd {
                #[allow(unsafe_code)]
                unsafe {
                    libc::dup2(saved, 2);
                    libc::close(saved);
                }
            }

            // Restore stdout before we emit the report.
            if let Some(saved) = saved_stdout_fd {
                #[allow(unsafe_code)]
                unsafe {
                    libc::dup2(saved, 1);
                    libc::close(saved);
                }
            }

            if let Some(ref name) = save_baseline {
                let home = criterion_home();
                let count = count_baseline_files(&home, name);
                eprintln!(
                    "[bench] Baseline '{name}' saved: {count} estimates written under {}",
                    home.display()
                );
            }

            match effective_format {
                BenchFormat::Json => collect_json_output(version_label.as_deref())?,
                BenchFormat::Markdown => generate_markdown_output()?,
                BenchFormat::Compact => generate_compact_output(run_start)?,
                BenchFormat::Text => {}
            }

            Ok(())
        })
        .await
        .map_err(|e| KmsCliError::Default(format!("Benchmark task panicked: {e}")))?
    }
}
