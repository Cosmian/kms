#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    let_underscore_drop,
    clippy::cast_possible_wrap,
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps,
    clippy::as_conversions
)]

use cosmian_kms_client::{
    KmsClient, KmsClientError,
    kmip_0::kmip_types::HashingAlgorithm,
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_operations::{Sign, SignatureVerify},
        kmip_types::{
            CryptographicParameters, DigitalSignatureAlgorithm, RecommendedCurve, UniqueIdentifier,
        },
        requests::{create_ec_key_pair_request, create_rsa_key_pair_request},
    },
};
use criterion::Criterion;
use test_kms_server::start_default_test_kms_server;
use zeroize::Zeroizing;

// ── EC key pair creation ─────────────────────────────────────────────────────

pub(crate) fn bench_create_ec_key_pair(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let kms_rest_client = runtime.block_on(async {
        let ctx = start_default_test_kms_server().await;
        ctx.get_owner_client()
    });

    let mut group = c.benchmark_group("EC key creation");
    for (label, curve) in [
        ("P-256", RecommendedCurve::P256),
        ("P-384", RecommendedCurve::P384),
        ("P-521", RecommendedCurve::P521),
    ] {
        group.bench_function(format!("{label} key pair creation"), |b| {
            b.to_async(&runtime).iter(|| async {
                let _ = create_ec_keypair(&kms_rest_client, curve).await;
            });
        });
    }
}

#[cfg(feature = "non-fips")]
pub(crate) fn bench_create_ec_key_pair_non_fips(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let kms_rest_client = runtime.block_on(async {
        let ctx = start_default_test_kms_server().await;
        ctx.get_owner_client()
    });

    let mut group = c.benchmark_group("EC key creation");
    for (label, curve) in [
        ("Ed25519", RecommendedCurve::CURVEED25519),
        ("Ed448", RecommendedCurve::CURVEED448),
        ("secp256k1", RecommendedCurve::SECP256K1),
    ] {
        group.bench_function(format!("{label} key pair creation"), |b| {
            b.to_async(&runtime).iter(|| async {
                let _ = create_ec_keypair(&kms_rest_client, curve).await;
            });
        });
    }
}

// ── ECDSA sign/verify ────────────────────────────────────────────────────────

pub(crate) fn bench_ecdsa_sign_verify(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let kms_rest_client = runtime.block_on(async {
        let ctx = start_default_test_kms_server().await;
        ctx.get_owner_client()
    });

    let mut group = c.benchmark_group("EC sign/verify");
    for (label, curve, dsa) in [
        (
            "ECDSA P-256 SHA-256",
            RecommendedCurve::P256,
            DigitalSignatureAlgorithm::ECDSAWithSHA256,
        ),
        (
            "ECDSA P-384 SHA-384",
            RecommendedCurve::P384,
            DigitalSignatureAlgorithm::ECDSAWithSHA384,
        ),
        (
            "ECDSA P-521 SHA-512",
            RecommendedCurve::P521,
            DigitalSignatureAlgorithm::ECDSAWithSHA512,
        ),
    ] {
        let (sk, pk) = runtime.block_on(create_ec_keypair(&kms_rest_client, curve));
        let message = Zeroizing::new(vec![0x42_u8; 32]);
        let params = CryptographicParameters {
            digital_signature_algorithm: Some(dsa),
            ..Default::default()
        };
        let sample_sig = runtime
            .block_on(sign(&kms_rest_client, &sk, &message, Some(&params)))
            .unwrap();

        group.bench_function(format!("{label} sign"), |b| {
            b.to_async(&runtime).iter(|| async {
                let _ = sign(&kms_rest_client, &sk, &message, Some(&params))
                    .await
                    .unwrap();
            });
        });
        group.bench_function(format!("{label} verify"), |b| {
            b.to_async(&runtime).iter(|| async {
                verify(&kms_rest_client, &pk, &message, &sample_sig, Some(&params))
                    .await
                    .unwrap();
            });
        });
    }
}

#[cfg(feature = "non-fips")]
pub(crate) fn bench_eddsa_sign_verify(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let kms_rest_client = runtime.block_on(async {
        let ctx = start_default_test_kms_server().await;
        ctx.get_owner_client()
    });

    let mut group = c.benchmark_group("EC sign/verify");
    for (label, curve) in [
        ("EdDSA Ed25519", RecommendedCurve::CURVEED25519),
        ("EdDSA Ed448", RecommendedCurve::CURVEED448),
    ] {
        let (sk, pk) = runtime.block_on(create_ec_keypair(&kms_rest_client, curve));
        let message = Zeroizing::new(vec![0x42_u8; 32]);
        let sample_sig = runtime
            .block_on(sign(&kms_rest_client, &sk, &message, None))
            .unwrap();

        group.bench_function(format!("{label} sign"), |b| {
            b.to_async(&runtime).iter(|| async {
                let _ = sign(&kms_rest_client, &sk, &message, None).await.unwrap();
            });
        });
        group.bench_function(format!("{label} verify"), |b| {
            b.to_async(&runtime).iter(|| async {
                verify(&kms_rest_client, &pk, &message, &sample_sig, None)
                    .await
                    .unwrap();
            });
        });
    }
}

#[cfg(feature = "non-fips")]
pub(crate) fn bench_ecdsa_secp256k1_sign_verify(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let kms_rest_client = runtime.block_on(async {
        let ctx = start_default_test_kms_server().await;
        ctx.get_owner_client()
    });

    let mut group = c.benchmark_group("EC sign/verify");
    let (sk, pk) = runtime.block_on(create_ec_keypair(
        &kms_rest_client,
        RecommendedCurve::SECP256K1,
    ));
    let message = Zeroizing::new(vec![0x42_u8; 32]);
    let params = CryptographicParameters {
        digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
        ..Default::default()
    };
    let sample_sig = runtime
        .block_on(sign(&kms_rest_client, &sk, &message, Some(&params)))
        .unwrap();

    group.bench_function("ECDSA secp256k1 SHA-256 sign", |b| {
        b.to_async(&runtime).iter(|| async {
            let _ = sign(&kms_rest_client, &sk, &message, Some(&params))
                .await
                .unwrap();
        });
    });
    group.bench_function("ECDSA secp256k1 SHA-256 verify", |b| {
        b.to_async(&runtime).iter(|| async {
            verify(&kms_rest_client, &pk, &message, &sample_sig, Some(&params))
                .await
                .unwrap();
        });
    });
}

// ── RSA-PSS sign/verify ──────────────────────────────────────────────────────

pub(crate) fn bench_rsa_pss_sign_verify(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let kms_rest_client = runtime.block_on(async {
        let ctx = start_default_test_kms_server().await;
        ctx.get_owner_client()
    });

    let params = CryptographicParameters {
        digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        ..Default::default()
    };
    let message = Zeroizing::new(vec![0x42_u8; 32]);

    let mut group = c.benchmark_group("RSA sign/verify");
    for key_size in [2048, 4096] {
        let (sk, pk) = runtime.block_on(create_rsa_keypair(&kms_rest_client, key_size));
        let sample_sig = runtime
            .block_on(sign(&kms_rest_client, &sk, &message, Some(&params)))
            .unwrap();

        group.bench_function(format!("RSA-PSS SHA-256 {key_size}bit sign"), |b| {
            b.to_async(&runtime).iter(|| async {
                let _ = sign(&kms_rest_client, &sk, &message, Some(&params))
                    .await
                    .unwrap();
            });
        });
        group.bench_function(format!("RSA-PSS SHA-256 {key_size}bit verify"), |b| {
            b.to_async(&runtime).iter(|| async {
                verify(&kms_rest_client, &pk, &message, &sample_sig, Some(&params))
                    .await
                    .unwrap();
            });
        });
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

async fn create_ec_keypair(
    kms_rest_client: &KmsClient,
    curve: RecommendedCurve,
) -> (String, String) {
    let req =
        create_ec_key_pair_request(VENDOR_ID_COSMIAN, None, ["bench"], curve, false, None).unwrap();
    let resp = kms_rest_client.create_key_pair(req).await.unwrap();
    (
        resp.private_key_unique_identifier.to_string(),
        resp.public_key_unique_identifier.to_string(),
    )
}

async fn create_rsa_keypair(
    kms_rest_client: &KmsClient,
    cryptographic_length: usize,
) -> (String, String) {
    let req = create_rsa_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        ["bench"],
        cryptographic_length,
        false,
        None,
    )
    .unwrap();
    let resp = kms_rest_client.create_key_pair(req).await.unwrap();
    (
        resp.private_key_unique_identifier.to_string(),
        resp.public_key_unique_identifier.to_string(),
    )
}

async fn sign(
    kms_rest_client: &KmsClient,
    sk: &str,
    message: &Zeroizing<Vec<u8>>,
    params: Option<&CryptographicParameters>,
) -> Result<Vec<u8>, KmsClientError> {
    let req = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(sk.to_owned())),
        cryptographic_parameters: params.cloned(),
        data: Some(message.clone()),
        ..Default::default()
    };
    let resp = kms_rest_client.sign(req).await?;
    resp.signature_data
        .ok_or_else(|| KmsClientError::UnexpectedError("No signature data".to_owned()))
}

async fn verify(
    kms_rest_client: &KmsClient,
    pk: &str,
    message: &Zeroizing<Vec<u8>>,
    signature: &[u8],
    params: Option<&CryptographicParameters>,
) -> Result<(), KmsClientError> {
    let req = SignatureVerify {
        unique_identifier: Some(UniqueIdentifier::TextString(pk.to_owned())),
        cryptographic_parameters: params.cloned(),
        data: Some(message.to_vec()),
        signature_data: Some(signature.to_vec()),
        ..Default::default()
    };
    let _ = kms_rest_client.signature_verify(req).await?;
    Ok(())
}
