use std::time::Duration;

use cosmian_kmip::{
    crypto::generic::kmip_requests::{build_decryption_request, build_encryption_request},
    kmip::kmip_types::{
        CryptographicAlgorithm, CryptographicParameters, HashingAlgorithm, PaddingMethod,
    },
};
use cosmian_kms_client::{
    cosmian_kmip::crypto::rsa::kmip_requests::create_rsa_key_pair_request, KmsClient,
};
use criterion::{criterion_group, criterion_main, Criterion};
use kms_test_server::{start_default_test_kms_server, ONCE};

criterion_main!(keypair_benches, encryption_benches);

criterion_group!(
    name = keypair_benches;
    config = Criterion::default().sample_size(150).measurement_time(Duration::from_secs(45));
    targets =
        bench_rsa_create_keypair,
);

criterion_group!(
    name = encryption_benches;
    config = Criterion::default().sample_size(1000).measurement_time(Duration::from_secs(10));
    targets =
        bench_rsa_encrypt_2048,
        bench_rsa_encrypt_4096,
        bench_rsa_decrypt_2048,
        bench_rsa_decrypt_4096,
);

fn bench_rsa_create_keypair(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let kms_rest_client = runtime.block_on(async {
        let ctx = ONCE
            .get_or_try_init(start_default_test_kms_server)
            .await
            .unwrap();
        ctx.owner_client_conf.initialize_kms_client().unwrap()
    });

    let mut group = c.benchmark_group("RSA tests");
    group.bench_function("RSA 2048bit key pair creation", |b| {
        b.to_async(&runtime).iter(|| async {
            let _ = create_rsa_keypair(&kms_rest_client, 2048).await;
        });
    });
    group.bench_function("RSA 4096bit key pair creation", |b| {
        b.to_async(&runtime).iter(|| async {
            let _ = create_rsa_keypair(&kms_rest_client, 4096).await;
        });
    });
}

fn bench_rsa_encrypt_2048(c: &mut Criterion) {
    bench_rsa_encrypt(c, 2048);
}
fn bench_rsa_encrypt_4096(c: &mut Criterion) {
    bench_rsa_encrypt(c, 4096);
}

fn bench_rsa_encrypt(c: &mut Criterion, key_size: usize) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let (kms_rest_client, _sk, pk) = runtime.block_on(async {
        let ctx = ONCE
            .get_or_try_init(start_default_test_kms_server)
            .await
            .unwrap();
        let kms_rest_client = ctx.owner_client_conf.initialize_kms_client().unwrap();
        let (sk, pk) = create_rsa_keypair(&kms_rest_client, key_size).await;
        (kms_rest_client, sk, pk)
    });

    let mut group = c.benchmark_group("RSA tests");
    group.bench_function(&format!("RSA {key_size}bit encryption"), |b| {
        b.to_async(&runtime).iter(|| async {
            let _ = encrypt(&kms_rest_client, &pk, &[0u8; 32]).await;
        });
    });
}

fn bench_rsa_decrypt_2048(c: &mut Criterion) {
    bench_rsa_decrypt(c, 2048);
}
fn bench_rsa_decrypt_4096(c: &mut Criterion) {
    bench_rsa_decrypt(c, 4096);
}

fn bench_rsa_decrypt(c: &mut Criterion, key_size: usize) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let (kms_rest_client, sk, _pk, ciphertext) = runtime.block_on(async {
        let ctx = ONCE
            .get_or_try_init(start_default_test_kms_server)
            .await
            .unwrap();
        let kms_rest_client = ctx.owner_client_conf.initialize_kms_client().unwrap();
        let (sk, pk) = create_rsa_keypair(&kms_rest_client, key_size).await;
        let ciphertext = encrypt(&kms_rest_client, &pk, &[0u8; 32]).await;
        (kms_rest_client, sk, pk, ciphertext)
    });

    let mut group = c.benchmark_group("RSA tests");
    group.bench_function(&format!("RSA {key_size}bit decryption"), |b| {
        b.to_async(&runtime).iter(|| async {
            let _ = decrypt(&kms_rest_client, &sk, &ciphertext).await;
        });
    });
}

async fn create_rsa_keypair(
    kms_rest_client: &KmsClient,
    cryptographic_length: usize,
) -> (String, String) {
    let create_key_pair_request =
        create_rsa_key_pair_request(["bench"], cryptographic_length).unwrap();
    // Query the KMS with your kmip data and get the key pair ids
    let response = kms_rest_client
        .create_key_pair(create_key_pair_request)
        .await
        .unwrap();
    (
        response.private_key_unique_identifier.to_string(),
        response.public_key_unique_identifier.to_string(),
    )
}

async fn encrypt(kms_rest_client: &KmsClient, pk: &str, cleartext: &[u8]) -> Vec<u8> {
    // Create the kmip query
    let encrypt_request = build_encryption_request(
        pk,
        None,
        cleartext.to_vec(),
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        }),
    )
    .unwrap();

    // Query the KMS with your kmip data and get the key pair ids
    let encrypt_response = kms_rest_client.encrypt(encrypt_request).await.unwrap();

    encrypt_response.data.unwrap()
}

async fn decrypt(kms_rest_client: &KmsClient, sk: &str, ciphertext: &[u8]) -> Vec<u8> {
    // Create the kmip query
    let decrypt_request = build_decryption_request(
        sk,
        None,
        ciphertext.to_vec(),
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        }),
    );

    // Query the KMS with your kmip data and get the key pair ids
    let decrypt_response = kms_rest_client.decrypt(decrypt_request).await.unwrap();

    decrypt_response.data.unwrap().to_vec()
}