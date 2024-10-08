#![allow(dead_code)]
use cosmian_kmip::{
    crypto::{
        generic::kmip_requests::{build_decryption_request, build_encryption_request},
        rsa::kmip_requests::create_rsa_key_pair_request,
    },
    kmip::kmip_types::{
        CryptographicAlgorithm, CryptographicParameters, HashingAlgorithm, PaddingMethod,
    },
};
use cosmian_kms_client::KmsClient;
use criterion::Criterion;
use kms_test_server::start_default_test_kms_server;

pub(crate) fn bench_rsa_create_keypair(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let kms_rest_client = runtime.block_on(async {
        let ctx = start_default_test_kms_server().await;
        ctx.owner_client_conf
            .initialize_kms_client(None, None, false)
            .unwrap()
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

pub(crate) fn bench_rsa_pkcs_v15_encrypt_2048(c: &mut Criterion) {
    bench_rsa_encrypt(
        c,
        2048,
        &CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PKCS1v15),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        "RSA PKCSv1.5",
    );
}
pub(crate) fn bench_rsa_pkcs_v15_encrypt_4096(c: &mut Criterion) {
    bench_rsa_encrypt(
        c,
        4096,
        &CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PKCS1v15),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        "RSA PKCSv1.5",
    );
}

pub(crate) fn bench_rsa_pkcs_v15_decrypt_2048(c: &mut Criterion) {
    bench_rsa_decrypt(
        c,
        2048,
        &CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PKCS1v15),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        "RSA PKCSv1.5",
    );
}
pub(crate) fn bench_rsa_pkcs_v15_decrypt_4096(c: &mut Criterion) {
    bench_rsa_decrypt(
        c,
        4096,
        &CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PKCS1v15),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        "RSA PKCSv1.5",
    );
}

pub(crate) fn bench_rsa_oaep_encrypt_2048(c: &mut Criterion) {
    bench_rsa_encrypt(
        c,
        2048,
        &CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        "RSA OAEP",
    );
}
pub(crate) fn bench_rsa_oaep_encrypt_4096(c: &mut Criterion) {
    bench_rsa_encrypt(
        c,
        4096,
        &CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        "RSA OAEP",
    );
}

pub(crate) fn bench_rsa_oaep_decrypt_2048(c: &mut Criterion) {
    bench_rsa_decrypt(
        c,
        2048,
        &CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        "RSA OAEP",
    );
}
pub(crate) fn bench_rsa_oaep_decrypt_4096(c: &mut Criterion) {
    bench_rsa_decrypt(
        c,
        4096,
        &CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        "RSA OAEP",
    );
}

pub(crate) fn bench_rsa_key_wrp_encrypt_2048(c: &mut Criterion) {
    bench_rsa_encrypt(
        c,
        2048,
        &CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        "RSA AES KWP",
    );
}
pub(crate) fn bench_rsa_key_wrp_encrypt_4096(c: &mut Criterion) {
    bench_rsa_encrypt(
        c,
        4096,
        &CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        "RSA AES KWP",
    );
}

pub(crate) fn bench_rsa_key_wrp_decrypt_2048(c: &mut Criterion) {
    bench_rsa_decrypt(
        c,
        2048,
        &CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        "RSA AES KWP",
    );
}
pub(crate) fn bench_rsa_key_wrp_decrypt_4096(c: &mut Criterion) {
    bench_rsa_decrypt(
        c,
        4096,
        &CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        "RSA AES KWP",
    );
}

pub(crate) fn bench_rsa_encrypt(
    c: &mut Criterion,
    key_size: usize,
    cryptographic_parameters: &CryptographicParameters,
    name: &str,
) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let (kms_rest_client, _sk, pk) = runtime.block_on(async {
        let ctx = start_default_test_kms_server().await;
        let kms_rest_client = ctx
            .owner_client_conf
            .initialize_kms_client(None, None, false)
            .unwrap();
        let (sk, pk) = create_rsa_keypair(&kms_rest_client, key_size).await;
        (kms_rest_client, sk, pk)
    });

    let mut group = c.benchmark_group("RSA tests");
    group.bench_function(format!("{name} {key_size}bit encryption"), |b| {
        b.to_async(&runtime).iter(|| async {
            let _ = encrypt(
                &kms_rest_client,
                &pk,
                vec![0u8; 32],
                cryptographic_parameters,
            )
            .await;
        });
    });
}

pub(crate) fn bench_rsa_decrypt(
    c: &mut Criterion,
    key_size: usize,
    cryptographic_parameters: &CryptographicParameters,
    name: &str,
) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let (kms_rest_client, sk, _pk, ciphertext) = runtime.block_on(async {
        let ctx = start_default_test_kms_server().await;
        let kms_rest_client = ctx
            .owner_client_conf
            .initialize_kms_client(None, None, false)
            .unwrap();
        let (sk, pk) = create_rsa_keypair(&kms_rest_client, key_size).await;
        let ciphertext = encrypt(
            &kms_rest_client,
            &pk,
            vec![0u8; 32],
            cryptographic_parameters,
        )
        .await;
        (kms_rest_client, sk, pk, ciphertext)
    });

    let mut group = c.benchmark_group("RSA tests");
    group.bench_function(format!("{name} {key_size}bit decryption"), |b| {
        b.to_async(&runtime).iter(|| async {
            let () = decrypt(&kms_rest_client, &sk, &ciphertext, cryptographic_parameters).await;
        });
    });
}

pub(crate) async fn create_rsa_keypair(
    kms_rest_client: &KmsClient,
    cryptographic_length: usize,
) -> (String, String) {
    let create_key_pair_request =
        create_rsa_key_pair_request(None, ["bench"], cryptographic_length).unwrap();
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

pub(crate) async fn encrypt(
    kms_rest_client: &KmsClient,
    pk: &str,
    cleartext: Vec<u8>,
    cryptographic_parameters: &CryptographicParameters,
) -> Vec<u8> {
    // Create the kmip query
    let encrypt_request = build_encryption_request(
        pk,
        None,
        cleartext,
        None,
        None,
        None,
        Some(cryptographic_parameters.to_owned()),
    )
    .unwrap();

    // Query the KMS with your kmip data and get the key pair ids
    let encrypt_response = kms_rest_client.encrypt(encrypt_request).await.unwrap();

    encrypt_response.data.unwrap()
}

pub(crate) async fn decrypt(
    kms_rest_client: &KmsClient,
    sk: &str,
    ciphertext: &[u8],
    cryptographic_parameters: &CryptographicParameters,
) {
    // Create the kmip query
    let decrypt_request = build_decryption_request(
        sk,
        None,
        ciphertext.to_vec(),
        None,
        None,
        Some(cryptographic_parameters.clone()),
    );

    // Query the KMS with your kmip data and get the key pair ids
    kms_rest_client
        .decrypt(decrypt_request)
        .await
        .unwrap()
        .data
        .unwrap();
}
