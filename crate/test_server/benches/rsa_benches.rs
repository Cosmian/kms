#![allow(dead_code)]

use cosmian_kmip::{
    crypto::{
        generic::kmip_requests::{build_decryption_request, build_encryption_request},
        rsa::kmip_requests::create_rsa_key_pair_request,
    },
    kmip::{
        kmip_messages::{Message, MessageBatchItem, MessageHeader, MessageResponse},
        kmip_operations::Operation,
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, HashingAlgorithm, PaddingMethod,
            ProtocolVersion,
        },
    },
};
use cosmian_kms_client::KmsClient;
use criterion::{BenchmarkId, Criterion, Throughput};
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
        create_rsa_key_pair_request(None, ["bench"], cryptographic_length, false).unwrap();
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

/// Parametrized benchmarks
/// We use the `Message` KMIP structure to send multiple requests in a single call
pub(crate) async fn message_encrypt(
    kms_rest_client: &KmsClient,
    pk: &str,
    plaintext: &[u8],
    num_plaintexts: usize,
    cryptographic_parameters: &CryptographicParameters,
) -> MessageResponse {
    // Create the kmip query
    let encrypt_request = build_encryption_request(
        pk,
        None,
        plaintext.to_vec(),
        None,
        None,
        None,
        Some(cryptographic_parameters.to_owned()),
    )
    .unwrap();

    // Create the kmip query
    let message_request = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            batch_count: num_plaintexts as u32,
            ..Default::default()
        },
        items: (0..num_plaintexts)
            .map(|_| MessageBatchItem::new(Operation::Encrypt(encrypt_request.clone())))
            .collect(),
    };

    kms_rest_client.message(message_request).await.unwrap()
}

pub(crate) async fn message_decrypt(
    kms_rest_client: &KmsClient,
    sk: &str,
    ciphertext: &[u8],
    num_ciphertexts: usize,
    cryptographic_parameters: &CryptographicParameters,
) -> MessageResponse {
    // Create the kmip query
    let decrypt_request = build_decryption_request(
        sk,
        None,
        ciphertext.to_vec(),
        None,
        None,
        Some(cryptographic_parameters.clone()),
    );

    // Create the kmip query
    let message_request = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            batch_count: num_ciphertexts as u32,
            ..Default::default()
        },
        items: (0..num_ciphertexts)
            .map(|_| MessageBatchItem::new(Operation::Decrypt(decrypt_request.clone())))
            .collect(),
    };

    kms_rest_client.message(message_request).await.unwrap()
}

pub(crate) fn bench_encrypt_decrypt_parametrized(
    c: &mut Criterion,
    name: &str,
    cryptographic_parameters: CryptographicParameters,
) {
    let mut group = c.benchmark_group(name);
    let runtime = tokio::runtime::Runtime::new().unwrap();

    for num_plaintexts in [1, 10, 50, 100, 500, 1000] {
        for key_size in [2048, 4096] {
            let (kms_rest_client, sk, pk, ciphertext) = runtime.block_on(async {
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
                    &cryptographic_parameters,
                )
                .await;
                (kms_rest_client, sk, pk, ciphertext)
            });

            let parameter_name = if num_plaintexts == 1 {
                format!("{num_plaintexts} request")
            } else {
                format!("{num_plaintexts} requests")
            };
            // We can use the throughput function to tell Criterion.rs how large the input is
            // so it can calculate the overall throughput of the function. If we wanted, we could
            // even change the benchmark configuration for different inputs (eg. to reduce the
            // number of samples for extremely large and slow inputs) or even different functions.
            group.throughput(Throughput::Elements(num_plaintexts as u64));
            group.bench_with_input(
                BenchmarkId::new(
                    format!("{}-bit key encrypt", key_size),
                    parameter_name.clone(),
                ),
                &vec![0u8; 32],
                |b, pt| {
                    b.to_async(&runtime).iter(|| async {
                        let _ = message_encrypt(
                            &kms_rest_client,
                            &pk,
                            pt,
                            num_plaintexts,
                            &cryptographic_parameters,
                        )
                        .await;
                    });
                },
            );
            group.bench_with_input(
                BenchmarkId::new(format!("{}-bit key decrypt", key_size), parameter_name),
                &ciphertext,
                |b, ct| {
                    b.to_async(&runtime).iter(|| async {
                        message_decrypt(
                            &kms_rest_client,
                            &sk,
                            ct,
                            num_plaintexts,
                            &cryptographic_parameters,
                        )
                        .await;
                    });
                },
            );
        }
    }

    group.finish();
}

pub(crate) fn bench_encrypt_rsa_pkcs15_parametrized(c: &mut Criterion) {
    bench_encrypt_decrypt_parametrized(
        c,
        "RSA PKCSv1.5 - plaintext of 32 bytes",
        CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PKCS1v15),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
    )
}

pub(crate) fn bench_encrypt_rsa_oaep_parametrized(c: &mut Criterion) {
    bench_encrypt_decrypt_parametrized(
        c,
        "RSA OAEP - plaintext of 32 bytes",
        CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
    )
}

pub(crate) fn bench_encrypt_rsa_aes_key_wrap_parametrized(c: &mut Criterion) {
    bench_encrypt_decrypt_parametrized(
        c,
        "RSA AES KEY WRAP - plaintext of 32 bytes",
        CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
    )
}
