#![allow(dead_code)]
use cosmian_cli::reexport::cosmian_kms_client::{
    KmsClient, KmsClientError,
    kmip_0::kmip_types::{BlockCipherMode, CryptographicUsageMask},
    kmip_2_1::{
        extra::BulkData,
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, Decrypt, Encrypt},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, KeyFormatType, UniqueIdentifier,
        },
    },
};
use criterion::{BenchmarkId, Criterion, Throughput};
use test_kms_server::start_default_test_kms_server;
use zeroize::Zeroizing;

pub(crate) fn bench_create_symmetric_key(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let kms_rest_client = runtime.block_on(async {
        let ctx = start_default_test_kms_server().await;
        KmsClient::new_with_config(ctx.owner_client_conf.kms_config.clone()).unwrap()
    });

    let mut group = c.benchmark_group("Symmetric key tests");
    group.bench_function("AES 128bit key creation", |b| {
        b.to_async(&runtime).iter(|| async {
            let _ =
                create_symmetric_key(&kms_rest_client, 128, aes_cryptographic_parameters()).await;
        });
    });
    group.bench_function("AES 256bit key creation", |b| {
        b.to_async(&runtime).iter(|| async {
            let _ =
                create_symmetric_key(&kms_rest_client, 256, aes_cryptographic_parameters()).await;
        });
    });

    group.bench_function("ChaCha20 128bit key creation", |b| {
        b.to_async(&runtime).iter(|| async {
            let _ =
                create_symmetric_key(&kms_rest_client, 128, chacha20_cryptographic_parameters())
                    .await;
        });
    });
    group.bench_function("ChaCha20 256bit key creation", |b| {
        b.to_async(&runtime).iter(|| async {
            let _ =
                create_symmetric_key(&kms_rest_client, 256, chacha20_cryptographic_parameters())
                    .await;
        });
    });
}

fn aes_cryptographic_parameters() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(BlockCipherMode::GCM),
        ..Default::default()
    }
}
fn chacha20_cryptographic_parameters() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::ChaCha20),
        ..Default::default()
    }
}

pub(crate) async fn create_symmetric_key(
    kms_rest_client: &KmsClient,
    num_bits: i32,
    cryptographic_parameters: CryptographicParameters,
) -> Result<UniqueIdentifier, KmsClientError> {
    let create_key_request =
        create_symmetric_key_request(num_bits, cryptographic_parameters, Vec::<String>::new())?;
    // Query the KMS with your kmip data and get the key pair ids
    let response = kms_rest_client.create(create_key_request).await?;
    Ok(response.unique_identifier)
}

fn create_symmetric_key_request<T: IntoIterator<Item = impl AsRef<str>>>(
    num_bits: i32,
    cryptographic_parameters: CryptographicParameters,
    tags: T,
) -> Result<Create, KmsClientError> {
    let mut attributes = Attributes {
        cryptographic_algorithm: Some(
            cryptographic_parameters
                .cryptographic_algorithm
                .unwrap_or(CryptographicAlgorithm::AES),
        ),
        cryptographic_length: Some(num_bits),
        cryptographic_parameters: Some(cryptographic_parameters),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::KeyAgreement,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    };
    attributes.set_tags(tags)?;
    Ok(Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    })
}

//
//
//

pub(crate) fn bench_encrypt_aes_128_gcm(c: &mut Criterion) {
    bench_encrypt(c, "AES 128 GCM", 128, aes_cryptographic_parameters(), 1)
}

pub(crate) fn bench_encrypt_aes_256_gcm(c: &mut Criterion) {
    bench_encrypt(c, "AES 256 GCM", 256, aes_cryptographic_parameters(), 1)
}

pub(crate) fn bench_encrypt_aes_256_gcm_100000(c: &mut Criterion) {
    bench_encrypt(
        c,
        "AES 256 GCM",
        256,
        aes_cryptographic_parameters(),
        100_000,
    )
}

pub(crate) fn bench_encrypt_chacha20_128_poly1305(c: &mut Criterion) {
    bench_encrypt(
        c,
        "ChaCha20 128 Poly1305",
        128,
        chacha20_cryptographic_parameters(),
        1,
    )
}

pub(crate) fn bench_encrypt_chacha20_256_poly1305(c: &mut Criterion) {
    bench_encrypt(
        c,
        "ChaCha20 256 Poly1305",
        256,
        chacha20_cryptographic_parameters(),
        1,
    )
}

pub(crate) fn bench_encrypt(
    c: &mut Criterion,
    name: &str,
    num_bits: i32,
    cryptographic_parameters: CryptographicParameters,
    num_plaintexts: usize,
) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let (kms_rest_client, key_id) = runtime.block_on(async {
        let ctx = start_default_test_kms_server().await;
        let kms_rest_client =
            KmsClient::new_with_config(ctx.owner_client_conf.kms_config.clone()).unwrap();
        let key_id =
            create_symmetric_key(&kms_rest_client, num_bits, cryptographic_parameters.clone())
                .await
                .unwrap();
        (kms_rest_client, key_id)
    });

    let plaintext = if num_plaintexts == 1 {
        Zeroizing::new(vec![1_u8; 64])
    } else {
        BulkData::new(vec![Zeroizing::new(vec![1_u8; 64]); num_plaintexts])
            .serialize()
            .unwrap()
    };

    let mut group = c.benchmark_group("Symmetric encryption");
    group.bench_function(
        format!(
            "{} {}bit encryption of {} plaintext(s)",
            name, num_bits, num_plaintexts
        ),
        |b| {
            b.to_async(&runtime).iter(|| async {
                let _ = encrypt(
                    &kms_rest_client,
                    key_id.clone(),
                    cryptographic_parameters.clone(),
                    plaintext.clone(),
                )
                .await
                .unwrap();
            });
        },
    );
}

pub(crate) async fn encrypt(
    kms_rest_client: &KmsClient,
    key_id: UniqueIdentifier,
    cryptographic_parameters: CryptographicParameters,
    plaintext: Zeroizing<Vec<u8>>,
) -> Result<(Option<Vec<u8>>, Vec<u8>, Option<Vec<u8>>), KmsClientError> {
    // Create the kmip query
    let encrypt_request = encrypt_request(key_id, cryptographic_parameters, plaintext)?;

    // Query the KMS with your kmip data and get the key pair ids
    let encrypt_response = kms_rest_client.encrypt(encrypt_request).await?;

    let nonce = encrypt_response.i_v_counter_nonce;
    let data = encrypt_response
        .data
        .ok_or_else(|| KmsClientError::UnexpectedError("No data".to_string()))?;
    let mac = encrypt_response.authenticated_encryption_tag;
    Ok((nonce, data, mac))
}

fn encrypt_request(
    key_id: UniqueIdentifier,
    cryptographic_parameters: CryptographicParameters,
    data: Zeroizing<Vec<u8>>,
) -> Result<Encrypt, KmsClientError> {
    Ok(Encrypt {
        unique_identifier: Some(key_id),
        cryptographic_parameters: Some(cryptographic_parameters),
        data: Some(data),
        i_v_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    })
}

//
//
//
pub(crate) fn bench_decrypt_aes_128_gcm(c: &mut Criterion) {
    bench_decrypt(c, "AES GCM", 128, aes_cryptographic_parameters(), 1)
}

pub(crate) fn bench_decrypt_aes_256_gcm(c: &mut Criterion) {
    bench_decrypt(c, "AES GCM", 256, aes_cryptographic_parameters(), 1)
}

pub(crate) fn bench_decrypt_aes_256_gcm_100000(c: &mut Criterion) {
    bench_decrypt(c, "AES GCM", 256, aes_cryptographic_parameters(), 100_000)
}

pub(crate) fn bench_decrypt_chacha20_128_poly1305(c: &mut Criterion) {
    bench_decrypt(
        c,
        "Chacha20 Poly1305",
        128,
        chacha20_cryptographic_parameters(),
        1,
    )
}

pub(crate) fn bench_decrypt_chacha20_256_poly1305(c: &mut Criterion) {
    bench_decrypt(
        c,
        "Chacha20 Poly1305",
        256,
        chacha20_cryptographic_parameters(),
        1,
    )
}

pub(crate) fn bench_decrypt(
    c: &mut Criterion,
    name: &str,
    num_bits: i32,
    cryptographic_parameters: CryptographicParameters,
    num_ciphertexts: usize,
) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let plaintext = if num_ciphertexts == 1 {
        Zeroizing::new(vec![1_u8; 64])
    } else {
        BulkData::new(vec![Zeroizing::new(vec![1_u8; 64]); num_ciphertexts])
            .serialize()
            .unwrap()
    };
    let (kms_rest_client, key_id, (nonce, ciphertext, mac)) = runtime.block_on(async {
        let ctx = start_default_test_kms_server().await;
        let kms_rest_client =
            KmsClient::new_with_config(ctx.owner_client_conf.kms_config.clone()).unwrap();
        let key_id =
            create_symmetric_key(&kms_rest_client, num_bits, cryptographic_parameters.clone())
                .await
                .unwrap();
        let (nonce, ciphertext, mac) = encrypt(
            &kms_rest_client,
            key_id.clone(),
            cryptographic_parameters.clone(),
            plaintext.clone(),
        )
        .await
        .unwrap();
        (kms_rest_client, key_id, (nonce, ciphertext, mac))
    });

    let mut group = c.benchmark_group("Symmetric encryption");
    group.bench_function(
        format!("{name} {num_bits}bit decryption of {num_ciphertexts} ciphertext(s)",),
        |b| {
            b.to_async(&runtime).iter(|| async {
                let _ = decrypt(
                    &kms_rest_client,
                    key_id.clone(),
                    cryptographic_parameters.clone(),
                    nonce.clone(),
                    ciphertext.clone(),
                    mac.clone(),
                )
                .await
                .unwrap();
            });
        },
    );
}

pub(crate) async fn decrypt(
    kms_rest_client: &KmsClient,
    key_id: UniqueIdentifier,
    cryptographic_parameters: CryptographicParameters,
    nonce: Option<Vec<u8>>,
    ciphertext: Vec<u8>,
    mac: Option<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, KmsClientError> {
    // Create the kmip query
    let decrypt_request =
        decrypt_request(key_id, cryptographic_parameters, nonce, ciphertext, mac)?;

    // Query the KMS with your kmip data and get the key pair ids
    let decrypt_response = kms_rest_client.decrypt(decrypt_request).await?;

    decrypt_response
        .data
        .ok_or_else(|| KmsClientError::UnexpectedError("No data".to_string()))
}

fn decrypt_request(
    key_id: UniqueIdentifier,
    cryptographic_parameters: CryptographicParameters,
    nonce: Option<Vec<u8>>,
    data: Vec<u8>,
    mac: Option<Vec<u8>>,
) -> Result<Decrypt, KmsClientError> {
    Ok(Decrypt {
        unique_identifier: Some(key_id),
        cryptographic_parameters: Some(cryptographic_parameters),
        data: Some(data),
        i_v_counter_nonce: nonce,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
        authenticated_encryption_tag: mac,
    })
}

pub(crate) fn bench_encrypt_aes_parametrized(c: &mut Criterion) {
    bench_encrypt_parametrized(
        c,
        "AES GCM - plaintext of 64 bytes",
        aes_cryptographic_parameters(),
    )
}

pub(crate) fn bench_encrypt_parametrized(
    c: &mut Criterion,
    name: &str,
    cryptographic_parameters: CryptographicParameters,
) {
    let mut group = c.benchmark_group(name);
    let runtime = tokio::runtime::Runtime::new().unwrap();

    for num_plaintexts in [1, 10, 50, 100, 500, 1000] {
        for num_bits in [128, 256] {
            // Generate input of an appropriate size...
            let plaintext = if num_plaintexts == 1 {
                Zeroizing::new(vec![1_u8; 64])
            } else {
                BulkData::new(vec![Zeroizing::new(vec![1_u8; 64]); num_plaintexts])
                    .serialize()
                    .unwrap()
            };

            let (kms_rest_client, key_id, (nonce, ciphertext, mac)) = runtime.block_on(async {
                let ctx = start_default_test_kms_server().await;
                let kms_rest_client =
                    KmsClient::new_with_config(ctx.owner_client_conf.kms_config.clone()).unwrap();
                let key_id = create_symmetric_key(
                    &kms_rest_client,
                    num_bits,
                    cryptographic_parameters.clone(),
                )
                .await
                .unwrap();
                let (nonce, ciphertext, mac) = encrypt(
                    &kms_rest_client,
                    key_id.clone(),
                    cryptographic_parameters.clone(),
                    plaintext.clone(),
                )
                .await
                .unwrap();
                (kms_rest_client, key_id, (nonce, ciphertext, mac))
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
                    format!("{}-bit key encrypt", num_bits),
                    parameter_name.clone(),
                ),
                &plaintext,
                |b, pt| {
                    b.to_async(&runtime).iter(|| async {
                        let _ = encrypt(
                            &kms_rest_client,
                            key_id.clone(),
                            cryptographic_parameters.clone(),
                            pt.clone(),
                        )
                        .await
                        .unwrap();
                    });
                },
            );
            group.bench_with_input(
                BenchmarkId::new(format!("{}-bit key decrypt", num_bits), parameter_name),
                &ciphertext,
                |b, ct| {
                    b.to_async(&runtime).iter(|| async {
                        let _ = decrypt(
                            &kms_rest_client,
                            key_id.clone(),
                            cryptographic_parameters.clone(),
                            nonce.clone(),
                            ct.clone(),
                            mac.clone(),
                        )
                        .await
                        .unwrap();
                    });
                },
            );
        }
    }

    group.finish();
}
