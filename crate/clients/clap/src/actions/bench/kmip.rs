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
            RecommendedCurve, UniqueIdentifier,
        },
        requests::{
            create_ec_key_pair_request, create_rsa_key_pair_request, decrypt_request,
            encrypt_request, symmetric_key_create_request,
        },
    },
};
use criterion::{BenchmarkId, Criterion, Throughput};
use sha2::{Digest as _, Sha256};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

#[cfg(feature = "non-fips")]
use super::helpers::{
    aes_gcm_siv_params, chacha20_params, kem_params, rsa_pkcs15_params, try_create_ec_kp_no_fips,
    try_create_pqc_kp, try_create_sym_key,
};
use super::{
    helpers::{
        aes_cbc_params, aes_gcm_params, aes_xts_params, create_rsa_kp, create_sym_key,
        hsm_rsa_pkcs1v15_encrypt_params, hsm_rsa_pkcs1v15_sign_params, hsm_uid, rsa_kwp_params,
        rsa_oaep_params, rsa_oaep_sha1_params, try_create_ec_kp, try_create_hsm_ec_kp,
        try_create_hsm_rsa_kp, try_create_hsm_sym_key, with_fips_ec_masks, with_fips_rsa_masks,
    },
    transport::{Transport, bench_message_id, bench_op, bench_op_id, timed_group},
    types::bench_ko,
};

pub(super) fn bench_encrypt(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
) {
    bench_encrypt_aes_gcm(c, client, rt, transport);
    bench_encrypt_aes_xts(c, client, rt, transport);

    #[cfg(feature = "non-fips")]
    bench_encrypt_aes_gcm_siv(c, client, rt, transport);

    #[cfg(feature = "non-fips")]
    bench_encrypt_chacha20(c, client, rt, transport);

    bench_rsa_encrypt_family(
        c,
        client,
        rt,
        transport,
        "rsa-oaep",
        &rsa_oaep_params(),
        &[4096],
    );

    bench_rsa_encrypt_family(
        c,
        client,
        rt,
        transport,
        "rsa-aes-kwp",
        &rsa_kwp_params(),
        &[4096],
    );

    #[cfg(feature = "non-fips")]
    bench_rsa_encrypt_family(
        c,
        client,
        rt,
        transport,
        "rsa-pkcs1v15",
        &rsa_pkcs15_params(),
        &[4096],
    );

    #[cfg(feature = "non-fips")]
    bench_encrypt_ecies(c, client, rt, transport);

    #[cfg(feature = "non-fips")]
    bench_encrypt_salsa(c, client, rt, transport);

    #[cfg(feature = "non-fips")]
    bench_encrypt_covercrypt(c, client, rt, transport);

    #[cfg(feature = "non-fips")]
    bench_kem(c, client, rt, transport);

    #[cfg(feature = "non-fips")]
    bench_pqc_kem(c, client, rt, transport);
}

pub(super) fn bench_encrypt_aes_gcm(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
) {
    let slug = transport.slug();
    let mut group = timed_group(c, format!("{slug}/encrypt/aes-gcm"));
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
            bench_ko(format!("{slug}/encrypt/aes-gcm"));
            continue;
        };

        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("encrypt", bits),
            Operation::Encrypt(Box::new(enc_req)),
        );

        let dec_req = Decrypt {
            unique_identifier: Some(key_id),
            cryptographic_parameters: Some(params.clone()),
            data: Some(enc_resp.data.map_or_else(Vec::new, |z| z.to_vec())),
            i_v_counter_nonce: enc_resp.i_v_counter_nonce,
            authenticated_encryption_tag: enc_resp.authenticated_encryption_tag,
            ..Default::default()
        };
        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("decrypt", bits),
            Operation::Decrypt(Box::new(dec_req)),
        );
    }
    group.finish();
}

#[cfg(feature = "non-fips")]
pub(super) fn bench_encrypt_chacha20(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
) {
    let slug = transport.slug();
    let Some(key_id) = try_create_sym_key(rt, client, 256, CryptographicAlgorithm::ChaCha20) else {
        eprintln!("[bench] ChaCha20 not supported by server, skipping");
        bench_ko(format!("{slug}/encrypt/chacha20-poly1305"));
        return;
    };

    let mut group = timed_group(c, format!("{slug}/encrypt/chacha20-poly1305"));
    let params = chacha20_params();

    let enc_req = Encrypt {
        unique_identifier: Some(key_id.clone()),
        cryptographic_parameters: Some(params.clone()),
        data: Some(Zeroizing::new(vec![1_u8; 64])),
        ..Default::default()
    };
    bench_op(
        &mut group,
        client,
        rt,
        transport,
        "encrypt/256",
        Operation::Encrypt(Box::new(enc_req.clone())),
    );

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
    bench_op(
        &mut group,
        client,
        rt,
        transport,
        "decrypt/256",
        Operation::Decrypt(Box::new(dec_req)),
    );
    group.finish();
}

fn bench_rsa_encrypt_family(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
    label: &str,
    params: &CryptographicParameters,
    key_sizes: &[usize],
) {
    let slug = transport.slug();
    let mut group = timed_group(c, format!("{slug}/encrypt/{label}"));
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
            bench_ko(format!("{slug}/encrypt/{label}"));
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
        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("encrypt", bits),
            Operation::Encrypt(Box::new(enc_req.clone())),
        );

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
        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("decrypt", bits),
            Operation::Decrypt(Box::new(dec_req)),
        );
    }
    group.finish();
}

pub(super) fn bench_encrypt_aes_xts(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
) {
    let slug = transport.slug();
    let mut group = timed_group(c, format!("{slug}/encrypt/aes-xts"));
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
            bench_ko(format!("{slug}/encrypt/aes-xts"));
            continue;
        }

        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("encrypt", label),
            Operation::Encrypt(Box::new(enc_req.clone())),
        );

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
        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("decrypt", label),
            Operation::Decrypt(Box::new(dec_req)),
        );
    }
    group.finish();
}

#[cfg(feature = "non-fips")]
pub(super) fn bench_encrypt_aes_gcm_siv(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
) {
    let slug = transport.slug();
    let mut group = timed_group(c, format!("{slug}/encrypt/aes-gcm-siv"));
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
            bench_ko(format!("{slug}/encrypt/aes-gcm-siv"));
            continue;
        }

        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("encrypt", bits),
            Operation::Encrypt(Box::new(enc_req.clone())),
        );

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
        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("decrypt", bits),
            Operation::Decrypt(Box::new(dec_req)),
        );
    }
    group.finish();
}

#[cfg(feature = "non-fips")]
pub(super) fn bench_encrypt_ecies(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
) {
    let slug = transport.slug();
    let mut group = timed_group(c, format!("{slug}/encrypt/ecies"));

    for (label, curve) in [
        ("P-256", RecommendedCurve::P256),
        ("P-384", RecommendedCurve::P384),
        ("P-521", RecommendedCurve::P521),
    ] {
        let Some((pub_id, priv_id)) = try_create_ec_kp_no_fips(rt, client, curve) else {
            eprintln!("[bench] ECIES {label} not supported by server, skipping");
            bench_ko(format!("{slug}/encrypt/ecies"));
            continue;
        };
        let pub_str = pub_id.to_string();

        let enc_req = encrypt_request(&pub_str, None, vec![0x42_u8; 64], None, None, None)
            .expect("encrypt request");

        if rt.block_on(client.encrypt(enc_req.clone())).is_err() {
            eprintln!("[bench] ECIES {label} encrypt failed, skipping");
            bench_ko(format!("{slug}/encrypt/ecies"));
            continue;
        }

        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("encrypt", label),
            Operation::Encrypt(Box::new(enc_req.clone())),
        );

        let enc_resp = rt
            .block_on(client.encrypt(enc_req))
            .expect("pre-encrypt for decrypt");
        let ct = enc_resp.data.map_or_else(Vec::new, |z| z.to_vec());
        let dec_req = decrypt_request(&priv_id.to_string(), None, ct, None, None, None);
        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("decrypt", label),
            Operation::Decrypt(Box::new(dec_req)),
        );
    }
    group.finish();
}

#[cfg(feature = "non-fips")]
pub(super) fn bench_encrypt_salsa(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
) {
    let slug = transport.slug();
    let Some((pub_id, priv_id)) =
        try_create_ec_kp_no_fips(rt, client, RecommendedCurve::CURVE25519)
    else {
        eprintln!("[bench] Salsa Sealed Box (X25519) not supported by server, skipping");
        bench_ko(format!("{slug}/encrypt/salsa-sealed-box"));
        return;
    };
    let pub_str = pub_id.to_string();

    let enc_req = encrypt_request(&pub_str, None, vec![0x42_u8; 64], None, None, None)
        .expect("encrypt request");

    if rt.block_on(client.encrypt(enc_req.clone())).is_err() {
        eprintln!("[bench] Salsa Sealed Box encrypt failed, skipping");
        bench_ko(format!("{slug}/encrypt/salsa-sealed-box"));
        return;
    }

    let mut group = timed_group(c, format!("{slug}/encrypt/salsa-sealed-box"));
    bench_op(
        &mut group,
        client,
        rt,
        transport,
        "encrypt",
        Operation::Encrypt(Box::new(enc_req.clone())),
    );

    let enc_resp = rt
        .block_on(client.encrypt(enc_req))
        .expect("pre-encrypt for decrypt");
    let ct = enc_resp.data.map_or_else(Vec::new, |z| z.to_vec());
    let dec_req = decrypt_request(&priv_id.to_string(), None, ct, None, None, None);
    bench_op(
        &mut group,
        client,
        rt,
        transport,
        "decrypt",
        Operation::Decrypt(Box::new(dec_req)),
    );
    group.finish();
}

#[cfg(feature = "non-fips")]
pub(super) fn bench_encrypt_covercrypt(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
) {
    let slug = transport.slug();
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
            bench_ko(format!("{slug}/encrypt/covercrypt"));
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
        bench_ko(format!("{slug}/encrypt/covercrypt"));
        return;
    }

    let mut group = timed_group(c, format!("{slug}/encrypt/covercrypt"));
    bench_op(
        &mut group,
        client,
        rt,
        transport,
        "encrypt",
        Operation::Encrypt(Box::new(enc_req.clone())),
    );

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
    bench_op(
        &mut group,
        client,
        rt,
        transport,
        "decrypt",
        Operation::Decrypt(Box::new(dec_req)),
    );
    group.finish();
}

#[cfg(feature = "non-fips")]
fn bench_kem(c: &mut Criterion, client: &KmsClient, rt: &Runtime, transport: Transport) {
    let slug = transport.slug();
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

    let mut group = timed_group(c, format!("{slug}/kem/configurable"));
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
                bench_ko(format!("{slug}/kem/configurable"));
                continue;
            }
        };

        let pub_str = pub_id.to_string();
        let enc_req = encrypt_request(&pub_str, None, Vec::new(), None, None, Some(params.clone()))
            .expect("KEM encapsulate request");

        if rt.block_on(client.encrypt(enc_req.clone())).is_err() {
            eprintln!("[bench] KEM {label} encapsulate failed, skipping");
            bench_ko(format!("{slug}/kem/configurable"));
            continue;
        }

        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("encapsulate", label),
            Operation::Encrypt(Box::new(enc_req.clone())),
        );

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
        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("decapsulate", label),
            Operation::Decrypt(Box::new(dec_req)),
        );
    }
    group.finish();
}

#[cfg(feature = "non-fips")]
fn bench_pqc_kem(c: &mut Criterion, client: &KmsClient, rt: &Runtime, transport: Transport) {
    let slug = transport.slug();
    let algorithms: &[(&str, CryptographicAlgorithm)] = &[
        ("ML-KEM-512", CryptographicAlgorithm::MLKEM_512),
        ("ML-KEM-768", CryptographicAlgorithm::MLKEM_768),
        ("ML-KEM-1024", CryptographicAlgorithm::MLKEM_1024),
        ("X25519MLKEM768", CryptographicAlgorithm::X25519MLKEM768),
        ("X448MLKEM1024", CryptographicAlgorithm::X448MLKEM1024),
    ];

    let mut group = timed_group(c, format!("{slug}/kem/pqc"));
    for &(label, algo) in algorithms {
        let Some((pub_id, priv_id)) = try_create_pqc_kp(rt, client, algo) else {
            eprintln!("[bench] PQC KEM {label} not supported by server, skipping");
            bench_ko(format!("{slug}/kem/pqc"));
            continue;
        };

        let pub_str = pub_id.to_string();
        let enc_req =
            encrypt_request(&pub_str, None, Vec::new(), None, None, None).expect("KEM request");

        let Ok(enc_resp) = rt.block_on(client.encrypt(enc_req.clone())) else {
            eprintln!("[bench] PQC KEM {label} encapsulate failed, skipping");
            bench_ko(format!("{slug}/kem/pqc"));
            continue;
        };

        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("encapsulate", label),
            Operation::Encrypt(Box::new(enc_req)),
        );

        // Standard PQC KEM: ciphertext is in i_v_counter_nonce
        let ct = enc_resp
            .i_v_counter_nonce
            .unwrap_or_else(|| enc_resp.data.map_or_else(Vec::new, |z| z.to_vec()));
        let dec_req = decrypt_request(&priv_id.to_string(), None, ct, None, None, None);
        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("decapsulate", label),
            Operation::Decrypt(Box::new(dec_req)),
        );
    }
    group.finish();
}

// =============================================================================
// KEY CREATION BENCHMARKS
// =============================================================================

pub(super) fn bench_key_creation(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
) {
    let slug = transport.slug();
    let vid = client.config.vendor_id.clone();

    // Symmetric keys
    {
        let mut group = timed_group(c, format!("{slug}/key-creation/symmetric"));
        for (label, bits, algo) in [
            ("aes-128", 128, CryptographicAlgorithm::AES),
            ("aes-192", 192, CryptographicAlgorithm::AES),
            ("aes-256", 256, CryptographicAlgorithm::AES),
        ] {
            let req = symmetric_key_create_request(
                &vid,
                None,
                bits,
                algo,
                Vec::<String>::new(),
                false,
                None,
            )
            .expect("sym key request");
            bench_op(
                &mut group,
                client,
                rt,
                transport,
                label,
                Operation::Create(req),
            );
        }
        #[cfg(feature = "non-fips")]
        if try_create_sym_key(rt, client, 256, CryptographicAlgorithm::ChaCha20).is_some() {
            let req = symmetric_key_create_request(
                &vid,
                None,
                256,
                CryptographicAlgorithm::ChaCha20,
                Vec::<String>::new(),
                false,
                None,
            )
            .expect("chacha20 key request");
            bench_op(
                &mut group,
                client,
                rt,
                transport,
                "chacha20-256",
                Operation::Create(req),
            );
        } else {
            bench_ko(format!("{slug}/key-creation/symmetric"));
        }
        group.finish();
    }

    // RSA key pairs
    {
        let mut group = timed_group(c, format!("{slug}/key-creation/rsa"));
        for bits in [4096] {
            let req = with_fips_rsa_masks(
                create_rsa_key_pair_request(&vid, None, Vec::<String>::new(), bits, false, None)
                    .expect("RSA kp request"),
            );
            bench_op(
                &mut group,
                client,
                rt,
                transport,
                format!("rsa-{bits}"),
                Operation::CreateKeyPair(Box::new(req)),
            );
        }
        group.finish();
    }

    // EC key pairs
    {
        let mut group = timed_group(c, format!("{slug}/key-creation/ec"));
        for (label, curve) in [
            ("p256", RecommendedCurve::P256),
            ("p384", RecommendedCurve::P384),
            ("p521", RecommendedCurve::P521),
        ] {
            let req = with_fips_ec_masks(
                create_ec_key_pair_request(&vid, None, Vec::<String>::new(), curve, false, None)
                    .expect("EC kp request"),
            );
            bench_op(
                &mut group,
                client,
                rt,
                transport,
                label,
                Operation::CreateKeyPair(Box::new(req)),
            );
        }
        #[cfg(feature = "non-fips")]
        for (label, curve) in [
            ("ed25519", RecommendedCurve::CURVEED25519),
            ("ed448", RecommendedCurve::CURVEED448),
            ("secp256k1", RecommendedCurve::SECP256K1),
        ] {
            if try_create_ec_kp(rt, client, curve).is_some() {
                let req = with_fips_ec_masks(
                    create_ec_key_pair_request(
                        &vid,
                        None,
                        Vec::<String>::new(),
                        curve,
                        false,
                        None,
                    )
                    .expect("EC kp request"),
                );
                bench_op(
                    &mut group,
                    client,
                    rt,
                    transport,
                    label,
                    Operation::CreateKeyPair(Box::new(req)),
                );
            } else {
                bench_ko(format!("{slug}/key-creation/ec"));
            }
        }
        group.finish();
    }

    // Covercrypt key pairs (non-FIPS)
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
            let req = build_create_covercrypt_master_keypair_request(
                &vid,
                access_structure,
                Vec::<String>::new(),
                false,
                None,
            )
            .expect("CC master keypair request");
            let mut group = timed_group(c, format!("{slug}/key-creation/covercrypt"));
            bench_op(
                &mut group,
                client,
                rt,
                transport,
                "master-keypair",
                Operation::CreateKeyPair(Box::new(req)),
            );
            group.finish();
        } else {
            bench_ko(format!("{slug}/key-creation/covercrypt"));
        }
    }

    // Configurable KEM key pairs (non-FIPS)
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

        let mut group = timed_group(c, format!("{slug}/key-creation/kem"));
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
                let req = build_create_configurable_kem_keypair_request(
                    &vid,
                    None,
                    Vec::<String>::new(),
                    algo,
                    false,
                    None,
                )
                .expect("KEM keypair request");
                bench_op(
                    &mut group,
                    client,
                    rt,
                    transport,
                    label,
                    Operation::CreateKeyPair(Box::new(req)),
                );
            } else {
                bench_ko(format!("{slug}/key-creation/kem"));
            }
        }
        group.finish();
    }

    // PQC key pairs (non-FIPS)
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
                "SLH-DSA-SHA2-128f",
                CryptographicAlgorithm::SLHDSA_SHA2_128f,
            ),
            (
                "SLH-DSA-SHA2-256f",
                CryptographicAlgorithm::SLHDSA_SHA2_256f,
            ),
            (
                "SLH-DSA-SHAKE-128f",
                CryptographicAlgorithm::SLHDSA_SHAKE_128f,
            ),
            (
                "SLH-DSA-SHAKE-256f",
                CryptographicAlgorithm::SLHDSA_SHAKE_256f,
            ),
        ];

        let mut group = timed_group(c, format!("{slug}/key-creation/pqc"));
        for &(label, algo) in pqc_algos {
            let vid2 = vid.clone();
            let result = rt.block_on(async {
                let req = create_pqc_key_pair_request(&vid2, ["bench"], algo, false).ok()?;
                client.create_key_pair(req).await.ok()
            });
            if result.is_some() {
                let req = create_pqc_key_pair_request(&vid, Vec::<String>::new(), algo, false)
                    .expect("PQC keypair request");
                bench_op(
                    &mut group,
                    client,
                    rt,
                    transport,
                    label,
                    Operation::CreateKeyPair(Box::new(req)),
                );
            } else {
                bench_ko(format!("{slug}/key-creation/pqc"));
            }
        }
        group.finish();
    }
}

// =============================================================================
// SIGN / VERIFY BENCHMARKS
// =============================================================================

pub(super) fn bench_sign_verify(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
) {
    // ECDSA - FIPS curves
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
        bench_ec_sign(c, client, rt, transport, label, curve, Some(algo));
    }

    // Non-FIPS EC signature algorithms
    #[cfg(feature = "non-fips")]
    {
        bench_ec_sign(
            c,
            client,
            rt,
            transport,
            "ecdsa-secp256k1",
            RecommendedCurve::SECP256K1,
            Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
        );

        bench_ec_sign(
            c,
            client,
            rt,
            transport,
            "eddsa-ed25519",
            RecommendedCurve::CURVEED25519,
            None,
        );

        bench_ec_sign(
            c,
            client,
            rt,
            transport,
            "eddsa-ed448",
            RecommendedCurve::CURVEED448,
            None,
        );
    }

    // RSA-PSS
    bench_rsa_pss_sign(c, client, rt, transport);

    // PQC signature algorithms (non-FIPS)
    #[cfg(feature = "non-fips")]
    bench_pqc_sign(
        c,
        client,
        rt,
        transport,
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
        transport,
        "sign-verify/slh-dsa",
        &[
            ("SHA2-128f", CryptographicAlgorithm::SLHDSA_SHA2_128f),
            ("SHA2-256f", CryptographicAlgorithm::SLHDSA_SHA2_256f),
            ("SHAKE-128f", CryptographicAlgorithm::SLHDSA_SHAKE_128f),
            ("SHAKE-256f", CryptographicAlgorithm::SLHDSA_SHAKE_256f),
        ],
    );
}

fn bench_ec_sign(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
    label: &str,
    curve: RecommendedCurve,
    sign_algo: Option<DigitalSignatureAlgorithm>,
) {
    let slug = transport.slug();
    let Some((pub_id, priv_id)) = try_create_ec_kp(rt, client, curve) else {
        eprintln!("[bench] {label} not supported by server, skipping");
        bench_ko(format!("{slug}/sign-verify/{label}"));
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
        bench_ko(format!("{slug}/sign-verify/{label}"));
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

    let mut group = timed_group(c, format!("{slug}/sign-verify/{label}"));
    bench_op(
        &mut group,
        client,
        rt,
        transport,
        "sign",
        Operation::Sign(sign_req),
    );
    bench_op(
        &mut group,
        client,
        rt,
        transport,
        "verify",
        Operation::SignatureVerify(verify_req),
    );
    group.finish();
}

fn bench_rsa_pss_sign(c: &mut Criterion, client: &KmsClient, rt: &Runtime, transport: Transport) {
    let slug = transport.slug();
    let sign_params = Some(CryptographicParameters {
        digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
        ..Default::default()
    });
    let message = Zeroizing::new(vec![0x42_u8; 32]);

    let mut group = timed_group(c, format!("{slug}/sign-verify/rsa-pss"));
    for bits in [4096] {
        let (pub_id, priv_id) = create_rsa_kp(rt, client, bits);

        let sign_req = Sign {
            unique_identifier: Some(priv_id),
            cryptographic_parameters: sign_params.clone(),
            data: Some(message.clone()),
            ..Default::default()
        };
        let Ok(sign_resp) = rt.block_on(client.sign(sign_req.clone())) else {
            eprintln!("[bench] rsa-pss-{bits} sign not supported by server, skipping");
            bench_ko(format!("{slug}/sign-verify/rsa-pss"));
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

        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("sign", bits),
            Operation::Sign(sign_req),
        );
        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("verify", bits),
            Operation::SignatureVerify(verify_req),
        );
    }
    group.finish();
}

#[cfg(feature = "non-fips")]
fn bench_pqc_sign(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
    group_name: &str,
    algorithms: &[(&str, CryptographicAlgorithm)],
) {
    let slug = transport.slug();
    let message = Zeroizing::new(vec![0x42_u8; 32]);
    let mut group = timed_group(c, format!("{slug}/{group_name}"));

    for &(label, algo) in algorithms {
        let Some((pub_id, priv_id)) = try_create_pqc_kp(rt, client, algo) else {
            eprintln!("[bench] {label} not supported by server, skipping");
            bench_ko(format!("{slug}/{group_name}"));
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
            bench_ko(format!("{slug}/{group_name}"));
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

        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("sign", label),
            Operation::Sign(sign_req),
        );
        bench_op_id(
            &mut group,
            client,
            rt,
            transport,
            BenchmarkId::new("verify", label),
            Operation::SignatureVerify(verify_req),
        );
    }
    group.finish();
}

// =============================================================================
// HSM-RESIDENT BENCHMARKS
// =============================================================================
//
// Ops executed against `hsm::`-prefixed keys are routed by the server to the
// HSM's `CryptoOracle` (PKCS#11), instead of KMS software. Every algorithm
// variant of `crate::interfaces::crypto_oracle::CryptoAlgorithm` (encrypt) and
// `SigningAlgorithm` (sign) reachable via ordinary (non-prehashed-digest-only)
// KMIP requests is covered:
// - Encrypt: AES-GCM, AES-CBC, RSA-OAEP-SHA256, RSA-OAEP-SHA1, RSA-PKCS1v15.
// - Sign: RSA-PSS, RSA-PKCS1v15 hash-and-sign (SHA1/256/384/512), ECDSA
//   (P-256/P-384 — requires `digested_data`/prehashed input because SoftHSM2
//   only implements raw `CKM_ECDSA`, not the combined `CKM_ECDSA_SHA*`
//   mechanisms), EdDSA (Ed25519/Ed448, non-FIPS only — pure, un-hashed
//   `CKM_EDDSA`, requires `cryptographic_algorithm` set to `Ed25519`/`Ed448`
//   in the request with no `digital_signature_algorithm` and no
//   `digested_data`, exactly mirroring `ckms ec sign`'s own request
//   construction; omitting `cryptographic_parameters` entirely also works,
//   since the server then falls back to the key's own stored curve).
// - `Verify` is NOT implemented for HSM-resident keys at all yet (any
//   algorithm), so it is intentionally omitted (unlike the software
//   `sign-verify` benches, which cover both directions).
// - P-521 key creation is NOT covered: `crate/crypto/src/crypto/
//   elliptic_curves/operation.rs` derives `cryptographic_length` from the
//   generated private scalar's serialized byte length rather than the
//   curve's nominal bit length, which can under-count P-521 (66-byte keys
//   occasionally serialize to 65 bytes) and makes `HSM::create_keypair`
//   reject the resulting length ("valid values are 224, 256, 384, 521") —
//   reproduced 3/3 attempts in this environment. Pre-existing bug unrelated
//   to this benchmark; tracked as a follow-up rather than fixed here.
// - The bare (un-hashed) `SigningAlgorithm::RsaPkcsV15` variant — a raw
//   `CKM_RSA_PKCS` sign over a caller-supplied `DigestInfo` blob — is not
//   reachable via ordinary `Sign` KMIP requests (`from_kmip` always infers a
//   hash and returns `Sha*WithRsa` instead when `padding_method` is
//   `PKCS1v15` without an explicit digest), so it has no bench entry either;
//   the hash-and-sign variants above exercise the same PKCS#11 mechanism
//   family end-to-end.
//
// Key creation cannot reuse `bench_op`'s pre-serialized-once-then-replay
// model (unlike software Create/CreateKeyPair, which omit `unique_identifier`
// and let the server assign a fresh UUID per call): the HSM has no
// auto-generated ID, so every request must carry a *distinct* `hsm::` UID.
// `bench_hsm_key_creation` therefore builds and serializes a fresh request
// inside the timed closure for each iteration.

pub(super) fn bench_hsm_encrypt(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
    hsm_prefix: &str,
) {
    let slug = transport.slug();

    // AES-GCM
    if let Some(key_id) =
        try_create_hsm_sym_key(rt, client, hsm_prefix, 256, CryptographicAlgorithm::AES)
    {
        let mut group = timed_group(c, format!("{slug}/encrypt/hsm-aes-gcm"));
        let enc_req = Encrypt {
            unique_identifier: Some(key_id),
            cryptographic_parameters: Some(aes_gcm_params()),
            data: Some(Zeroizing::new(vec![1_u8; 64])),
            ..Default::default()
        };
        bench_op(
            &mut group,
            client,
            rt,
            transport,
            "encrypt/256",
            Operation::Encrypt(Box::new(enc_req)),
        );
        group.finish();
    } else {
        eprintln!("[bench] HSM AES-GCM not available, skipping");
        bench_ko(format!("{slug}/encrypt/hsm-aes-gcm"));
    }

    // AES-CBC
    if let Some(key_id) =
        try_create_hsm_sym_key(rt, client, hsm_prefix, 256, CryptographicAlgorithm::AES)
    {
        let mut group = timed_group(c, format!("{slug}/encrypt/hsm-aes-cbc"));
        let enc_req = Encrypt {
            unique_identifier: Some(key_id),
            cryptographic_parameters: Some(aes_cbc_params()),
            data: Some(Zeroizing::new(vec![1_u8; 64])),
            i_v_counter_nonce: Some(vec![0_u8; 16]),
            ..Default::default()
        };
        bench_op(
            &mut group,
            client,
            rt,
            transport,
            "encrypt/256",
            Operation::Encrypt(Box::new(enc_req)),
        );
        group.finish();
    } else {
        eprintln!("[bench] HSM AES-CBC not available, skipping");
        bench_ko(format!("{slug}/encrypt/hsm-aes-cbc"));
    }

    // RSA-OAEP-SHA256, RSA-OAEP-SHA1, RSA-PKCS1v15 (encrypt uses the public
    // key). One RSA-2048 key pair is created and reused for all three
    // variants — RSA key generation is comparatively slow, and `CryptoAlgorithm`
    // does not vary by key size, so there is no benefit to separate key pairs.
    if let Some((pub_id, _priv_id)) = try_create_hsm_rsa_kp(rt, client, hsm_prefix, 2048) {
        for (label, params) in [
            ("hsm-rsa-oaep", rsa_oaep_params()),
            ("hsm-rsa-oaep-sha1", rsa_oaep_sha1_params()),
            ("hsm-rsa-pkcs1v15", hsm_rsa_pkcs1v15_encrypt_params()),
        ] {
            let mut group = timed_group(c, format!("{slug}/encrypt/{label}"));
            let enc_req = Encrypt {
                unique_identifier: Some(pub_id.clone()),
                cryptographic_parameters: Some(params),
                data: Some(Zeroizing::new(vec![1_u8; 64])),
                ..Default::default()
            };
            bench_op(
                &mut group,
                client,
                rt,
                transport,
                "encrypt/2048",
                Operation::Encrypt(Box::new(enc_req)),
            );
            group.finish();
        }
    } else {
        eprintln!("[bench] HSM RSA encrypt not available, skipping");
        bench_ko(format!("{slug}/encrypt/hsm-rsa-oaep"));
        bench_ko(format!("{slug}/encrypt/hsm-rsa-oaep-sha1"));
        bench_ko(format!("{slug}/encrypt/hsm-rsa-pkcs1v15"));
    }
}

pub(super) fn bench_hsm_sign_verify(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
    hsm_prefix: &str,
) {
    let slug = transport.slug();
    let message = Zeroizing::new(vec![0x42_u8; 32]);

    // RSA-PSS
    if let Some((_pub_id, priv_id)) = try_create_hsm_rsa_kp(rt, client, hsm_prefix, 2048) {
        let mut group = timed_group(c, format!("{slug}/sign-verify/hsm-rsa-pss"));
        let sign_req = Sign {
            unique_identifier: Some(priv_id),
            cryptographic_parameters: Some(CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
                ..Default::default()
            }),
            data: Some(message.clone()),
            ..Default::default()
        };
        bench_op(
            &mut group,
            client,
            rt,
            transport,
            "sign/2048",
            Operation::Sign(sign_req),
        );
        group.finish();
    } else {
        eprintln!("[bench] HSM RSA-PSS not available, skipping");
        bench_ko(format!("{slug}/sign-verify/hsm-rsa-pss"));
    }

    // RSA PKCS#1 v1.5 hash-and-sign (SigningAlgorithm::Sha1WithRsa/
    // Sha256WithRsa/Sha384WithRsa/Sha512WithRsa on the oracle). One RSA-2048
    // key pair is reused for all four hash variants.
    if let Some((_pub_id, priv_id)) = try_create_hsm_rsa_kp(rt, client, hsm_prefix, 2048) {
        for (label, dsa) in [
            (
                "hsm-rsa-pkcs1v15-sha1",
                DigitalSignatureAlgorithm::SHA1WithRSAEncryption,
            ),
            (
                "hsm-rsa-pkcs1v15-sha256",
                DigitalSignatureAlgorithm::SHA256WithRSAEncryption,
            ),
            (
                "hsm-rsa-pkcs1v15-sha384",
                DigitalSignatureAlgorithm::SHA384WithRSAEncryption,
            ),
            (
                "hsm-rsa-pkcs1v15-sha512",
                DigitalSignatureAlgorithm::SHA512WithRSAEncryption,
            ),
        ] {
            let mut group = timed_group(c, format!("{slug}/sign-verify/{label}"));
            let sign_req = Sign {
                unique_identifier: Some(priv_id.clone()),
                cryptographic_parameters: Some(hsm_rsa_pkcs1v15_sign_params(dsa)),
                data: Some(message.clone()),
                ..Default::default()
            };
            bench_op(
                &mut group,
                client,
                rt,
                transport,
                "sign/2048",
                Operation::Sign(sign_req),
            );
            group.finish();
        }
    } else {
        eprintln!("[bench] HSM RSA PKCS1v15 sign not available, skipping");
        bench_ko(format!("{slug}/sign-verify/hsm-rsa-pkcs1v15-sha1"));
        bench_ko(format!("{slug}/sign-verify/hsm-rsa-pkcs1v15-sha256"));
        bench_ko(format!("{slug}/sign-verify/hsm-rsa-pkcs1v15-sha384"));
        bench_ko(format!("{slug}/sign-verify/hsm-rsa-pkcs1v15-sha512"));
    }

    // ECDSA — prehashed only (SoftHSM2 lacks combined CKM_ECDSA_SHA*, see
    // module docs above).
    for (label, curve) in [
        ("ecdsa-p256", RecommendedCurve::P256),
        ("ecdsa-p384", RecommendedCurve::P384),
    ] {
        let Some((_pub_id, priv_id)) = try_create_hsm_ec_kp(rt, client, hsm_prefix, curve) else {
            eprintln!("[bench] HSM {label} not available, skipping");
            bench_ko(format!("{slug}/sign-verify/hsm-{label}"));
            continue;
        };
        let digest = Sha256::digest(message.as_slice()).to_vec();
        let sign_req = Sign {
            unique_identifier: Some(priv_id),
            cryptographic_parameters: Some(CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                ..Default::default()
            }),
            digested_data: Some(digest),
            ..Default::default()
        };
        let mut group = timed_group(c, format!("{slug}/sign-verify/hsm-{label}"));
        bench_op(
            &mut group,
            client,
            rt,
            transport,
            "sign",
            Operation::Sign(sign_req),
        );
        group.finish();
    }

    // EdDSA (Ed25519/Ed448, non-FIPS) — pure, un-hashed CKM_EDDSA. Verified
    // working end-to-end against a live SoftHSM2 2.6.1 token: the request
    // must set `cryptographic_algorithm` to `Ed25519`/`Ed448` (mirroring
    // `ckms ec sign`'s own request construction — see module docs above) with
    // no `digital_signature_algorithm` and no `digested_data`.
    #[cfg(feature = "non-fips")]
    for (label, curve, algorithm) in [
        (
            "eddsa-ed25519",
            RecommendedCurve::CURVEED25519,
            CryptographicAlgorithm::Ed25519,
        ),
        (
            "eddsa-ed448",
            RecommendedCurve::CURVEED448,
            CryptographicAlgorithm::Ed448,
        ),
    ] {
        let Some((_pub_id, priv_id)) = try_create_hsm_ec_kp(rt, client, hsm_prefix, curve) else {
            eprintln!("[bench] HSM {label} not available, skipping");
            bench_ko(format!("{slug}/sign-verify/hsm-{label}"));
            continue;
        };
        let sign_req = Sign {
            unique_identifier: Some(priv_id),
            cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(algorithm),
                ..Default::default()
            }),
            data: Some(message.clone()),
            ..Default::default()
        };
        let mut group = timed_group(c, format!("{slug}/sign-verify/hsm-{label}"));
        bench_op(
            &mut group,
            client,
            rt,
            transport,
            "sign",
            Operation::Sign(sign_req),
        );
        group.finish();
    }
}

pub(super) fn bench_hsm_key_creation(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
    hsm_prefix: &str,
) {
    let slug = transport.slug();
    let vid = client.config.vendor_id.clone();

    // AES symmetric key
    {
        let mut group = timed_group(c, format!("{slug}/key-creation/hsm-aes-256"));
        group.bench_function("create", |b| {
            b.to_async(rt).iter(|| {
                let vid = vid.clone();
                let hsm_prefix = hsm_prefix.to_owned();
                async move {
                    let uid = hsm_uid(&hsm_prefix, "sym");
                    let req = symmetric_key_create_request(
                        &vid,
                        Some(UniqueIdentifier::TextString(uid)),
                        256,
                        CryptographicAlgorithm::AES,
                        Vec::<String>::new(),
                        false,
                        None,
                    )
                    .expect("HSM sym key request");
                    drop(client.create(req).await);
                }
            });
        });
        group.finish();
    }

    // RSA key pair
    {
        let mut group = timed_group(c, format!("{slug}/key-creation/hsm-rsa-2048"));
        group.bench_function("create", |b| {
            b.to_async(rt).iter(|| {
                let vid = vid.clone();
                let hsm_prefix = hsm_prefix.to_owned();
                async move {
                    let uid = hsm_uid(&hsm_prefix, "rsa");
                    let req = create_rsa_key_pair_request(
                        &vid,
                        Some(UniqueIdentifier::TextString(uid)),
                        Vec::<String>::new(),
                        2048,
                        false,
                        None,
                    )
                    .expect("HSM RSA kp request");
                    drop(client.create_key_pair(req).await);
                }
            });
        });
        group.finish();
    }

    // EC key pair (P-256)
    {
        let mut group = timed_group(c, format!("{slug}/key-creation/hsm-ec-p256"));
        group.bench_function("create", |b| {
            b.to_async(rt).iter(|| {
                let vid = vid.clone();
                let hsm_prefix = hsm_prefix.to_owned();
                async move {
                    let uid = hsm_uid(&hsm_prefix, "ec");
                    let req = create_ec_key_pair_request(
                        &vid,
                        Some(UniqueIdentifier::TextString(uid)),
                        Vec::<String>::new(),
                        RecommendedCurve::P256,
                        false,
                        None,
                    )
                    .expect("HSM EC kp request");
                    drop(client.create_key_pair(req).await);
                }
            });
        });
        group.finish();
    }

    // EdDSA key pairs (Ed25519/Ed448, non-FIPS). Key creation succeeds
    // unconditionally on SoftHSM2 (unlike P-521, see module docs above).
    #[cfg(feature = "non-fips")]
    for (label, curve) in [
        ("hsm-ed25519", RecommendedCurve::CURVEED25519),
        ("hsm-ed448", RecommendedCurve::CURVEED448),
    ] {
        let mut group = timed_group(c, format!("{slug}/key-creation/{label}"));
        group.bench_function("create", |b| {
            b.to_async(rt).iter(|| {
                let vid = vid.clone();
                let hsm_prefix = hsm_prefix.to_owned();
                async move {
                    let uid = hsm_uid(&hsm_prefix, "ed");
                    let req = create_ec_key_pair_request(
                        &vid,
                        Some(UniqueIdentifier::TextString(uid)),
                        Vec::<String>::new(),
                        curve,
                        false,
                        None,
                    )
                    .expect("HSM EdDSA kp request");
                    drop(client.create_key_pair(req).await);
                }
            });
        });
        group.finish();
    }
}

// =============================================================================
// BATCH BENCHMARKS
// =============================================================================

pub(super) fn bench_batch(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
    sanity: bool,
) {
    bench_batch_aes_bulk(c, client, rt, transport, sanity);

    bench_batch_rsa_message(
        c,
        client,
        rt,
        transport,
        "batch/rsa-oaep",
        &rsa_oaep_params(),
        sanity,
    );

    bench_batch_rsa_message(
        c,
        client,
        rt,
        transport,
        "batch/rsa-aes-kwp",
        &rsa_kwp_params(),
        sanity,
    );

    #[cfg(feature = "non-fips")]
    bench_batch_rsa_message(
        c,
        client,
        rt,
        transport,
        "batch/rsa-pkcs1v15",
        &rsa_pkcs15_params(),
        sanity,
    );
}

pub(super) fn bench_batch_aes_bulk(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
    sanity: bool,
) {
    let slug = transport.slug();
    let mut group = timed_group(c, format!("{slug}/batch/aes-gcm"));
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
            bench_op_id(
                &mut group,
                client,
                rt,
                transport,
                BenchmarkId::new(format!("{bits}-bit key encrypt"), &parameter_name),
                Operation::Encrypt(Box::new(req)),
            );
            bench_op_id(
                &mut group,
                client,
                rt,
                transport,
                BenchmarkId::new(format!("{bits}-bit key decrypt"), &parameter_name),
                Operation::Decrypt(Box::new(dec_req)),
            );
        }
    }
    group.finish();
}

pub(super) fn bench_batch_rsa_message(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
    group_name: &str,
    params: &CryptographicParameters,
    sanity: bool,
) {
    let slug = transport.slug();
    let mut group = timed_group(c, format!("{slug}/{group_name}"));

    for bits in [4096] {
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
            bench_ko(format!("{slug}/{group_name}"));
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
            bench_message_id(
                &mut group,
                client,
                rt,
                transport,
                BenchmarkId::new(format!("{bits}-bit key encrypt"), &parameter_name),
                &enc_msg,
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

            bench_message_id(
                &mut group,
                client,
                rt,
                transport,
                BenchmarkId::new(format!("{bits}-bit key decrypt"), &parameter_name),
                &dec_msg,
            );
        }
    }
    group.finish();
}
