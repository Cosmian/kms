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
            create_ec_key_pair_request, create_rsa_key_pair_request, encrypt_request,
            symmetric_key_create_request,
        },
    },
};
use criterion::{BenchmarkId, Criterion, Throughput};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

#[cfg(feature = "non-fips")]
use super::helpers::{
    aes_gcm_siv_params, chacha20_params, rsa_pkcs15_params, try_create_ec_kp_no_fips,
    try_create_sym_key,
};
use super::{
    helpers::{
        aes_gcm_params, aes_xts_params, create_rsa_kp, create_sym_key, rsa_kwp_params,
        rsa_oaep_params, try_create_ec_kp, with_fips_ec_masks, with_fips_rsa_masks,
    },
    types::bench_ko,
};

// =============================================================================
// KMIP WIRE (BINARY TTLV) BENCHMARKS
// =============================================================================

/// Helper: serialize a KMIP request to binary TTLV and bench it via POST /kmip.
#[allow(clippy::needless_pass_by_value)] // body is moved into the closure and cloned per-iteration
fn bench_wire_post(
    group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>,
    client: &KmsClient,
    rt: &Runtime,
    label: impl Into<String>,
    body: Vec<u8>,
) {
    let url = format!("{}/kmip", client.client.server_url);
    let label = label.into();
    group.bench_function(label, |b| {
        b.to_async(rt).iter(|| {
            client
                .client
                .post_bytes(&url, body.clone(), "application/octet-stream")
        });
    });
}

/// Wrap a single KMIP operation in a `RequestMessage` ready for binary TTLV serialization.
/// The KMIP binary wire format requires a `RequestMessage` at the top level; bare operation
/// structs do not have a registered binary tag and will produce an "Unknown tag" error.
pub(super) fn make_wire_request(op: Operation) -> RequestMessage {
    RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem::new(op),
        )],
    }
}

/// Serialize a `RequestMessage` to binary TTLV bytes for the `/kmip` endpoint.
pub(super) fn to_wire_bytes(msg: &RequestMessage) -> Vec<u8> {
    use cosmian_kms_client::cosmian_kmip::ttlv::{KmipFlavor, to_ttlv};
    let ttlv = to_ttlv(msg).expect("TTLV serialization");
    ttlv.to_bytes(KmipFlavor::Kmip2)
        .expect("Binary TTLV serialization")
}

/// Parse a binary TTLV response from `/kmip` and return `true` iff the first
/// batch item carries `ResultStatus = Success`.
///
/// The binary KMIP endpoint **always** returns HTTP 200 even on KMIP-level
/// errors; the actual result is encoded inside the binary TTLV response body.
/// Check whether a binary TTLV response from `/kmip` (octet-stream) indicates success.
///
/// Uses a zero-allocation byte scan instead of full TTLV tree deserialisation.
/// The KMIP binary format encodes `ResultStatus` as a fixed 16-byte TLV:
///
/// ```text
/// 42 00 7F  05  00 00 00 04  00 00 00 00  00 00 00 00
/// ─tag────  ty  ──length──   ───value──   ──padding──
/// ResultSt  Enum  4 bytes     0=Success
/// ```
///
/// Scanning for the 8-byte header and checking the 4-byte value costs ~100 ns with
/// zero heap allocations, compared to ~3–5 µs for the previous full-tree path
/// (`TTLV::from_bytes` + `from_ttlv::<ResponseMessage>`).
pub(super) fn wire_response_ok(bytes: &[u8]) -> bool {
    // Tag=0x42007F (ResultStatus), Type=0x05 (Enumeration), Length=4
    const RESULT_STATUS_HEADER: [u8; 8] = [0x42, 0x00, 0x7F, 0x05, 0x00, 0x00, 0x00, 0x04];
    // Value 0x00000000 == Success (KMIP `ResultStatusEnumeration::Success = 0`).
    bytes
        .windows(8)
        .position(|w| w == RESULT_STATUS_HEADER)
        .and_then(|i| bytes.get(i + 8..i + 12))
        .is_some_and(|v| v == [0x00, 0x00, 0x00, 0x00])
}

/// Test that the server accepts and successfully processes a binary TTLV request.
fn wire_supported(rt: &Runtime, client: &KmsClient, body: &[u8]) -> bool {
    let url = format!("{}/kmip", client.client.server_url);
    rt.block_on(async {
        let Ok(resp) = client
            .client
            .post_bytes(&url, body.to_vec(), "application/octet-stream")
            .await
        else {
            return false;
        };
        wire_response_ok(resp.bytes())
    })
}

/// AES-XTS wire benchmark.
/// XTS requires double-length keys (256-bit → AES-128-XTS, 512-bit → AES-256-XTS) and
/// a 16-byte sector tweak in `i_v_counter_nonce`.  Labels match the ttlv-json convention:
/// "128"/"256" = effective cipher width, not the raw key size.
fn bench_wire_encrypt_aes_xts(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let params = aes_xts_params();
    let mut group = c.benchmark_group("ttlv-bytes/encrypt/aes-xts");
    for (label, key_bits) in [("128", 256_usize), ("256", 512)] {
        let key_id = create_sym_key(rt, client, key_bits, CryptographicAlgorithm::AES);
        let enc_req = Encrypt {
            unique_identifier: Some(key_id.clone()),
            cryptographic_parameters: Some(params.clone()),
            data: Some(Zeroizing::new(vec![1_u8; 64])),
            i_v_counter_nonce: Some(vec![0_u8; 16]),
            ..Default::default()
        };
        let enc_body = to_wire_bytes(&make_wire_request(Operation::Encrypt(Box::new(
            enc_req.clone(),
        ))));
        if !wire_supported(rt, client, &enc_body) {
            eprintln!("[bench] Wire AES-XTS-{label} not supported, skipping");
            bench_ko("ttlv-bytes/encrypt/aes-xts");
            continue;
        }
        bench_wire_post(&mut group, client, rt, format!("encrypt/{label}"), enc_body);
        let enc_resp = rt
            .block_on(client.encrypt(enc_req))
            .expect("pre-encrypt for wire AES-XTS decrypt");
        let dec_req = Decrypt {
            unique_identifier: Some(key_id),
            cryptographic_parameters: Some(params.clone()),
            data: Some(enc_resp.data.map_or_else(Vec::new, |z| z.to_vec())),
            i_v_counter_nonce: enc_resp.i_v_counter_nonce,
            ..Default::default()
        };
        let dec_body = to_wire_bytes(&make_wire_request(Operation::Decrypt(Box::new(dec_req))));
        bench_wire_post(&mut group, client, rt, format!("decrypt/{label}"), dec_body);
    }
    group.finish();
}

/// Symmetric wire encrypt/decrypt benchmark for AES-family ciphers (GCM, GCM-SIV).
/// Runs encrypt and decrypt for each key size in `key_sizes`.
fn bench_wire_encrypt_aes_sym(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    group_name: &str,
    algo: CryptographicAlgorithm,
    params: &CryptographicParameters,
    key_sizes: &[usize],
) {
    let mut group = c.benchmark_group(group_name);
    for &bits in key_sizes {
        let key_id = create_sym_key(rt, client, bits, algo);
        let enc_req = Encrypt {
            unique_identifier: Some(key_id.clone()),
            cryptographic_parameters: Some(params.clone()),
            data: Some(Zeroizing::new(vec![1_u8; 64])),
            ..Default::default()
        };
        let enc_body = to_wire_bytes(&make_wire_request(Operation::Encrypt(Box::new(
            enc_req.clone(),
        ))));
        if !wire_supported(rt, client, &enc_body) {
            eprintln!("[bench] Wire {group_name}/{bits} not supported, skipping");
            bench_ko(group_name);
            continue;
        }
        bench_wire_post(&mut group, client, rt, format!("encrypt/{bits}"), enc_body);
        let enc_resp = rt
            .block_on(client.encrypt(enc_req))
            .expect("pre-encrypt for wire decrypt");
        let dec_req = Decrypt {
            unique_identifier: Some(key_id),
            cryptographic_parameters: Some(params.clone()),
            data: Some(enc_resp.data.map_or_else(Vec::new, |z| z.to_vec())),
            i_v_counter_nonce: enc_resp.i_v_counter_nonce,
            authenticated_encryption_tag: enc_resp.authenticated_encryption_tag,
            ..Default::default()
        };
        let dec_body = to_wire_bytes(&make_wire_request(Operation::Decrypt(Box::new(dec_req))));
        bench_wire_post(&mut group, client, rt, format!("decrypt/{bits}"), dec_body);
    }
    group.finish();
}

/// ChaCha20-Poly1305 wire benchmark (256-bit key). Non-FIPS only.
#[cfg(feature = "non-fips")]
fn bench_wire_encrypt_chacha20(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let Some(key_id) = try_create_sym_key(rt, client, 256, CryptographicAlgorithm::ChaCha20) else {
        eprintln!("[bench] Wire ChaCha20 not supported, skipping");
        bench_ko("ttlv-bytes/encrypt/chacha20-poly1305");
        return;
    };
    let params = chacha20_params();
    let enc_req = Encrypt {
        unique_identifier: Some(key_id.clone()),
        cryptographic_parameters: Some(params.clone()),
        data: Some(Zeroizing::new(vec![1_u8; 64])),
        ..Default::default()
    };
    let enc_body = to_wire_bytes(&make_wire_request(Operation::Encrypt(Box::new(
        enc_req.clone(),
    ))));
    if !wire_supported(rt, client, &enc_body) {
        eprintln!("[bench] Wire ChaCha20 not supported, skipping");
        bench_ko("ttlv-bytes/encrypt/chacha20-poly1305");
        return;
    }
    let mut group = c.benchmark_group("ttlv-bytes/encrypt/chacha20-poly1305");
    bench_wire_post(&mut group, client, rt, "encrypt/256", enc_body);
    let enc_resp = rt
        .block_on(client.encrypt(enc_req))
        .expect("pre-encrypt for wire ChaCha20 decrypt");
    let dec_req = Decrypt {
        unique_identifier: Some(key_id),
        cryptographic_parameters: Some(params),
        data: Some(enc_resp.data.map_or_else(Vec::new, |z| z.to_vec())),
        i_v_counter_nonce: enc_resp.i_v_counter_nonce,
        authenticated_encryption_tag: enc_resp.authenticated_encryption_tag,
        ..Default::default()
    };
    let dec_body = to_wire_bytes(&make_wire_request(Operation::Decrypt(Box::new(dec_req))));
    bench_wire_post(&mut group, client, rt, "decrypt/256", dec_body);
    group.finish();
}

/// RSA wire encrypt/decrypt family (OAEP, KWP, PKCS#1v1.5).
fn bench_wire_encrypt_rsa_family(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    label: &str,
    params: &CryptographicParameters,
    key_sizes: &[usize],
) {
    let group_name = format!("ttlv-bytes/encrypt/{label}");
    let mut group = c.benchmark_group(&group_name);
    for &bits in key_sizes {
        let (pub_id, priv_id) = create_rsa_kp(rt, client, bits);
        let pub_str = pub_id.to_string();
        let enc_req = encrypt_request(
            &pub_str,
            None,
            vec![0x42_u8; 32],
            None,
            None,
            Some(params.clone()),
        )
        .expect("RSA encrypt request");
        let enc_body = to_wire_bytes(&make_wire_request(Operation::Encrypt(Box::new(
            enc_req.clone(),
        ))));
        if !wire_supported(rt, client, &enc_body) {
            eprintln!("[bench] Wire {label}-{bits} not supported, skipping");
            bench_ko(&group_name);
            continue;
        }
        bench_wire_post(&mut group, client, rt, format!("encrypt/{bits}"), enc_body);
        let enc_resp = rt
            .block_on(client.encrypt(enc_req))
            .expect("pre-encrypt for wire RSA decrypt");
        let ct = enc_resp.data.map_or_else(Vec::new, |z| z.to_vec());
        let dec_req = Decrypt {
            unique_identifier: Some(priv_id),
            cryptographic_parameters: Some(params.clone()),
            data: Some(ct),
            ..Default::default()
        };
        let dec_body = to_wire_bytes(&make_wire_request(Operation::Decrypt(Box::new(dec_req))));
        bench_wire_post(&mut group, client, rt, format!("decrypt/{bits}"), dec_body);
    }
    group.finish();
}

pub(super) fn bench_wire_encrypt(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    bench_wire_encrypt_aes_sym(
        c,
        client,
        rt,
        "ttlv-bytes/encrypt/aes-gcm",
        CryptographicAlgorithm::AES,
        &aes_gcm_params(),
        &[128, 192, 256],
    );
    bench_wire_encrypt_aes_xts(c, client, rt);
    #[cfg(feature = "non-fips")]
    bench_wire_encrypt_aes_sym(
        c,
        client,
        rt,
        "ttlv-bytes/encrypt/aes-gcm-siv",
        CryptographicAlgorithm::AES,
        &aes_gcm_siv_params(),
        &[128, 256],
    );
    #[cfg(feature = "non-fips")]
    bench_wire_encrypt_chacha20(c, client, rt);
    bench_wire_encrypt_rsa_family(
        c,
        client,
        rt,
        "rsa-oaep",
        &rsa_oaep_params(),
        &[2048, 3072, 4096],
    );
    bench_wire_encrypt_rsa_family(
        c,
        client,
        rt,
        "rsa-aes-kwp",
        &rsa_kwp_params(),
        &[2048, 3072, 4096],
    );
    #[cfg(feature = "non-fips")]
    bench_wire_encrypt_rsa_family(
        c,
        client,
        rt,
        "rsa-pkcs1v15",
        &rsa_pkcs15_params(),
        &[2048, 3072, 4096],
    );
    #[cfg(feature = "non-fips")]
    bench_wire_encrypt_ecies(c, client, rt);
    #[cfg(feature = "non-fips")]
    bench_wire_encrypt_salsa(c, client, rt);
    #[cfg(feature = "non-fips")]
    bench_wire_encrypt_covercrypt(c, client, rt);
}

/// Binary-TTLV wire benchmark for ECIES (EC public-key encryption) on P-256/384/521.
#[cfg(feature = "non-fips")]
fn bench_wire_encrypt_ecies(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let mut group = c.benchmark_group("ttlv-bytes/encrypt/ecies");
    for (label, curve) in [
        ("P-256", RecommendedCurve::P256),
        ("P-384", RecommendedCurve::P384),
        ("P-521", RecommendedCurve::P521),
    ] {
        let Some((pub_id, priv_id)) = try_create_ec_kp_no_fips(rt, client, curve) else {
            eprintln!("[bench] Wire ECIES {label} not supported, skipping");
            bench_ko("ttlv-bytes/encrypt/ecies");
            continue;
        };
        let enc_req = encrypt_request(
            &pub_id.to_string(),
            None,
            vec![0x42_u8; 64],
            None,
            None,
            None,
        )
        .expect("ECIES encrypt request");
        let enc_body = to_wire_bytes(&make_wire_request(Operation::Encrypt(Box::new(
            enc_req.clone(),
        ))));
        if !wire_supported(rt, client, &enc_body) {
            eprintln!("[bench] Wire ECIES {label} not supported, skipping");
            bench_ko("ttlv-bytes/encrypt/ecies");
            continue;
        }
        bench_wire_post(&mut group, client, rt, format!("encrypt/{label}"), enc_body);
        let enc_resp = rt
            .block_on(client.encrypt(enc_req))
            .expect("pre-encrypt for wire ECIES decrypt");
        let ct = enc_resp.data.map_or_else(Vec::new, |z| z.to_vec());
        let dec_req = Decrypt {
            unique_identifier: Some(priv_id),
            data: Some(ct),
            ..Default::default()
        };
        let dec_body = to_wire_bytes(&make_wire_request(Operation::Decrypt(Box::new(dec_req))));
        bench_wire_post(&mut group, client, rt, format!("decrypt/{label}"), dec_body);
    }
    group.finish();
}

/// Binary-TTLV wire benchmark for Salsa Sealed Box (X25519 / ChaCha20-Poly1305).
#[cfg(feature = "non-fips")]
fn bench_wire_encrypt_salsa(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let Some((pub_id, priv_id)) =
        try_create_ec_kp_no_fips(rt, client, RecommendedCurve::CURVE25519)
    else {
        eprintln!("[bench] Wire Salsa Sealed Box (X25519) not supported, skipping");
        bench_ko("ttlv-bytes/encrypt/salsa-sealed-box");
        return;
    };
    let enc_req = encrypt_request(
        &pub_id.to_string(),
        None,
        vec![0x42_u8; 64],
        None,
        None,
        None,
    )
    .expect("Salsa encrypt request");
    let enc_body = to_wire_bytes(&make_wire_request(Operation::Encrypt(Box::new(
        enc_req.clone(),
    ))));
    if !wire_supported(rt, client, &enc_body) {
        eprintln!("[bench] Wire Salsa Sealed Box not supported, skipping");
        bench_ko("ttlv-bytes/encrypt/salsa-sealed-box");
        return;
    }
    let mut group = c.benchmark_group("ttlv-bytes/encrypt/salsa-sealed-box");
    bench_wire_post(&mut group, client, rt, "encrypt", enc_body);
    let enc_resp = rt
        .block_on(client.encrypt(enc_req))
        .expect("pre-encrypt for wire Salsa decrypt");
    let ct = enc_resp.data.map_or_else(Vec::new, |z| z.to_vec());
    let dec_req = Decrypt {
        unique_identifier: Some(priv_id),
        data: Some(ct),
        ..Default::default()
    };
    let dec_body = to_wire_bytes(&make_wire_request(Operation::Decrypt(Box::new(dec_req))));
    bench_wire_post(&mut group, client, rt, "decrypt", dec_body);
    group.finish();
}

/// Binary-TTLV wire benchmark for Covercrypt attribute-based hybrid encryption.
#[cfg(feature = "non-fips")]
fn bench_wire_encrypt_covercrypt(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
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
            eprintln!("[bench] Wire Covercrypt not supported: {e}, skipping");
            bench_ko("ttlv-bytes/encrypt/covercrypt");
            return;
        }
    };

    let enc_req = encrypt_request(
        &pub_id.to_string(),
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
    let enc_body = to_wire_bytes(&make_wire_request(Operation::Encrypt(Box::new(
        enc_req.clone(),
    ))));
    if !wire_supported(rt, client, &enc_body) {
        eprintln!("[bench] Wire Covercrypt encrypt not supported, skipping");
        bench_ko("ttlv-bytes/encrypt/covercrypt");
        return;
    }
    let mut group = c.benchmark_group("ttlv-bytes/encrypt/covercrypt");
    bench_wire_post(&mut group, client, rt, "encrypt", enc_body);
    let enc_resp = rt
        .block_on(client.encrypt(enc_req))
        .expect("pre-encrypt for wire Covercrypt decrypt");
    let ct = enc_resp.data.map_or_else(Vec::new, |z| z.to_vec());
    let dec_req = Decrypt {
        unique_identifier: Some(usk_id),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Default::default()
        }),
        data: Some(ct),
        ..Default::default()
    };
    let dec_body = to_wire_bytes(&make_wire_request(Operation::Decrypt(Box::new(dec_req))));
    bench_wire_post(&mut group, client, rt, "decrypt", dec_body);
    group.finish();
}

pub(super) fn bench_wire_sign_verify(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    // ── ECDSA / EdDSA via try_create_ec_kp ───────────────────────────────────
    // Each entry: (label, curve, sign_algo)
    // FIPS-approved curves
    for (label, curve, sign_algo) in [
        (
            "ecdsa-p256",
            RecommendedCurve::P256,
            Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
        ),
        (
            "ecdsa-p384",
            RecommendedCurve::P384,
            Some(DigitalSignatureAlgorithm::ECDSAWithSHA384),
        ),
        (
            "ecdsa-p521",
            RecommendedCurve::P521,
            Some(DigitalSignatureAlgorithm::ECDSAWithSHA512),
        ),
    ] {
        bench_wire_ec_sign(c, client, rt, label, curve, sign_algo);
    }

    // Non-FIPS EC / EdDSA
    #[cfg(feature = "non-fips")]
    {
        use super::helpers::try_create_ec_kp_no_fips;
        for (label, curve, sign_algo) in [
            (
                "ecdsa-secp256k1",
                RecommendedCurve::SECP256K1,
                Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
            ),
            ("eddsa-ed25519", RecommendedCurve::CURVEED25519, None),
            ("eddsa-ed448", RecommendedCurve::CURVEED448, None),
        ] {
            if let Some((pub_id, priv_id)) = try_create_ec_kp_no_fips(rt, client, curve) {
                bench_wire_ec_sign_ids(c, client, rt, label, pub_id, priv_id, sign_algo);
            } else {
                bench_ko(format!("ttlv-bytes/sign-verify/{label}"));
            }
        }
    }

    // ── RSA-PSS (2048, 3072, 4096) ────────────────────────────────────────────
    let sign_params = Some(CryptographicParameters {
        digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
        ..Default::default()
    });
    let message = Zeroizing::new(vec![0x42_u8; 32]);
    let mut group = c.benchmark_group("ttlv-bytes/sign-verify/rsa-pss");
    for bits in [2048_usize, 3072, 4096] {
        let (pub_id, priv_id) = create_rsa_kp(rt, client, bits);
        let sign_req = Sign {
            unique_identifier: Some(priv_id),
            cryptographic_parameters: sign_params.clone(),
            data: Some(message.clone()),
            ..Default::default()
        };
        let sign_body = to_wire_bytes(&make_wire_request(Operation::Sign(sign_req.clone())));
        if wire_supported(rt, client, &sign_body) {
            bench_wire_post(&mut group, client, rt, format!("sign/{bits}"), sign_body);
            let sign_resp = rt
                .block_on(client.sign(sign_req))
                .expect("pre-sign for wire RSA verify");
            let verify_req = SignatureVerify {
                unique_identifier: Some(pub_id),
                cryptographic_parameters: sign_params.clone(),
                data: Some(message.to_vec()),
                signature_data: Some(sign_resp.signature_data.unwrap_or_default()),
                ..Default::default()
            };
            let verify_body =
                to_wire_bytes(&make_wire_request(Operation::SignatureVerify(verify_req)));
            bench_wire_post(
                &mut group,
                client,
                rt,
                format!("verify/{bits}"),
                verify_body,
            );
        } else {
            bench_ko("ttlv-bytes/sign-verify/rsa-pss");
        }
    }
    group.finish();
}

/// Benchmark wire sign/verify for an ECDSA/EdDSA curve (creates the key pair internally).
fn bench_wire_ec_sign(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    label: &str,
    curve: RecommendedCurve,
    sign_algo: Option<DigitalSignatureAlgorithm>,
) {
    let Some((pub_id, priv_id)) = try_create_ec_kp(rt, client, curve) else {
        bench_ko(format!("ttlv-bytes/sign-verify/{label}"));
        return;
    };
    bench_wire_ec_sign_ids(c, client, rt, label, pub_id, priv_id, sign_algo);
}

/// Benchmark wire sign/verify given pre-created key UIDs.
fn bench_wire_ec_sign_ids(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    label: &str,
    pub_id: UniqueIdentifier,
    priv_id: UniqueIdentifier,
    sign_algo: Option<DigitalSignatureAlgorithm>,
) {
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
    let sign_body = to_wire_bytes(&make_wire_request(Operation::Sign(sign_req.clone())));
    if !wire_supported(rt, client, &sign_body) {
        bench_ko(format!("ttlv-bytes/sign-verify/{label}"));
        return;
    }
    let mut group = c.benchmark_group(format!("ttlv-bytes/sign-verify/{label}"));
    bench_wire_post(&mut group, client, rt, "sign", sign_body);

    let sign_resp = rt
        .block_on(client.sign(sign_req))
        .expect("pre-sign for wire verify");
    let verify_req = SignatureVerify {
        unique_identifier: Some(pub_id),
        cryptographic_parameters: sign_params,
        data: Some(message.to_vec()),
        signature_data: Some(sign_resp.signature_data.unwrap_or_default()),
        ..Default::default()
    };
    let verify_body = to_wire_bytes(&make_wire_request(Operation::SignatureVerify(verify_req)));
    bench_wire_post(&mut group, client, rt, "verify", verify_body);
    group.finish();
}

pub(super) fn bench_wire_key_creation(c: &mut Criterion, client: &KmsClient, rt: &Runtime) {
    let vid = client.config.vendor_id.clone();
    let mut group = c.benchmark_group("ttlv-bytes/key-creation");

    // AES-128
    let sym_req = symmetric_key_create_request(
        &vid,
        None,
        128,
        CryptographicAlgorithm::AES,
        ["bench"],
        false,
        None,
    )
    .expect("sym key request");
    let sym_body = to_wire_bytes(&make_wire_request(Operation::Create(sym_req)));
    if wire_supported(rt, client, &sym_body) {
        bench_wire_post(&mut group, client, rt, "aes-128", sym_body);
    } else {
        bench_ko("ttlv-bytes/key-creation");
    }

    // AES-256
    let sym_req = symmetric_key_create_request(
        &vid,
        None,
        256,
        CryptographicAlgorithm::AES,
        ["bench"],
        false,
        None,
    )
    .expect("sym key request");
    let sym_body = to_wire_bytes(&make_wire_request(Operation::Create(sym_req)));
    if wire_supported(rt, client, &sym_body) {
        bench_wire_post(&mut group, client, rt, "aes-256", sym_body);
    } else {
        bench_ko("ttlv-bytes/key-creation");
    }

    // EC P-256
    if let Ok(ec_req) =
        create_ec_key_pair_request(&vid, None, ["bench"], RecommendedCurve::P256, false, None)
    {
        let ec_req = with_fips_ec_masks(ec_req);
        let ec_body = to_wire_bytes(&make_wire_request(Operation::CreateKeyPair(Box::new(
            ec_req,
        ))));
        if wire_supported(rt, client, &ec_body) {
            bench_wire_post(&mut group, client, rt, "ec-p256", ec_body);
        } else {
            bench_ko("ttlv-bytes/key-creation");
        }
    }

    // RSA-2048
    let rsa_req = with_fips_rsa_masks(
        create_rsa_key_pair_request(&vid, None, ["bench"], 2048, false, None).expect("RSA kp req"),
    );
    let rsa_body = to_wire_bytes(&make_wire_request(Operation::CreateKeyPair(Box::new(
        rsa_req,
    ))));
    if wire_supported(rt, client, &rsa_body) {
        bench_wire_post(&mut group, client, rt, "rsa-2048", rsa_body);
    } else {
        bench_ko("ttlv-bytes/key-creation");
    }

    group.finish();
}

pub(super) fn bench_wire_batch(c: &mut Criterion, client: &KmsClient, rt: &Runtime, sanity: bool) {
    let mut group = c.benchmark_group("ttlv-bytes/batch/aes-gcm");
    let params = aes_gcm_params();
    let key_id = create_sym_key(rt, client, 128, CryptographicAlgorithm::AES);
    let key_str = key_id.to_string();

    let batch_sizes: &[usize] = if sanity { &[1] } else { &[1, 10, 50, 100] };
    for &n in batch_sizes {
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
        let body = to_wire_bytes(&make_wire_request(Operation::Encrypt(Box::new(req))));

        if !wire_supported(rt, client, &body) {
            bench_ko("ttlv-bytes/batch/aes-gcm");
            break;
        }

        group.throughput(Throughput::Elements(n as u64));
        let url = format!("{}/kmip", client.client.server_url);
        group.bench_with_input(BenchmarkId::new("encrypt", &parameter_name), &n, |b, _| {
            b.to_async(rt).iter(|| {
                client
                    .client
                    .post_bytes(&url, body.clone(), "application/octet-stream")
            });
        });
    }
    group.finish();
}

// =============================================================================
