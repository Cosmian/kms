use std::time::{Duration, Instant};

#[cfg(feature = "non-fips")]
use cosmian_kms_client::kmip_2_1::requests::create_pqc_key_pair_request;
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm, PaddingMethod},
    kmip_2_1::{
        extra::fips::{
            FIPS_PRIVATE_ECC_MASK_SIGN_ECDH, FIPS_PRIVATE_RSA_MASK, FIPS_PUBLIC_ECC_MASK_SIGN_ECDH,
            FIPS_PUBLIC_RSA_MASK,
        },
        kmip_operations::{CreateKeyPair, Destroy, Encrypt},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
            RecommendedCurve, UniqueIdentifier,
        },
        requests::{
            create_ec_key_pair_request, create_rsa_key_pair_request, symmetric_key_create_request,
        },
    },
};
use tokio::runtime::Runtime;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Send lightweight requests to the KMS server for `warmup_secs` seconds to
/// warm up HTTP connection pools, TLS sessions, and server-side caches.
pub(super) fn run_warmup(rt: &Runtime, client: &KmsClient, warmup_secs: u64) {
    if warmup_secs == 0 {
        return;
    }
    let warmup_duration = Duration::from_secs(warmup_secs);
    eprintln!("[bench] Warmup: {warmup_secs}s...");
    let start = Instant::now();

    // Create a temporary AES-128 key for warmup
    let key_id = create_sym_key(rt, client, 128, CryptographicAlgorithm::AES);
    let params = aes_gcm_params();
    let data = Zeroizing::new(vec![0xAB_u8; 64]);

    let mut count: u64 = 0;
    while start.elapsed() < warmup_duration {
        let enc_req = Encrypt {
            unique_identifier: Some(key_id.clone()),
            cryptographic_parameters: Some(params.clone()),
            data: Some(data.clone()),
            ..Default::default()
        };
        drop(rt.block_on(client.encrypt(enc_req)));
        count += 1;
    }

    // Clean up the warmup key
    drop(rt.block_on(client.destroy(Destroy {
        unique_identifier: Some(key_id),
        ..Default::default()
    })));

    eprintln!(
        "[bench] Warmup complete: {count} requests in {:.1}s",
        start.elapsed().as_secs_f64()
    );
}

// =============================================================================
// FIPS MASK HELPERS
// =============================================================================

pub(super) fn with_fips_rsa_masks(mut req: CreateKeyPair) -> CreateKeyPair {
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

pub(super) fn with_fips_ec_masks(mut req: CreateKeyPair) -> CreateKeyPair {
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

pub(super) fn aes_gcm_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(BlockCipherMode::GCM),
        ..Default::default()
    }
}

/// AES-CBC parameters. Used by the HSM-resident encrypt bench (`--hsm`) —
/// the oracle supports `CryptoAlgorithm::AesCbc` alongside `AesGcm`, unlike
/// the software `bench_encrypt` group, which does not have a dedicated
/// AES-CBC category (only GCM/GCM-SIV/XTS/ChaCha20).
pub(super) fn aes_cbc_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(BlockCipherMode::CBC),
        ..Default::default()
    }
}

#[cfg(feature = "non-fips")]
pub(super) fn chacha20_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::ChaCha20),
        ..Default::default()
    }
}

pub(super) fn rsa_oaep_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        padding_method: Some(PaddingMethod::OAEP),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        ..Default::default()
    }
}

/// RSA-OAEP with SHA-1 (`CryptoAlgorithm::RsaOaepSha1` on the HSM oracle).
/// Distinct from `rsa_oaep_params()` (SHA-256): the oracle selects the OAEP
/// hash/MGF1 variant from `hashing_algorithm`, so both are separate
/// HSM-delegated operations worth benchmarking individually. Not gated by
/// `non-fips`: confirmed supported by the oracle unconditionally (see
/// `test_data/vectors/hsm/resident_rsa2048_encrypt_oaep_sha1`).
pub(super) fn rsa_oaep_sha1_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        padding_method: Some(PaddingMethod::OAEP),
        hashing_algorithm: Some(HashingAlgorithm::SHA1),
        ..Default::default()
    }
}

/// RSA PKCS#1 v1.5 encrypt (`CryptoAlgorithm::RsaPkcsV15` on the HSM oracle).
/// Not gated by `non-fips` like the software `rsa_pkcs15_params()` below: the
/// HSM oracle exposes `CKM_RSA_PKCS` encrypt unconditionally (see
/// `test_data/vectors/hsm/resident_rsa2048_encrypt_pkcs1v15`), independent of
/// the software crypto module's own FIPS restriction on this legacy padding.
pub(super) fn hsm_rsa_pkcs1v15_encrypt_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        padding_method: Some(PaddingMethod::PKCS1v15),
        ..Default::default()
    }
}

/// RSA PKCS#1 v1.5 sign, hash-and-sign in one HSM call
/// (`SigningAlgorithm::Sha1WithRsa`/`Sha256WithRsa`/`Sha384WithRsa`/
/// `Sha512WithRsa` on the oracle, selected via the explicit
/// `DigitalSignatureAlgorithm::SHA*WithRSAEncryption`, non-digested input —
/// see `test_data/vectors/hsm/resident_rsa2048_sign_sha{1,256,384,512}`).
/// Not gated by `non-fips`: confirmed supported unconditionally by the oracle.
pub(super) fn hsm_rsa_pkcs1v15_sign_params(
    dsa: DigitalSignatureAlgorithm,
) -> CryptographicParameters {
    CryptographicParameters {
        digital_signature_algorithm: Some(dsa),
        ..Default::default()
    }
}

pub(super) fn rsa_kwp_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        ..Default::default()
    }
}

#[cfg(feature = "non-fips")]
pub(super) fn rsa_pkcs15_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        padding_method: Some(PaddingMethod::PKCS1v15),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        ..Default::default()
    }
}

pub(super) fn aes_xts_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(BlockCipherMode::XTS),
        ..Default::default()
    }
}

#[cfg(feature = "non-fips")]
pub(super) fn aes_gcm_siv_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(BlockCipherMode::GCMSIV),
        ..Default::default()
    }
}

#[cfg(feature = "non-fips")]
pub(super) fn kem_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::ConfigurableKEM),
        ..Default::default()
    }
}

// =============================================================================
// KEY CREATION HELPERS
// =============================================================================

pub(super) fn create_sym_key(
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
pub(super) fn try_create_sym_key(
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

pub(super) fn create_rsa_kp(
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

pub(super) fn try_create_ec_kp(
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
pub(super) fn try_create_ec_kp_no_fips(
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
pub(super) fn try_create_pqc_kp(
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
// HSM-RESIDENT KEY HELPERS
// =============================================================================
//
// Creating a key whose `unique_identifier` carries an `hsm::<slot>::` prefix
// (the legacy flat single-HSM UID format — see
// `crate/server/src/config/params/server_params.rs::build_hsm_instances`)
// causes the server to generate the key material directly ON the HSM (via the
// registered `HsmStore`/`CryptoOracle`), and any subsequent Encrypt/Sign
// against that key executes on the HSM itself (PKCS#11) instead of in KMS
// software. See `crate/interfaces/src/hsm/hsm_store.rs` and
// `crate/server/src/core/operations/key_ops/crypto_op.rs` ("Oracle routing").
//
// `hsm_prefix` is expected to already contain `hsm::<slot>` (built by the
// `--hsm-slot` CLI flag); a random UUID suffix is appended here to keep
// unique identifiers distinct across runs.

/// Build a fresh HSM-resident unique identifier: `<hsm_prefix>::<label>_<uuid>`.
pub(super) fn hsm_uid(hsm_prefix: &str, label: &str) -> String {
    format!("{hsm_prefix}::{label}_{}", Uuid::new_v4())
}

/// Create an HSM-resident symmetric key (e.g. AES). Key generation happens on
/// the HSM itself via `HsmKeyAlgorithm::AES`.
pub(super) fn try_create_hsm_sym_key(
    rt: &Runtime,
    client: &KmsClient,
    hsm_prefix: &str,
    bits: usize,
    algo: CryptographicAlgorithm,
) -> Option<UniqueIdentifier> {
    rt.block_on(async {
        let uid = hsm_uid(hsm_prefix, "sym");
        let req = symmetric_key_create_request(
            &client.config.vendor_id,
            Some(UniqueIdentifier::TextString(uid)),
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

/// Create an HSM-resident RSA key pair. Key generation happens on the HSM
/// itself via `HsmKeypairAlgorithm::RSA`.
pub(super) fn try_create_hsm_rsa_kp(
    rt: &Runtime,
    client: &KmsClient,
    hsm_prefix: &str,
    bits: usize,
) -> Option<(UniqueIdentifier, UniqueIdentifier)> {
    rt.block_on(async {
        let uid = hsm_uid(hsm_prefix, "rsa");
        let req = create_rsa_key_pair_request(
            &client.config.vendor_id,
            Some(UniqueIdentifier::TextString(uid)),
            ["bench"],
            bits,
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

/// Create an HSM-resident EC/EdDSA key pair for the given curve. Key
/// generation happens on the HSM itself via `HsmKeypairAlgorithm::EC` (NIST
/// curves) or `HsmKeypairAlgorithm::Ed25519`/`Ed448` (non-FIPS only).
///
/// Curve support on the HSM oracle: P-224/256/384/521 (FIPS), Ed25519/Ed448
/// (non-FIPS). Note: as of this writing, Ed25519/Ed448 keys can be created on
/// the HSM but `Sign` against them fails on `SoftHSM2` (`CKR_MECHANISM_INVALID`)
/// — this helper is still useful for HSM key-*creation* timing, but callers
/// must not use its output for HSM sign benchmarks.
pub(super) fn try_create_hsm_ec_kp(
    rt: &Runtime,
    client: &KmsClient,
    hsm_prefix: &str,
    curve: RecommendedCurve,
) -> Option<(UniqueIdentifier, UniqueIdentifier)> {
    rt.block_on(async {
        let uid = hsm_uid(hsm_prefix, "ec");
        let req = create_ec_key_pair_request(
            &client.config.vendor_id,
            Some(UniqueIdentifier::TextString(uid)),
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

// =============================================================================
// ENCRYPT BENCHMARKS
// =============================================================================
