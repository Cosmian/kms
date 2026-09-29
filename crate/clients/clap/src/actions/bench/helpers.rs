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
            CryptographicAlgorithm, CryptographicParameters, RecommendedCurve, UniqueIdentifier,
        },
        requests::{
            create_ec_key_pair_request, create_rsa_key_pair_request, symmetric_key_create_request,
        },
    },
};
use tokio::runtime::Runtime;
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
// ENCRYPT BENCHMARKS
// =============================================================================
