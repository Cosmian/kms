//! Provisions the KMS objects used by the benchmark hot loops.
//!
//! Reuses the KMIP request builders exposed through the client crate's reexport
//! chain, so the created objects are tagged/typed exactly the way the PKCS#11
//! provider's backend expects (`crate/kmip/src/kmip_2_1/requests/{create,create_key_pair}.rs`
//! already insert the system tags the provider's `find_all_*` functions look for).

use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::extra::VENDOR_ID_COSMIAN,
    kmip_2_1::{
        kmip_types::{CryptographicAlgorithm, RecommendedCurve, UniqueIdentifier},
        requests::{
            create_ec_key_pair_request, create_rsa_key_pair_request, symmetric_key_create_request,
        },
    },
};
use uuid::Uuid;

use super::error::{BenchError, BenchResult};

/// Object identifiers provisioned for one benchmark process.
pub(crate) struct BenchSetup {
    pub(crate) ed25519_private_key_id: Option<UniqueIdentifier>,
}

/// Bits of key material for the AES key used by the `encrypt-decrypt` benchmark.
const AES_KEY_BITS: usize = 128;
/// Bits of key material for the RSA key pair used by the `sign`/`verify` benchmark.
const RSA_KEY_BITS: usize = 2048;

/// Tag applied to every object created for this benchmark, so runs are easy to spot
/// and clean up if a temporary server is ever reused.
const BENCH_TAG: &str = "pkcs11-bench";

/// Default value of `COSMIAN_PKCS11_DISK_ENCRYPTION_TAG`, matching
/// `crate/clients/pkcs11/provider/src/backend.rs`'s own default. The provider's
/// `find_all_private_keys` only returns private keys tagged with this value (AND'd
/// with its own system tag), so the benchmark's RSA and Ed25519 keys must both carry
/// it.
const DISK_ENCRYPTION_TAG: &str = "disk-encryption";

fn benchmark_key_uid(delegated: bool, hsm_slot: usize, name: &str) -> Option<UniqueIdentifier> {
    delegated.then(|| {
        UniqueIdentifier::TextString(format!("hsm::{hsm_slot}::{name}_{}", Uuid::new_v4()))
    })
}

/// Creates one AES secret key, one RSA key pair, one EC P-256 key pair, and
/// (opt-in) one Ed25519 and/or one secp256k1 key pair in the KMS pointed at by
/// `client`. With `delegated`, all keys are created in `hsm_slot`.
pub(crate) async fn provision_bench_keys(
    client: &KmsClient,
    provision_ed25519: bool,
    provision_secp256k1: bool,
    delegated: bool,
    hsm_slot: usize,
) -> BenchResult<BenchSetup> {
    let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
        .unwrap_or_else(|_| DISK_ENCRYPTION_TAG.to_owned());

    let create_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        benchmark_key_uid(delegated, hsm_slot, "pkcs11_sym"),
        AES_KEY_BITS,
        CryptographicAlgorithm::AES,
        [BENCH_TAG],
        false,
        None,
    )
    .map_err(|e| BenchError::Kmip(e.to_string()))?;
    client.create(create_request).await?;

    let create_key_pair_request = create_rsa_key_pair_request(
        VENDOR_ID_COSMIAN,
        benchmark_key_uid(delegated, hsm_slot, "pkcs11_rsa"),
        [BENCH_TAG, disk_encryption_tag.as_str()],
        RSA_KEY_BITS,
        false,
        None,
    )
    .map_err(|e| BenchError::Kmip(e.to_string()))?;
    client.create_key_pair(create_key_pair_request).await?;

    // EC P-256 is FIPS-approved (unlike Ed25519 below), so this key pair is always
    // provisioned regardless of `provision_ed25519` — `sign-ecdsa`/`verify-ecdsa`
    // (and the aggregate `sign`/`verify`/`all` modes) must work in every build.
    let create_ecdsa_key_pair_request = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        benchmark_key_uid(delegated, hsm_slot, "pkcs11_ec"),
        [BENCH_TAG, disk_encryption_tag.as_str()],
        RecommendedCurve::P256,
        false,
        None,
    )
    .map_err(|e| BenchError::Kmip(e.to_string()))?;
    client
        .create_key_pair(create_ecdsa_key_pair_request)
        .await?;

    #[cfg(feature = "non-fips")]
    let ed25519_private_key_id = if provision_ed25519 {
        // Tagged exactly like the RSA key pair so the provider's
        // `find_all_private_keys` discovers it.
        let request = create_ec_key_pair_request(
            VENDOR_ID_COSMIAN,
            benchmark_key_uid(delegated, hsm_slot, "pkcs11_ed25519"),
            [BENCH_TAG, disk_encryption_tag.as_str()],
            RecommendedCurve::CURVEED25519,
            false,
            None,
        )
        .map_err(|e| BenchError::Kmip(e.to_string()))?;
        Some(
            client
                .create_key_pair(request)
                .await?
                .private_key_unique_identifier,
        )
    } else {
        None
    };

    #[cfg(not(feature = "non-fips"))]
    let ed25519_private_key_id = {
        let _ = provision_ed25519;
        None
    };

    // secp256k1 is not FIPS-approved (unlike P-256 above), so this key pair is
    // only provisioned when `sign-secp256k1`/`verify-secp256k1` (or an aggregate
    // `sign`/`verify`/`all` mode under a non-FIPS build) was requested — mirroring
    // how the Ed25519 key pair above is opt-in.
    #[cfg(feature = "non-fips")]
    if provision_secp256k1 {
        let request = create_ec_key_pair_request(
            VENDOR_ID_COSMIAN,
            benchmark_key_uid(delegated, hsm_slot, "pkcs11_secp256k1"),
            [BENCH_TAG, disk_encryption_tag.as_str()],
            RecommendedCurve::SECP256K1,
            false,
            None,
        )
        .map_err(|e| BenchError::Kmip(e.to_string()))?;
        client.create_key_pair(request).await?;
    }

    #[cfg(not(feature = "non-fips"))]
    let _ = provision_secp256k1;

    Ok(BenchSetup {
        ed25519_private_key_id,
    })
}

#[cfg(test)]
mod tests {
    use super::benchmark_key_uid;

    #[test]
    fn delegated_uid_targets_requested_slot() {
        let uid = benchmark_key_uid(true, 42, "pkcs11_sym");
        assert!(uid.is_some());
        assert!(uid.is_some_and(|uid| uid.to_string().starts_with("hsm::42::pkcs11_sym_")));
    }

    #[test]
    fn software_uid_is_server_generated() {
        assert!(benchmark_key_uid(false, 42, "pkcs11_sym").is_none());
    }
}
