//! Provisions the KMS objects used by the benchmark hot loops.
//!
//! Reuses the KMIP request builders exposed through the `ckms` crate's reexport
//! chain (the same ones used by `cosmian_pkcs11`'s own `tests.rs`), so the created
//! objects are tagged/typed exactly the way the PKCS#11 provider's backend expects
//! (`crate/kmip/src/kmip_2_1/requests/{create,create_key_pair}.rs` already insert the
//! system tags the provider's `find_all_*` functions look for).

use ckms::reexport::cosmian_kms_cli_actions::reexport::{
    cosmian_kmip::kmip_2_1::{
        extra::VENDOR_ID_COSMIAN,
        kmip_types::CryptographicAlgorithm,
        requests::{create_rsa_key_pair_request, symmetric_key_create_request},
    },
    cosmian_kms_client::{KmsClient, KmsClientConfig},
};

use crate::error::{BenchError, BenchResult};

/// Bits of key material for the AES key used by the `encrypt-decrypt` benchmark.
const AES_KEY_BITS: usize = 128;
/// Bits of key material for the RSA key pair used by the `sign-verify` benchmark.
const RSA_KEY_BITS: usize = 2048;

/// Tag applied to every object created for this benchmark, so runs are easy to spot
/// and clean up if a temporary server is ever reused.
const BENCH_TAG: &str = "pkcs11-bench";

/// Default value of `COSMIAN_PKCS11_DISK_ENCRYPTION_TAG`, matching
/// `crate/clients/pkcs11/provider/src/backend.rs`'s own default. The provider's
/// `find_all_private_keys` only returns private keys tagged with this value (AND'd
/// with its own system tag), so the benchmark's RSA key must carry it too.
const DISK_ENCRYPTION_TAG: &str = "disk-encryption";

/// Creates one AES secret key and one RSA key pair in the KMS pointed at by
/// `server_url`, returning a ready-to-use [`KmsClient`] for any further setup calls.
pub(crate) async fn provision_bench_keys(server_url: &str) -> BenchResult<KmsClient> {
    let mut config = KmsClientConfig::default();
    server_url.clone_into(&mut config.http_config.server_url);
    let client = KmsClient::new_with_config(config)?;

    let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
        .unwrap_or_else(|_| DISK_ENCRYPTION_TAG.to_owned());

    let create_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
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
        None,
        [BENCH_TAG, disk_encryption_tag.as_str()],
        RSA_KEY_BITS,
        false,
        None,
    )
    .map_err(|e| BenchError::Kmip(e.to_string()))?;
    client.create_key_pair(create_key_pair_request).await?;

    Ok(client)
}
