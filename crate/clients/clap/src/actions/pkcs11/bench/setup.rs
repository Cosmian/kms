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

use super::{error::BenchResult, load::ConcreteMode};

/// Object identifiers provisioned for one benchmark process.
pub(crate) struct BenchSetup {
    pub(crate) symmetric: UniqueIdentifier,
    pub(crate) rsa_private: UniqueIdentifier,
    pub(crate) rsa_public: UniqueIdentifier,
    pub(crate) ecdsa_private: UniqueIdentifier,
    pub(crate) ecdsa_public: UniqueIdentifier,
    pub(crate) ecdsa_p384_private: UniqueIdentifier,
    pub(crate) ecdsa_p384_public: UniqueIdentifier,
    pub(crate) ed25519_private: Option<UniqueIdentifier>,
    pub(crate) ed25519_public: Option<UniqueIdentifier>,
    pub(crate) secp256k1_private: Option<UniqueIdentifier>,
    pub(crate) secp256k1_public: Option<UniqueIdentifier>,
}

/// Bits of key material for the AES key used by the `encrypt-decrypt` benchmark.
///
/// AES-256 is supported by every delegated HSM backend, including `Crypt2Pay`.
const AES_KEY_BITS: usize = 256;
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

/// Which of the optional (non-FIPS-only) key pairs a set of benchmark modes needs.
#[derive(Debug, PartialEq, Eq)]
struct OptionalKeyNeeds {
    ed25519: bool,
    secp256k1: bool,
}

impl OptionalKeyNeeds {
    fn of(modes: &[ConcreteMode]) -> Self {
        Self {
            ed25519: modes
                .iter()
                .any(|mode| matches!(mode, ConcreteMode::SignEdDsa | ConcreteMode::VerifyEdDsa)),
            secp256k1: modes.iter().any(|mode| {
                matches!(
                    mode,
                    ConcreteMode::SignSecp256k1 | ConcreteMode::VerifySecp256k1
                )
            }),
        }
    }
}

/// Creates the Ed25519 and/or secp256k1 key pairs required by `modes` (each only
/// when at least one mode needs it) and records them in `setup`. A key pair whose
/// creation fails is left absent so the modes that need it are skipped.
pub(crate) async fn provision_optional_keys(
    mut setup: BenchSetup,
    client: &KmsClient,
    modes: &[ConcreteMode],
    delegated: bool,
    hsm_slot: usize,
) -> BenchResult<BenchSetup> {
    let disk_encryption_tag = disk_encryption_tag();
    let OptionalKeyNeeds {
        ed25519: needs_ed25519,
        secp256k1: needs_secp256k1,
    } = OptionalKeyNeeds::of(modes);

    if needs_ed25519 {
        let request = create_ec_key_pair_request(
            VENDOR_ID_COSMIAN,
            benchmark_key_uid(delegated, hsm_slot, "pkcs11_ed25519"),
            [BENCH_TAG, disk_encryption_tag.as_str()],
            RecommendedCurve::CURVEED25519,
            false,
            None,
        )?;
        match client.create_key_pair(request).await {
            Ok(response) => {
                setup.ed25519_private = Some(response.private_key_unique_identifier);
                setup.ed25519_public = Some(response.public_key_unique_identifier);
            }
            Err(error) => {
                eprintln!("[bench:pkcs11] Ed25519 key creation failed, skipping: {error}");
            }
        }
    }

    if needs_secp256k1 {
        let request = create_ec_key_pair_request(
            VENDOR_ID_COSMIAN,
            benchmark_key_uid(delegated, hsm_slot, "pkcs11_secp256k1"),
            [BENCH_TAG, disk_encryption_tag.as_str()],
            RecommendedCurve::SECP256K1,
            false,
            None,
        )?;
        match client.create_key_pair(request).await {
            Ok(response) => {
                setup.secp256k1_private = Some(response.private_key_unique_identifier);
                setup.secp256k1_public = Some(response.public_key_unique_identifier);
            }
            Err(error) => {
                eprintln!("[bench:pkcs11] secp256k1 key creation failed, skipping: {error}");
            }
        }
    }

    Ok(setup)
}

/// Tag the provider's `find_all_private_keys` filters on, overridable with
/// `COSMIAN_PKCS11_DISK_ENCRYPTION_TAG` exactly like the provider's own default.
fn disk_encryption_tag() -> String {
    std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
        .unwrap_or_else(|_| DISK_ENCRYPTION_TAG.to_owned())
}

fn benchmark_key_uid(delegated: bool, hsm_slot: usize, name: &str) -> Option<UniqueIdentifier> {
    delegated.then(|| {
        UniqueIdentifier::TextString(format!("hsm::{hsm_slot}::{name}_{}", Uuid::new_v4()))
    })
}

/// Creates one AES secret key, one RSA key pair, and the EC P-256 and P-384 key
/// pairs in the KMS pointed at by `client`. With `delegated`, all keys are created
/// in `hsm_slot`. Non-FIPS builds then add the opt-in Ed25519 / secp256k1 key pairs
/// with [`provision_optional_keys`].
pub(crate) async fn provision_bench_keys(
    client: &KmsClient,
    delegated: bool,
    hsm_slot: usize,
) -> BenchResult<BenchSetup> {
    let disk_encryption_tag = disk_encryption_tag();

    let create_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        benchmark_key_uid(delegated, hsm_slot, "pkcs11_sym"),
        AES_KEY_BITS,
        CryptographicAlgorithm::AES,
        [BENCH_TAG],
        false,
        None,
    )?;
    let symmetric = client.create(create_request).await?.unique_identifier;

    let create_key_pair_request = create_rsa_key_pair_request(
        VENDOR_ID_COSMIAN,
        benchmark_key_uid(delegated, hsm_slot, "pkcs11_rsa"),
        [BENCH_TAG, disk_encryption_tag.as_str()],
        RSA_KEY_BITS,
        false,
        None,
    )?;
    let rsa_key_pair = client.create_key_pair(create_key_pair_request).await?;

    // EC P-256 is FIPS-approved (unlike Ed25519), so this key pair is always
    // provisioned — `sign-ecdsa`/`verify-ecdsa` (and the aggregate
    // `sign`/`verify`/`all` modes) must work in every build.
    let create_ecdsa_key_pair_request = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        benchmark_key_uid(delegated, hsm_slot, "pkcs11_ec"),
        [BENCH_TAG, disk_encryption_tag.as_str()],
        RecommendedCurve::P256,
        false,
        None,
    )?;
    let ecdsa_key_pair = client
        .create_key_pair(create_ecdsa_key_pair_request)
        .await?;

    // EC P-384 is also FIPS-approved and advertised by both Proteccio
    // (secp384r1) and Crypt2Pay (ansix9p384r1) in their PKCS#11 mechanism
    // tables, so — like P-256 — it is always provisioned.
    let create_ecdsa_p384_key_pair_request = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        benchmark_key_uid(delegated, hsm_slot, "pkcs11_ec_p384"),
        [BENCH_TAG, disk_encryption_tag.as_str()],
        RecommendedCurve::P384,
        false,
        None,
    )?;
    let ecdsa_p384_key_pair = client
        .create_key_pair(create_ecdsa_p384_key_pair_request)
        .await?;

    Ok(BenchSetup {
        symmetric,
        rsa_private: rsa_key_pair.private_key_unique_identifier,
        rsa_public: rsa_key_pair.public_key_unique_identifier,
        ecdsa_private: ecdsa_key_pair.private_key_unique_identifier,
        ecdsa_public: ecdsa_key_pair.public_key_unique_identifier,
        ecdsa_p384_private: ecdsa_p384_key_pair.private_key_unique_identifier,
        ecdsa_p384_public: ecdsa_p384_key_pair.public_key_unique_identifier,
        ed25519_private: None,
        ed25519_public: None,
        secp256k1_private: None,
        secp256k1_public: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{ConcreteMode, OptionalKeyNeeds, benchmark_key_uid};

    #[test]
    fn optional_keys_are_only_needed_by_their_modes() {
        let none = OptionalKeyNeeds {
            ed25519: false,
            secp256k1: false,
        };
        assert_eq!(
            OptionalKeyNeeds::of(&[ConcreteMode::SignRsaPkcs, ConcreteMode::VerifyEcdsaP384]),
            none
        );
        assert_eq!(OptionalKeyNeeds::of(&[]), none);
        assert_eq!(
            OptionalKeyNeeds::of(&[ConcreteMode::VerifyEdDsa]),
            OptionalKeyNeeds {
                ed25519: true,
                secp256k1: false,
            }
        );
        assert_eq!(
            OptionalKeyNeeds::of(&[ConcreteMode::SignSecp256k1, ConcreteMode::SignRsaPss]),
            OptionalKeyNeeds {
                ed25519: false,
                secp256k1: true,
            }
        );
        assert_eq!(
            OptionalKeyNeeds::of(&[ConcreteMode::SignEdDsa, ConcreteMode::VerifySecp256k1]),
            OptionalKeyNeeds {
                ed25519: true,
                secp256k1: true,
            }
        );
    }

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
