use clap::{Parser, ValueEnum};
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
        requests::create_pqc_key_pair_request,
    },
    reexport::cosmian_kms_client_utils::configurable_kem_utils::{
        KemAlgorithm, build_create_configurable_kem_keypair_request,
    },
};

use crate::{
    actions::kms::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// The PQC algorithm to use for key pair generation.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum PqcAlgorithm {
    /// ML-KEM-512 (post-quantum KEM)
    #[value(name = "ml-kem-512")]
    MlKem512,
    /// ML-KEM-768 (post-quantum KEM)
    #[value(name = "ml-kem-768")]
    MlKem768,
    /// ML-KEM-1024 (post-quantum KEM)
    #[value(name = "ml-kem-1024")]
    MlKem1024,
    /// ML-DSA-44 (post-quantum signature)
    #[value(name = "ml-dsa-44")]
    MlDsa44,
    /// ML-DSA-65 (post-quantum signature)
    #[value(name = "ml-dsa-65")]
    MlDsa65,
    /// ML-DSA-87 (post-quantum signature)
    #[value(name = "ml-dsa-87")]
    MlDsa87,
    /// X25519MLKEM768 (hybrid KEM)
    #[value(name = "x25519-ml-kem-768")]
    X25519MlKem768,
    /// X448MLKEM1024 (hybrid KEM)
    #[value(name = "x448-ml-kem-1024")]
    X448MlKem1024,
    /// SLH-DSA-SHA2-128s (stateless hash-based signature)
    #[value(name = "slh-dsa-sha2-128s")]
    SlhDsaSha2_128s,
    /// SLH-DSA-SHA2-128f (stateless hash-based signature)
    #[value(name = "slh-dsa-sha2-128f")]
    SlhDsaSha2_128f,
    /// SLH-DSA-SHA2-192s (stateless hash-based signature)
    #[value(name = "slh-dsa-sha2-192s")]
    SlhDsaSha2_192s,
    /// SLH-DSA-SHA2-192f (stateless hash-based signature)
    #[value(name = "slh-dsa-sha2-192f")]
    SlhDsaSha2_192f,
    /// SLH-DSA-SHA2-256s (stateless hash-based signature)
    #[value(name = "slh-dsa-sha2-256s")]
    SlhDsaSha2_256s,
    /// SLH-DSA-SHA2-256f (stateless hash-based signature)
    #[value(name = "slh-dsa-sha2-256f")]
    SlhDsaSha2_256f,
    /// SLH-DSA-SHAKE-128s (stateless hash-based signature)
    #[value(name = "slh-dsa-shake-128s")]
    SlhDsaShake128s,
    /// SLH-DSA-SHAKE-128f (stateless hash-based signature)
    #[value(name = "slh-dsa-shake-128f")]
    SlhDsaShake128f,
    /// SLH-DSA-SHAKE-192s (stateless hash-based signature)
    #[value(name = "slh-dsa-shake-192s")]
    SlhDsaShake192s,
    /// SLH-DSA-SHAKE-192f (stateless hash-based signature)
    #[value(name = "slh-dsa-shake-192f")]
    SlhDsaShake192f,
    /// SLH-DSA-SHAKE-256s (stateless hash-based signature)
    #[value(name = "slh-dsa-shake-256s")]
    SlhDsaShake256s,
    /// SLH-DSA-SHAKE-256f (stateless hash-based signature)
    #[value(name = "slh-dsa-shake-256f")]
    SlhDsaShake256f,
    /// ML-KEM-512 hybridized with P-256 (`ConfigurableKEM`)
    #[value(name = "ml-kem-512-p256")]
    MlKem512P256,
    /// ML-KEM-768 hybridized with P-256 (`ConfigurableKEM`)
    #[value(name = "ml-kem-768-p256")]
    MlKem768P256,
    /// ML-KEM-512 hybridized with Curve25519 (`ConfigurableKEM`)
    #[value(name = "ml-kem-512-curve25519")]
    MlKem512Curve25519,
    /// ML-KEM-768 hybridized with Curve25519 (`ConfigurableKEM`)
    #[value(name = "ml-kem-768-curve25519")]
    MlKem768Curve25519,
}

impl PqcAlgorithm {
    /// Convert to KMIP `CryptographicAlgorithm`.
    pub(crate) const fn to_cryptographic_algorithm(self) -> CryptographicAlgorithm {
        match self {
            Self::MlKem512 => CryptographicAlgorithm::MLKEM_512,
            Self::MlKem768 => CryptographicAlgorithm::MLKEM_768,
            Self::MlKem1024 => CryptographicAlgorithm::MLKEM_1024,
            Self::MlDsa44 => CryptographicAlgorithm::MLDSA_44,
            Self::MlDsa65 => CryptographicAlgorithm::MLDSA_65,
            Self::MlDsa87 => CryptographicAlgorithm::MLDSA_87,
            Self::X25519MlKem768 => CryptographicAlgorithm::X25519MLKEM768,
            Self::X448MlKem1024 => CryptographicAlgorithm::X448MLKEM1024,
            Self::SlhDsaSha2_128s => CryptographicAlgorithm::SLHDSA_SHA2_128s,
            Self::SlhDsaSha2_128f => CryptographicAlgorithm::SLHDSA_SHA2_128f,
            Self::SlhDsaSha2_192s => CryptographicAlgorithm::SLHDSA_SHA2_192s,
            Self::SlhDsaSha2_192f => CryptographicAlgorithm::SLHDSA_SHA2_192f,
            Self::SlhDsaSha2_256s => CryptographicAlgorithm::SLHDSA_SHA2_256s,
            Self::SlhDsaSha2_256f => CryptographicAlgorithm::SLHDSA_SHA2_256f,
            Self::SlhDsaShake128s => CryptographicAlgorithm::SLHDSA_SHAKE_128s,
            Self::SlhDsaShake128f => CryptographicAlgorithm::SLHDSA_SHAKE_128f,
            Self::SlhDsaShake192s => CryptographicAlgorithm::SLHDSA_SHAKE_192s,
            Self::SlhDsaShake192f => CryptographicAlgorithm::SLHDSA_SHAKE_192f,
            Self::SlhDsaShake256s => CryptographicAlgorithm::SLHDSA_SHAKE_256s,
            Self::SlhDsaShake256f => CryptographicAlgorithm::SLHDSA_SHAKE_256f,
            Self::MlKem512P256
            | Self::MlKem768P256
            | Self::MlKem512Curve25519
            | Self::MlKem768Curve25519 => CryptographicAlgorithm::ConfigurableKEM,
        }
    }

    /// Convert to `KemAlgorithm` for `ConfigurableKEM` variants.
    /// Returns `None` for standard PQC algorithms.
    pub(crate) const fn to_kem_algorithm(self) -> Option<KemAlgorithm> {
        match self {
            Self::MlKem512P256 => Some(KemAlgorithm::MlKem512P256),
            Self::MlKem768P256 => Some(KemAlgorithm::MlKem768P256),
            Self::MlKem512Curve25519 => Some(KemAlgorithm::MlKem512Curve25519),
            Self::MlKem768Curve25519 => Some(KemAlgorithm::MlKem768Curve25519),
            _ => None,
        }
    }
}

/// Create a new post-quantum key pair (ML-KEM or ML-DSA).
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreatePqcKeyPairAction {
    /// The PQC algorithm to use
    #[clap(long = "algorithm", short = 'a', value_enum)]
    pub(crate) algorithm: PqcAlgorithm,

    /// Tag to associate with the key pair.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub(crate) tags: Vec<String>,

    /// Sensitive: if set, the private key will not be exportable
    #[clap(long = "sensitive", default_value = "false")]
    pub(crate) sensitive: bool,
}

impl CreatePqcKeyPairAction {
    pub async fn run(
        &self,
        kms_rest_client: KmsClient,
    ) -> KmsCliResult<(UniqueIdentifier, UniqueIdentifier)> {
        let vendor_id = kms_rest_client.config.vendor_id.as_str();

        let request = if let Some(kem_algorithm) = self.algorithm.to_kem_algorithm() {
            build_create_configurable_kem_keypair_request(
                vendor_id,
                None,
                &self.tags,
                kem_algorithm,
                self.sensitive,
                None,
            )?
        } else {
            create_pqc_key_pair_request(
                vendor_id,
                &self.tags,
                self.algorithm.to_cryptographic_algorithm(),
                self.sensitive,
            )?
        };

        let response = kms_rest_client
            .create_key_pair(request)
            .await
            .with_context(|| "failed creating a PQC key pair")?;

        let mut stdout = console::Stdout::new("The PQC key pair has been properly generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_key_pair_unique_identifier(
            &response.private_key_unique_identifier,
            &response.public_key_unique_identifier,
        );
        stdout.write()?;

        Ok((
            response.private_key_unique_identifier,
            response.public_key_unique_identifier,
        ))
    }
}
