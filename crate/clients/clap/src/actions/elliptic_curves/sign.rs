use std::path::PathBuf;

use clap::Parser;
#[cfg(feature = "non-fips")]
use cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
use cosmian_kmip::{
    kmip_0::kmip_types::HashingAlgorithm,
    kmip_2_1::kmip_types::{CryptographicParameters, DigitalSignatureAlgorithm},
};
use cosmian_kms_client::{KmsClient, reexport::cosmian_kms_client_utils::create_utils::Curve};

use crate::{
    actions::{labels::KEY_ID, shared::sign::run_sign},
    error::result::KmsCliResult,
};

/// Sign a file using elliptic curve digital signature algorithms (ECDSA)
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SignAction {
    /// The elliptic curve
    #[clap(long, short = 'c', default_value = "nist-p256")]
    pub(crate) curve: Curve,

    /// The file to sign
    #[clap(required = true, name = "FILE")]
    pub(crate) input_file: PathBuf,

    /// The private key unique identifier
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The signature output file path
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,

    /// Treat input as already-digested data (pre-hash)
    #[clap(long = "digested", action)]
    pub(crate) digested: bool,
}

impl SignAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let cryptographic_parameters = Some(match self.curve {
            Curve::NistP256 => CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            },
            Curve::NistP384 => CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA384),
                hashing_algorithm: Some(HashingAlgorithm::SHA384),
                ..CryptographicParameters::default()
            },
            Curve::NistP521 => CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA512),
                hashing_algorithm: Some(HashingAlgorithm::SHA512),
                ..CryptographicParameters::default()
            },
            #[cfg(feature = "non-fips")]
            Curve::Ed25519 => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::Ed25519),
                ..CryptographicParameters::default()
            },
            #[cfg(feature = "non-fips")]
            Curve::Ed448 => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::Ed448),
                ..CryptographicParameters::default()
            },
            #[cfg(feature = "non-fips")]
            Curve::X25519 | Curve::X448 => {
                return Err(crate::error::KmsCliError::Default(
                    "X25519/X448 cannot be used for signing".to_owned(),
                ));
            }
            #[cfg(feature = "non-fips")]
            Curve::Secp256k1 => CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            },
            #[cfg(feature = "non-fips")]
            Curve::Secp224k1 => CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            },
        });
        #[cfg(feature = "non-fips")]
        if self.digested && matches!(self.curve, Curve::Ed25519 | Curve::Ed448) {
            return Err(crate::error::KmsCliError::Default(
                "Ed25519/Ed448 signing expects the raw message; --digested is not supported"
                    .to_owned(),
            ));
        }
        run_sign(
            kms_rest_client,
            self.input_file.clone(),
            self.key_id.clone(),
            self.tags.clone(),
            self.output_file.clone(),
            cryptographic_parameters,
            self.digested,
        )
        .await
    }
}
