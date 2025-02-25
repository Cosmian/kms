use std::fmt::Display;

use clap::{Parser, ValueEnum};
use cosmian_kms_client::{
    cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier,
    kmip_2_1::{
        kmip_operations::Mac,
        kmip_types::{CryptographicParameters, HashingAlgorithm},
    },
    KmsClient,
};

use crate::{actions::console, error::result::CliResult};

#[derive(ValueEnum, Debug, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum CHashingAlgorithm {
    SHA256,
    SHA384,
    SHA512,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

impl Display for CHashingAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SHA256 => write!(f, "sha256"),
            Self::SHA384 => write!(f, "sha384"),
            Self::SHA512 => write!(f, "sha512"),
            Self::SHA3_224 => write!(f, "sha3-224"),
            Self::SHA3_256 => write!(f, "sha3-256"),
            Self::SHA3_384 => write!(f, "sha3-384"),
            Self::SHA3_512 => write!(f, "sha3-512"),
        }
    }
}

impl From<CHashingAlgorithm> for HashingAlgorithm {
    fn from(algo: CHashingAlgorithm) -> Self {
        match algo {
            CHashingAlgorithm::SHA256 => Self::SHA256,
            CHashingAlgorithm::SHA384 => Self::SHA384,
            CHashingAlgorithm::SHA512 => Self::SHA512,
            CHashingAlgorithm::SHA3_224 => Self::SHA3224,
            CHashingAlgorithm::SHA3_256 => Self::SHA3256,
            CHashingAlgorithm::SHA3_384 => Self::SHA3384,
            CHashingAlgorithm::SHA3_512 => Self::SHA3512,
        }
    }
}

#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct MacAction {
    /// Locate an object which has a link to this MAC key id.
    #[clap(long, short = 'k')]
    pub mac_key_id: String,

    /// Hashing algorithm (case insensitive)
    ///
    /// Running the locate sub-command with a wrong value will list all the possible values.
    /// e.g. `ckms mac --algorithm WRONG`
    #[clap(
        long = "algorithm",
        short = 'a',
        value_name = "ALGORITHM",
        verbatim_doc_comment
    )]
    pub hashing_algorithm: CHashingAlgorithm,

    /// The data to be hashed in hexadecimal format.
    /// The data to be hashed in hexadecimal format.
    #[clap(
        long,
        short = 'd',
        value_parser = |s: &str| hex::decode(s).map(|_| s.to_string()).map_err(|e| format!("Invalid hex format: {}", e))
    )]
    pub data: Option<String>,

    /// Specifies the existing stream or by-parts cryptographic operation (as returned from a previous call to this operation).
    /// The correlation value is represented as a hexadecimal string.
    #[clap(long,
        short = 'c',
        value_parser = |s: &str| hex::decode(s).map(|_| s.to_string()).map_err(|e| format!("Invalid hex format: {}", e))
)]
    pub correlation_value: Option<String>,

    /// Initial operation as Boolean
    #[clap(long, short = 'i')]
    pub init_indicator: bool,

    /// Final operation as Boolean
    #[clap(long, short = 'f')]
    pub final_indicator: bool,
}

impl MacAction {
    /// Processes the access action.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem running the action.
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let unique_identifier = Some(UniqueIdentifier::TextString(self.mac_key_id.clone()));

        let cryptographic_parameters = CryptographicParameters {
            hashing_algorithm: Some(self.hashing_algorithm.clone().into()),
            ..Default::default()
        };

        let data = match self.data.clone() {
            Some(data) => Some(hex::decode(data)?),
            None => None,
        };

        let correlation_value = match self.correlation_value.clone() {
            Some(correlation_value) => Some(hex::decode(correlation_value)?),
            None => None,
        };

        let init_indicator = Some(self.init_indicator);
        let final_indicator = Some(self.final_indicator);

        let response = kms_rest_client
            .mac(Mac {
                unique_identifier: unique_identifier.clone(),
                cryptographic_parameters,
                data,
                correlation_value,
                init_indicator,
                final_indicator,
            })
            .await?;

        let hex_output = response.data.map_or_else(String::new, hex::encode);

        console::Stdout::new(&format!("Mac output: {hex_output}")).write()?;
        Ok(())
    }
}
