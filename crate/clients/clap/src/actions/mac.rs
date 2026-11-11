use std::fmt::Display;

use clap::{Parser, Subcommand, ValueEnum};
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::{
        kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm},
        kmip_2_1::kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
    },
    kmip_2_1::{
        kmip_operations::{MAC, MACVerify},
        kmip_types::CryptographicParameters,
    },
};

use crate::{
    actions::console,
    error::{KmsCliError, result::KmsCliResult},
};

#[derive(ValueEnum, Debug, Clone, PartialEq, Eq)]
pub enum CHashingAlgorithm {
    SHA1,
    SHA224,
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
            Self::SHA1 => write!(f, "sha1"),
            Self::SHA224 => write!(f, "sha224"),
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
            CHashingAlgorithm::SHA1 => Self::SHA1,
            CHashingAlgorithm::SHA224 => Self::SHA224,
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

/// MAC algorithm family used by `ckms mac`.
#[derive(ValueEnum, Debug, Clone, PartialEq, Eq)]
pub enum CMacMode {
    Hmac,
    Cmac,
    Gmac,
}

/// Build the KMIP cryptographic parameters selecting HMAC, AES-CMAC or AES-GMAC.
fn mac_parameters(
    mode: &CMacMode,
    hash: Option<&CHashingAlgorithm>,
) -> KmsCliResult<CryptographicParameters> {
    let block_cipher_mode = match (mode, hash) {
        (CMacMode::Hmac, Some(h)) => {
            return Ok(CryptographicParameters {
                hashing_algorithm: Some(h.clone().into()),
                ..Default::default()
            });
        }
        (CMacMode::Hmac, None) => {
            return Err(KmsCliError::Default(
                "--algorithm is required for HMAC".to_owned(),
            ));
        }
        (_, Some(_)) => {
            return Err(KmsCliError::Default(
                "--algorithm must not be set with --mode cmac or gmac".to_owned(),
            ));
        }
        (CMacMode::Cmac, None) => BlockCipherMode::CMAC,
        (CMacMode::Gmac, None) => BlockCipherMode::GCM,
    };
    Ok(CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(block_cipher_mode),
        ..Default::default()
    })
}

/// MAC utilities: compute or verify a MAC value.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct MacCommands {
    #[command(subcommand)]
    pub command: MacSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum MacSubcommand {
    /// Compute a MAC over data with a MAC key.
    Compute(MacAction),
    /// Verify a MAC over data with a MAC key.
    Verify(MacVerifyAction),
}

/// Compute a MAC over data with a MAC key.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct MacAction {
    /// Locate an object which has a link to this MAC key id.
    #[clap(long, short = 'k')]
    pub mac_key_id: String,

    /// MAC mode: `hmac` (default, needs `--algorithm`), `cmac` (AES-CMAC) or `gmac` (AES-GMAC).
    /// The key must be an AES key with the MAC Generate / MAC Verify usage bits (keys from `sym keys create`
    /// do not have them; e.g. `ckms sym keys import -f aes key.bin --key-usage mac-generate --key-usage mac-verify`).
    /// A `cmac` MAC is the 16-byte tag; a `gmac` MAC is the IV (12 bytes) followed by
    /// the tag (16 bytes), hex encoded (56 characters).
    #[clap(long, short = 'M', value_enum, default_value_t = CMacMode::Hmac)]
    pub mode: CMacMode,

    /// Hashing algorithm (case insensitive); required for `hmac`, forbidden for `cmac`/`gmac`.
    ///
    /// Running the locate sub-command with a wrong value will list all the possible values.
    /// e.g. `ckms mac --algorithm WRONG`
    #[clap(
        long = "algorithm",
        short = 'a',
        value_name = "ALGORITHM",
        required_if_eq("mode", "hmac"),
        verbatim_doc_comment
    )]
    pub hashing_algorithm: Option<CHashingAlgorithm>,

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
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let unique_identifier = Some(UniqueIdentifier::TextString(self.mac_key_id.clone()));

        let cryptographic_parameters = mac_parameters(&self.mode, self.hashing_algorithm.as_ref())?;

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
            .mac(MAC {
                unique_identifier: unique_identifier.clone(),
                cryptographic_parameters: Some(cryptographic_parameters),
                data,
                correlation_value,
                init_indicator,
                final_indicator,
            })
            .await?;

        let hex_output = response.mac_data.map_or_else(String::new, hex::encode);

        console::Stdout::new(&format!("Mac output: {hex_output}")).write()?;
        Ok(())
    }
}

/// Verify a MAC over provided data with a MAC key.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct MacVerifyAction {
    /// Locate an object which has a link to this MAC key id.
    #[clap(long, short = 'k')]
    pub mac_key_id: String,

    /// MAC mode: `hmac` (default, needs `--algorithm`), `cmac` (AES-CMAC) or `gmac` (AES-GMAC).
    /// For `gmac` the MAC to verify is the IV (12 bytes) followed by the tag (16 bytes), in hex.
    /// The key must be an AES key with the MAC Generate / MAC Verify usage bits (e.g. imported with
    /// `ckms sym keys import -f aes key.bin --key-usage mac-generate --key-usage mac-verify`).
    #[clap(long, short = 'M', value_enum, default_value_t = CMacMode::Hmac)]
    pub mode: CMacMode,

    /// Hashing algorithm (case insensitive); required for `hmac`, forbidden for `cmac`/`gmac`.
    #[clap(
        long = "algorithm",
        short = 'a',
        value_name = "ALGORITHM",
        required_if_eq("mode", "hmac"),
        verbatim_doc_comment
    )]
    pub hashing_algorithm: Option<CHashingAlgorithm>,

    /// The data to verify in hexadecimal format.
    #[clap(
        long,
        short = 'd',
        value_parser = |s: &str| hex::decode(s).map(|_| s.to_string()).map_err(|e| format!("Invalid hex format: {}", e))
    )]
    pub data: String,

    /// The MAC to verify in hexadecimal format.
    #[clap(
        long = "mac",
        short = 'm',
        value_parser = |s: &str| hex::decode(s).map(|_| s.to_string()).map_err(|e| format!("Invalid hex format: {}", e))
    )]
    pub mac_hex: String,
}

impl MacVerifyAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let unique_identifier = UniqueIdentifier::TextString(self.mac_key_id.clone());

        let cryptographic_parameters = mac_parameters(&self.mode, self.hashing_algorithm.as_ref())?;

        let data = hex::decode(&self.data)?;
        let mac_data = hex::decode(&self.mac_hex)?;

        let resp = kms_rest_client
            .mac_verify(MACVerify {
                unique_identifier,
                cryptographic_parameters: Some(cryptographic_parameters),
                data,
                mac_data,
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            })
            .await?;

        let validity = resp
            .validity_indicator
            .map_or_else(|| "Unknown".to_owned(), |v| v.to_string());
        console::Stdout::new(&format!("MAC validity: {validity}")).write()?;
        Ok(())
    }
}

impl MacCommands {
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match &self.command {
            MacSubcommand::Compute(action) => action.run(kms_rest_client).await?,
            MacSubcommand::Verify(action) => action.run(kms_rest_client).await?,
        }
        Ok(())
    }
}
