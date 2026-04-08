use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
};

use clap::{Parser, ValueEnum};
use cosmian_kms_client::KmsClient;
use serde::Serialize;

pub use self::{decrypt::DecryptAction, encrypt::EncryptAction, keys::KeysCommands};
use crate::{
    actions::{labels::KEY_ID, shared::get_key_uid},
    error::result::KmsCliResult,
};

pub mod decrypt;
pub mod encrypt;
pub mod keys;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum FpeDataType {
    #[default]
    Text,
    Integer,
    Float,
}

#[derive(Serialize)]
struct FpeMetadata<'a> {
    #[serde(rename = "type")]
    data_type: FpeDataType,
    #[serde(skip_serializing_if = "Option::is_none")]
    alphabet: Option<&'a str>,
}

/// Arguments shared by `ckms fpe encrypt` and `ckms fpe decrypt`.
#[derive(Parser, Debug, Default)]
pub struct FpeArgs {
    /// The FPE key unique identifier.
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The FPE data type.
    #[clap(long = "type", default_value = "text")]
    pub(crate) data_type: FpeDataType,

    /// The alphabet to use for encryption/decryption.
    ///
    /// Either a built-in preset name or a custom alphabet string (all distinct characters).
    ///
    /// Preset names: `numeric`, `hexadecimal`, `alpha_lower`, `alpha_upper`, `alpha`,
    /// `alpha_numeric`, `chinese`, `latin1sup`, `latin1sup_alphanum`, `utf`,
    /// `ascii_printable`, `base64`.
    #[clap(long = "alphabet")]
    pub(crate) alphabet: Option<String>,

    /// Optional tweak bytes as a hex string.
    #[clap(long = "tweak")]
    pub(crate) tweak: Option<String>,

    /// Input file to read from. If not specified, reads from stdin.
    #[clap(name = "FILE", value_name = "FILE")]
    pub(crate) input_file: Option<PathBuf>,

    /// Write the output to a file instead of stdout.
    #[clap(long = "output-file", short = 'o')]
    pub(crate) output_file: Option<PathBuf>,
}

impl FpeArgs {
    pub(crate) fn key_id(&self) -> KmsCliResult<String> {
        get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)
    }

    pub(crate) fn input_bytes(&self) -> KmsCliResult<Vec<u8>> {
        Ok(normalize_input_bytes(
            read_input_bytes(self.input_file.as_ref())?,
            self.data_type,
        ))
    }

    pub(crate) fn tweak_bytes(&self) -> KmsCliResult<Option<Vec<u8>>> {
        decode_tweak_hex(self.tweak.as_deref())
    }

    pub(crate) fn authenticated_data(&self) -> KmsCliResult<Option<Vec<u8>>> {
        build_authenticated_data(self.data_type, self.alphabet.as_deref())
    }
}

pub(crate) fn build_authenticated_data(
    data_type: FpeDataType,
    alphabet: Option<&str>,
) -> KmsCliResult<Option<Vec<u8>>> {
    match data_type {
        FpeDataType::Text => Ok(Some(
            alphabet.unwrap_or("alpha_numeric").as_bytes().to_vec(),
        )),
        FpeDataType::Integer => {
            let alphabet = alphabet.unwrap_or("numeric");
            Ok(Some(serde_json::to_vec(&FpeMetadata {
                data_type,
                alphabet: Some(alphabet),
            })?))
        }
        FpeDataType::Float => Ok(Some(serde_json::to_vec(&FpeMetadata {
            data_type,
            alphabet: None,
        })?)),
    }
}

pub(crate) fn decode_tweak_hex(tweak: Option<&str>) -> KmsCliResult<Option<Vec<u8>>> {
    tweak.map(hex::decode).transpose().map_err(Into::into)
}

pub(crate) fn read_input_bytes(input_file: Option<&PathBuf>) -> KmsCliResult<Vec<u8>> {
    if let Some(input_file) = input_file {
        return Ok(fs::read(input_file)?);
    }

    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data)?;
    Ok(data)
}

fn normalize_input_bytes(mut data: Vec<u8>, data_type: FpeDataType) -> Vec<u8> {
    if matches!(data_type, FpeDataType::Integer | FpeDataType::Float) {
        if data.ends_with(b"\r\n") {
            data.truncate(data.len().saturating_sub(2));
        } else if data.ends_with(b"\n") {
            data.truncate(data.len().saturating_sub(1));
        }
    }
    data
}

pub(crate) fn write_output_bytes(output_file: Option<&PathBuf>, output: &[u8]) -> KmsCliResult<()> {
    if let Some(output_file) = output_file {
        fs::write(output_file, output)?;
    } else {
        std::io::stdout().write_all(output)?;
        std::io::stdout().flush()?;
    }
    Ok(())
}

/// Manage FPE keys and perform FPE encryption/decryption through KMIP Encrypt/Decrypt.
#[derive(Parser)]
pub enum FpeCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl FpeCommands {
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Keys(command) => Box::pin(command.process(kms_rest_client)).await?,
            Self::Encrypt(action) => action.run(kms_rest_client).await?,
            Self::Decrypt(action) => action.run(kms_rest_client).await?,
        }
        Ok(())
    }
}
