use std::{fmt::Display, path::PathBuf};

use base64::Engine;
use clap::{Parser, ValueEnum};
use cosmian_kms_client::{
    cosmian_kmip::kmip_2_1::kmip_types::{BlockCipherMode, KeyFormatType},
    der_to_pem, export_object,
    kmip_2_1::kmip_types::{
        CryptographicAlgorithm, CryptographicParameters, HashingAlgorithm, PaddingMethod,
    },
    write_bytes_to_file, write_kmip_object_to_file, ExportObjectParams, KmsClient,
};

use crate::{
    actions::console,
    cli_bail,
    error::result::{CliResult, CliResultHelper},
};

#[derive(ValueEnum, Debug, Clone, PartialEq, Eq)]
pub enum ExportKeyFormat {
    JsonTtlv,
    Sec1Pem,
    Sec1Der,
    Pkcs1Pem,
    Pkcs1Der,
    Pkcs8Pem,
    Pkcs8Der,
    SpkiPem,
    SpkiDer,
    Base64,
    Raw,
}

#[derive(ValueEnum, Debug, Clone, PartialEq, Eq)]
pub(crate) enum WrappingAlgorithm {
    NistKeyWrap,
    AesGCM,
    RsaPkcsV15,
    RsaOaep,
    RsaAesKeyWrap,
}

impl WrappingAlgorithm {
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::NistKeyWrap => "nist-key-wrap",
            Self::AesGCM => "aes-gcm",
            Self::RsaPkcsV15 => "rsa-pkcs-v15",
            Self::RsaOaep => "rsa-oaep",
            Self::RsaAesKeyWrap => "rsa-aes-key-wrap",
        }
    }
}

impl Display for WrappingAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Export a key from the KMS
///
/// If not format is specified, the key is exported as a json-ttlv with a
/// `KeyFormatType` that follows the section 4.26 of the KMIP specification.
/// <https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html#_Toc57115585>
///
/// The key can optionally be unwrapped and/or wrapped when exported.
///
/// If wrapping is specified, the key is wrapped using the specified wrapping key.
/// The chosen Key Format must be either `json-ttlv` or `raw`. When `raw` is selected,
/// only the wrapped bytes are returned.
///
/// Wrapping a key that is already wrapped is an error.
/// Unwrapping a key that is not wrapped is ignored and returns the unwrapped key.
///
/// When using tags to retrieve the key, rather than the key id,
/// an error is returned if multiple keys matching the tags are found.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ExportKeyAction {
    /// The file to export the key to
    #[clap(required = true)]
    key_file: PathBuf,

    /// The key unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,

    /// The format of the key
    ///  - `json-ttlv` [default]. It should be the format to use to later re-import the key
    ///  - `sec1-pem` and `sec1-der`only apply to NIST EC private keys (Not Curve25519 or X448)
    ///  - `pkcs1-pem` and `pkcs1-der` only apply to RSA private and public keys
    ///  - `pkcs8-pem` and `pkcs8-der` only apply to RSA and EC private keys
    ///  - `spki-pem` and `spki-der` only apply to RSA and EC public keys
    ///  - `raw` returns the raw bytes of
    ///       - symmetric keys
    ///       - Covercrypt keys
    ///       - wrapped keys
    #[clap(
        long = "key-format",
        short = 'f',
        default_value = "json-ttlv",
        verbatim_doc_comment
    )]
    key_format: ExportKeyFormat,

    /// Unwrap the key if it is wrapped before export
    #[clap(
        long = "unwrap",
        short = 'u',
        default_value = "false",
        group = "wrapping"
    )]
    unwrap: bool,

    /// The id of the key/certificate to use to wrap this key before export
    #[clap(
        long = "wrap-key-id",
        short = 'w',
        required = false,
        group = "wrapping"
    )]
    wrap_key_id: Option<String>,

    /// Allow exporting revoked and destroyed keys.
    /// The user must be the owner of the key.
    /// Destroyed keys have their key material removed.
    #[clap(
        long = "allow-revoked",
        short = 'i',
        default_value = "false",
        verbatim_doc_comment
    )]
    allow_revoked: bool,

    /// Wrapping algorithm to use when exporting the key
    /// By default, the algorithm used is
    /// - `NISTKeyWrap` for symmetric keys (a.k.a. RFC 5649)
    /// - `RsaPkcsOaep` for RSA keys
    #[clap(
        long = "wrapping-algorithm",
        short = 'm',
        default_value = None,
        verbatim_doc_comment
    )]
    wrapping_algorithm: Option<WrappingAlgorithm>,

    /// Authenticated encryption additional data
    /// Only available for AES GCM wrapping
    #[clap(
        long = "authenticated-additional-data",
        short = 'd',
        default_value = None,
    )]
    authenticated_additional_data: Option<String>,
}

impl ExportKeyAction {
    /// Export a key from the KMS
    ///
    /// # Errors
    ///
    /// This function can return an error if:
    ///
    /// - Either `--key-id` or one or more `--tag` is not specified.
    /// - There is a server error while exporting the object.
    ///
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let id_or_tags = if let Some(key_id) = &self.key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --key-id or one or more --tag must be specified")
        };

        let (key_format_type, encode_to_pem) = match self.key_format {
            // For Raw: use the default format then do the local extraction of the bytes
            ExportKeyFormat::JsonTtlv | ExportKeyFormat::Raw | ExportKeyFormat::Base64 => {
                (None, false)
            }
            ExportKeyFormat::Sec1Pem => (Some(KeyFormatType::ECPrivateKey), true),
            ExportKeyFormat::Sec1Der => (Some(KeyFormatType::ECPrivateKey), false),
            ExportKeyFormat::Pkcs1Pem => (Some(KeyFormatType::PKCS1), true),
            ExportKeyFormat::Pkcs1Der => (Some(KeyFormatType::PKCS1), false),
            ExportKeyFormat::Pkcs8Pem | ExportKeyFormat::SpkiPem => {
                (Some(KeyFormatType::PKCS8), true)
            }
            ExportKeyFormat::Pkcs8Der | ExportKeyFormat::SpkiDer => {
                (Some(KeyFormatType::PKCS8), false)
            }
        };

        let encode_to_ttlv = self.key_format == ExportKeyFormat::JsonTtlv;

        let wrapping_cryptographic_parameters =
            self.wrapping_algorithm
                .as_ref()
                .map(|wrapping_algorithm| match wrapping_algorithm {
                    WrappingAlgorithm::NistKeyWrap => CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        block_cipher_mode: Some(BlockCipherMode::NISTKeyWrap),
                        ..CryptographicParameters::default()
                    },
                    WrappingAlgorithm::AesGCM => CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        block_cipher_mode: Some(BlockCipherMode::GCM),
                        ..CryptographicParameters::default()
                    },
                    WrappingAlgorithm::RsaPkcsV15 => CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                        padding_method: Some(PaddingMethod::PKCS1v15),
                        hashing_algorithm: Some(HashingAlgorithm::SHA256),
                        ..CryptographicParameters::default()
                    },
                    WrappingAlgorithm::RsaOaep => CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                        padding_method: Some(PaddingMethod::OAEP),
                        hashing_algorithm: Some(HashingAlgorithm::SHA256),
                        ..CryptographicParameters::default()
                    },
                    WrappingAlgorithm::RsaAesKeyWrap => CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        padding_method: Some(PaddingMethod::OAEP),
                        hashing_algorithm: Some(HashingAlgorithm::SHA256),
                        ..CryptographicParameters::default()
                    },
                });

        // export the object
        let (id, object, _) = export_object(
            kms_rest_client,
            &id_or_tags,
            ExportObjectParams {
                unwrap: self.unwrap,
                wrapping_key_id: self.wrap_key_id.as_deref(),
                allow_revoked: self.allow_revoked,
                key_format_type,
                encode_to_ttlv,
                wrapping_cryptographic_parameters,
                authenticated_encryption_additional_data: self
                    .authenticated_additional_data
                    .clone(),
            },
        )
        .await?;

        // write the object to a file
        if self.key_format == ExportKeyFormat::JsonTtlv {
            // save it to a file
            write_kmip_object_to_file(&object, &self.key_file)?;
        } else if self.key_format == ExportKeyFormat::Base64 {
            // export the key bytes in base64
            let base64_key = base64::engine::general_purpose::STANDARD
                .encode(object.key_block()?.key_bytes()?)
                .to_lowercase();
            write_bytes_to_file(base64_key.as_bytes(), &self.key_file)?;
        } else {
            // export the bytes only
            let bytes = {
                let mut bytes = object.key_block()?.key_bytes()?;
                if encode_to_pem {
                    bytes = der_to_pem(
                        bytes.as_slice(),
                        key_format_type.context(
                            "Server Error: the Key Format Type should be known at this stage",
                        )?,
                        object.object_type(),
                    )?;
                }
                bytes
            };
            write_bytes_to_file(&bytes, &self.key_file)?;
        }

        let stdout = format!(
            "The key {} of type {} was exported to {:?}",
            &id,
            object.object_type(),
            &self.key_file
        );
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_unique_identifier(id);
        stdout.write()?;

        Ok(())
    }
}
