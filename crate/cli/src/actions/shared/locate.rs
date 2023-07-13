use std::ffi::OsString;

use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    Parser,
};
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::Locate,
    kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType},
};
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::tagging::set_tags;
use strum::IntoEnumIterator;

use crate::error::CliError;

/// Locate Objects inside the KMS
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct LocateObjectsAction {
    /// User tags or system tags to locate the object.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Option<Vec<String>>,

    /// Cryptographic algorithm
    /// in lowercase as specified by KMIP 2.1 + covercrypt
    ///
    /// Possible values include "covercrypt", "ecdh", "chacha20poly1305", "aes", "ed25519"
    #[clap(
        long = "algorithm",
        short = 'a',
        value_parser = CryptographicAlgorithmParser
    )]
    cryptographic_algorithm: Option<CryptographicAlgorithm>,

    /// Cryptographic length (e.g. key size) in bits
    #[clap(long = "cryptographic_length", short = 'l')]
    cryptographic_length: Option<i32>,

    /// key format type as specified by KMIP 2.1 + covercrypt: CoverCryptSecretKey and CoverCryptPublicKey
    #[clap(long = "key_format_type", short = 'f',
        value_parser = KeyFormatTypeParser)]
    key_format_type: Option<KeyFormatType>,
}

impl LocateObjectsAction {
    /// Export a key from the KMS
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        // the object type is ignored
        let mut attributes = Attributes::new(ObjectType::SecretData);

        if let Some(crypto_algo) = self.cryptographic_algorithm {
            attributes.cryptographic_algorithm = Some(crypto_algo);
        }

        if let Some(cryptographic_length) = self.cryptographic_length {
            attributes.cryptographic_length = Some(cryptographic_length);
        }

        if let Some(key_format_type) = self.key_format_type {
            attributes.key_format_type = Some(key_format_type);
        }

        if let Some(tags) = &self.tags {
            set_tags(&mut attributes, tags)?;
        }

        let locate = Locate {
            maximum_items: None,
            offset_items: None,
            storage_status_mask: None,
            object_group_member: None,
            attributes,
        };

        let response = client_connector.locate(locate).await?;
        if let Some(identifiers) = response.unique_identifiers {
            for identifier in identifiers {
                println!("{}", identifier);
            }
        } else {
            println!("No objects found");
        }

        Ok(())
    }
}

/// Parse a string entered by the user into a CryptographicAlgorithm
#[derive(Clone)]
struct CryptographicAlgorithmParser;

impl clap::builder::TypedValueParser for CryptographicAlgorithmParser {
    type Value = CryptographicAlgorithm;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        CryptographicAlgorithm::iter()
            .find(|algo| {
                OsString::from(algo.to_string().to_lowercase()) == value.to_ascii_lowercase()
            })
            .ok_or_else(|| {
                let mut err = clap::Error::new(ErrorKind::ValueValidation).with_cmd(cmd);
                if let Some(arg) = arg {
                    err.insert(
                        ContextKind::InvalidArg,
                        ContextValue::String(arg.to_string()),
                    );
                }
                err.insert(
                    ContextKind::InvalidValue,
                    ContextValue::String(value.to_string_lossy().to_string()),
                );
                err.insert(
                    ContextKind::SuggestedValue,
                    ContextValue::Strings(
                        CryptographicAlgorithm::iter()
                            .map(|algo| algo.to_string().to_lowercase())
                            .collect::<Vec<String>>(),
                    ),
                );
                err
            })
    }
}

/// Parse a string entered by the user into a KeyFormatType
#[derive(Clone)]
struct KeyFormatTypeParser;

impl clap::builder::TypedValueParser for KeyFormatTypeParser {
    type Value = KeyFormatType;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        KeyFormatType::iter()
            .find(|algo| {
                OsString::from(algo.to_string().to_lowercase()) == value.to_ascii_lowercase()
            })
            .ok_or_else(|| {
                let mut err = clap::Error::new(ErrorKind::ValueValidation).with_cmd(cmd);
                if let Some(arg) = arg {
                    err.insert(
                        ContextKind::InvalidArg,
                        ContextValue::String(arg.to_string()),
                    );
                }
                err.insert(
                    ContextKind::InvalidValue,
                    ContextValue::String(value.to_string_lossy().to_string()),
                );
                err.insert(
                    ContextKind::SuggestedValue,
                    ContextValue::Strings(
                        KeyFormatType::iter()
                            .map(|algo| algo.to_string().to_lowercase())
                            .collect::<Vec<String>>(),
                    ),
                );
                err
            })
    }
}
