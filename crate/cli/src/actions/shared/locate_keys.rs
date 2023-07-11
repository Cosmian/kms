use std::ffi::OsString;

use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    Parser,
};
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::Locate,
    kmip_types::{Attributes, CryptographicAlgorithm},
};
use cosmian_kms_client::KmsRestClient;
use strum::IntoEnumIterator;

use crate::{
    actions::shared::utils::{export_object, write_bytes_to_file, write_kmip_object_to_file},
    cli_bail,
    error::CliError,
};

/// Locate Objects inside the KMS
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct LocateKeysAction {
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
}

impl LocateKeysAction {
    /// Export a key from the KMS
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        // TODO make the Object Type selectable
        let attributes = Attributes::new(ObjectType::SymmetricKey);

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
