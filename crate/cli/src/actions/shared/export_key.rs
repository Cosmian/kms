use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::{kmip::kmip_types::KeyFormatType, result::KmipResultHelper};
use cosmian_kms_client::KmsRestClient;

use crate::{
    actions::shared::utils::{
        der_to_pem, export_object, write_bytes_to_file, write_kmip_object_to_file,
    },
    cli_bail,
    error::CliError,
};

#[derive(clap::ValueEnum, Debug, Clone, PartialEq)]
pub enum KeyFormat {
    JsonTtlv,
    Sec1Pem,
    Sec1Der,
    Pkcs1Pem,
    Pkcs1Der,
    Pkcs8Pem,
    Pkcs8Der,
    SpkiPem,
    SpkiDer,
    Raw,
}

/// Export a key from the KMS
///
/// The key is exported in JSON KMIP TTLV format
/// unless the `--bytes` option is specified, in which case
/// the key bytes are exported without metadata, such as
///  - the links between the keys in a pair
///  - other metadata: policies, etc.
/// Key bytes are sufficient to perform local encryption or decryption.
///
/// The key can be wrapped or unwrapped when exported.
/// If nothing is specified, it is returned as it is stored.
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
    #[clap(long = "key-format", short = 'f', default_value = "json-ttlv")]
    key_format: KeyFormat,

    /// Unwrap the key if it is wrapped before export
    #[clap(
        long = "unwrap",
        short = 'u',
        default_value = "false",
        group = "wrapping"
    )]
    unwrap: bool,

    /// The id of key/certificate to use to wrap this key before export
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
    #[clap(long = "allow-revoked", short = 'i', default_value = "false")]
    allow_revoked: bool,
}

impl ExportKeyAction {
    /// Export a key from the KMS
    pub async fn run(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        let id = if let Some(key_id) = &self.key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --key-id or one or more --tag must be specified")
        };

        let (key_format_type, encode_to_pem) = match self.key_format {
            KeyFormat::JsonTtlv => (None, false),
            KeyFormat::Sec1Pem => (Some(KeyFormatType::ECPrivateKey), true),
            KeyFormat::Sec1Der => (Some(KeyFormatType::ECPrivateKey), false),
            KeyFormat::Pkcs1Pem => (Some(KeyFormatType::PKCS1), true),
            KeyFormat::Pkcs1Der => (Some(KeyFormatType::PKCS1), false),
            KeyFormat::Pkcs8Pem => (Some(KeyFormatType::PKCS8), true),
            KeyFormat::Pkcs8Der => (Some(KeyFormatType::PKCS8), false),
            KeyFormat::SpkiPem => (Some(KeyFormatType::PKCS8), true),
            KeyFormat::SpkiDer => (Some(KeyFormatType::PKCS8), false),
            // For Raw: use the default format then do the local extraction of the bytes
            KeyFormat::Raw => (None, false),
        };

        // export the object
        let object = export_object(
            kms_rest_client,
            &id,
            self.unwrap,
            self.wrap_key_id.as_deref(),
            self.allow_revoked,
            key_format_type,
        )
        .await?;

        // write the object to a file
        if self.key_format != KeyFormat::JsonTtlv {
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
                    )?
                }
                bytes
            };
            write_bytes_to_file(&bytes, &self.key_file)?;
        } else {
            // save it to a file
            write_kmip_object_to_file(&object, &self.key_file)?;
        }

        println!(
            "The key {} of type {} was exported to {:?}",
            &id,
            object.object_type(),
            &self.key_file
        );
        Ok(())
    }
}
