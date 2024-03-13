use std::path::PathBuf;

use clap::Parser;

use cosmian_kms_client::{export_object, KmsRestClient};
use cosmian_kms_client::{
    cosmian_kmip::{kmip::kmip_types::KeyFormatType, result::KmipResultHelper},
    KmsRestClient,
};

use crate::{
    actions::shared::utils::{der_to_pem, write_bytes_to_file, write_kmip_object_to_file},
    cli_bail,
    error::CliError,
};

#[derive(clap::ValueEnum, Debug, Clone, PartialEq, Eq)]
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
    Raw,
}

/// Export a key from the KMS
///
/// If not format is specified, the key is exported as a json-ttlv with a
/// `KeyFormatType` that follows the section 4.26 of the KMIP specification.
/// https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html#_Toc57115585
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
            ExportKeyFormat::JsonTtlv => (None, false),
            ExportKeyFormat::Sec1Pem => (Some(KeyFormatType::ECPrivateKey), true),
            ExportKeyFormat::Sec1Der => (Some(KeyFormatType::ECPrivateKey), false),
            ExportKeyFormat::Pkcs1Pem => (Some(KeyFormatType::PKCS1), true),
            ExportKeyFormat::Pkcs1Der => (Some(KeyFormatType::PKCS1), false),
            ExportKeyFormat::Pkcs8Pem => (Some(KeyFormatType::PKCS8), true),
            ExportKeyFormat::Pkcs8Der => (Some(KeyFormatType::PKCS8), false),
            ExportKeyFormat::SpkiPem => (Some(KeyFormatType::PKCS8), true),
            ExportKeyFormat::SpkiDer => (Some(KeyFormatType::PKCS8), false),
            // For Raw: use the default format then do the local extraction of the bytes
            ExportKeyFormat::Raw => (None, false),
        };

        // export the object
        let (object, _) = export_object(
            kms_rest_client,
            &id,
            self.unwrap,
            self.wrap_key_id.as_deref(),
            self.allow_revoked,
            key_format_type,
        )
        .await?;

        // write the object to a file
        if self.key_format != ExportKeyFormat::JsonTtlv {
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
