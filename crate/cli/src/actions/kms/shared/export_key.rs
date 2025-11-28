use std::path::PathBuf;

use base64::Engine;
use clap::Parser;
use cosmian_kms_client::{
    ExportObjectParams, KmsClient, export_object,
    kmip_2_1::{
        kmip_data_structures::{KeyMaterial, KeyValue},
        kmip_objects::Object,
        kmip_types::UniqueIdentifier,
    },
    reexport::cosmian_kms_client_utils::export_utils::{
        ExportKeyFormat, WrappingAlgorithm, der_to_pem, prepare_key_export_elements,
    },
    write_bytes_to_file, write_kmip_object_to_file,
};

use super::get_key_uid;
use crate::{
    actions::kms::{console, labels::KEY_ID},
    error::{
        KmsCliError,
        result::{KmsCliResult, KmsCliResultHelper},
    },
};

/// Export a key or secret data from the KMS
///
/// If not format is specified, the key or secret data is exported as a json-ttlv with a
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
#[derive(Parser, Default, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ExportSecretDataOrKeyAction {
    /// The file to export the key to
    #[clap(required = true)]
    pub key_file: PathBuf,

    /// The key or secret data unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub key_id: Option<String>,

    /// Tag to use to retrieve the key when no key or secret data id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub tags: Option<Vec<String>>,

    /// The format of the key
    ///  - `json-ttlv` [default]. It should be the format to use to later re-import the key
    ///  - `sec1-pem` and `sec1-der`only apply to NIST EC private keys (Not Curve25519 or X448)
    ///  - `pkcs1-pem` and `pkcs1-der` only apply to RSA private and public keys
    ///  - `pkcs8-pem` and `pkcs8-der` only apply to RSA and EC private keys
    ///  - `raw` returns the raw bytes of
    ///       - symmetric keys
    ///       - Covercrypt keys
    ///       - wrapped keys
    ///       - secret data
    #[clap(
        long = "key-format",
        short = 'f',
        default_value = "json-ttlv",
        verbatim_doc_comment
    )]
    pub export_format: ExportKeyFormat,

    /// Unwrap the key if it is wrapped before export
    #[clap(
        long = "unwrap",
        short = 'u',
        default_value = "false",
        group = "wrapping"
    )]
    pub unwrap: bool,

    /// The id of the key/certificate (a.k.a. Key Encryption Key - KEK)
    /// to use to wrap this key before export
    #[clap(
        long = "wrap-key-id",
        short = 'w',
        required = false,
        group = "wrapping"
    )]
    pub wrap_key_id: Option<String>,

    /// Allow exporting revoked and destroyed keys.
    /// The user must be the owner of the key.
    /// Destroyed keys have their key material removed.
    #[clap(
        long = "allow-revoked",
        short = 'i',
        default_value = "false",
        verbatim_doc_comment
    )]
    pub allow_revoked: bool,

    /// Wrapping algorithm to use when exporting the key
    /// The possible wrapping algorithms are
    ///  - using a symmetric KEK:
    ///     - `nist-key-wrap` (default - a.k.a RFC 5649, `CKM_AES_KEY_WRAP_PAD`)
    ///     - `aes-gcm`
    ///  - using an RSA KEK:
    ///     - `rsa-oaep` (default - CKM-RSA-OAEP)
    ///     - `rsa-aes-key-wrap` (CKM-RSA-AES-KEY-WRP)
    ///     - `rsa-pkcs-v15` (CKM-RSA v1.5)
    ///
    /// The RSA algorithms use SHA256 by default. To use SHA1,
    /// use the version with -sha1 suffix (e.g. `rsa-aes-key-wrap-sha1`).
    #[clap(
        long = "wrapping-algorithm",
        short = 'm',
        default_value = None,
        verbatim_doc_comment
    )]
    pub wrapping_algorithm: Option<WrappingAlgorithm>,

    /// Authenticated encryption additional data
    /// Only available for AES GCM wrapping
    #[clap(
        long = "authenticated-additional-data",
        short = 'd',
        default_value = None,
    )]
    pub authenticated_additional_data: Option<String>,
}

impl ExportSecretDataOrKeyAction {
    /// Export a key or secret data from the KMS
    ///
    /// # Errors
    ///
    /// This function can return an error if:
    ///
    /// - Either `--key-id` or one or more `--tag` is not specified.
    /// - There is a server error while exporting the object.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        let (key_format_type, encode_to_pem, encode_to_ttlv, wrapping_cryptographic_parameters) =
            prepare_key_export_elements(&self.export_format, &self.wrapping_algorithm)?;

        // export the object
        let export_params = ExportObjectParams {
            unwrap: self.unwrap,
            wrapping_key_id: self.wrap_key_id.as_deref(),
            allow_revoked: self.allow_revoked,
            key_format_type,
            encode_to_ttlv,
            wrapping_cryptographic_parameters,
            authenticated_encryption_additional_data: self.authenticated_additional_data.clone(),
        };

        let (id, object, _) = export_object(&kms_rest_client, &id, export_params).await?;

        // write the object to a file
        if self.export_format == ExportKeyFormat::JsonTtlv {
            // save it to a file
            write_kmip_object_to_file(&object, &self.key_file)?;
        } else if self.export_format == ExportKeyFormat::Base64 {
            // export the key bytes in base64
            let base64_key = base64::engine::general_purpose::STANDARD
                .encode(get_object_bytes(&object)?)
                .to_lowercase();
            write_bytes_to_file(base64_key.as_bytes(), &self.key_file)?;
        } else {
            // export the bytes only
            let bytes = {
                let mut bytes = get_object_bytes(&object)?;
                if encode_to_pem {
                    bytes = der_to_pem(
                        bytes.as_slice(),
                        key_format_type.context(
                            "Server Error: the Key Format Type should be known at this stage",
                        )?,
                        object.object_type(),
                    )?
                    .to_vec();
                }
                bytes
            };
            write_bytes_to_file(&bytes, &self.key_file)?;
        }

        let stdout = format!(
            "The key {} of type {} was exported to {:?}",
            &id,
            object.object_type(),
            self.key_file.display()
        );
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_unique_identifier(&id);
        stdout.write()?;

        Ok(id)
    }
}

fn get_object_bytes(object: &Object) -> KmsCliResult<Vec<u8>> {
    // OpaqueObject does not have a KeyBlock; return its raw bytes directly
    if let Object::OpaqueObject(o) = object {
        return Ok(o.opaque_data_value.clone());
    }
    let key_block = object.key_block()?;
    match key_block
        .key_value
        .as_ref()
        .ok_or_else(|| KmsCliError::Default("Key value is missing".to_owned()))?
    {
        KeyValue::ByteString(v) => Ok(v.to_vec()),
        KeyValue::Structure { key_material, .. } => match key_material {
            KeyMaterial::ByteString(v) => Ok(v.to_vec()),
            KeyMaterial::TransparentSymmetricKey { key } => Ok(key.to_vec()),
            KeyMaterial::TransparentECPrivateKey { .. }
            | KeyMaterial::TransparentECPublicKey { .. } => key_block
                .ec_raw_bytes()
                .map(|v| v.to_vec())
                .map_err(Into::into),
            x => Err(KmsCliError::Default(format!(
                "Unsupported key material type: {x:?}"
            ))),
        },
    }
}
