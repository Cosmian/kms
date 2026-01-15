use std::{fs, path::PathBuf};

use base64::Engine;
use clap::Parser;
use cosmian_kmip::{
    kmip_0::kmip_types::{HashingAlgorithm, PaddingMethod},
    kmip_2_1::{
        kmip_data_structures::KeyValue,
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, Tag},
    },
};
use cosmian_kms_client::{ExportObjectParams, KmsClient, export_object};
use cosmian_logger::warn;

use crate::{
    actions::kms::{
        attributes::get_attributes, aws::byok::wrapping_algorithms::AwsKmsWrappingAlgorithm,
        console,
    },
    cli_bail,
    error::{
        KmsCliError,
        result::{KmsCliResult, KmsCliResultHelper},
    },
};

/// Wrap a KMS key with an AWS Key Encryption Key (KEK),
/// previously imported using the `cosmian kms aws byok import` command.
/// Generate the `.byok` file that can be used to import the KMS key into AWS KMS.
/// See: <https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html>
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ExportByokAction {
    /// The unique ID of the KMS private key that will be wrapped and then exported
    #[clap(required = true)]
    pub(crate) key_id: String,

    /// The AWS KEK ID in this KMS.
    #[clap(required = true)]
    pub(crate) kek_id: String,

    /// The file path containing the import token previously generated when importing the KEK.
    /// This file isn't red and neither used by the KMS, it's simply for providing copy-paste ready output for
    /// aws cli users upon a successful key material wrapping
    #[clap(required = false)]
    pub(crate) token_file_path: Option<PathBuf>,

    /// If not specified, a base64 encoded blob containing the key material will be printed to stdout.
    #[clap(required = false)]
    pub(crate) output_file_path: Option<PathBuf>,
}

impl ExportByokAction {
    #[allow(clippy::or_fun_call)]
    pub async fn run(&self, kms_client: KmsClient) -> KmsCliResult<String> {
        // Recover the attributes of the KEK key
        let (_kek_id, kek_attributes) =
            get_attributes(&kms_client, &self.kek_id, &[Tag::Tag], &[]).await?;
        let kek_tag_error = |msg: &str| -> String {
            format!(
                "The KEK is not an AWS Key Encryption Key: {msg}. Import it using the \
                 `cosmian kms aws byok import` command."
            )
        };

        let tags: Vec<String> = serde_json::from_value(
            kek_attributes
                .get("Tag")
                .context(&kek_tag_error("no tags"))?
                .clone(),
        )?;

        if !tags.contains(&"aws".to_owned()) {
            return Err(KmsCliError::InconsistentOperation(kek_tag_error(
                "missing `aws` tag",
            )));
        }

        let key_arn = tags
            .iter()
            .find(|t| t.starts_with("key_arn:"))
            .context(&kek_tag_error("AWS key ARN not found"))?
            .strip_prefix("key_arn:")
            .ok_or(KmsCliError::Default(kek_tag_error("invalid arn tag")))?;

        let wrapping_algorithm_str = tags
            .iter()
            .find(|t| t.starts_with("wrapping_algorithm:"))
            .context(&kek_tag_error("wrapping algorithm not found"))?
            .strip_prefix("wrapping_algorithm:")
            .ok_or(KmsCliError::Default(kek_tag_error(
                "invalid wrapping algorithm tag",
            )))?
            .parse::<AwsKmsWrappingAlgorithm>()
            .context(&kek_tag_error("invalid wrapping algorithm tag"))?;

        let wrapping_cryptographic_parameters = Some(match wrapping_algorithm_str {
            AwsKmsWrappingAlgorithm::RsaesOaepSha1 => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                padding_method: Some(PaddingMethod::OAEP),
                hashing_algorithm: Some(HashingAlgorithm::SHA1),
                ..CryptographicParameters::default()
            },
            AwsKmsWrappingAlgorithm::RsaesOaepSha256 => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                padding_method: Some(PaddingMethod::OAEP),
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            },
            AwsKmsWrappingAlgorithm::RsaAesKeyWrapSha1 => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                padding_method: Some(PaddingMethod::OAEP),
                hashing_algorithm: Some(HashingAlgorithm::SHA1),
                ..CryptographicParameters::default()
            },
            AwsKmsWrappingAlgorithm::RsaAesKeyWrapSha256 => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                padding_method: Some(PaddingMethod::OAEP),
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            },
            // SM2PKE: SM2 public key encryption (China Regions only)
            // Supported for: RSA private keys, ECC private keys, SM2 private keys
            AwsKmsWrappingAlgorithm::Sm2Pke => {
                warn!(
                    "This encrypted key material can only be imported into AWS KMS in China Regions."
                );
                CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::SM2),
                    padding_method: None, // SM2 uses its own encryption scheme per GM/T 0003.4-2012
                    ..CryptographicParameters::default()
                }
            }
        });

        // Export the key wrapped with the KEK
        // export the object
        let export_params = ExportObjectParams {
            unwrap: false,
            wrapping_key_id: Some(&self.kek_id),
            allow_revoked: false,
            key_format_type: None,
            encode_to_ttlv: false,
            wrapping_cryptographic_parameters,
            authenticated_encryption_additional_data: None,
        };

        let (_, object, _) = export_object(&kms_client, &self.key_id, export_params).await?;

        // Recover the wrapped bytes from the KeyBlock
        let key_block = object.key_block()?;
        let Some(KeyValue::ByteString(wrapped_key)) = &key_block.key_value else {
            cli_bail!("The wrapped key should be a byte string");
        };
        let b64_key = base64::engine::general_purpose::STANDARD.encode(wrapped_key);

        if let Some(file_path) = &self.output_file_path {
            fs::write(file_path, wrapped_key)?;

            let stdout = console::Stdout::new(&format!(
                "The encrypted key material ({} bytes) was written to {} for key {}.\n\n\
                 To import into AWS KMS, run:\n\
                 aws kms import-key-material \\\n\
                     --key-id {} \\\n\
                     --encrypted-key-material fileb://{} \\\n\
                     --import-token fileb://{} \\\n\
                     --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE",
                wrapped_key.len(),
                file_path.display(),
                self.key_id,
                key_arn,
                file_path.display(),
                self.token_file_path.as_ref().map_or_else(
                    || "<IMPORT_TOKEN_FILE>".to_owned(),
                    |p| { p.display().to_string() }
                )
            ));
            stdout.write()?;
        } else {
            let stdout = console::Stdout::new(&b64_key);
            stdout.write()?;
        }
        Ok(b64_key)
    }
}
