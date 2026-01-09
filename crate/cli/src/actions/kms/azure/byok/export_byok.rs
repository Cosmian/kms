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
use serde_json::json;

use crate::{
    actions::kms::{attributes::get_attributes, console},
    cli_bail,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Wrap a KMS key with an Azure Key Encryption Key (KEK),
/// previously imported using the `cosmian kms azure byok import` command.
/// Generate the `.byok` file that can be used to import the KMS key into Azure Key Vault.
/// See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification>
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ExportByokAction {
    /// The unique ID of the KMS private key that will be wrapped and then exported
    #[clap(required = true)]
    pub(crate) wrapped_key_id: String,

    /// The Azure KEK ID in this KMS.
    #[clap(required = true)]
    pub(crate) kek_id: String,

    /// The file path to export the `.byok` file to.
    /// If not specified, the file will be called `<wrapped_key_id>.byok`
    #[clap(required = false)]
    pub(crate) byok_file: Option<PathBuf>,
}

impl ExportByokAction {
    pub async fn run(&self, kms_client: KmsClient) -> KmsCliResult<()> {
        // Recover the attributes of the KEK key
        let (_kek_id, kek_attributes) =
            get_attributes(&kms_client, &self.kek_id, &[Tag::Tag], &[]).await?;

        let tags: Vec<String> = serde_json::from_value(
            kek_attributes
                .get("Tag")
                .context(
                    "The KEK is not an Azure Key Encryption Key: no tags. Import it using the \
                     `cosmian kms azure byok import` command.",
                )?
                .clone(),
        )?;

        if !tags.contains(&"azure".to_owned()) {
            cli_bail!(
                "The KEK is not an Azure Key Encryption Key: missing `azure` tag. Import it using \
                 the `cosmian kms azure byok import` command."
            );
        }

        let kid = tags.iter().find(|t| t.starts_with("kid:")).context(
            "The KEK is not an Azure Key Encryption Key: Azure kid not found. Import it using the \
             `cosmian kms azure byok import` command.",
        )?[4..]
            .to_string();

        // Export the key wrapped with the KEK
        // export the object
        let export_params = ExportObjectParams {
            unwrap: true,
            wrapping_key_id: Some(&self.kek_id),
            allow_revoked: false,
            key_format_type: None,
            encode_to_ttlv: false,
            wrapping_cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                padding_method: Some(PaddingMethod::None),
                hashing_algorithm: Some(HashingAlgorithm::SHA1),
                ..CryptographicParameters::default()
            }),
            authenticated_encryption_additional_data: None,
        };

        let (_id, object, _) =
            export_object(&kms_client, &self.wrapped_key_id, export_params).await?;

        // Recover the wrapped bytes from the KeyBlock
        let key_block = object.key_block()?;
        let Some(KeyValue::ByteString(wrapped_key)) = &key_block.key_value else {
            cli_bail!("The wrapped key should be a byte string");
        };

        // Generate .byok file
        let byok_value = json!({
            "schema_version": "1.0.0",
            "header":
            {
                "kid": kid,
                "alg": "dir",
                "enc": "CKM_RSA_AES_KEY_WRAP"
            },
            "ciphertext": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wrapped_key), // TODO: check the docs, why use URL_SAFE_NO_PAD here instead of standard one
            "generator": "Cosmian_KMS;v5"
        });
        // write byok file
        // Determine the name of the byok file
        let byok_file = self
            .byok_file
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("{}.byok", self.wrapped_key_id)));
        fs::write(&byok_file, byok_value.to_string())?;

        let stdout = console::Stdout::new(&format!(
            "The byok file was written to {} for key {}.",
            byok_file.display(),
            self.wrapped_key_id
        ));
        stdout.write()?;

        Ok(())
    }
}
