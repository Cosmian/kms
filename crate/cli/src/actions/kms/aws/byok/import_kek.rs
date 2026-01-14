use std::path::PathBuf;

use crate::{
    actions::kms::{
        aws::byok::wrapping_algorithms::WrappingAlgorithm, shared::ImportSecretDataOrKeyAction,
    },
    error::result::KmsCliResult,
};
use base64::{Engine, prelude::BASE64_STANDARD};
use clap::{ArgGroup, Parser};
use cosmian_kms_client::{
    KmsClient,
    reexport::cosmian_kms_client_utils::import_utils::{ImportKeyFormat, KeyUsage},
};

/// Validate that the string is valid base64 and its decoded length is between 1 and 4096 bytes.
fn validate_kek_base64(s: &str) -> Result<String, String> {
    let decoded = BASE64_STANDARD
        .decode(s)
        .map_err(|e| format!("Invalid base64 encoding: {e}"))?;

    if decoded.is_empty() {
        return Err("KEK decoded data is empty".to_owned());
    }

    if decoded.len() > 4096 {
        return Err(format!(
            "KEK decoded data exceeds maximum length of 4096 bytes (got {})",
            decoded.len()
        ));
    }
    Ok(s.to_owned())
}
/// Import into the KMS an RSA Key Encryption Key (KEK) generated on Azure Key Vault.
/// See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification#generate-kek>
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
#[clap(group(ArgGroup::new("kek_input").required(true).args(["kek_file", "kek_blob"])))] // At least one of kek_file or kek_blob must be provided
pub struct ImportKekAction {
    /// The RSA Key Encryption public key (the KEK) as a base64-encoded string
    #[clap(long,value_parser = clap::builder::ValueParser::new(validate_kek_base64))]
    pub(crate) kek_base64: Option<String>,

    /// In case of KEK provided as a file blob.
    #[clap(long)]
    pub(crate) kek_file: Option<PathBuf>,

    /// The Amazon Resource Name (key ARN) of the KMS key.
    #[clap(required = true, verbatim_doc_comment)]
    pub(crate) key_arn: String,

    #[clap(required = true, verbatim_doc_comment)]
    pub(crate) wrapping_algorithm: WrappingAlgorithm,

    /// The unique ID of the key in this KMS; a random UUID
    /// is generated if not specified.
    #[clap(required = false)]
    pub(crate) key_id: Option<String>,
}

impl ImportKekAction {
    #[allow(clippy::expect_used, clippy::unwrap_used)] // TODO
    pub async fn run(&self, kms_client: KmsClient) -> KmsCliResult<()> {
        let import_action = ImportSecretDataOrKeyAction {
            key_file: self
                .kek_file
                .clone()
                .or_else(|| {
                    self.kek_base64.as_ref().map(|base64_str| {
                        let temp_path =
                            std::env::temp_dir().join(format!("{}", uuid::Uuid::new_v4()));
                        std::fs::write(&temp_path, BASE64_STANDARD.decode(base64_str).unwrap())
                            .unwrap(); // TODO
                        temp_path
                    })
                })
                .expect("msg"), // TODO
            key_id: self.key_id.clone(),
            key_format: ImportKeyFormat::Pkcs8Pub,
            tags: vec![
                "aws".to_owned(),
                format!("key_arn:{}", self.key_arn),
                format!("wrapping_algorithm:{}", self.wrapping_algorithm),
            ],
            key_usage: Some(vec![KeyUsage::WrapKey, KeyUsage::Encrypt]),
            replace_existing: true,
            ..Default::default()
        };

        import_action.run(kms_client).await.map(|_| ())
    }
}
