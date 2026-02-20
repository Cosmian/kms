use std::path::PathBuf;

use crate::{
    actions::kms::{
        aws::byok::wrapping_algorithms::AwsKmsWrappingAlgorithm,
        shared::ImportSecretDataOrKeyAction,
    },
    error::{KmsCliError, result::KmsCliResult},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use clap::{ArgGroup, Parser};
use cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier;
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

/// Import an AWS Key Encryption Key (KEK) into the KMS.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
#[clap(group(ArgGroup::new("kek_input").required(true).args(["kek_base64", "kek_file"])))] // At least one of kek_file or kek_blob must be provided
pub struct ImportKekAction {
    /// The RSA Key Encryption public key (the KEK) as a base64-encoded string
    #[clap(
        short = 'b',
        long,
        value_parser = clap::builder::ValueParser::new(validate_kek_base64),
        group = "kek_input"
    )]
    pub(crate) kek_base64: Option<String>,

    /// In case of KEK provided as a file blob.
    #[clap(short = 'f', long, group = "kek_input")]
    pub(crate) kek_file: Option<PathBuf>,

    #[clap(short = 'w', long, required = true)]
    pub(crate) wrapping_algorithm: AwsKmsWrappingAlgorithm,

    /// The Amazon Resource Name (key ARN) of the KMS key. It's recommended to provide it for an easier export later.
    #[clap(short = 'a', long, required = false)]
    pub(crate) key_arn: Option<String>,

    /// The unique ID of the key in this KMS; a random UUID
    /// is generated if not specified.
    #[clap(short = 'i', long, required = false)]
    pub(crate) key_id: Option<String>,
}

impl ImportKekAction {
    pub async fn run(&self, kms_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        // build tags
        let mut tags = vec![
            "aws".to_owned(),
            format!("wrapping_algorithm:{}", self.wrapping_algorithm),
        ];
        if let Some(arn) = &self.key_arn {
            tags.push(format!("key_arn:{arn}"));
        }

        let import_action = ImportSecretDataOrKeyAction {
            key_file: match (&self.kek_file, &self.kek_base64) {
                (Some(file), _) => file.clone(),
                (None, Some(base64_str)) => {
                    let temp_path = std::env::temp_dir().join(format!("{}", uuid::Uuid::new_v4()));
                    std::fs::write(&temp_path, BASE64_STANDARD.decode(base64_str)?)?;
                    temp_path
                }
                (None, None) => {
                    return Err(KmsCliError::Default(
                        "KEK file or base64 data must be provided".to_owned(),
                    ));
                }
            },
            key_id: self.key_id.clone(),
            key_format: ImportKeyFormat::Pkcs8Pub,
            tags,
            key_usage: Some(vec![KeyUsage::WrapKey, KeyUsage::Encrypt]),
            replace_existing: true,
            ..Default::default()
        };

        import_action.run(kms_client).await
    }
}
