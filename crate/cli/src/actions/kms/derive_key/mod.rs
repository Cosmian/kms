use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::DerivationParameters,
        kmip_objects::ObjectType,
        kmip_operations::{DeriveKey, DeriveKeyResponse},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, DerivationMethod, KeyFormatType,
            UniqueIdentifier,
        },
    },
};
use zeroize::Zeroizing;

use crate::{
    actions::kms::{console, mac::CHashingAlgorithm},
    error::{KmsCliError, result::KmsCliResult},
};

/// Derive a new key from an existing key
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct DeriveKeyAction {
    /// The unique identifier of the base key to derive from
    #[clap(long, short = 'k')]
    pub key_id: String,

    /// The derivation method to use (PBKDF2 or HKDF)
    #[clap(long, short = 'm', default_value = "PBKDF2")]
    pub derivation_method: String,

    /// Salt for key derivation (in hex format)
    #[clap(long , short = 's',
        value_parser = |s: &str| hex::decode(s).map(|_| s.to_string()).map_err(|e| format!("Invalid hex format: {}", e)))]
    pub salt: String,

    /// Number of iterations for PBKDF2 derivation
    #[clap(long, short = 'i', default_value = "4096")]
    pub iteration_count: i32,

    /// Initialization vector for derivation (in hex format)
    #[clap(long , short = 'v',
        value_parser = |s: &str| hex::decode(s).map(|_| s.to_string()).map_err(|e| format!("Invalid hex format: {}", e)))]
    pub initialization_vector: Option<String>,

    /// Digest algorithm for derivation
    #[clap(long, short = 'd', default_value = "SHA256")]
    pub digest_algorithm: CHashingAlgorithm,

    /// Length of the derived key in bits
    #[clap(long = "length", short = 'l', default_value = "256")]
    pub cryptographic_length: i32,

    /// Optional unique identifier for the derived key
    #[clap(long)]
    pub derived_key_id: Option<String>,
}

impl DeriveKeyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        // Parse derivation method
        let derivation_method = match self.derivation_method.to_uppercase().as_str() {
            "PBKDF2" => DerivationMethod::PBKDF2,
            "HKDF" => DerivationMethod::HKDF,
            _ => {
                return Err(KmsCliError::Default(format!(
                    "Unsupported derivation method: {}",
                    self.derivation_method
                )));
            }
        };

        // Decode salt from hex
        let salt = hex::decode(&self.salt)
            .map_err(|e| KmsCliError::Default(format!("Invalid salt hex format: {e}")))?;

        // Decode initialization vector if provided
        let initialization_vector = if let Some(iv_hex) = &self.initialization_vector {
            Some(hex::decode(iv_hex).map_err(|e| {
                KmsCliError::Default(format!("Invalid initialization vector hex format: {e}"))
            })?)
        } else {
            None
        };

        // Create derivation parameters
        let derivation_parameters = DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(self.digest_algorithm.clone().into()),
                ..Default::default()
            }),
            initialization_vector,
            derivation_data: if self.derivation_method.to_uppercase() == "HKDF" {
                // For HKDF, use a unique context based on the key ID and timestamp
                use std::time::{SystemTime, UNIX_EPOCH};
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let context = format!("CLI-HKDF-{}-{}", self.key_id, timestamp);
                Some(Zeroizing::new(context.into_bytes()))
            } else {
                // For PBKDF2, derivation_data is optional, so we can omit it
                None
            },
            salt: Some(salt),
            iteration_count: Some(self.iteration_count),
        };

        // Create attributes for the derived key
        let mut attributes = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(self.cryptographic_length),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Default::default()
        };

        // Only set unique_identifier if derived_key_id is provided
        if let Some(ref derived_key_id) = self.derived_key_id {
            attributes.unique_identifier =
                Some(UniqueIdentifier::TextString(derived_key_id.clone()));
        }

        // Create the DeriveKey request
        let derive_request = DeriveKey {
            object_type: ObjectType::SymmetricKey,
            object_unique_identifier: UniqueIdentifier::TextString(self.key_id.clone()),
            derivation_method,
            derivation_parameters,
            attributes,
        };

        // Call the KMS to derive the key
        let response: DeriveKeyResponse = kms_rest_client.derive_key(derive_request).await?;

        // Display the result
        console::Stdout::new(&format!(
            "DeriveKey operation successful. Derived key ID: {}",
            response.unique_identifier
        ))
        .write()?;

        Ok(())
    }
}
