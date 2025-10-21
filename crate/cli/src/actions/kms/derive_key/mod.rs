use clap::Parser;
use cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes, requests::create_secret_data_kmip_object,
};
use cosmian_kms_client::{
    KmsClient,
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes as KmipAttributes,
        kmip_data_structures::DerivationParameters,
        kmip_objects::ObjectType,
        kmip_operations::DeriveKey,
        kmip_types::{CryptographicParameters, DerivationMethod, KeyFormatType, UniqueIdentifier},
        requests::import_object_request,
    },
    reexport::cosmian_kms_client_utils::create_utils::{
        SymmetricAlgorithm, prepare_sym_key_elements,
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
    /// Mutually exclusive with --password
    #[clap(long, short = 'k', conflicts_with = "password")]
    pub key_id: Option<String>,

    /// UTF-8 password to use as base material for key derivation
    /// Will create a `SecretData` of type Password internally
    /// Mutually exclusive with --key-id
    #[clap(long, short = 'p', conflicts_with = "key_id")]
    pub password: Option<String>,

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

    /// The algorithm
    #[clap(
        long = "algorithm",
        short = 'a',
        required = false,
        default_value = "aes"
    )]
    pub algorithm: SymmetricAlgorithm,

    /// Length of the derived key in bits
    #[clap(long = "length", short = 'l', default_value = "256")]
    pub cryptographic_length: usize,

    /// Optional unique identifier for the derived key
    #[clap(long)]
    pub derived_key_id: Option<String>,
}

impl DeriveKeyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        // Validate that either key_id or password is provided
        if self.key_id.is_none() && self.password.is_none() {
            return Err(KmsCliError::Default(
                "Either --key-id or --password must be provided".to_owned(),
            ));
        }

        // Determine the base key identifier
        let base_key_id = if let Some(key_id) = &self.key_id {
            // Use existing key
            key_id.clone()
        } else if let Some(password) = &self.password {
            // Create SecretData from password
            let password_bytes = Zeroizing::from(password.as_bytes().to_vec());

            let secret_data_object = create_secret_data_kmip_object(
                password_bytes.as_slice(),
                cosmian_kmip::kmip_0::kmip_types::SecretDataType::Password,
                &Attributes::default(),
            )?;

            let import_request = import_object_request(
                None, // Let the server generate the ID
                secret_data_object,
                None,
                false,
                false,
                Vec::<String>::new(), // No tags for temporary password object
            );

            let import_response = kms_rest_client.import(import_request).await?;
            import_response.unique_identifier.to_string()
        } else {
            return Err(KmsCliError::Default(
                "Either key_id or password must be provided".to_owned(),
            ));
        };

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
                // For HKDF, use a unique context based on the key ID, timestamp, and random value
                use std::time::{SystemTime, UNIX_EPOCH};
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(); // Use nanoseconds for higher precision
                let random_id = uuid::Uuid::new_v4();
                let context = format!("CLI-HKDF-{base_key_id}-{timestamp}-{random_id}");
                Some(Zeroizing::new(context.into_bytes()))
            } else {
                // For PBKDF2, derivation_data is optional, so we can omit it
                None
            },
            salt: Some(salt),
            iteration_count: Some(self.iteration_count),
        };

        let (cryptographic_length, _, algorithm) =
            prepare_sym_key_elements(Some(self.cryptographic_length), &None, self.algorithm)
                .map_err(|e| KmsCliError::Default(format!("Invalid cryptographic length: {e}")))?;

        // Create attributes for the derived key
        let mut attributes = KmipAttributes {
            cryptographic_algorithm: Some(algorithm),
            cryptographic_length: Some(i32::try_from(cryptographic_length)?),
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
            object_unique_identifier: UniqueIdentifier::TextString(base_key_id),
            derivation_method,
            derivation_parameters,
            attributes,
        };

        // Call the KMS to derive the key
        let response = kms_rest_client.derive_key(derive_request).await?;

        // Display the result
        console::Stdout::new(&format!(
            "DeriveKey operation successful. Derived key ID: {}",
            response.unique_identifier
        ))
        .write()?;

        Ok(())
    }
}
