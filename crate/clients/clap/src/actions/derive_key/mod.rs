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
    actions::{console, mac::CHashingAlgorithm},
    error::{KmsCliError, result::KmsCliResult},
};

/// Derive a new key from an existing key
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct DeriveKeyAction {
    /// The unique identifier of the base key to derive from
    /// Mutually exclusive with --password and --x25519
    #[clap(long, short = 'k')]
    #[cfg_attr(feature = "non-fips", clap(conflicts_with_all = ["password", "x25519"]))]
    #[cfg_attr(not(feature = "non-fips"), clap(conflicts_with = "password"))]
    pub key_id: Option<String>,

    /// UTF-8 password to use as base material for key derivation
    /// Will create a `SecretData` of type Password internally
    /// Mutually exclusive with --key-id and --x25519
    #[clap(long, short = 'p')]
    #[cfg_attr(feature = "non-fips", clap(conflicts_with_all = ["key_id", "x25519"]))]
    #[cfg_attr(not(feature = "non-fips"), clap(conflicts_with = "key_id"))]
    pub password: Option<String>,

    /// Perform an asymmetric X25519 ECDH key agreement instead of a
    /// symmetric (PBKDF2/HKDF) derivation. Requires --private-key-id and
    /// --peer-public-key-id. The result is always a non-extractable 256-bit
    /// `SecretData` object. Available in non-FIPS mode only.
    /// Mutually exclusive with --key-id and --password
    #[cfg(feature = "non-fips")]
    #[clap(
        long,
        conflicts_with_all = ["key_id", "password"],
        requires_all = ["private_key_id", "peer_public_key_id"]
    )]
    pub x25519: bool,

    /// The unique identifier of the local X25519 private key.
    /// Required (and only used) with --x25519
    #[cfg(feature = "non-fips")]
    #[clap(long)]
    pub private_key_id: Option<String>,

    /// The unique identifier of the peer's X25519 public key.
    /// Required (and only used) with --x25519
    #[cfg(feature = "non-fips")]
    #[clap(long)]
    pub peer_public_key_id: Option<String>,

    /// The derivation method to use (PBKDF2 or HKDF). Ignored with --x25519
    #[clap(long, short = 'm', default_value = "PBKDF2")]
    pub derivation_method: String,

    /// Salt for key derivation (in hex format).
    /// Required unless --x25519 is used
    #[clap(long , short = 's',
        value_parser = |s: &str| hex::decode(s).map(|_| s.to_string()).map_err(|e| format!("Invalid hex format: {}", e)))]
    pub salt: Option<String>,

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
        #[cfg(feature = "non-fips")]
        if self.x25519 {
            return self.run_x25519(kms_rest_client).await;
        }

        // Validate that either key_id or password is provided
        if self.key_id.is_none() && self.password.is_none() {
            return Err(KmsCliError::Default(
                "Either --key-id or --password must be provided".to_owned(),
            ));
        }

        if self.salt.is_none() {
            return Err(KmsCliError::Default(
                "--salt is required for PBKDF2/HKDF derivation".to_owned(),
            ));
        }

        let base_key_id = self.resolve_base_key_id(kms_rest_client).await?;
        let derivation_parameters = self.build_derivation_params(&base_key_id)?;

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

        if let Some(ref derived_key_id) = self.derived_key_id {
            attributes.unique_identifier =
                Some(UniqueIdentifier::TextString(derived_key_id.clone()));
        }

        // Create and send the DeriveKey request
        let derive_request = DeriveKey::new_single_base(
            ObjectType::SymmetricKey,
            UniqueIdentifier::TextString(base_key_id),
            self.parse_derivation_method()?,
            derivation_parameters,
            attributes,
        );

        let response = kms_rest_client.derive_key(derive_request).await?;

        console::Stdout::new(&format!(
            "DeriveKey operation successful. Derived key ID: {}",
            response.unique_identifier
        ))
        .write()?;

        Ok(())
    }

    /// Derive a non-exportable X25519 ECDH shared secret from a local private
    /// key and a peer public key. Always produces a fixed 256-bit `SecretData`
    /// object; server access control requires only Derive Key permission on
    /// both referenced keys (no cryptographic usage mask check).
    #[cfg(feature = "non-fips")]
    async fn run_x25519(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let private_key_id = self.private_key_id.as_ref().ok_or_else(|| {
            KmsCliError::Default("--private-key-id is required with --x25519".to_owned())
        })?;
        let peer_public_key_id = self.peer_public_key_id.as_ref().ok_or_else(|| {
            KmsCliError::Default("--peer-public-key-id is required with --x25519".to_owned())
        })?;

        let mut attributes = KmipAttributes {
            object_type: Some(ObjectType::SecretData),
            ..Default::default()
        };
        if let Some(ref derived_key_id) = self.derived_key_id {
            attributes.unique_identifier =
                Some(UniqueIdentifier::TextString(derived_key_id.clone()));
        }

        let derive_request = DeriveKey::new_asymmetric(
            UniqueIdentifier::TextString(private_key_id.clone()),
            UniqueIdentifier::TextString(peer_public_key_id.clone()),
            DerivationParameters::default(),
            attributes,
        );

        let response = kms_rest_client.derive_key(derive_request).await?;

        console::Stdout::new(&format!(
            "DeriveKey operation successful. Derived key ID: {}",
            response.unique_identifier
        ))
        .write()?;

        Ok(())
    }

    /// Resolve the base key identifier: either use the provided `key_id` directly,
    /// or import a password as a temporary `SecretData` object and return its ID.
    async fn resolve_base_key_id(&self, kms_rest_client: &KmsClient) -> KmsCliResult<String> {
        if let Some(key_id) = &self.key_id {
            return Ok(key_id.clone());
        }

        let password = self.password.as_ref().ok_or_else(|| {
            KmsCliError::Default("Either key_id or password must be provided".to_owned())
        })?;

        let password_bytes = Zeroizing::from(password.as_bytes().to_vec());
        let secret_data_object = create_secret_data_kmip_object(
            kms_rest_client.config.vendor_id.as_str(),
            password_bytes.as_slice(),
            cosmian_kmip::kmip_0::kmip_types::SecretDataType::Password,
            &Attributes::default(),
        )?;

        let import_request = import_object_request(
            kms_rest_client.config.vendor_id.as_str(),
            None,
            secret_data_object,
            None,
            false,
            false,
            Vec::<String>::new(),
        )?;

        let import_response = kms_rest_client.import(import_request).await?;
        Ok(import_response.unique_identifier.to_string())
    }

    /// Parse the derivation method string into the KMIP enum.
    fn parse_derivation_method(&self) -> KmsCliResult<DerivationMethod> {
        match self.derivation_method.to_uppercase().as_str() {
            "PBKDF2" => Ok(DerivationMethod::PBKDF2),
            "HKDF" => Ok(DerivationMethod::HKDF),
            _ => Err(KmsCliError::Default(format!(
                "Unsupported derivation method: {}",
                self.derivation_method
            ))),
        }
    }

    /// Build the `DerivationParameters` from the CLI arguments.
    fn build_derivation_params(&self, base_key_id: &str) -> KmsCliResult<DerivationParameters> {
        let salt_hex = self
            .salt
            .as_ref()
            .ok_or_else(|| KmsCliError::Default("--salt is required".to_owned()))?;
        let salt = hex::decode(salt_hex)
            .map_err(|e| KmsCliError::Default(format!("Invalid salt hex format: {e}")))?;

        let initialization_vector = if let Some(iv_hex) = &self.initialization_vector {
            Some(hex::decode(iv_hex).map_err(|e| {
                KmsCliError::Default(format!("Invalid initialization vector hex format: {e}"))
            })?)
        } else {
            None
        };

        let derivation_data = if self.derivation_method.to_uppercase() == "HKDF" {
            use std::time::{SystemTime, UNIX_EPOCH};
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let random_id = uuid::Uuid::new_v4();
            let context = format!("CLI-HKDF-{base_key_id}-{timestamp}-{random_id}");
            Some(Zeroizing::new(context.into_bytes()))
        } else {
            None
        };

        Ok(DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(self.digest_algorithm.clone().into()),
                ..Default::default()
            }),
            initialization_vector,
            derivation_data,
            salt: Some(salt),
            iteration_count: Some(self.iteration_count),
        })
    }
}
