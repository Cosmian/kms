use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_types::UniqueIdentifier,
        requests::{
            create_symmetric_key_kmip_object, import_object_request, symmetric_key_create_request,
        },
    },
    reexport::cosmian_kms_client_utils::create_utils::{
        SymmetricAlgorithm, prepare_sym_key_elements,
    },
};

use crate::{
    actions::kms::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Create a new symmetric key
///
/// When the `--bytes-b64` option is specified, the key will be created from the provided bytes;
/// otherwise, the key will be randomly generated with a length of `--number-of-bits`.
///
/// If no options are specified, a fresh 256-bit AES key will be created.
///
/// Tags can later be used to retrieve the key. Tags are optional.
#[derive(Parser, Default)]
#[clap(verbatim_doc_comment)]
pub struct CreateKeyAction {
    /// The length of the generated random key or salt in bits.
    #[clap(
        long = "number-of-bits",
        short = 'l',
        group = "key",
        default_value = "256"
    )]
    pub number_of_bits: Option<usize>,

    /// The symmetric key bytes or salt as a base 64 string
    #[clap(long = "bytes-b64", short = 'k', required = false, group = "key")]
    pub wrap_key_b64: Option<String>,

    /// The algorithm
    #[clap(
        long = "algorithm",
        short = 'a',
        required = false,
        default_value = "aes"
    )]
    pub algorithm: SymmetricAlgorithm,

    /// The tag to associate with the key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub tags: Vec<String>,

    /// The unique id of the key; a random uuid
    /// is generated if not specified.
    #[clap(required = false)]
    pub key_id: Option<String>,

    /// Sensitive: if set, the key will not be exportable
    #[clap(long = "sensitive", default_value = "false")]
    pub sensitive: bool,

    /// The key encryption key (KEK) used to wrap this new key with.
    /// If the wrapping key is:
    /// - a symmetric key, AES-GCM will be used
    /// - a RSA key, RSA-OAEP will be used
    /// - a EC key, ECIES will be used (salsa20poly1305 for X25519)
    #[clap(
        long = "wrapping-key-id",
        short = 'w',
        required = false,
        verbatim_doc_comment
    )]
    pub wrapping_key_id: Option<String>,
}

impl CreateKeyAction {
    /// Create a new symmetric key
    ///
    /// # Errors
    /// Fail in input key parsing fails
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let (number_of_bits, key_bytes, algorithm) =
            prepare_sym_key_elements(self.number_of_bits, &self.wrap_key_b64, self.algorithm)
                .with_context(|| "failed preparing key elements")?;

        let unique_identifier = if let Some(key_bytes) = key_bytes {
            let mut object = create_symmetric_key_kmip_object(
                key_bytes.as_slice(),
                &Attributes {
                    cryptographic_algorithm: Some(algorithm),
                    ..Default::default()
                },
            )?;
            if let Some(wrapping_key_id) = &self.wrapping_key_id {
                let attributes = object.attributes_mut()?;
                attributes.set_wrapping_key_id(wrapping_key_id);
            }
            let import_object_request =
                import_object_request(self.key_id.clone(), object, None, false, false, &self.tags)?;
            kms_rest_client
                .import(import_object_request)
                .await
                .with_context(|| "failed importing the key")?
                .unique_identifier
        } else {
            let key_id = self
                .key_id
                .as_ref()
                .map(|id| UniqueIdentifier::TextString(id.clone()));
            let create_key_request = symmetric_key_create_request(
                key_id,
                number_of_bits,
                algorithm,
                &self.tags,
                self.sensitive,
                self.wrapping_key_id.as_ref(),
            )?;
            kms_rest_client
                .create(create_key_request)
                .await
                .with_context(|| "failed creating the key")?
                .unique_identifier
        };

        let mut stdout = console::Stdout::new("The symmetric key was successfully generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(&unique_identifier);
        stdout.write()?;

        Ok(unique_identifier)
    }
}
