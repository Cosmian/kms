use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::kmip_objects::ObjectType,
    kmip_2_1::{kmip_types::UniqueIdentifier, requests::import_object_request},
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::import_utils::{
        ImportKeyFormat, KeyUsage, prepare_key_import_elements,
    },
};

use crate::{actions::kms::console, error::result::KmsCliResult};

/// Import a secret data or a key in the KMS.
///
/// When no unique ID is specified, a unique ID is generated.
///
/// By default, the format is expected to be JSON TTLV but
/// other formats can be specified with the `-f` option.
///   * json-ttlv (the default)
///   * pem (PKCS#1, PKCS#8, SEC1): the function will attempt to detect the type of key and key format
///   * sec1: an elliptic curve private key in SEC1 DER format (NIST curves only - SECG SEC1-v2 #C.4)
///   * pkcs1-priv: an RSA private key in PKCS#1 DER format (RFC 8017)
///   * pkcs1-pub: an RSA public key in PKCS#1 DER format (RFC 8017)
///   * pkcs8: an RSA or Elliptic Curve private key in PKCS#8 DER format (RFC 5208 and 5958)
///   * aes: the bytes of an AES symmetric key
///   * chacha20: the bytes of a `ChaCha20` symmetric key
///
/// Tags can later be used to retrieve the key. Tags are optional.
#[derive(Parser, Default, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ImportSecretDataOrKeyAction {
    /// The file holding the key or secret data to import.
    #[clap(required = true)]
    pub(crate) key_file: PathBuf,

    /// The unique ID of the key; a random UUID
    /// is generated if not specified.
    #[clap(required = false)]
    pub(crate) key_id: Option<String>,

    /// The format of the key.
    #[clap(long, short = 'f', default_value = "json-ttlv")]
    pub(crate) key_format: ImportKeyFormat,

    /// For a private key: the corresponding KMS public key ID, if any.
    #[clap(long, short = 'p')]
    pub(crate) public_key_id: Option<String>,

    /// For a public key: the corresponding KMS private key ID, if any.
    #[clap(long, short = 'k')]
    pub(crate) private_key_id: Option<String>,

    /// For a public or private key: the corresponding certificate ID, if any.
    #[clap(long, short = 'c')]
    pub(crate) certificate_id: Option<String>,

    /// In the case of a JSON TTLV key,
    /// unwrap the key if it is wrapped before storing it.
    #[clap(long, short = 'u', required = false, default_value = "false")]
    pub(crate) unwrap: bool,

    /// Replace an existing key under the same ID.
    #[clap(
        required = false,
        long = "replace",
        short = 'r',
        default_value = "false"
    )]
    pub(crate) replace_existing: bool,

    /// The tag to associate with the key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub(crate) tags: Vec<String>,

    /// The cryptographic operations the key is allowed to perform.
    #[clap(long)]
    pub(crate) key_usage: Option<Vec<KeyUsage>>,

    /// The key encryption key (KEK) used to wrap this imported key with.
    /// If the wrapping key is:
    /// - A symmetric key, AES-GCM will be used,
    /// - An RSA key, RSA-OAEP with SHA-256 will be used,
    /// - An EC key, ECIES will be used (salsa20poly1305 for X25519),
    #[clap(
        long = "wrapping-key-id",
        short = 'w',
        required = false,
        verbatim_doc_comment
    )]
    pub(crate) wrapping_key_id: Option<String>,
}

impl ImportSecretDataOrKeyAction {
    /// Run the import key/secret data action.
    ///
    /// # Errors
    ///
    /// This function can return a [`KmsCliError`] if an error occurs during the import process.
    ///
    /// Possible error cases include:
    ///
    /// - Failed to read the key file.
    /// - Failed to parse the key file in the specified format.
    /// - Invalid key format specified.
    /// - Failed to assign cryptographic usage mask.
    /// - Failed to generate import attributes.
    /// - Failed to import the key.
    /// - Failed to write the response to stdout.
    ///
    /// [`KmsCliError`]: ../error/result/enum.KmsCliError.html
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let key_bytes = read_bytes_from_file(&self.key_file)?;

        let (object, import_attributes) = prepare_key_import_elements(
            &self.key_usage,
            &self.key_format,
            key_bytes,
            &self.certificate_id,
            &self.private_key_id,
            &self.public_key_id,
            self.wrapping_key_id.as_ref(),
        )?;
        let object_type: ObjectType = object.object_type();

        // import the key
        let import_object_request = import_object_request(
            self.key_id.clone(),
            object,
            Some(import_attributes),
            self.unwrap,
            self.replace_existing,
            &self.tags,
        )?;
        let unique_identifier = kms_rest_client
            .import(import_object_request)
            .await?
            .unique_identifier;

        // print the response
        let stdout = format!(
            "The {:?} in file {} was successfully imported with id: {}.",
            object_type,
            self.key_file.display(),
            unique_identifier,
        );
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(&unique_identifier);
        stdout.write()?;

        Ok(unique_identifier)
    }
}
