use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_types::{
            Attributes, CryptographicAlgorithm, KeyFormatType, LinkType, LinkedObjectIdentifier,
        },
    },
    import_object, objects_from_pem, read_bytes_from_file, read_object_from_json_ttlv_bytes,
    KmsClient,
};
use zeroize::Zeroizing;

use super::utils::{build_usage_mask_from_key_usage, KeyUsage};
use crate::{actions::console, error::CliError};

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum ImportKeyFormat {
    JsonTtlv,
    Pem,
    Sec1,
    Pkcs1Priv,
    Pkcs1Pub,
    Pkcs8,
    Spki,
    Aes,
    Chacha20,
}

/// Import a private or public key in the KMS.
///
/// When no unique id is specified, a unique id based on the key material is generated.
///
/// Import of a private key will automatically generate the corresponding public key
/// with id `{private_key_id}-pub`.
///
/// By default, the format is expected to be JSON TTLV but
/// other formats can be specified with the option `-f`.
///   * json-ttlv (the default)
///   * pem (PKCS#1, PKCS#8, SEC1, SPKI): the function will attempt to detect the type of key and key format
///   * sec1: an elliptic curve private key in SEC1 DER format (NIST curves only - SECG SEC1-v2 #C.4)
///   * pkcs1-priv: an RSA private key in PKCS#1 DER format (RFC 8017)
///   * pkcs1-pub: an RSA public key in PKCS#1 DER format (RFC 8017)
///   * pkcs8: an RSA or Elliptic Curve private key in PKCS#8 DER format (RFC 5208 and 5958)
///   * spki: an RSA or Elliptic Curve public key in Subject Public Key Info DER format (RFC 5480)
///   * aes: the bytes of an AES symmetric key
///   * chacha20: the bytes of a `ChaCha20` symmetric key
///
/// Tags can later be used to retrieve the key. Tags are optional.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ImportKeyAction {
    /// The KMIP JSON TTLV key file.
    #[clap(required = true)]
    key_file: PathBuf,

    /// The unique id of the key; a unique id based
    /// on the key material is generated if not specified.
    #[clap(required = false)]
    key_id: Option<String>,

    /// The format of the key.
    #[clap(long = "key-format", short = 'f', default_value = "json-ttlv")]
    key_format: ImportKeyFormat,

    /// For a private key: the corresponding public key id if any.
    #[clap(long = "public-key-id", short = 'p')]
    public_key_id: Option<String>,

    /// For a public key: the corresponding private key id if any.
    #[clap(long = "private-key-id", short = 'k')]
    private_key_id: Option<String>,

    /// For a public or private key: the corresponding certificate id if any.
    #[clap(long = "certificate-id", short = 'c')]
    certificate_id: Option<String>,

    /// In the case of a JSON TTLV key,
    /// unwrap the key if it is wrapped before storing it.
    #[clap(
        long = "unwrap",
        short = 'u',
        required = false,
        default_value = "false"
    )]
    unwrap: bool,

    /// Replace an existing key under the same id.
    #[clap(
        required = false,
        long = "replace",
        short = 'r',
        default_value = "false"
    )]
    replace_existing: bool,

    /// The tag to associate with the key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,

    /// For what operations should the key be used.
    #[clap(long = "key-usage")]
    key_usage: Option<Vec<KeyUsage>>,
}

impl ImportKeyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
        let cryptographic_usage_mask = self
            .key_usage
            .as_deref()
            .and_then(build_usage_mask_from_key_usage);
        // read the key file
        let bytes = Zeroizing::from(read_bytes_from_file(&self.key_file)?);
        let mut object = match &self.key_format {
            ImportKeyFormat::JsonTtlv => read_object_from_json_ttlv_bytes(&bytes)?,
            ImportKeyFormat::Pem => read_key_from_pem(&bytes)?,
            ImportKeyFormat::Sec1 => {
                build_private_key_from_der_bytes(KeyFormatType::ECPrivateKey, bytes)
            }
            ImportKeyFormat::Pkcs1Priv => {
                build_private_key_from_der_bytes(KeyFormatType::PKCS1, bytes)
            }
            ImportKeyFormat::Pkcs1Pub => {
                build_public_key_from_der_bytes(KeyFormatType::PKCS1, bytes)
            }
            ImportKeyFormat::Pkcs8 => build_private_key_from_der_bytes(KeyFormatType::PKCS8, bytes),
            ImportKeyFormat::Spki => build_public_key_from_der_bytes(KeyFormatType::PKCS8, bytes),
            ImportKeyFormat::Aes => {
                build_symmetric_key_from_bytes(CryptographicAlgorithm::AES, bytes)
            }
            ImportKeyFormat::Chacha20 => {
                build_symmetric_key_from_bytes(CryptographicAlgorithm::ChaCha20, bytes)
            }
        };
        // Assign CryptographicUsageMask from command line arguments.
        object
            .attributes_mut()?
            .set_cryptographic_usage_mask(cryptographic_usage_mask);

        let object_type = object.object_type();

        // Generate the import attributes if links are specified.
        let mut import_attributes = object
            .attributes()
            .unwrap_or(&Attributes {
                cryptographic_usage_mask,
                ..Default::default()
            })
            .clone();

        if let Some(issuer_certificate_id) = &self.certificate_id {
            //let attributes = import_attributes.get_or_insert(Attributes::default());
            import_attributes.add_link(
                LinkType::CertificateLink,
                LinkedObjectIdentifier::TextString(issuer_certificate_id.clone()),
            );
        };
        if let Some(private_key_id) = &self.private_key_id {
            //let attributes = import_attributes.get_or_insert(Attributes::default());
            import_attributes.add_link(
                LinkType::PrivateKeyLink,
                LinkedObjectIdentifier::TextString(private_key_id.clone()),
            );
        };
        if let Some(public_key_id) = &self.public_key_id {
            import_attributes.add_link(
                LinkType::PublicKeyLink,
                LinkedObjectIdentifier::TextString(public_key_id.clone()),
            );
        };

        // import the key
        let unique_identifier = import_object(
            kms_rest_client,
            self.key_id.clone(),
            object,
            Some(import_attributes),
            self.unwrap,
            self.replace_existing,
            &self.tags,
        )
        .await?;

        // print the response
        let stdout = format!(
            "The {:?} in file {:?} was imported with id: {}",
            object_type, &self.key_file, unique_identifier,
        );
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(unique_identifier);
        stdout.write()?;

        Ok(())
    }
}

/// Read a key from a PEM file
fn read_key_from_pem(bytes: &[u8]) -> Result<Object, CliError> {
    let mut objects = objects_from_pem(bytes)?;
    let object = objects
        .pop()
        .ok_or_else(|| CliError::Default("The PEM file does not contain any object".to_owned()))?;
    match object.object_type() {
        ObjectType::PrivateKey | ObjectType::PublicKey => {
            if !objects.is_empty() {
                println!(
                    "WARNING: the PEM file contains multiple objects. Only the private key will \
                     be imported. A corresponding public key will be generated automatically."
                );
            }
            Ok(object)
        }
        ObjectType::Certificate => Err(CliError::Default(
            "For certificates, use the `ckms certificate` sub-command".to_owned(),
        )),
        _ => Err(CliError::Default(format!(
            "The PEM file contains an object of type {:?} which is not supported",
            object.object_type()
        ))),
    }
}

pub(crate) fn build_private_key_from_der_bytes(
    key_format_type: KeyFormatType,
    bytes: Zeroizing<Vec<u8>>,
) -> Object {
    Object::PrivateKey {
        key_block: KeyBlock {
            key_format_type,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(bytes),
                attributes: Some(Box::default()),
            },
            // According to the KMIP spec, the cryptographic algorithm is not required
            // as long as it can be recovered from the Key Format Type or the Key Value.
            // Also it should not be specified if the cryptographic length is not specified.
            cryptographic_algorithm: None,
            // See comment above
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    }
}

// Here the zeroizing type on public key bytes is overkill but it aligns with
// other methods dealing with private components.
fn build_public_key_from_der_bytes(
    key_format_type: KeyFormatType,
    bytes: Zeroizing<Vec<u8>>,
) -> Object {
    Object::PublicKey {
        key_block: KeyBlock {
            key_format_type,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(bytes),
                attributes: Some(Box::default()),
            },
            // According to the KMIP spec, the cryptographic algorithm is not required
            // as long as it can be recovered from the Key Format Type or the Key Value.
            // Also it should not be specified if the cryptographic length is not specified.
            cryptographic_algorithm: None,
            // See comment above
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    }
}

fn build_symmetric_key_from_bytes(
    cryptographic_algorithm: CryptographicAlgorithm,
    bytes: Zeroizing<Vec<u8>>,
) -> Object {
    let len = bytes.len() as i32 * 8;
    Object::SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentSymmetricKey { key: bytes },
                attributes: Some(Box::default()),
            },
            cryptographic_algorithm: Some(cryptographic_algorithm),
            cryptographic_length: Some(len),
            key_wrapping_data: None,
        },
    }
}
