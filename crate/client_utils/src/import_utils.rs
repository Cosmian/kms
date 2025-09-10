use clap::ValueEnum;
use cosmian_kmip::{
    kmip_0::kmip_types::{CertificateType, CryptographicUsageMask},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::{Certificate, ObjectType, PrivateKey, PublicKey, SymmetricKey},
        kmip_types::{CryptographicAlgorithm, LinkType, LinkedObjectIdentifier},
    },
    ttlv::{TTLV, from_ttlv},
};
use cosmian_logger::info;
use serde::Deserialize;
use strum::{EnumIter, EnumString};

#[derive(Debug, Clone, EnumString, ValueEnum, Default)]
#[strum(serialize_all = "kebab-case")]
pub enum ImportKeyFormat {
    #[default]
    JsonTtlv,
    Pem,
    Sec1,
    Pkcs1Priv,
    Pkcs1Pub,
    Pkcs8Priv,
    Pkcs8Pub,
    Aes,
    Chacha20,
}

#[derive(Deserialize, Debug, Clone, EnumIter, PartialEq, Eq, EnumString, ValueEnum)]
pub enum KeyUsage {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    WrapKey,
    UnwrapKey,
    MACGenerate,
    MACVerify,
    DeriveKey,
    KeyAgreement,
    CertificateSign,
    CRLSign,
    Authenticate,
    Unrestricted,
}

impl From<KeyUsage> for String {
    fn from(key_usage: KeyUsage) -> Self {
        match key_usage {
            KeyUsage::Sign => "sign",
            KeyUsage::Verify => "verify",
            KeyUsage::Encrypt => "encrypt",
            KeyUsage::Decrypt => "decrypt",
            KeyUsage::WrapKey => "wrap-key",
            KeyUsage::UnwrapKey => "unwrap-key",
            KeyUsage::MACGenerate => "mac-generate",
            KeyUsage::MACVerify => "mac-verify",
            KeyUsage::DeriveKey => "derive-key",
            KeyUsage::KeyAgreement => "key-agreement",
            KeyUsage::CertificateSign => "certificate-sign",
            KeyUsage::CRLSign => "crl-sign",
            KeyUsage::Authenticate => "authenticate",
            KeyUsage::Unrestricted => "unrestricted",
        }
        .to_owned()
    }
}

// Read a key from a PEM file
fn read_key_from_pem(bytes: &[u8]) -> Result<Object, UtilsError> {
    let mut objects = objects_from_pem(bytes)?;
    let object = objects.pop().ok_or_else(|| {
        UtilsError::Default("The PEM file does not contain any object".to_owned())
    })?;
    match object.object_type() {
        ObjectType::PrivateKey | ObjectType::PublicKey => {
            if !objects.is_empty() {
                info!(
                    "WARNING: the PEM file contains multiple objects. Only the private key will \
                     be imported. A corresponding public key will be generated automatically."
                );
            }
            Ok(object)
        }
        ObjectType::Certificate => Err(UtilsError::Default(
            "For certificates, use the `cosmian kms certificate` sub-command".to_owned(),
        )),
        _ => Err(UtilsError::Default(format!(
            "The PEM file contains an object of type {:?} which is not supported",
            object.object_type()
        ))),
    }
}

#[must_use]
pub fn build_private_key_from_der_bytes(
    key_format_type: KeyFormatType,
    bytes: Zeroizing<Vec<u8>>,
) -> Object {
    Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            key_format_type,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(bytes),
                attributes: Some(Attributes::default()),
            }),
            // According to the KMIP spec, the cryptographic algorithm is not required
            // as long as it can be recovered from the Key Format Type or the Key Value.
            // Also it should not be specified if the cryptographic length is not specified.
            cryptographic_algorithm: None,
            // See comment above
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    })
}

// Here the zeroizing type on public key bytes is overkill, but it aligns with
// other methods dealing with private components.
fn build_public_key_from_der_bytes(
    key_format_type: KeyFormatType,
    bytes: Zeroizing<Vec<u8>>,
) -> Object {
    Object::PublicKey(PublicKey {
        key_block: KeyBlock {
            key_format_type,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(bytes),
                attributes: Some(Attributes::default()),
            }),
            // According to the KMIP spec, the cryptographic algorithm is not required
            // as long as it can be recovered from the Key Format Type or the Key Value.
            // Also it should not be specified if the cryptographic length is not specified.
            cryptographic_algorithm: None,
            // See comment above
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    })
}

fn build_symmetric_key_from_bytes(
    cryptographic_algorithm: CryptographicAlgorithm,
    bytes: Zeroizing<Vec<u8>>,
) -> Result<Object, UtilsError> {
    let len = i32::try_from(bytes.len())? * 8;
    Ok(Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentSymmetricKey { key: bytes },
                attributes: Some(Attributes::default()),
            }),
            cryptographic_algorithm: Some(cryptographic_algorithm),
            cryptographic_length: Some(len),
            key_wrapping_data: None,
        },
    }))
}

#[must_use]
pub fn build_usage_mask_from_key_usage(
    key_usage_vec: &[KeyUsage],
) -> Option<CryptographicUsageMask> {
    let mut flags = 0;
    for key_usage in key_usage_vec {
        flags |= match key_usage {
            KeyUsage::Sign => CryptographicUsageMask::Sign,
            KeyUsage::Verify => CryptographicUsageMask::Verify,
            KeyUsage::Encrypt => CryptographicUsageMask::Encrypt,
            KeyUsage::Decrypt => CryptographicUsageMask::Decrypt,
            KeyUsage::WrapKey => CryptographicUsageMask::WrapKey,
            KeyUsage::UnwrapKey => CryptographicUsageMask::UnwrapKey,
            KeyUsage::MACGenerate => CryptographicUsageMask::MACGenerate,
            KeyUsage::MACVerify => CryptographicUsageMask::MACVerify,
            KeyUsage::DeriveKey => CryptographicUsageMask::DeriveKey,
            KeyUsage::KeyAgreement => CryptographicUsageMask::KeyAgreement,
            KeyUsage::CertificateSign => CryptographicUsageMask::CertificateSign,
            KeyUsage::CRLSign => CryptographicUsageMask::CRLSign,
            KeyUsage::Authenticate => CryptographicUsageMask::Authenticate,
            KeyUsage::Unrestricted => CryptographicUsageMask::Unrestricted,
        }
        .bits();
    }
    CryptographicUsageMask::from_bits(flags)
}

/// Read an object from KMIP JSON TTLV bytes slice
pub fn read_object_from_json_ttlv_bytes(bytes: &[u8]) -> Result<Object, UtilsError> {
    // Read the object from the file
    let ttlv = serde_json::from_slice::<TTLV>(bytes)?;
    // Deserialize the object
    let object: Object = from_ttlv(ttlv)?;
    Ok(object)
}

use cosmian_kmip::kmip_2_1::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::Object,
    kmip_types::KeyFormatType,
};
use zeroize::Zeroizing;

use crate::error::UtilsError;

/// Build KMIP Objects from a PEM file.
/// The PEM file can contain multiple objects.
///
/// The PEM content is not verified.
///
/// The vector of objects is ordered child to parent:
///  - In a keypair: the private keys is appended at the end of the vector, the public key is inserted at the beginning.
///  - The certificates chain have the leaf at the beginning and the root at the end (i.e. as they are submitted).
///
/// # Arguments
/// * `bytes` - The PEM file bytes
///
/// # Returns
/// * `Ok(Vec<Object>)` - The KMIP objects
/// * `Err(RestClientError)` - The error
///
/// # PEM Tags
///
/// | PEM Tag | PKCS Name |
/// |---------|-----------|
/// | RSA PRIVATE KEY | PKCS#1 |
/// | RSA PUBLIC KEY | PKCS#1 |
/// | PRIVATE KEY | PKCS#8 |
/// | PUBLIC KEY | PKCS#8 |
/// | ENCRYPTED PRIVATE KEY | PKCS#8 |
/// | ENCRYPTED PUBLIC KEY | PKCS#8 |
/// | EC PRIVATE KEY | SEC1 |
/// | CERTIFICATE | X.509 |
/// | X509 CRL | X.509 |
/// | NEW CERTIFICATE REQUEST | PKCS#10 |
/// | CERTIFICATE REQUEST | PKCS#10 |
/// | PKCS12 | PKCS#12 |
///
pub fn objects_from_pem(bytes: &[u8]) -> Result<Vec<Object>, UtilsError> {
    let mut objects = Vec::<Object>::new();
    let pem_s = pem::parse_many(bytes)?;
    for pem in pem_s {
        let key_block_with_format_type =
            |kft: KeyFormatType| key_block(kft, pem.contents().to_vec());

        match pem.tag() {
            "RSA PRIVATE KEY" => objects.push(Object::PrivateKey(PrivateKey {
                key_block: key_block_with_format_type(KeyFormatType::PKCS1),
            })),
            "RSA PUBLIC KEY" => objects.insert(
                0,
                Object::PublicKey(PublicKey {
                    key_block: key_block_with_format_type(KeyFormatType::PKCS1),
                }),
            ),
            "PRIVATE KEY" => objects.push(Object::PrivateKey(PrivateKey {
                key_block: key_block_with_format_type(KeyFormatType::PKCS8),
            })),
            "PUBLIC KEY" => objects.insert(
                0,
                Object::PublicKey(PublicKey {
                    key_block: key_block_with_format_type(KeyFormatType::PKCS8),
                }),
            ),
            "EC PRIVATE KEY" => objects.push(Object::PrivateKey(PrivateKey {
                key_block: key_block_with_format_type(KeyFormatType::ECPrivateKey),
            })),
            "EC PUBLIC KEY" => {
                return Err(UtilsError::NotSupported(
                    "PEM files with EC PUBLIC KEY are not supported: SEC1 should be reserved for \
                     EC private keys only"
                        .to_owned(),
                ))
            }
            "CERTIFICATE" => objects.push(Object::Certificate(Certificate {
                certificate_type: CertificateType::X509,
                certificate_value: pem.into_contents(),
            })),
            "X509 CRL" => {
                return Err(UtilsError::NotSupported(
                    "X509 CRL not supported on this server".to_owned(),
                ))
            }
            "NEW CERTIFICATE REQUEST" => {
                return Err(UtilsError::NotSupported(
                    "NEW CERTIFICATE REQUEST not supported on this server".to_owned(),
                ))
            }
            "CERTIFICATE REQUEST" => {
                return Err(UtilsError::NotSupported(
                    "CERTIFICATE REQUEST not supported on this server".to_owned(),
                ))
            }
            x => {
                return Err(UtilsError::NotSupported(format!(
                    "PEM tag {x} not supported"
                )))
            }
        }
    }
    Ok(objects)
}

fn key_block(key_format_type: KeyFormatType, bytes: Vec<u8>) -> KeyBlock {
    KeyBlock {
        key_format_type,
        key_compression_type: None,
        key_value: Some(KeyValue::Structure {
            // No need to specify zeroizing as parameter type for this function
            // seems to only deal with public components.
            key_material: KeyMaterial::ByteString(Zeroizing::from(bytes)),
            attributes: Some(Attributes::default()),
        }),
        // According to the KMIP spec, the cryptographic algorithm is not required
        // as long as it can be recovered from the Key Format Type or the Key Value.
        // Also, it should not be specified if the cryptographic length is not specified.
        cryptographic_algorithm: None,
        // See comment above
        cryptographic_length: None,
        key_wrapping_data: None,
    }
}

pub fn prepare_key_import_elements(
    key_usage: &Option<Vec<KeyUsage>>,
    key_format: &ImportKeyFormat,
    key_bytes: Vec<u8>,
    certificate_id: &Option<String>,
    private_key_id: &Option<String>,
    public_key_id: &Option<String>,
    wrapping_key_id: Option<&String>,
) -> Result<(Object, Attributes), UtilsError> {
    let cryptographic_usage_mask = key_usage
        .as_deref()
        .and_then(build_usage_mask_from_key_usage);
    let bytes = Zeroizing::from(key_bytes);

    let object = match &key_format {
        ImportKeyFormat::JsonTtlv => read_object_from_json_ttlv_bytes(&bytes)?,
        ImportKeyFormat::Pem => read_key_from_pem(&bytes)?,
        ImportKeyFormat::Sec1 => {
            build_private_key_from_der_bytes(KeyFormatType::ECPrivateKey, bytes)
        }
        ImportKeyFormat::Pkcs1Priv => build_private_key_from_der_bytes(KeyFormatType::PKCS1, bytes),
        ImportKeyFormat::Pkcs1Pub => build_public_key_from_der_bytes(KeyFormatType::PKCS1, bytes),
        ImportKeyFormat::Pkcs8Priv => build_private_key_from_der_bytes(KeyFormatType::PKCS8, bytes),
        ImportKeyFormat::Pkcs8Pub => build_public_key_from_der_bytes(KeyFormatType::PKCS8, bytes),
        ImportKeyFormat::Aes => build_symmetric_key_from_bytes(CryptographicAlgorithm::AES, bytes)?,
        ImportKeyFormat::Chacha20 => {
            build_symmetric_key_from_bytes(CryptographicAlgorithm::ChaCha20, bytes)?
        }
    };

    // Generate the import attributes if links are specified.
    let mut import_attributes = object.attributes().cloned().unwrap_or_default();

    // Assign CryptographicUsageMask from command line arguments.
    if let Some(cryptographic_usage_mask) = cryptographic_usage_mask {
        import_attributes.set_cryptographic_usage_mask(Some(cryptographic_usage_mask));
    }

    if let Some(issuer_certificate_id) = &certificate_id {
        //let attributes = import_attributes.get_or_insert(Attributes::default());
        import_attributes.set_link(
            LinkType::CertificateLink,
            LinkedObjectIdentifier::TextString(issuer_certificate_id.clone()),
        );
    }
    if let Some(private_key_id) = &private_key_id {
        //let attributes = import_attributes.get_or_insert(Attributes::default());
        import_attributes.set_link(
            LinkType::PrivateKeyLink,
            LinkedObjectIdentifier::TextString(private_key_id.clone()),
        );
    }
    if let Some(public_key_id) = &public_key_id {
        import_attributes.set_link(
            LinkType::PublicKeyLink,
            LinkedObjectIdentifier::TextString(public_key_id.clone()),
        );
    }
    if let Some(kek) = wrapping_key_id {
        import_attributes.set_wrapping_key_id(kek);
    }

    Ok((object, import_attributes))
}

// Certificates import utils
#[derive(Default, ValueEnum, Debug, Clone, EnumString)]
pub enum CertificateInputFormat {
    JsonTtlv,
    #[default]
    Pem,
    Der,
    Chain,
    Pkcs12,
    CCADB,
}

#[must_use]
pub fn prepare_certificate_attributes(
    issuer_certificate_id: &Option<String>,
    private_key_id: &Option<String>,
    public_key_id: &Option<String>,
) -> Option<Attributes> {
    let mut certificate_attributes = None;
    if let Some(issuer_certificate_id) = &issuer_certificate_id {
        let attributes = certificate_attributes.get_or_insert(Attributes::default());
        attributes.set_link(
            LinkType::CertificateLink,
            LinkedObjectIdentifier::TextString(issuer_certificate_id.clone()),
        );
    }
    if let Some(private_key_id) = &private_key_id {
        let attributes = certificate_attributes.get_or_insert(Attributes::default());
        attributes.set_link(
            LinkType::PrivateKeyLink,
            LinkedObjectIdentifier::TextString(private_key_id.clone()),
        );
    }
    if let Some(public_key_id) = &public_key_id {
        let attributes = certificate_attributes.get_or_insert(Attributes::default());
        attributes.set_link(
            LinkType::PublicKeyLink,
            LinkedObjectIdentifier::TextString(public_key_id.clone()),
        );
    }

    certificate_attributes
}
