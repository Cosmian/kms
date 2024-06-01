use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_types::{Attributes, CertificateType, KeyFormatType},
};
use pem::{EncodeConfig, LineEnding};
use zeroize::Zeroizing;

use crate::{client_bail, ClientError};

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
pub fn objects_from_pem(bytes: &[u8]) -> Result<Vec<Object>, ClientError> {
    let mut objects = Vec::<Object>::new();
    let pem_s = pem::parse_many(bytes)?;
    for pem in pem_s {
        let key_block_with_format_type =
            |kft: KeyFormatType| key_block(kft, pem.contents().to_vec());

        match pem.tag() {
            "RSA PRIVATE KEY" => objects.push(Object::PrivateKey {
                key_block: key_block_with_format_type(KeyFormatType::PKCS1),
            }),
            "RSA PUBLIC KEY" => objects.insert(
                0,
                Object::PublicKey {
                    key_block: key_block_with_format_type(KeyFormatType::PKCS1),
                },
            ),
            "PRIVATE KEY" => objects.push(Object::PrivateKey {
                key_block: key_block_with_format_type(KeyFormatType::PKCS8),
            }),
            "PUBLIC KEY" => objects.insert(
                0,
                Object::PublicKey {
                    key_block: key_block_with_format_type(KeyFormatType::PKCS8),
                },
            ),
            "EC PRIVATE KEY" => objects.push(Object::PrivateKey {
                key_block: key_block_with_format_type(KeyFormatType::ECPrivateKey),
            }),
            "EC PUBLIC KEY" => {
                return Err(ClientError::NotSupported(
                    "PEM files with EC PUBLIC KEY are not supported: SEC1 should be reserved for \
                     EC private keys only"
                        .to_string(),
                ))
            }
            "CERTIFICATE" => objects.push(Object::Certificate {
                certificate_type: CertificateType::X509,
                certificate_value: pem.into_contents(),
            }),
            "X509 CRL" => {
                return Err(ClientError::NotSupported(
                    "X509 CRL not supported on this server".to_owned(),
                ))
            }
            "NEW CERTIFICATE REQUEST" => {
                return Err(ClientError::NotSupported(
                    "NEW CERTIFICATE REQUEST not supported on this server".to_owned(),
                ))
            }
            "CERTIFICATE REQUEST" => {
                return Err(ClientError::NotSupported(
                    "CERTIFICATE REQUEST not supported on this server".to_owned(),
                ))
            }
            x => {
                return Err(ClientError::NotSupported(format!(
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
        key_value: KeyValue {
            // No need to specify zeroizing as parameter type for this function
            // seems to only deal with public components.
            key_material: KeyMaterial::ByteString(Zeroizing::from(bytes)),
            attributes: Some(Attributes::default()),
        },
        // According to the KMIP spec, the cryptographic algorithm is not required
        // as long as it can be recovered from the Key Format Type or the Key Value.
        // Also, it should not be specified if the cryptographic length is not specified.
        cryptographic_algorithm: None,
        // See comment above
        cryptographic_length: None,
        key_wrapping_data: None,
    }
}

/// Converts DER bytes to PEM bytes for keys
pub fn der_to_pem(
    bytes: &[u8],
    key_format_type: KeyFormatType,
    object_type: ObjectType,
) -> Result<Zeroizing<Vec<u8>>, ClientError> {
    let pem = match key_format_type {
        KeyFormatType::PKCS1 => {
            let tag = match object_type {
                ObjectType::PrivateKey => "RSA PRIVATE KEY",
                ObjectType::PublicKey => "RSA PUBLIC KEY",
                x => {
                    client_bail!(
                        "Object type {x:?} not supported for PKCS1. Must be a private key or \
                         public key"
                    )
                }
            };
            pem::Pem::new(tag, bytes)
        }
        KeyFormatType::PKCS8 => {
            let tag = match object_type {
                ObjectType::PrivateKey => "PRIVATE KEY",
                ObjectType::PublicKey => "PUBLIC KEY",
                x => {
                    client_bail!(
                        "Object type {x:?} not supported for PKCS#8 / SPKI. Must be a private key \
                         (PKCS#8) or public key (SPKI)"
                    )
                }
            };
            pem::Pem::new(tag, bytes)
        }
        KeyFormatType::ECPrivateKey => {
            let tag = match object_type {
                ObjectType::PrivateKey => "EC PRIVATE KEY",
                x => {
                    client_bail!("Object type {x:?} not supported for SEC1. Must be a private key.")
                }
            };
            pem::Pem::new(tag, bytes)
        }
        _ => {
            client_bail!("Key format type {key_format_type:?} not supported for PEM conversion")
        }
    };
    Ok(Zeroizing::new(
        pem::encode_config(&pem, EncodeConfig::new().set_line_ending(LineEnding::LF)).into_bytes(),
    ))
}
