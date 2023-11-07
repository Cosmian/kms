use std::collections::HashSet;

use cosmian_kmip::{
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Import, ImportResponse},
        kmip_types::{
            Attributes, CertificateType, CryptographicAlgorithm, CryptographicDomainParameters,
            CryptographicUsageMask, KeyFormatType, KeyWrapType, Link, LinkType,
            LinkedObjectIdentifier, RecommendedCurve, StateEnumeration,
        },
    },
    openssl::{kmip_private_key_to_openssl, kmip_public_key_to_openssl},
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    crypto::curve_25519::operation::Q_LENGTH_BITS,
    tagging::{check_user_tags, remove_tags},
};
use num_bigint_dig::BigUint;
use openssl::{
    ec::{EcKey, PointConversionForm},
    nid::Nid,
    pkey::{Id, PKey, Private},
    sha::Sha1,
};
use tracing::{debug, trace, warn};
use x509_parser::parse_x509_certificate;

use super::wrapping::unwrap_key;
use crate::{
    core::{
        certificate::{
            locate::locate_certificate_by_spki,
            parsing::{get_certificate_subject_key_identifier, get_common_name},
        },
        KMS,
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

fn parse_certificate_and_create_tags(
    tags: &mut HashSet<String>,
    certificate_value: &[u8],
) -> KResult<()> {
    debug!("Import with _cert system tag");
    tags.insert("_cert".to_string());

    let (_, x509) = parse_x509_certificate(certificate_value)?;

    if !x509.validity().is_valid() {
        warn!(
            "The certificate is expired. Certificate details: {:?}",
            x509.validity()
        );
    }

    let cert_spki = get_certificate_subject_key_identifier(&x509)?;
    debug!(
        "parse_certificate_and_create_tags: Subject Key Identifier: {:?}",
        cert_spki
    );

    if let Some(spki) = cert_spki {
        let spki_tag = format!("_cert_spki={spki}");
        debug!("Add spki system tag: {spki_tag}");
        tags.insert(spki_tag);
    }
    if x509.is_ca() {
        match get_common_name(&x509.subject) {
            Ok(subject_common_name) => {
                let ca_tag = format!("_cert_ca={subject_common_name}");
                debug!("Add CA system tag: {}", &ca_tag);
                tags.insert(ca_tag);
            }
            Err(_) => {
                warn!("no common name for certificate: {:?}", x509);
            }
        }
    }
    Ok(())
}

fn get_ec_private_key_object(
    private_key_bytes: Vec<u8>,
    recommended_curve: RecommendedCurve,
    links: Option<Vec<Link>>,
) -> Object {
    Object::PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentECPrivateKey,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentECPrivateKey {
                    recommended_curve,
                    d: BigUint::from_bytes_be(&private_key_bytes),
                },
                attributes: Some(Attributes {
                    activation_date: None,
                    cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                    cryptographic_length: Some(Q_LENGTH_BITS),
                    cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                        q_length: Some(Q_LENGTH_BITS),
                        recommended_curve: Some(recommended_curve),
                    }),
                    cryptographic_parameters: None,
                    cryptographic_usage_mask: Some(
                        CryptographicUsageMask::Encrypt
                            | CryptographicUsageMask::Decrypt
                            | CryptographicUsageMask::WrapKey
                            | CryptographicUsageMask::UnwrapKey
                            | CryptographicUsageMask::KeyAgreement,
                    ),
                    key_format_type: Some(KeyFormatType::ECPrivateKey),
                    link: links,
                    object_type: Some(ObjectType::PrivateKey),
                    vendor_attributes: None,
                }),
            },
            cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
            cryptographic_length: Some(Q_LENGTH_BITS),
            key_compression_type: None,
            key_wrapping_data: None,
        },
    }
}

fn get_rsa_private_key_object(
    private_key: PKey<Private>,
    links: Option<Vec<Link>>,
) -> KResult<Object> {
    let private_key_size = private_key.rsa()?.n().num_bits();
    debug!("get_rsa_private_key_object: private_key_size in bits: {private_key_size:?}");
    let object = Object::PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentRSAPrivateKey,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(private_key.private_key_to_pkcs8()?),
                attributes: Some(Attributes {
                    activation_date: None,
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    cryptographic_length: Some(private_key_size),
                    cryptographic_domain_parameters: None,
                    cryptographic_parameters: None,
                    cryptographic_usage_mask: Some(
                        CryptographicUsageMask::Encrypt
                            | CryptographicUsageMask::Decrypt
                            | CryptographicUsageMask::WrapKey
                            | CryptographicUsageMask::UnwrapKey
                            | CryptographicUsageMask::KeyAgreement,
                    ),
                    key_format_type: Some(KeyFormatType::TransparentRSAPrivateKey),
                    link: links,
                    object_type: Some(ObjectType::PrivateKey),
                    vendor_attributes: None,
                }),
            },
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            cryptographic_length: Some(private_key_size),
            key_compression_type: None,
            key_wrapping_data: None,
        },
    };

    Ok(object)
}

fn create_ec_spki_tag(
    tags: &mut Option<HashSet<String>>,
    private_key: &EcKey<Private>,
) -> KResult<String> {
    debug!("create_spki_tag: entering");
    let mut ctx = openssl::bn::BigNumContext::new()?;
    let group = private_key.group();
    let public_key_bytes =
        private_key
            .public_key()
            .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;

    create_spki_tag(tags, &public_key_bytes)
}

fn create_spki_tag(tags: &mut Option<HashSet<String>>, public_key_bytes: &[u8]) -> KResult<String> {
    // Compute SPKI as described in <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2>: implementing first method
    debug!(
        "create_spki_tag: public_key_bytes:{}",
        hex::encode(public_key_bytes)
    );
    let mut sha1 = Sha1::default();
    sha1.update(public_key_bytes);
    let spki = hex::encode(sha1.finish());

    if let Some(tags) = tags.as_mut() {
        let spki_tag = format!("_cert_spki={spki}");
        debug!("create_spki_tag: add spki system tag: {spki_tag}");
        tags.insert(spki_tag);
    }
    Ok(spki)
}

async fn create_certificate_link(
    spki: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> Option<Vec<Link>> {
    match locate_certificate_by_spki(spki, kms, owner, params).await {
        Ok(certificate_id) => {
            debug!("import_der: add Link with certificate_id: {certificate_id:?}");
            let link = Link {
                link_type: LinkType::CertificateLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(certificate_id),
            };
            Some(vec![link])
        }
        Err(e) => {
            warn!("No certificate found matching the private key SPKI: {spki:?}. Error: {e:?}");
            // continue
            None
        }
    }
}

/// The function `import_der` takes in a DER value, parses it, and creates an object
/// based on the type of DER (certificate or private key).
///
/// Arguments:
///
/// * `tags`: If provided, the mutable `HashSet` of strings that will store store
/// tags associated with the imported object.
/// * `pem_value`: The `pem_value` parameter is a byte slice that contains the
/// PEM-encoded data. PEM stands for Privacy-Enhanced Mail and is a format for
/// storing and transmitting cryptographic keys, certificates, and other data.
/// * `kms`: The `kms` parameter is of type `KMS`, which is likely an abbreviation
/// for Key Management Service. It is used for cryptographic operations such as
/// creating certificate links and retrieving private key objects. The specific
/// implementation and functionality of the `KMS` type would depend on the context
/// and the code
/// * `owner`: The `owner` parameter in the `import_der` function is a string that
/// represents the owner of the imported object. It is used in the
/// `create_certificate_link` function to associate the imported object with the
/// owner.
/// * `params`: The `params` parameter is an optional reference to an
/// `ExtraDatabaseParams` struct. It is used to provide additional parameters for
/// creating a certificate link.
///
/// Returns:
///
/// The imported PEM certificate as a KMIP `Object`
async fn import_pem(
    tags: &mut Option<HashSet<String>>,
    pem_value: &[u8],
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    let der_is_a_cert = parse_x509_certificate(der_value).is_ok();

    let object = if pem.label == "CERTIFICATE" {
        debug!("import_pem: parsing certificate: {}", pem.label);
        if let Some(tags) = tags.as_mut() {
            parse_certificate_and_create_tags(tags, pem_value)?;
        }
        Object::Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: der_value.into(),
        }
    } else {
        debug!("import_der: parsing private key");
        let pkey = PKey::private_key_from_der(der_value)?;
        match pkey.id() {
            Id::EC => {
                debug!("import_der: parsing private key with PKey: {:?}", pkey);
                let private_key = EcKey::private_key_from_der(der_value)?;
                debug!("import_der: convert private key to EcKey");

                // Create tag from public key sha1 digest
                let spki = create_ec_spki_tag(tags, &private_key)?;
                let links = create_certificate_link(&spki, kms, owner, params).await;

                let recommended_curve = match private_key.group().curve_name() {
                    Some(nid) => match nid {
                        Nid::X9_62_PRIME192V1 => RecommendedCurve::P192,
                        Nid::SECP224R1 => RecommendedCurve::P224,
                        Nid::X9_62_PRIME256V1 => RecommendedCurve::P256,
                        Nid::SECP384R1 => RecommendedCurve::P384,
                        _ => {
                            kms_bail!("Elliptic curve not supported: {}", nid.long_name()?);
                        }
                    },
                    None => kms_bail!("No curve name for this EC curve"),
                };
                let private_key_bytes = private_key.private_key().to_vec();
                debug!(
                    "import_der: private_key_bytes len: {}",
                    private_key_bytes.len()
                );
                get_ec_private_key_object(private_key_bytes, recommended_curve, links)
            }
            Id::ED25519 => {
                let spki = create_spki_tag(tags, &pkey.raw_public_key()?)?;
                let links = create_certificate_link(&spki, kms, owner, params).await;
                let private_key_bytes = pkey.raw_private_key()?;
                get_ec_private_key_object(private_key_bytes, RecommendedCurve::CURVEED25519, links)
            }
            Id::X25519 => {
                let spki = create_spki_tag(tags, &pkey.raw_public_key()?)?;
                let links = create_certificate_link(&spki, kms, owner, params).await;
                let private_key_bytes = pkey.raw_private_key()?;
                get_ec_private_key_object(private_key_bytes, RecommendedCurve::CURVE25519, links)
            }
            Id::RSA => {
                let spki = create_spki_tag(tags, &pkey.rsa()?.public_key_to_der_pkcs1()?.clone())?;
                let links = create_certificate_link(&spki, kms, owner, params).await;
                get_rsa_private_key_object(pkey, links)?
            }
            _ => kms_bail!("Private key id not supported: {:?}", pkey.id()),
        }
    };

    Ok(object)
}

/// Import a new object
pub async fn import(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ImportResponse> {
    trace!("Entering import KMIP operation: {:?}", request);
    // Unique identifiers starting with `[` are reserved for queries on tags
    // see tagging
    // For instance, a request for unique identifier `[tag1]` will
    // attempt to find a valid single object tagged with `tag1`
    if request.unique_identifier.starts_with('[') {
        kms_bail!("Importing objects with unique identifiers starting with `[` is not supported");
    }

    // recover user tags
    let mut request_attributes = request.attributes;
    let mut tags = remove_tags(&mut request_attributes);
    if let Some(tags) = tags.as_ref() {
        check_user_tags(&tags)?;
    }

    let object_type = request.object.object_type();
    let object = match object_type {
        ObjectType::SymmetricKey => {
            let mut object = request.object;
            // insert the tag corresponding to the object type if tags should be updated
            if let Some(tags) = tags.as_mut() {
                tags.insert("_sk".to_string());
            }
            // unwrap key block if required
            let object_key_block = object.key_block_mut()?;
            // unwrap before storing if requested
            if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
                unwrap_key(object_key_block, kms, owner, params).await?;
            }
            // replace attributes
            object_key_block.key_value.attributes = Some(request_attributes);
            object
        }
        ObjectType::PublicKey => {
            // insert the tag corresponding to the object type if tags should be updated
            if let Some(tags) = tags.as_mut() {
                tags.insert("_pk".to_string());
            }

            // unwrap key block if required
            let object = if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
                let mut object = request.object;
                let object_key_block = object.key_block_mut()?;
                unwrap_key(object_key_block, kms, owner, params).await?;
                object
            } else {
                request.object
            };

            // if the key is not wrapped, try to parse it as an openssl object and import it
            // else import it as such
            let mut object = if object.key_wrapping_data().is_none() {
                // TODO: add Covercrypt keys when support for SPKI is added
                // TODO: https://github.com/Cosmian/cover_crypt/issues/118
                if object.key_block()?.cryptographic_algorithm
                    == Some(CryptographicAlgorithm::CoverCrypt)
                {
                    object
                } else {
                    // first, see if the public key can be parsed as an openssl object
                    let openssl_pk = kmip_public_key_to_openssl(&object)?;
                    let mut object = object;
                    let object_key_block = object.key_block_mut()?;
                    // The Key Format Type should really be SPKI, but it does not exist
                    object_key_block.key_format_type = KeyFormatType::PKCS8;
                    object_key_block.key_value = KeyValue {
                        key_material: KeyMaterial::ByteString(openssl_pk.public_key_to_der()?),
                        attributes: None,
                    };
                    object
                }
            } else {
                object
            };

            // replace attributes
            let object_key_block = object.key_block_mut()?;
            object_key_block.key_value.attributes = Some(request_attributes);
            object
        }
        ObjectType::PrivateKey => {
            // insert the tag corresponding to the object type if tags should be updated
            if let Some(tags) = tags.as_mut() {
                tags.insert("_sk".to_string());
            }

            // unwrap key block if required
            let object = if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
                let mut object = request.object;
                let object_key_block = object.key_block_mut()?;
                unwrap_key(object_key_block, kms, owner, params).await?;
                object
            } else {
                request.object
            };

            // if the key is not wrapped, try to parse it as an openssl object and import it
            // else import it as such
            let mut object = if object.key_wrapping_data().is_none() {
                // TODO: add Covercrypt keys when support for PKCS#8 is added
                // TODO: https://github.com/Cosmian/cover_crypt/issues/118
                if object.key_block()?.cryptographic_algorithm
                    == Some(CryptographicAlgorithm::CoverCrypt)
                {
                    object
                } else {
                    // first, see if the private key can be parsed as an openssl object
                    let openssl_sk = kmip_private_key_to_openssl(&object)?;
                    // Update the object
                    let mut object = object;
                    let object_key_block = object.key_block_mut()?;
                    object_key_block.key_format_type = KeyFormatType::PKCS8;
                    object_key_block.key_value = KeyValue {
                        key_material: KeyMaterial::ByteString(openssl_sk.private_key_to_pkcs8()?),
                        // replace attributes
                        attributes: None,
                    };
                    object
                }
            } else {
                object
            };

            // replace attributes
            let object_key_block = object.key_block_mut()?;
            object_key_block.key_value.attributes = Some(request_attributes);
            object
        }

        ObjectType::Certificate => {
            debug!("Import with _cert system tag");
            // insert the tag corresponding to the object type if tags should be updated
            if let Some(tags) = tags.as_mut() {
                tags.insert("_cert".to_string());
            }
            let certificate_pem_bytes = match &request.object {
                Object::Certificate {
                    certificate_value, ..
                } => Ok(certificate_value),
                _ => Err(KmsError::Certificate(format!(
                    "Invalid object type {object_type:?} when importing a certificate"
                ))),
            }?;
            import_der(&mut tags, certificate_der_bytes, kms, owner, params).await?
        }
        x => {
            return Err(KmsError::InvalidRequest(format!(
                "Import is not yet supported for objects of type : {x}"
            )))
        }
    };

    // check if the object will be replaced if it already exists
    let replace_existing = request.replace_existing.unwrap_or(false);

    // insert or update the object
    let uid = if replace_existing {
        debug!(
            "Upserting object of type: {}, with uid: {}",
            request.object_type, request.unique_identifier
        );

        kms.db
            .upsert(
                &request.unique_identifier,
                owner,
                &object,
                tags.as_ref(),
                StateEnumeration::Active,
                params,
            )
            .await?;
        request.unique_identifier
    } else {
        debug!("Inserting object of type: {}", request.object_type);
        let id = if request.unique_identifier.is_empty() {
            None
        } else {
            Some(request.unique_identifier)
        };

        kms.db
            .create(id, owner, &object, &(tags.unwrap_or_default()), params)
            .await?
    };
    Ok(ImportResponse {
        unique_identifier: uid,
    })
}
