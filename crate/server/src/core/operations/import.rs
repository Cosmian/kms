use std::collections::HashSet;

use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Import, ImportResponse},
    kmip_types::{
        Attributes, CertificateType, CryptographicAlgorithm, CryptographicDomainParameters,
        CryptographicUsageMask, KeyFormatType, KeyWrapType, RecommendedCurve, StateEnumeration,
    },
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    crypto::curve_25519::operation::Q_LENGTH_BITS,
    tagging::{check_user_tags, get_tags},
};
use openssl::{
    ec::EcKey,
    nid::Nid,
    pkey::{Id, PKey},
};
use tracing::debug;
use x509_parser::{parse_x509_certificate, prelude::parse_x509_pem};

use super::wrapping::unwrap_key;
use crate::{
    core::{
        certificate::parsing::{get_certificate_subject_key_identifier, get_common_name},
        operations::wrapping::wrap_key,
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

    let (_, pem) = parse_x509_pem(certificate_value)?;
    let (_, x509) = parse_x509_certificate(&pem.contents)?;

    if !x509.validity().is_valid() {
        return Err(KmsError::Certificate(format!(
            "Cannot import expired certificate. Certificate details: {x509:?}"
        )))
    }
    debug!("Certificate is not expired: {:?}", x509.validity());

    let cert_spki = get_certificate_subject_key_identifier(&x509)?;
    if let Some(spki) = cert_spki {
        let spki_tag = format!("_cert_spki={spki}");
        debug!("Add spki system tag: {spki_tag}");
        tags.insert(spki_tag);
    }
    if x509.is_ca() {
        let subject_common_name = get_common_name(&x509.subject)?;
        let ca_tag = format!("_ca={subject_common_name}");
        debug!("Add CA system tag: {}", &ca_tag);
        tags.insert(ca_tag);
    }
    Ok(())
}

fn get_private_key_object(
    private_key_bytes: Vec<u8>,
    recommended_curve: RecommendedCurve,
) -> Object {
    Object::PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentECPrivateKey,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(private_key_bytes),
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
                    link: None,
                    object_type: Some(ObjectType::PrivateKey),
                    vendor_attributes: None,
                }),
            },
            cryptographic_algorithm: CryptographicAlgorithm::ECDH,
            cryptographic_length: Q_LENGTH_BITS,
            key_compression_type: None,
            key_wrapping_data: None,
        },
    }
}

fn import_pem(tags: &mut HashSet<String>, pem_value: &[u8]) -> KResult<Object> {
    let (_, pem) = parse_x509_pem(pem_value)?;

    let object = if pem.label == "CERTIFICATE" {
        debug!("CLI: parsing certificate: {}", pem.label);
        parse_certificate_and_create_tags(tags, pem_value)?;
        Object::Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: pem_value.to_vec(),
        }
    } else if pem.label.contains("PRIVATE KEY") {
        debug!("CLI: parsing private key: {}", pem.label);
        let pkey = PKey::private_key_from_pem(pem_value)?;
        match pkey.id() {
            Id::EC => {
                debug!("CLI: parsing private key with PKey: {:?}", pkey);
                let private_key = EcKey::private_key_from_der(&pem.contents)?;
                debug!("CLI: convert private key to EcKey");
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
                debug!("CLI: private_key_bytes len: {}", private_key_bytes.len());
                get_private_key_object(private_key_bytes, recommended_curve)
            }
            Id::ED25519 => {
                let private_key_bytes = pkey.raw_private_key()?;
                get_private_key_object(private_key_bytes, RecommendedCurve::CURVEED25519)
            }
            Id::X25519 => {
                let private_key_bytes = pkey.raw_private_key()?;
                get_private_key_object(private_key_bytes, RecommendedCurve::CURVE25519)
            }
            _ => kms_bail!("Private key id not supported: {:?}", pkey.id()),
        }
    } else {
        kms_bail!("Unsupported PEM format: found {}", pem.label);
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
    debug!("Entering import KMIP operation");
    // Unique identifiers starting with `[` are reserved for queries on tags
    // see tagging
    // For instance, a request for uniquer identifier `[tag1]` will
    // attempt to find a valid single object tagged with `tag1`
    if request.unique_identifier.starts_with('[') {
        kms_bail!("Importing objects with uniquer identifiers starting with `[` is not supported");
    }

    // recover user tags
    let mut tags = get_tags(&request.attributes);
    check_user_tags(&tags)?;

    let object_type = request.object.object_type();
    let mut object = match object_type {
        ObjectType::SymmetricKey | ObjectType::PublicKey | ObjectType::PrivateKey => {
            let mut object = request.object;
            let object_key_block = object.key_block_mut()?;
            // unwrap before storing if requested
            if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
                unwrap_key(object_type, object_key_block, kms, owner, params).await?;
            }
            // replace attributes
            object_key_block.key_value = KeyValue {
                key_material: object_key_block.key_value.key_material.clone(),
                attributes: Some(request.attributes),
            };
            // insert the tag corresponding to the object type
            match object_type {
                ObjectType::SymmetricKey => {
                    tags.insert("_kk".to_string());
                }
                ObjectType::PublicKey => {
                    tags.insert("_pk".to_string());
                }
                ObjectType::PrivateKey => {
                    tags.insert("_sk".to_string());
                }
                _ => unreachable!(),
            }
            object
        }
        ObjectType::Certificate => {
            debug!("Import with _cert system tag");
            tags.insert("_cert".to_string());
            let certificate_pem_bytes = match &request.object {
                Object::Certificate {
                    certificate_value, ..
                } => Ok(certificate_value),
                _ => Err(KmsError::Certificate(format!(
                    "Invalid object type {object_type:?} when importing a certificate"
                ))),
            }?;
            import_pem(&mut tags, certificate_pem_bytes)?
        }
        x => {
            return Err(KmsError::InvalidRequest(format!(
                "Import is not yet supported for objects of type : {x}"
            )))
        }
    };

    // check if the object will be replaced if it already exists
    let replace_existing = if let Some(v) = request.replace_existing {
        v
    } else {
        false
    };

    if let Some(kws) = &request.key_wrapping_specification {
        // wrap
        let key_block = object.key_block_mut()?;
        wrap_key(
            &request.unique_identifier,
            key_block,
            kws,
            kms,
            owner,
            params,
        )
        .await?;
    }

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
                &tags,
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

        kms.db.create(id, owner, &object, &tags, params).await?
    };
    Ok(ImportResponse {
        unique_identifier: uid,
    })
}
