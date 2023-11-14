use std::collections::HashSet;

use cosmian_kmip::{
    kmip::{
        kmip_data_structures::{KeyMaterial, KeyValue},
        kmip_objects::{Object, Object::Certificate, ObjectType},
        kmip_operations::{Import, ImportResponse},
        kmip_types::{
            Attributes, CertificateType, CryptographicAlgorithm, KeyFormatType, KeyWrapType,
            LinkType, LinkedObjectIdentifier, StateEnumeration,
        },
    },
    openssl::{
        kmip_private_key_to_openssl, kmip_public_key_to_openssl, openssl_private_key_to_kmip,
    },
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    tagging::{check_user_tags, remove_tags},
};
use openssl::{sha::Sha1, x509::X509};
use tracing::{debug, trace};

use super::wrapping::unwrap_key;
use crate::{core::KMS, error::KmsError, kms_bail, kms_error, result::KResult};

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
            //TODO: this needs to be revisited when fixing: https://github.com/Cosmian/kms/issues/88
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
                let key_block = object.key_block()?;
                // TODO: add Covercrypt keys when support for PKCS#8 is added
                // TODO: https://github.com/Cosmian/cover_crypt/issues/118
                if key_block.cryptographic_algorithm == Some(CryptographicAlgorithm::CoverCrypt) {
                    object
                } else if key_block.key_format_type == KeyFormatType::PKCS12 {
                    //PKCS#12 contain more than just a private key, perform specific processing
                    pre_process_pkcs12(
                        kms,
                        owner,
                        params,
                        &request.unique_identifier,
                        object,
                        &request_attributes,
                        &tags,
                    )
                    .await?
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

            // insert the tag corresponding to the object type if tags should be updated
            if let Some(tags) = tags.as_mut() {
                tags.insert("_sk".to_string());
            }

            // replace attributes
            //TODO: this needs to be revisited when fixing: https://github.com/Cosmian/kms/issues/88
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
            import_pem(&mut tags, certificate_pem_bytes, kms, owner, params).await?
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

async fn pre_process_pkcs12(
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
    private_key_id: &str,
    object: Object,
    request_attributes: &Attributes,
    tags: &Option<HashSet<String>>,
) -> Result<Object, KmsError> {
    // recover the PKCS#12 bytes from the object
    let pkcs12_bytes = match object {
        Object::PrivateKey { key_block } => key_block.key_bytes()?,
        _ => kms_bail!("The PKCS12 object is not correctly formatted"),
    };
    // recover the password from the attributes
    let password = request_attributes
        .get_link(LinkType::PKCS12PasswordLink)
        .unwrap_or_default();
    let pkcs12_parser = openssl::pkcs12::Pkcs12::from_der(&pkcs12_bytes)?;
    let pkcs12 = pkcs12_parser.parse2(&password)?;

    // Recover the private key
    let private_key = openssl_private_key_to_kmip(
        &pkcs12.pkey.ok_or_else(|| {
            KmsError::InvalidRequest("Private key not found in PKCS12".to_string())
        })?,
        KeyFormatType::PKCS8,
    )?;

    //import the leaf certificate
    let leaf_certificate = {
        // Recover the PKCS12 X509 certificate
        let openssl_cert = pkcs12.cert.ok_or_else(|| {
            KmsError::InvalidRequest("X509 certificate not found in PKCS12".to_string())
        })?;
        let leaf_certificate = Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: openssl_cert.to_der()?,
        };
        // first set the Link to the private key on the attributes
        let mut request_attributes = request_attributes.clone();
        request_attributes.add_link(
            LinkType::PrivateKeyLink,
            LinkedObjectIdentifier::TextString(private_key_id.to_string()),
        );
        // set tags
        let mut tags = tags.to_owned().unwrap_or_default();
        add_certificate_tags(&request_attributes, &openssl_cert, &mut tags)?;
        //upsert
        kms.db
            .upsert(
                &format!("{}-cert", private_key_id),
                owner,
                &leaf_certificate,
                Some(&tags),
                StateEnumeration::Active,
                params,
            )
            .await?;
        leaf_certificate
    };

    // import the chain if any  (the chain is optional)
    let mut child_certificate = leaf_certificate;
    if let Some(chain) = pkcs12.ca {
        // import the chain
        for cert in chain.into_iter() {
            let chain_certificate = Certificate {
                certificate_type: CertificateType::X509,
                certificate_value: cert.to_der()?,
            };
            // first set the Link to the private key on the attributes
            let mut request_attributes = request_attributes.clone();
            request_attributes.add_link(
                LinkType::ChildLink,
                LinkedObjectIdentifier::TextString(private_key_id.to_string()),
            );
            // set tags
            let mut tags = tags.to_owned().unwrap_or_default();
            add_certificate_tags(&request_attributes, &cert, &mut tags)?;
            //upsert
            kms.db
                .upsert(
                    &format!("{}-cert", private_key_id),
                    owner,
                    &chain_certificate,
                    Some(&tags),
                    StateEnumeration::Active,
                    params,
                )
                .await?;
        }
    }

    //return the private key
    Ok(private_key)
}

fn pre_process_certificate(
    object: &Object,
    request_attributes: &Attributes,
    tags: &mut Option<HashSet<String>>,
) -> Result<Object, KmsError> {
    // The specification says that this should be DER bytes
    let certificate_der_bytes = match object {
        Certificate {
            certificate_value, ..
        } => Ok(certificate_value),
        o => Err(KmsError::Certificate(format!(
            "invalid object type {:?} on import",
            o.object_type()
        ))),
    }?;

    // parse the certificate as an openssl object to convert it to the pivot
    let certificate = X509::from_der(&certificate_der_bytes)?;

    // insert the tag corresponding to the object type if tags should be updated
    if let Some(tags) = tags.as_mut() {
        add_certificate_tags(request_attributes, &certificate, tags)?;
    }
    Ok(Certificate {
        certificate_type: CertificateType::X509,
        certificate_value: certificate.to_der()?,
    })
}

fn add_certificate_tags(
    request_attributes: &Attributes,
    certificate: &X509,
    tags: &mut HashSet<String>,
) -> Result<(), KmsError> {
    tags.insert("_cert".to_string());

    // Create tags from links passed in attributes
    //TODO: there is no way of keeping the CA signer in the tags
    //TODO: tagging and associated problems will go when fixing: https://github.com/Cosmian/kms/issues/88

    // this tag will help finding the certificate when a Private key is known
    if let Some(private_key_id) = request_attributes.get_link(LinkType::PrivateKeyLink) {
        let sk_tag = format!("_cert_sk={private_key_id}");
        tags.insert(sk_tag);
    }

    // add the SPKI tag corresponding to the `SubjectKeyIdentifier` X509 extension
    let hash_value = hex::encode(get_or_create_subject_key_identifier_value(&certificate)?);
    let spki_tag = format!("_cert_spki={hash_value}");
    tags.insert(spki_tag);

    // add a tag with Subject Common Name
    let subject_name = certificate.subject_name();
    if let Some(subject_common_name) = subject_name
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|cn| cn.data().as_utf8().ok())
    {
        let cn_tag = format!("_cert_cn={subject_common_name}");
        tags.insert(cn_tag);
    }
    Ok(())
}

/// Get the `SubjectKeyIdentifier` X509 extension value
/// If it not available, it is
/// calculated according to RFC 5280 section 4.2.1.2
fn get_or_create_subject_key_identifier_value(certificate: &X509) -> Result<Vec<u8>, KmsError> {
    Ok(if let Some(ski) = certificate.subject_key_id() {
        ski.as_slice().to_vec()
    } else {
        let pk = certificate.public_key()?;
        let spki_der = pk.public_key_to_der()?;
        let mut sha1 = Sha1::default();
        sha1.update(&spki_der);
        sha1.finish().to_vec()
    })
}
