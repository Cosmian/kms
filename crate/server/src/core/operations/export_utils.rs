use cosmian_kmip::{
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingSpecification},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Export, ExportResponse},
        kmip_types::{
            Attributes, CryptographicAlgorithm, KeyFormatType, KeyWrapType, LinkType,
            StateEnumeration, UniqueIdentifier,
        },
    },
    openssl::{
        kmip_certificate_to_openssl, kmip_private_key_to_openssl, kmip_public_key_to_openssl,
        openssl_private_key_to_kmip, openssl_public_key_to_kmip,
    },
};
use cosmian_kms_client::access::ObjectOperationType;
use openssl::{
    pkey::{Id, PKey, Private, Public},
    stack::Stack,
    x509::X509,
};
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::{
    core::{
        certificate::retrieve_certificate_for_private_key,
        extra_database_params::ExtraDatabaseParams,
        operations::{import::add_imported_links_to_attributes, unwrap_key, wrapping::wrap_key},
        KMS,
    },
    database::{object_with_metadata::ObjectWithMetadata, retrieve_object_for_operation},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Export an object
///
/// This function is used by the KMIP Export and Get operations
pub async fn export_get(
    kms: &KMS,
    request: impl Into<Export>,
    operation_type: ObjectOperationType,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ExportResponse> {
    let request: Export = request.into();
    trace!("Export: {}", serde_json::to_string(&request)?);

    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Export: unique_identifier or tags must be a string")?;
    let mut owm =
        retrieve_object_for_operation(uid_or_tags, operation_type, kms, user, params).await?;
    let object_type = owm.object.object_type();
    let export = operation_type == ObjectOperationType::Export;

    // export based on the Object type
    let export_attributes = match object_type {
        ObjectType::PrivateKey => {
            // determine if the user wants a PKCS#12
            let is_pkcs12 = request.key_format_type == Some(KeyFormatType::PKCS12);
            // according to the KMIP specs the KeyMaterial is not returned if the object is destroyed
            if export
                && (owm.state == StateEnumeration::Destroyed
                    || owm.state == StateEnumeration::Destroyed_Compromised)
            {
                let key_block = owm.object.key_block_mut()?;
                key_block.key_value = KeyValue {
                    key_material: KeyMaterial::ByteString(Zeroizing::from(vec![])),
                    attributes: None,
                };
                key_block.key_format_type = KeyFormatType::Opaque;
            } else {
                process_private_key(
                    &mut owm,
                    &request.key_format_type,
                    &request.key_wrap_type,
                    if is_pkcs12 {
                        // the key wrapping specifications supplied are to encrypt the PKCS#12,
                        // not the private key
                        &None
                    } else {
                        &request.key_wrapping_specification
                    },
                    kms,
                    user,
                    params,
                )
                .await?;
            }
            //in the case of a PKCS#12, the private key must be packaged with the certificate
            if is_pkcs12 {
                post_process_pkcs12_for_private_key(
                    kms,
                    operation_type,
                    user,
                    params,
                    &request,
                    &mut owm,
                )
                .await?;
            }
            owm.object
                .attributes()
                .map_or(Attributes::default(), std::clone::Clone::clone)
        }
        ObjectType::PublicKey => {
            // according to the KMIP specs the KeyMaterial is not returned if the object is destroyed
            if export
                && (owm.state == StateEnumeration::Destroyed
                    || owm.state == StateEnumeration::Destroyed_Compromised)
            {
                let key_block = owm.object.key_block_mut()?;
                key_block.key_value = KeyValue {
                    key_material: KeyMaterial::ByteString(Zeroizing::from(vec![])),
                    attributes: None,
                };
                key_block.key_format_type = KeyFormatType::Opaque;
            } else {
                process_public_key(
                    &mut owm,
                    &request.key_format_type,
                    &request.key_wrap_type,
                    &request.key_wrapping_specification,
                    kms,
                    user,
                    params,
                )
                .await?;
            }
            owm.object
                .attributes()
                .map_or(Attributes::default(), std::clone::Clone::clone)
        }
        ObjectType::SymmetricKey => {
            // according to the KMIP specs the KeyMaterial is not returned if the object is destroyed
            if export
                && (owm.state == StateEnumeration::Destroyed
                    || owm.state == StateEnumeration::Destroyed_Compromised)
            {
                let key_block = owm.object.key_block_mut()?;
                key_block.key_value = KeyValue {
                    key_material: KeyMaterial::ByteString(Zeroizing::from(vec![])),
                    attributes: None,
                };
                key_block.key_format_type = KeyFormatType::Opaque;
            } else {
                process_symmetric_key(
                    &mut owm,
                    &request.key_format_type,
                    &request.key_wrap_type,
                    &request.key_wrapping_specification,
                    kms,
                    user,
                    params,
                )
                .await?;
            }
            owm.object
                .attributes()
                .map_or(Attributes::default(), std::clone::Clone::clone)
        }
        ObjectType::Certificate => {
            if let Some(key_format_type) = &request.key_format_type {
                if *key_format_type != KeyFormatType::X509 {
                    kms_bail!(
                        "export: unsupported Key Format Type for a certificate: {:?}",
                        key_format_type
                    )
                }
            }
            owm.attributes
        }
        _ => {
            kms_bail!(
                "export: unsupported object type: {:?}",
                owm.object.object_type()
            )
        }
    };

    Ok(ExportResponse {
        object_type: owm.object.object_type(),
        unique_identifier: UniqueIdentifier::TextString(owm.id),
        attributes: export_attributes,
        object: *owm.object,
    })
}

async fn process_private_key(
    object_with_metadata: &mut ObjectWithMetadata,
    key_format_type: &Option<KeyFormatType>,
    key_wrap_type: &Option<KeyWrapType>,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    let object_type = object_with_metadata.object.object_type();
    let key_block = object_with_metadata.object.key_block_mut()?;

    // First check if any unwrapping needs to be done
    maybe_unwrap(key_block, object_type, kms, key_wrap_type, user, params).await?;

    // If the key is still wrapped then the exported `KeyFormatType` must be the default (`None`)
    if key_block.key_wrapping_data.is_some() {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to export a wrapped key with a requested Key Format Type. It must \
                 be the default"
            )
        } else {
            // The key is wrapped and the Key Format Type is the default (none)
            // The key is exported as such
            return Ok(())
        }
    }

    // Covercrypt keys cannot be post-processed, process them here
    if key_block.cryptographic_algorithm == Some(CryptographicAlgorithm::CoverCrypt) {
        return process_covercrypt_key(
            key_block,
            key_wrapping_specification,
            key_format_type,
            kms,
            user,
            params,
        )
        .await
    }

    // Make a copy of the existing attributes
    let mut attributes = object_with_metadata.attributes.clone();
    add_imported_links_to_attributes(
        &mut attributes,
        key_block
            .key_value
            .attributes
            .get_or_insert(Attributes::default()),
    );

    // parse the key to an openssl object
    let openssl_key = kmip_private_key_to_openssl(&object_with_metadata.object)
        .context("export: unable to parse the private key to openssl")?;

    // Wrapping is only available for KeyFormatType being the default (i.e. None)
    if let Some(key_wrapping_specification) = key_wrapping_specification {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to wrap a key with a specified Key Format Type. It must be the \
                 default"
            )
        } else {
            // generate a KMIP PrivateKey in the default format
            let mut object = openssl_private_key_to_kmip_default_format(&openssl_key)?;
            // add the attributes back
            let key_block = object.key_block_mut()?;
            key_block.key_value.attributes = Some(attributes);
            // wrap the key
            wrap_key(key_block, key_wrapping_specification, kms, user, params).await?;
            // reassign the wrapped key
            object_with_metadata.object = Box::new(object);
            return Ok(())
        }
    }

    //No wrapping requested: export the private key to the requested format
    match key_format_type {
        Some(kft) => match kft {
            KeyFormatType::PKCS1
            | KeyFormatType::PKCS8
            | KeyFormatType::TransparentECPrivateKey
            | KeyFormatType::TransparentRSAPrivateKey
            | KeyFormatType::ECPrivateKey
            | KeyFormatType::PKCS12 => {
                let object = openssl_private_key_to_kmip(&openssl_key, *kft)?;
                object_with_metadata.object = Box::new(object);
            }
            _ => kms_bail!("export: unsupported Key Format Type: {:?}", kft),
        },
        None => {
            // No format type requested: export the private key to the default format
            let object = openssl_private_key_to_kmip_default_format(&openssl_key)?;
            object_with_metadata.object = Box::new(object);
        }
    }
    // add the attributes back
    let key_block = object_with_metadata.object.key_block_mut()?;
    key_block.key_value.attributes = Some(attributes);
    Ok(())
}

async fn process_public_key(
    object_with_metadata: &mut ObjectWithMetadata,
    key_format_type: &Option<KeyFormatType>,
    key_wrap_type: &Option<KeyWrapType>,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    let object_type = object_with_metadata.object.object_type();
    let key_block = object_with_metadata.object.key_block_mut()?;

    // First check if any unwrapping needs to be done
    maybe_unwrap(key_block, object_type, kms, key_wrap_type, user, params).await?;

    // If the key is still wrapped then the exported `KeyFormatType` must be the default (`None`)
    if key_block.key_wrapping_data.is_some() {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to export a wrapped key with a requested Key Format Type. It must \
                 be the default"
            )
        } else {
            // The key is wrapped and the Key Format Type is the default (none)
            // The key is exported as such
            return Ok(())
        }
    }

    // process Covercrypt keys
    if key_block.cryptographic_algorithm == Some(CryptographicAlgorithm::CoverCrypt) {
        return process_covercrypt_key(
            key_block,
            key_wrapping_specification,
            key_format_type,
            kms,
            user,
            params,
        )
        .await
    }

    //make a copy of the existing attributes
    let mut attributes = object_with_metadata.attributes.clone();
    add_imported_links_to_attributes(
        &mut attributes,
        key_block
            .key_value
            .attributes
            .get_or_insert(Attributes::default()),
    );

    // parse the key to an openssl object
    let openssl_key = kmip_public_key_to_openssl(&object_with_metadata.object)
        .context("export: unable to parse the private key to openssl")?;

    // Wrapping is only available for KeyFormatType being the default (i.e. None)
    if let Some(key_wrapping_specification) = key_wrapping_specification {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to wrap a key with a specified Key Format Type. It must be the \
                 default"
            )
        } else {
            // generate a KMIP PrivateKey in the default format
            let mut object = openssl_public_key_to_kmip_default_format(&openssl_key)?;
            // add the attributes back
            let key_block = object.key_block_mut()?;
            key_block.key_value.attributes = Some(attributes);

            // wrap the key
            wrap_key(
                object.key_block_mut()?,
                key_wrapping_specification,
                kms,
                user,
                params,
            )
            .await?;
            // reassign the wrapped key
            object_with_metadata.object = Box::new(object);
            return Ok(())
        }
    }

    //No wrapping requested: export the private key to the requested format
    match key_format_type {
        Some(kft) => match kft {
            KeyFormatType::PKCS1
            | KeyFormatType::PKCS8
            | KeyFormatType::TransparentECPublicKey
            | KeyFormatType::TransparentRSAPublicKey => {
                let object = openssl_public_key_to_kmip(&openssl_key, *kft)?;
                object_with_metadata.object = Box::new(object);
            }
            _ => kms_bail!("export: unsupported Key Format Type: {:?}", kft),
        },
        None => {
            // No format type requested: export the private key to the default format
            let object = openssl_public_key_to_kmip_default_format(&openssl_key)?;
            object_with_metadata.object = Box::new(object);
        }
    }

    // add the attributes back
    let key_block = object_with_metadata.object.key_block_mut()?;
    key_block.key_value.attributes = Some(attributes);

    Ok(())
}

async fn maybe_unwrap(
    key_block: &mut KeyBlock,
    object_type: ObjectType,
    kms: &KMS,
    key_wrap_type: &Option<KeyWrapType>,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    if key_block.key_wrapping_data.is_none() {
        return Ok(())
    }
    if let Some(key_wrap_type) = key_wrap_type {
        if *key_wrap_type == KeyWrapType::NotWrapped {
            debug!(
                "export: unwrapping before exporting on object: {:?}",
                object_type
            );
            unwrap_key(key_block, kms, user, params).await?;
        }
    }
    Ok(())
}

async fn process_covercrypt_key(
    key_block: &mut KeyBlock,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    key_format_type: &Option<KeyFormatType>,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    // Wrapping is only available for KeyFormatType being the default (i.e. None)
    if let Some(key_wrapping_specification) = key_wrapping_specification {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to wrap a Covercrypt key with a specified Key Format Type. It \
                 must be the default"
            )
        } else {
            // wrap the key
            wrap_key(key_block, key_wrapping_specification, kms, user, params).await?;
        }
    }
    Ok(())
}

pub(crate) fn openssl_private_key_to_kmip_default_format(key: &PKey<Private>) -> KResult<Object> {
    let key_type_id = key.id();
    let object = match key_type_id {
        Id::RSA => {
            // The default for RSA is `PKCS#1`
            openssl_private_key_to_kmip(key, KeyFormatType::PKCS1)?
        }
        Id::EC | Id::ED25519 | Id::X448 | Id::X25519 => {
            // The default for EC is `TransparentECPrivateKey`
            openssl_private_key_to_kmip(key, KeyFormatType::TransparentECPrivateKey)?
        }
        x => kms_bail!("Private Keys of type: {x:?}, are not supported"),
    };
    Ok(object)
}

pub(crate) fn openssl_public_key_to_kmip_default_format(key: &PKey<Public>) -> KResult<Object> {
    let key_type_id = key.id();
    let object = match key_type_id {
        Id::RSA => {
            // The default for RSA is `PKCS#1`
            openssl_public_key_to_kmip(key, KeyFormatType::PKCS1)?
        }
        Id::EC | Id::ED25519 | Id::X448 | Id::X25519 => {
            // The default for EC is `TransparentECPrivateKey`
            openssl_public_key_to_kmip(key, KeyFormatType::TransparentECPublicKey)?
        }
        x => kms_bail!("Private Keys of type: {x:?}, are not supported"),
    };
    Ok(object)
}

async fn process_symmetric_key(
    object_with_metadata: &mut ObjectWithMetadata,
    key_format_type: &Option<KeyFormatType>,
    key_wrap_type: &Option<KeyWrapType>,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    trace!(
        "process_symmetric_key: object_with_metadata: {:?}",
        object_with_metadata
    );
    let object_type = object_with_metadata.object.object_type();
    let key_block = object_with_metadata.object.key_block_mut()?;

    // First check is any unwrapping needs to be done
    maybe_unwrap(key_block, object_type, kms, key_wrap_type, user, params).await?;

    // If the key is still wrapped the the export KeyFormatType must be the default (none)
    if key_block.key_wrapping_data.is_some() {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to export a wrapped symmetric key with a requested Key Format \
                 Type. It must be the default"
            )
        } else {
            // The key is wrapped and as expected the requested  Key Format Type is the default (none)
            // => The key is exported as such
            return Ok(())
        }
    }

    // we have an unwrapped key, convert it to the pivotal format first,
    // which is getting the key bytes
    let key_bytes = match key_block.key_value.key_material {
        KeyMaterial::ByteString(ref mut key_bytes) => key_bytes.clone(),
        KeyMaterial::TransparentSymmetricKey { ref mut key } => key.clone(),
        _ => kms_bail!("export: unsupported key material"),
    };

    // Wrapping is only available for KeyFormatType being the default (i.e. None)
    if let Some(key_wrapping_specification) = key_wrapping_specification {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to wrap a symmetric key with a specified Key Format Type. It must \
                 be the default"
            )
        } else {
            // generate a key block in the default format, which is Raw
            key_block.key_value = KeyValue {
                key_material: KeyMaterial::ByteString(key_bytes),
                attributes: key_block.key_value.attributes.clone(),
            };
            key_block.key_format_type = KeyFormatType::Raw;
            key_block.attributes_mut()?.key_format_type = Some(KeyFormatType::Raw);
            // wrap the key
            wrap_key(key_block, key_wrapping_specification, kms, user, params).await?;
            return Ok(())
        }
    }

    // The key  is not wrapped => export to desired format
    match key_format_type {
        Some(KeyFormatType::TransparentSymmetricKey) => {
            key_block.key_value = KeyValue {
                key_material: KeyMaterial::TransparentSymmetricKey { key: key_bytes },
                attributes: key_block.key_value.attributes.clone(),
            };
            key_block.key_format_type = KeyFormatType::TransparentSymmetricKey;
        }
        None | Some(KeyFormatType::Raw) => {
            key_block.key_value = KeyValue {
                key_material: KeyMaterial::ByteString(key_bytes),
                attributes: key_block.key_value.attributes.clone(),
            };
            key_block.key_format_type = KeyFormatType::Raw;
            key_block.attributes_mut()?.key_format_type = Some(KeyFormatType::Raw);
        }
        _ => kms_bail!(
            "export: unsupported requested Key Format Type for a symmetric key: {:?}",
            key_format_type
        ),
    }

    Ok(())
}

async fn post_process_pkcs12_for_private_key(
    kms: &KMS,
    operation_type: ObjectOperationType,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
    request: &Export,
    owm: &mut ObjectWithMetadata,
) -> Result<(), KmsError> {
    // convert the Private Key to openssl
    let private_key = kmip_private_key_to_openssl(&owm.object)
        .context("export: unable to parse the private key to openssl")?;

    let mut cert_owm =
        retrieve_certificate_for_private_key(&owm.object, operation_type, kms, user, params)
            .await?;
    let certificate = kmip_certificate_to_openssl(&cert_owm.object)?;

    // retrieve the certificate chain
    let mut chain: Stack<X509> = Stack::new()?;
    while let Some(parent_id) = cert_owm.attributes.get_link(LinkType::CertificateLink) {
        // retrieve the parent certificate
        cert_owm =
            retrieve_object_for_operation(&parent_id, operation_type, kms, user, params).await?;
        let certificate = kmip_certificate_to_openssl(&cert_owm.object)?;
        chain.push(certificate)?;
    }

    // recover the password
    let password = request
        .key_wrapping_specification
        .as_ref()
        .and_then(|kws| kws.encryption_key_information.as_ref())
        .and_then(|eki| eki.unique_identifier.to_string())
        .unwrap_or_default();
    // Create the PKCS12
    let pkcs12 = openssl::pkcs12::Pkcs12::builder()
        .pkey(&private_key)
        .cert(&certificate)
        .ca(chain)
        .build2(&password)?;

    // add the certificate to the private key
    owm.object = Box::new(Object::PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::PKCS12,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(Zeroizing::from(pkcs12.to_der()?)),
                // attributes are added later
                attributes: None,
            },
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });
    Ok(())
}
