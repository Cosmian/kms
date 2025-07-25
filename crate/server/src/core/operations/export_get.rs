use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        KmipError,
        kmip_0::kmip_types::{CertificateType, CryptographicUsageMask, KeyWrapType, State},
        kmip_2_1::{
            KmipOperation,
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingSpecification},
            kmip_objects::{Certificate, Object, ObjectType, PrivateKey},
            kmip_operations::{Export, ExportResponse},
            kmip_types::{CryptographicAlgorithm, KeyFormatType, LinkType, UniqueIdentifier},
        },
    },
    cosmian_kms_crypto::openssl::{
        kmip_certificate_to_openssl, kmip_private_key_to_openssl, kmip_public_key_to_openssl,
        openssl_private_key_to_kmip, openssl_public_key_to_kmip,
    },
    cosmian_kms_interfaces::{ObjectWithMetadata, SessionParams},
};
#[cfg(feature = "non-fips")]
use openssl::{hash::MessageDigest, nid::Nid};
use openssl::{
    pkcs7::Pkcs7,
    pkey::{Id, PKey, Private, Public},
    stack::Stack,
    x509::X509,
};
use tracing::{debug, info, trace};
use zeroize::Zeroizing;

use crate::{
    core::{
        KMS,
        certificate::{retrieve_certificate_for_private_key, retrieve_private_key_for_certificate},
        retrieve_object_utils::retrieve_object_for_operation,
        wrapping::wrap_object,
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Export an object
///
/// This function is used by the KMIP Export and Get operations
pub(crate) async fn export_get(
    kms: &KMS,
    request: impl Into<Export>,
    operation_type: KmipOperation,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<ExportResponse> {
    let request: Export = request.into();
    trace!("export-get: {}", serde_json::to_string(&request)?);

    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Export: unique_identifier or tags must be a string")?;
    let mut owm =
        retrieve_object_for_operation(uid_or_tags, operation_type, kms, user, params.clone())
            .await?;

    // The object cannot be exported if it is sensitive and is not wrapped on export,
    if owm.attributes().sensitive == Some(true) && request.key_wrapping_specification.is_none() {
        return Err(KmsError::InvalidRequest(
            "this object is marked sensitive and cannot be exported".to_owned(),
        ));
    }

    let object_type = owm.object().object_type();
    let export = operation_type == KmipOperation::Export;

    // export based on the Object type
    match object_type {
        ObjectType::PrivateKey => {
            post_process_private_key(
                kms,
                operation_type,
                user,
                params.clone(),
                &request,
                &mut owm,
            )
            .await?;
        }
        ObjectType::PublicKey => {
            // according to the KMIP specs the KeyMaterial is not returned if the object is destroyed
            if export
                && (owm.state() == State::Destroyed || owm.state() == State::Destroyed_Compromised)
            {
                let key_block = owm.object_mut().key_block_mut()?;
                key_block.key_value = Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(Zeroizing::from(vec![])),
                    attributes: None,
                });
                key_block.key_format_type = KeyFormatType::Opaque;
            } else {
                process_public_key(
                    &mut owm,
                    &request.key_format_type,
                    &request.key_wrap_type,
                    &request.key_wrapping_specification,
                    kms,
                    user,
                    params.clone(),
                )
                .await?;
            }
        }
        ObjectType::SymmetricKey => {
            // according to the KMIP specs the KeyMaterial is not returned if the object is destroyed
            if export
                && (owm.state() == State::Destroyed || owm.state() == State::Destroyed_Compromised)
            {
                let key_block = owm.object_mut().key_block_mut()?;
                key_block.key_value = Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(Zeroizing::from(vec![])),
                    attributes: None,
                });
                key_block.key_format_type = KeyFormatType::Opaque;
            } else {
                process_symmetric_key(
                    &mut owm,
                    &request.key_format_type,
                    &request.key_wrap_type,
                    &request.key_wrapping_specification,
                    kms,
                    user,
                    params.clone(),
                )
                .await?;
            }
        }
        ObjectType::Certificate => {
            if let Some(key_format_type) = &request.key_format_type {
                #[cfg(not(feature = "non-fips"))]
                let is_pkcs12 = *key_format_type == KeyFormatType::PKCS12;
                #[cfg(feature = "non-fips")]
                let is_pkcs12 = *key_format_type == KeyFormatType::PKCS12
                    || *key_format_type == KeyFormatType::Pkcs12Legacy;
                if is_pkcs12 {
                    // retrieve the private key
                    owm = retrieve_private_key_for_certificate(
                        uid_or_tags,
                        operation_type,
                        kms,
                        user,
                        params.clone(),
                    )
                    .await?;
                    post_process_private_key(
                        kms,
                        operation_type,
                        user,
                        params.clone(),
                        &Export {
                            unique_identifier: Some(UniqueIdentifier::TextString(
                                owm.id().to_owned(),
                            )),
                            key_format_type: Some(*key_format_type),
                            key_wrap_type: Some(KeyWrapType::NotWrapped),
                            key_compression_type: request.key_compression_type,
                            key_wrapping_specification: request.key_wrapping_specification.clone(),
                        },
                        &mut owm,
                    )
                    .await?;
                } else if *key_format_type == KeyFormatType::PKCS7 {
                    owm = Box::pin(post_process_pkcs7(kms, operation_type, user, params, owm))
                        .await?;
                }

                #[cfg(not(feature = "non-fips"))]
                let is_wrong_format = *key_format_type != KeyFormatType::X509
                    && *key_format_type != KeyFormatType::PKCS7
                    && *key_format_type != KeyFormatType::PKCS12;
                #[cfg(feature = "non-fips")]
                let is_wrong_format = *key_format_type != KeyFormatType::X509
                    && *key_format_type != KeyFormatType::PKCS7
                    && *key_format_type != KeyFormatType::PKCS12
                    && *key_format_type != KeyFormatType::Pkcs12Legacy;
                if is_wrong_format {
                    kms_bail!(
                        "export: unsupported Key Format Type for a certificate: {:?}",
                        key_format_type
                    )
                }
            }
        }
        ObjectType::SecretData => {
            // according to the KMIP specs the KeyMaterial is not returned if the object is destroyed
            if export
                && (owm.state() == State::Destroyed || owm.state() == State::Destroyed_Compromised)
            {
                let key_block = owm.object_mut().key_block_mut()?;
                key_block.key_value = Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(Zeroizing::from(vec![])),
                    attributes: None,
                });
                key_block.key_format_type = KeyFormatType::Opaque;
            } else {
                process_secret_data(
                    &mut owm,
                    &request.key_format_type,
                    &request.key_wrap_type,
                    &request.key_wrapping_specification,
                    kms,
                    user,
                    params.clone(),
                )
                .await?;
            }
        }
        _ => {
            kms_bail!(
                "export: unsupported object type: {:?}",
                owm.object().object_type()
            )
        }
    }

    info!(
        uid = owm.id(),
        user = user,
        "Exported object of type: {}",
        owm.object().object_type()
    );

    Ok(ExportResponse {
        object_type: owm.object().object_type(),
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        attributes: owm.attributes().clone(),
        object: owm.object().clone(),
    })
}

/// Post-process a private key
///
/// This function is used to export a private key
/// It will wrap or unwrap the key if necessary and convert it to the requested format.
async fn post_process_private_key(
    kms: &KMS,
    operation_type: KmipOperation,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
    request: &Export,
    owm: &mut ObjectWithMetadata,
) -> Result<(), KmsError> {
    trace!(
        "export_get_private_key: {} for operation: {}",
        owm.id(),
        operation_type
    );
    // determine if the user wants a PKCS#12
    #[cfg(feature = "non-fips")]
    let is_pkcs12 = request.key_format_type == Some(KeyFormatType::PKCS12)
        || request.key_format_type == Some(KeyFormatType::Pkcs12Legacy);

    #[cfg(not(feature = "non-fips"))]
    let is_pkcs12 = request.key_format_type == Some(KeyFormatType::PKCS12);
    // according to the KMIP specs the KeyMaterial is not returned if the object is destroyed
    trace!("post_process_private_key: operation type: {operation_type:?}");
    if (operation_type == KmipOperation::Export)
        && (owm.state() == State::Destroyed || owm.state() == State::Destroyed_Compromised)
    {
        let key_block = owm.object_mut().key_block_mut()?;
        let attributes = key_block.attributes().ok().cloned();
        key_block.key_value = Some(KeyValue::Structure {
            key_material: KeyMaterial::ByteString(Zeroizing::from(vec![])),
            attributes,
        });
        key_block.key_format_type = KeyFormatType::Opaque;
    } else {
        post_process_active_private_key(
            owm,
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
            params.clone(),
        )
        .await?;
    }
    //in the case of a PKCS#12, the private key must be packaged with the certificate
    if is_pkcs12 {
        build_pkcs12_for_private_key(kms, operation_type, user, params, request, owm).await?;
    }
    Ok(())
}

/// Post-process an active private key
///
/// This function is used to export a private key
/// It will wrap or unwrap the key if necessary and convert it to the requested format.
async fn post_process_active_private_key(
    object_with_metadata: &mut ObjectWithMetadata,
    key_format_type: &Option<KeyFormatType>,
    key_wrap_type: &Option<KeyWrapType>,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    kms: &KMS,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<()> {
    trace!("post_process_active_private_key: key_format_type: {key_format_type:?}",);
    // First perform any necessary unwrapping to the expected type
    unwrap_if_requested(
        object_with_metadata,
        key_wrap_type,
        kms,
        user,
        params.clone(),
    )
    .await?;

    let owm_attributes = object_with_metadata.attributes().clone();
    let object = object_with_metadata.object_mut();
    let key_block = object.key_block_mut()?;

    // If the key is still wrapped, then the exported `KeyFormatType` must be the default (`None`)
    if key_block.key_wrapping_data.is_some() {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to export a wrapped key with a requested Key Format Type. It must \
                 be the default"
            )
        }
        // The key is wrapped, and the Key Format Type is the default (none)
        // The key is exported as such
        return Ok(());
    }

    // Covercrypt keys cannot be post-processed, process them here
    if key_block.cryptographic_algorithm == Some(CryptographicAlgorithm::CoverCrypt) {
        return process_covercrypt_key(
            object,
            key_wrapping_specification,
            key_format_type,
            kms,
            user,
            params.clone(),
        )
        .await;
    }

    // Take the existing attributes from the Object and merge them with the object attributes
    let mut attributes = match key_block.attributes() {
        Ok(attrs) => {
            let mut attributes = attrs.clone();
            attributes.merge(&owm_attributes, false);
            attributes
        }
        Err(_) => {
            // if the attributes are not present, we use the existing attributes
            owm_attributes
        }
    };

    // parse the key to an openssl object
    let openssl_key = kmip_private_key_to_openssl(object)
        .context("export: unable to parse the private key to openssl")?;

    // Wrapping is only available, for KeyFormatType being the default (i.e. None)

    if let Some(key_wrapping_specification) = key_wrapping_specification {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to wrap a key with a specified Key Format Type. It must be the \
                 default"
            )
        }
        // generate a KMIP PrivateKey in the default format
        let mut object = openssl_private_key_to_kmip_default_format(
            &openssl_key,
            attributes.cryptographic_usage_mask,
        )?;

        // Merge the correct cryptographic attributes in the attributes
        attributes.merge(object.attributes()?, true);

        // Get the key block
        let key_block = object.key_block_mut()?;
        // add the attributes back
        *key_block.attributes_mut()? = attributes;

        // wrap the key
        wrap_object(&mut object, key_wrapping_specification, kms, user, params).await?;
        // reassign the wrapped key
        object_with_metadata.set_object(object);
        return Ok(())
    }

    //No wrapping requested: export the private key to the requested format
    if let Some(key_format_type) = key_format_type {
        debug!(
            "export: exporting private key with format: {:?}",
            key_format_type
        );
        #[cfg(feature = "non-fips")]
        let supported_formats = [
            KeyFormatType::PKCS1,
            KeyFormatType::PKCS8,
            KeyFormatType::TransparentECPrivateKey,
            KeyFormatType::TransparentRSAPrivateKey,
            KeyFormatType::ECPrivateKey,
            KeyFormatType::PKCS12,
            KeyFormatType::Pkcs12Legacy,
        ];

        #[cfg(not(feature = "non-fips"))]
        let supported_formats = [
            KeyFormatType::PKCS1,
            KeyFormatType::PKCS8,
            KeyFormatType::TransparentECPrivateKey,
            KeyFormatType::TransparentRSAPrivateKey,
            KeyFormatType::ECPrivateKey,
            KeyFormatType::PKCS12,
        ];
        if !supported_formats.contains(key_format_type) {
            kms_bail!(
                "export: unsupported Key Format Type: {:?} for a private key",
                key_format_type
            )
        }
        let object = openssl_private_key_to_kmip(
            &openssl_key,
            *key_format_type,
            attributes.cryptographic_usage_mask,
        )?;
        object_with_metadata.set_object(object);
    } else {
        // No format type requested: export the private key to the default format
        let object = openssl_private_key_to_kmip_default_format(
            &openssl_key,
            attributes.cryptographic_usage_mask,
        )?;
        object_with_metadata.set_object(object);
    }
    // Get the key block
    let key_block = object_with_metadata.object_mut().key_block_mut()?;

    // Merge the correct cryptographic attributes in the attributes
    if let Ok(key_block_attributes) = key_block.attributes() {
        attributes.merge(key_block_attributes, true);
    }

    // add the attributes back
    *key_block.attributes_mut()? = attributes;

    Ok(())
}

#[allow(clippy::ref_option)]
async fn process_public_key(
    object_with_metadata: &mut ObjectWithMetadata,
    key_format_type: &Option<KeyFormatType>,
    key_wrap_type: &Option<KeyWrapType>,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    kms: &KMS,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<()> {
    // perform any necessary unwrapping
    unwrap_if_requested(
        object_with_metadata,
        key_wrap_type,
        kms,
        user,
        params.clone(),
    )
    .await?;

    //make a copy of the existing attributes
    let owm_attributes = object_with_metadata.attributes().clone();
    {
        let key_block = object_with_metadata.object().key_block()?;

        // If the key is still wrapped, then the exported `KeyFormatType` must be the default (`None`)
        if key_block.key_wrapping_data.is_some() {
            if key_format_type.is_some() {
                kms_bail!(
                    "export: unable to export a wrapped key with a requested Key Format Type. It \
                     must be the default"
                )
            }
            // If the key is wrapped and the Key Format Type is the default (none), the key is exported as such
            return Ok(());
        }

        // process Covercrypt keys
        if key_block.cryptographic_algorithm == Some(CryptographicAlgorithm::CoverCrypt) {
            let object = object_with_metadata.object_mut();
            return process_covercrypt_key(
                object,
                key_wrapping_specification,
                key_format_type,
                kms,
                user,
                params.clone(),
            )
            .await;
        }
    }

    // Take the existing attributes from the Object and merge them with the object attributes
    let mut attributes = match object_with_metadata.object().key_block()?.attributes() {
        Ok(attrs) => {
            let mut attributes = attrs.clone();
            attributes.merge(&owm_attributes, false);
            attributes
        }
        Err(_) => {
            // if the attributes are not present, we use the existing attributes
            owm_attributes
        }
    };

    // parse the key to an openssl object
    let openssl_key = kmip_public_key_to_openssl(object_with_metadata.object())
        .context("export: unable to parse the private key to openssl")?;

    // Wrapping is only available when the KeyFormatType is the default (i.e., None)
    if let Some(key_wrapping_specification) = key_wrapping_specification {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to wrap a key with a specified Key Format Type. It must be the \
                 default"
            )
        }
        // generate a KMIP Public in the default format
        let mut object = openssl_public_key_to_kmip_default_format(
            &openssl_key,
            attributes.cryptographic_usage_mask,
        )?;
        // add the attributes back
        let new_attributes = attributes;
        let key_block = object.key_block_mut()?;
        if let Some(&mut KeyValue::Structure {
            ref mut attributes, ..
        }) = key_block.key_value.as_mut()
        {
            *attributes = Some(new_attributes);
        }

        // wrap the key
        wrap_object(&mut object, key_wrapping_specification, kms, user, params).await?;
        // reassign the wrapped key
        *object_with_metadata.object_mut() = object;
        return Ok(());
    }

    //No wrapping requested: export the private key to the requested format
    if let Some(key_format_type) = key_format_type {
        match key_format_type {
            KeyFormatType::PKCS1
            | KeyFormatType::PKCS8
            | KeyFormatType::TransparentECPublicKey
            | KeyFormatType::TransparentRSAPublicKey => {
                let object = openssl_public_key_to_kmip(
                    &openssl_key,
                    *key_format_type,
                    attributes.cryptographic_usage_mask,
                )?;
                *object_with_metadata.object_mut() = object;
            }
            _ => kms_bail!("export: unsupported Key Format Type: {:?}", key_format_type),
        }
    } else {
        // No format type requested: export the private key to the default format
        let object = openssl_public_key_to_kmip_default_format(
            &openssl_key,
            attributes.cryptographic_usage_mask,
        )?;
        object_with_metadata.set_object(object);
    }

    // Merge the correct cryptographic attributes in the attributes
    if let Ok(key_block_attributes) = object_with_metadata.object().attributes() {
        attributes.merge(key_block_attributes, true);
    }

    // set the attributes back
    if let Ok(attrs) = object_with_metadata
        .object_mut()
        .key_block_mut()?
        .attributes_mut()
    {
        *attrs = attributes;
    }

    Ok(())
}

async fn unwrap_if_requested(
    object_with_metadata: &mut ObjectWithMetadata,
    key_wrap_type: &Option<KeyWrapType>,
    kms: &KMS,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> Result<(), KmsError> {
    if let Some(key_wrap_type) = key_wrap_type {
        if *key_wrap_type == KeyWrapType::NotWrapped {
            let mut object = kms
                .get_unwrapped(
                    object_with_metadata.id(),
                    object_with_metadata.object(),
                    user,
                    params,
                )
                .await?;
            // If we have lost attributes on the unwrapped object, we need to restore them
            if let Ok(key_block) = object.key_block_mut() {
                if let Some(KeyValue::Structure { attributes, .. }) = key_block.key_value.as_mut() {
                    if attributes.is_none() {
                        // if the attributes are None, we need to set them to the existing
                        // attributes
                        *attributes = Some(object_with_metadata.attributes().clone());
                    }
                }
            }
            object_with_metadata.set_object(object);
        }
    }
    Ok(())
}

#[allow(clippy::ref_option)]
async fn process_covercrypt_key(
    covercrypt_key: &mut Object,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    key_format_type: &Option<KeyFormatType>,
    kms: &KMS,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<()> {
    // Wrapping is only available for KeyFormatType being the default (i.e. None)
    if let Some(key_wrapping_specification) = key_wrapping_specification {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to wrap a Covercrypt key with a specified Key Format Type. It \
                 must be the default"
            )
        }
        // wrap the key
        wrap_object(
            covercrypt_key,
            key_wrapping_specification,
            kms,
            user,
            params,
        )
        .await?;
    }
    Ok(())
}

pub(crate) fn openssl_private_key_to_kmip_default_format(
    key: &PKey<Private>,
    cryptographic_usage_mask: Option<CryptographicUsageMask>,
) -> KResult<Object> {
    let key_type_id = key.id();
    let object = match key_type_id {
        Id::RSA => {
            // The default for RSA is `PKCS#1`
            openssl_private_key_to_kmip(key, KeyFormatType::PKCS1, cryptographic_usage_mask)?
        }
        Id::EC | Id::ED25519 | Id::X448 | Id::X25519 => {
            // The default for EC is `TransparentECPrivateKey`
            openssl_private_key_to_kmip(
                key,
                KeyFormatType::TransparentECPrivateKey,
                cryptographic_usage_mask,
            )?
        }
        x => kms_bail!("Private Keys of type: {x:?}, are not supported"),
    };
    Ok(object)
}

pub(crate) fn openssl_public_key_to_kmip_default_format(
    key: &PKey<Public>,
    cryptographic_usage_mask: Option<CryptographicUsageMask>,
) -> KResult<Object> {
    let key_type_id = key.id();
    let object = match key_type_id {
        Id::RSA => {
            // The default for RSA is `PKCS#1`
            openssl_public_key_to_kmip(key, KeyFormatType::PKCS1, cryptographic_usage_mask)?
        }
        Id::EC | Id::ED25519 | Id::X448 | Id::X25519 => {
            // The default for EC is `TransparentECPrivateKey`
            openssl_public_key_to_kmip(
                key,
                KeyFormatType::TransparentECPublicKey,
                cryptographic_usage_mask,
            )?
        }
        x => kms_bail!("Private Keys of type: {x:?}, are not supported"),
    };
    Ok(object)
}

#[allow(clippy::ref_option)]
async fn process_symmetric_key(
    object_with_metadata: &mut ObjectWithMetadata,
    key_format_type: &Option<KeyFormatType>,
    key_wrap_type: &Option<KeyWrapType>,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    kms: &KMS,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<()> {
    trace!(
        "process_symmetric_key: object_with_metadata: {}",
        object_with_metadata
    );

    // First check is any unwrapping needs to be done
    unwrap_if_requested(
        object_with_metadata,
        key_wrap_type,
        kms,
        user,
        params.clone(),
    )
    .await?;

    let object = object_with_metadata.object_mut();
    let key_block = object.key_block_mut()?;

    // If the key is still wrapped the the export KeyFormatType must be the default (none)
    if key_block.key_wrapping_data.is_some() {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to export a wrapped symmetric key with a requested Key Format \
                 Type. It must be the default"
            )
        }
        // The key is wrapped and as expected the requested Key Format Type is the default (none)
        // => The key is exported as such
        return Ok(());
    }

    // we have an unwrapped key, convert it to the pivotal format first,
    // which is getting the key bytes

    let Some(&mut KeyValue::Structure {
        ref mut key_material,
        ref mut attributes,
    }) = key_block.key_value.as_mut()
    else {
        return Err(KmsError::Default(
            "process_symmetric_key: key value not found in key".to_owned(),
        ));
    };

    let key_bytes = match key_material {
        KeyMaterial::ByteString(key_bytes) => key_bytes.clone(),
        KeyMaterial::TransparentSymmetricKey { key } => key.clone(),
        _ => kms_bail!("export: unsupported key material"),
    };

    // Wrapping is only available for KeyFormatType being the default (i.e. None)
    if let Some(key_wrapping_specification) = key_wrapping_specification {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to wrap a symmetric key with a specified Key Format Type. It must \
                 be the default"
            )
        }
        // generate a key block in the default format, which is Raw
        key_block.key_value = Some(KeyValue::Structure {
            key_material: KeyMaterial::ByteString(key_bytes),
            attributes: attributes.clone(),
        });
        key_block.key_format_type = KeyFormatType::Raw;
        key_block.attributes_mut()?.key_format_type = Some(KeyFormatType::Raw);
        // wrap the key
        wrap_object(object, key_wrapping_specification, kms, user, params).await?;
        return Ok(());
    }

    // The key  is not wrapped => export to desired format
    match key_format_type {
        Some(KeyFormatType::TransparentSymmetricKey) => {
            key_block.key_value = Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentSymmetricKey { key: key_bytes },
                attributes: attributes.clone(),
            });
            key_block.key_format_type = KeyFormatType::TransparentSymmetricKey;
        }
        None | Some(KeyFormatType::Raw) => {
            key_block.key_value = Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(key_bytes),
                attributes: attributes.clone(),
            });
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

async fn build_pkcs12_for_private_key(
    kms: &KMS,
    operation_type: KmipOperation,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
    request: &Export,
    private_key_owm: &mut ObjectWithMetadata,
) -> Result<(), KmsError> {
    trace!(
        "build_pkcs12_for_private_key: {} with format: {:?}",
        private_key_owm.id(),
        request.key_format_type
    );

    let mut cert_owm = retrieve_certificate_for_private_key(
        private_key_owm,
        operation_type,
        kms,
        user,
        params.clone(),
    )
    .await?;
    let certificate = kmip_certificate_to_openssl(cert_owm.object())?;

    trace!("building chain from leaf certificate:  {}", cert_owm.id());

    // retrieve the certificate chain
    let mut chain: Stack<X509> = Stack::new()?;
    while let Some(parent_id) = cert_owm.attributes().get_link(LinkType::CertificateLink) {
        // if the parent_id is identical to the current certificate => self-signed cert, we must stop
        if parent_id.to_string() == cert_owm.id() {
            break;
        }
        trace!("certificate parent id is:  {}", parent_id);
        // retrieve the parent certificate
        cert_owm = retrieve_object_for_operation(
            &parent_id.to_string(),
            operation_type,
            kms,
            user,
            params.clone(),
        )
        .await?;
        let certificate = kmip_certificate_to_openssl(cert_owm.object())?;
        chain.push(certificate)?;
    }

    // recover the password
    let password = request
        .key_wrapping_specification
        .as_ref()
        .and_then(|kws| kws.encryption_key_information.as_ref())
        .map(|eki| eki.unique_identifier.to_string())
        .unwrap_or_default();
    // convert the Private Key to openssl
    trace!(
        "converting the private key {} to openssl pkey",
        private_key_owm.id()
    );
    let private_key = kmip_private_key_to_openssl(private_key_owm.object())
        .context("export: unable to parse the private key to openssl")?;

    // Create the PKCS12
    trace!("building the PKCS12");
    let mut pkcs12_builder = openssl::pkcs12::Pkcs12::builder();
    pkcs12_builder
        .pkey(&private_key)
        .cert(&certificate)
        .ca(chain);

    #[cfg(feature = "non-fips")]
    {
        // support for OLD PKCS#12 formats
        if request.key_format_type == Some(KeyFormatType::Pkcs12Legacy) {
            pkcs12_builder
                .cert_algorithm(Nid::PBE_WITHSHA1AND40BITRC2_CBC)
                .key_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
                .mac_md(MessageDigest::sha1());
        }
    }
    let pkcs12 = pkcs12_builder
        .build2(&password)
        .context("export: unable to build the PKCS12")?;

    // add the certificate to the private key
    private_key_owm.set_object(Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::PKCS12,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::from(pkcs12.to_der()?)),
                // attributes are added later
                attributes: None,
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    }));
    Ok(())
}

async fn post_process_pkcs7(
    kms: &KMS,
    operation_type: KmipOperation,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
    owm: ObjectWithMetadata,
) -> KResult<ObjectWithMetadata> {
    // convert the cert to openssl
    let certificate = kmip_certificate_to_openssl(owm.object())
        .context("export: unable to parse the certificate to openssl")?;

    let mut cert_owm = owm.clone();

    let leaf_cert = certificate.clone();
    let public_key_id = cert_owm
        .attributes()
        .get_link(LinkType::PublicKeyLink)
        .ok_or_else(|| {
            KmipError::Default("No Public Key found in the leaf certificate".to_owned())
        })?;
    let public_key_owm = retrieve_object_for_operation(
        &public_key_id.to_string(),
        operation_type,
        kms,
        user,
        params.clone(),
    )
    .await?;
    let private_key_id = public_key_owm
        .attributes()
        .get_link(LinkType::PrivateKeyLink);
    if let Some(private_key_id) = private_key_id {
        let private_key_owm = retrieve_object_for_operation(
            &private_key_id.to_string(),
            operation_type,
            kms,
            user,
            params.clone(),
        )
        .await?;
        let pkey = kmip_private_key_to_openssl(private_key_owm.object())
            .context("export: unable to parse the private key to openssl")?;

        // Create the PKCS7 structure
        let mut chain: Stack<X509> = Stack::new()?;

        // Retrieve the certificate chain
        while let Some(parent_id) = cert_owm.attributes().get_link(LinkType::CertificateLink) {
            trace!("Certificate parent id is: {parent_id}");
            if parent_id.to_string() == cert_owm.id() {
                break;
            }
            // Retrieve the parent certificate
            cert_owm = retrieve_object_for_operation(
                &parent_id.to_string(),
                operation_type,
                kms,
                user,
                params.clone(),
            )
            .await?;
            let certificate = kmip_certificate_to_openssl(cert_owm.object())
                .context("export: unable to parse the certificate to openssl")?;
            chain.push(certificate)?;
        }

        // Build PKCS7
        let pkcs7 = Pkcs7::sign(
            &leaf_cert,
            &pkey,
            &chain,
            &[],
            openssl::pkcs7::Pkcs7Flags::empty(),
        )?;

        // Modify initial owm
        cert_owm.set_object(Object::Certificate(Certificate {
            certificate_type: CertificateType::PKCS7,
            certificate_value: pkcs7.to_der()?,
        }));
    }

    Ok(cert_owm)
}

#[allow(clippy::ref_option)]
async fn process_secret_data(
    object_with_metadata: &mut ObjectWithMetadata,
    key_format_type: &Option<KeyFormatType>,
    key_wrap_type: &Option<KeyWrapType>,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    kms: &KMS,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<()> {
    trace!(
        "process_secret_data: object_with_metadata: {}",
        object_with_metadata
    );

    // First check is any unwrapping needs to be done
    unwrap_if_requested(
        object_with_metadata,
        key_wrap_type,
        kms,
        user,
        params.clone(),
    )
    .await?;

    let object = object_with_metadata.object_mut();
    let key_block = object.key_block_mut()?;

    // If the key is still wrapped the the export KeyFormatType must be the default (none)
    if key_block.key_wrapping_data.is_some() {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to export a wrapped secret datawith a requested Key Format Type. \
                 It must be the default"
            )
        }
        // The key is wrapped and as expected the requested Key Format Type is the default (none)
        // => The key is exported as such
        return Ok(())
    }

    // we have an unwrapped key, convert it to the pivotal format first,
    // which is getting the key bytes

    let Some(&mut KeyValue::Structure {
        ref mut key_material,
        ref mut attributes,
    }) = key_block.key_value.as_mut()
    else {
        return Err(KmsError::Default(
            "process_secret_data: key value not found in key".to_owned(),
        ));
    };

    let key_bytes = match key_material {
        KeyMaterial::ByteString(key_bytes) => key_bytes.clone(),
        _ => kms_bail!("export: unsupported key material"),
    };

    // Wrapping is only available for KeyFormatType being the default (i.e. None)
    if let Some(key_wrapping_specification) = key_wrapping_specification {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to wrap a secret data with a specified Key Format Type. It must \
                 be the default"
            )
        }
        // generate a key block in the default format, which is Raw
        key_block.key_value = Some(KeyValue::Structure {
            key_material: KeyMaterial::ByteString(key_bytes),
            attributes: attributes.clone(),
        });
        key_block.key_format_type = KeyFormatType::Raw;
        key_block.attributes_mut()?.key_format_type = Some(KeyFormatType::Raw);
        // wrap the key
        wrap_object(object, key_wrapping_specification, kms, user, params).await?;
        return Ok(())
    }

    // The key  is not wrapped => export to desired format
    match key_format_type {
        None | Some(KeyFormatType::Raw) => {
            key_block.key_value = Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(key_bytes),
                attributes: attributes.clone(),
            });
            key_block.key_format_type = KeyFormatType::Raw;
            key_block.attributes_mut()?.key_format_type = Some(KeyFormatType::Raw);
        }
        _ => kms_bail!(
            "export: unsupported requested Key Format Type for a secret data: {:?}",
            key_format_type
        ),
    }

    Ok(())
}
