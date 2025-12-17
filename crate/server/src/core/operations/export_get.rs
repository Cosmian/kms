use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        KmipError,
        kmip_0::kmip_types::{
            CertificateType, CryptographicUsageMask, ErrorReason, KeyWrapType, State,
        },
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
    cosmian_kms_interfaces::{AtomicOperation, ObjectWithMetadata},
};
use cosmian_logger::{debug, info, trace};
#[cfg(feature = "non-fips")]
use openssl::{hash::MessageDigest, nid::Nid};
use openssl::{
    pkcs7::Pkcs7,
    pkey::{Id, PKey, Private, Public},
    stack::Stack,
    x509::X509,
};
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
) -> KResult<ExportResponse> {
    let request: Export = request.into();
    trace!(target: "kmip", "[diag-export_get] enter export_get op={:?} req={}", operation_type, request);

    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Export: unique_identifier or tags must be a string")?;
    let mut owm = Box::pin(retrieve_object_for_operation(
        uid_or_tags,
        operation_type,
        kms,
        user,
    ))
    .await?;

    // Log basic object metadata before any processing
    trace!(target: "kmip", "[diag-export_get] retrieved object uid={} type={:?} state={:?} key_fmt={:?}",
        owm.id(), owm.object().object_type(), owm.state(), owm.object().key_block().ok().map(|kb| kb.key_format_type));

    // The object cannot be returned (Get/Export) if it is sensitive and not wrapped.
    // Per KMIP Profiles vector BL-M-12-21 the server must return ResultReason=Sensitive and message DENIED.
    if owm.attributes().sensitive == Some(true) && request.key_wrapping_specification.is_none() {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Sensitive,
            "DENIED".to_owned(),
        ));
    }

    // Revoked (Deactivated / Compromised) objects must NOT be accessible via Get (without
    // allow_revoked). The client uses Export with allow_revoked=true when retrieval of a revoked
    // object is explicitly requested. Enforce denial only for Get so that Export path continues
    // to work for revoked objects but still blocks destroyed objects later.
    if operation_type == KmipOperation::Get && matches!(owm.state(), State::Deactivated) {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Wrong_Key_Lifecycle_State,
            "DENIED".to_owned(),
        ));
    }

    let object_type = owm.object().object_type();
    let export = operation_type == KmipOperation::Export;

    // Lifecycle enforcement adjustments: If object is Destroyed, KMIP Get / Export MUST fail with ObjectDestroyed
    // (BL-M-8-21 expects ResultReason=ObjectDestroyed, message DENIED). We surface the specific KMIP error here.
    if matches!(owm.state(), State::Destroyed | State::Destroyed_Compromised) {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Object_Destroyed,
            "DENIED".to_owned(),
        ));
    }

    // export based on the Object type
    match object_type {
        ObjectType::PrivateKey => {
            Box::pin(post_process_private_key(
                kms,
                operation_type,
                user,
                &request,
                &mut owm,
            ))
            .await?;
            // KMIP Fresh semantics: once the private key material has been returned unwrapped,
            // Fresh should flip to false. Persist this so a subsequent GetAttributes shows false
            // (BL-M-13-21 step 5).
            if owm.attributes().fresh == Some(true) {
                if let Ok(kb) = owm.object().key_block() {
                    if kb.key_wrapping_data.is_none() {
                        let mut updated_attrs = owm.attributes().clone();
                        updated_attrs.fresh = Some(false);
                        let uid = owm.id().to_owned();
                        // Also flip Fresh inside the embedded KeyBlock attributes if present
                        let mut obj = owm.object().clone();
                        if let Ok(kb) = obj.key_block_mut() {
                            if let Some(KeyValue::Structure { attributes, .. }) =
                                kb.key_value.as_mut()
                            {
                                if let Some(inner) = attributes.as_mut() {
                                    inner.fresh = Some(false);
                                }
                            }
                        }
                        // Persist update without modifying tags
                        kms.database
                            .atomic(
                                user,
                                &[AtomicOperation::UpdateObject((
                                    uid,
                                    obj,
                                    updated_attrs,
                                    None,
                                ))],
                            )
                            .await?;
                        // Mirror change in-memory for immediate consistency
                        let attrs_mut = owm.attributes_mut();
                        attrs_mut.fresh = Some(false);
                        if let Ok(kb_mut) = owm.object_mut().key_block_mut() {
                            if let Some(KeyValue::Structure { attributes, .. }) =
                                kb_mut.key_value.as_mut()
                            {
                                if let Some(inner) = attributes.as_mut() {
                                    inner.fresh = Some(false);
                                }
                            }
                        }
                    }
                }
            }
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
                Box::pin(process_public_key(
                    &mut owm,
                    &request.key_format_type,
                    &request.key_wrap_type,
                    &request.key_wrapping_specification,
                    kms,
                    user,
                ))
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
                trace!(target: "kmip", "[diag-export_get] processing symmetric key uid={} state={:?} requested_format={:?}", owm.id(), owm.state(), request.key_format_type);
                Box::pin(process_symmetric_key(
                    &mut owm,
                    &request.key_format_type,
                    &request.key_wrap_type,
                    &request.key_wrapping_specification,
                    kms,
                    user,
                ))
                .await?;
                trace!(target: "kmip", "[diag-export_get] post-process symmetric key uid={} final_format={:?}", owm.id(), owm.object().key_block().ok().map(|kb| kb.key_format_type));

                // KMIP Fresh semantics for symmetric keys: once the key material has been
                // returned unwrapped, Fresh should flip to false and be persisted so that
                // subsequent GetAttributes reflects it (e.g., TL-M-3-21 step=2).
                if owm.attributes().fresh != Some(false) {
                    if let Ok(kb) = owm.object().key_block() {
                        if kb.key_wrapping_data.is_none() {
                            let mut updated_attrs = owm.attributes().clone();
                            updated_attrs.fresh = Some(false);
                            let uid = owm.id().to_owned();
                            // Also flip Fresh inside the embedded KeyBlock attributes if present
                            let mut obj = owm.object().clone();
                            if let Ok(kb_mut) = obj.key_block_mut() {
                                if let Some(KeyValue::Structure { attributes, .. }) =
                                    kb_mut.key_value.as_mut()
                                {
                                    if let Some(inner) = attributes.as_mut() {
                                        inner.fresh = Some(false);
                                    }
                                }
                            }
                            // Persist update without modifying tags
                            kms.database
                                .atomic(
                                    user,
                                    &[AtomicOperation::UpdateObject((
                                        uid,
                                        obj,
                                        updated_attrs,
                                        None,
                                    ))],
                                )
                                .await?;
                            // Mirror change in-memory for immediate consistency
                            let attrs_mut = owm.attributes_mut();
                            attrs_mut.fresh = Some(false);
                            if let Ok(kb_mut) = owm.object_mut().key_block_mut() {
                                if let Some(KeyValue::Structure { attributes, .. }) =
                                    kb_mut.key_value.as_mut()
                                {
                                    if let Some(inner) = attributes.as_mut() {
                                        inner.fresh = Some(false);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        ObjectType::Certificate => {
            if let Some(key_format_type) = &request.key_format_type {
                #[cfg(not(feature = "non-fips"))]
                let is_pkcs12 = *key_format_type == KeyFormatType::PKCS12;
                #[cfg(feature = "non-fips")]
                let is_pkcs12 = *key_format_type == KeyFormatType::PKCS12 || {
                    #[cfg(feature = "non-fips")]
                    {
                        *key_format_type == KeyFormatType::Pkcs12Legacy
                    }
                    #[cfg(not(feature = "non-fips"))]
                    {
                        false
                    }
                };
                if is_pkcs12 {
                    // retrieve the private key
                    owm = retrieve_private_key_for_certificate(
                        uid_or_tags,
                        operation_type,
                        kms,
                        user,
                    )
                    .await?;
                    Box::pin(post_process_private_key(
                        kms,
                        operation_type,
                        user,
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
                    ))
                    .await?;
                } else if *key_format_type == KeyFormatType::PKCS7 {
                    owm = Box::pin(post_process_pkcs7(kms, operation_type, user, owm)).await?;
                }

                #[cfg(not(feature = "non-fips"))]
                let is_wrong_format = *key_format_type != KeyFormatType::X509
                    && *key_format_type != KeyFormatType::PKCS7
                    && *key_format_type != KeyFormatType::PKCS12;
                #[cfg(feature = "non-fips")]
                let is_wrong_format = *key_format_type != KeyFormatType::X509
                    && *key_format_type != KeyFormatType::PKCS7
                    && *key_format_type != KeyFormatType::PKCS12
                    && {
                        #[cfg(feature = "non-fips")]
                        {
                            *key_format_type != KeyFormatType::Pkcs12Legacy
                        }
                        #[cfg(not(feature = "non-fips"))]
                        {
                            true
                        }
                    };
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
                Box::pin(process_secret_data(
                    &mut owm,
                    &request.key_format_type,
                    &request.key_wrap_type,
                    &request.key_wrapping_specification,
                    kms,
                    user,
                ))
                .await?;
            }
        }
        ObjectType::OpaqueObject => {
            // Opaque Objects are returned as-is. KMIP does not define alternate export
            // formats for OpaqueObject; no wrapping/unwrapping semantics apply here beyond
            // what retrieve_object_for_operation has already enforced. If future profile
            // vectors require additional behaviors (e.g., redaction on destroyed state),
            // they can be added analogously to SecretData above.
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
    let is_pkcs12 = request.key_format_type == Some(KeyFormatType::PKCS12) || {
        #[cfg(feature = "non-fips")]
        {
            request.key_format_type == Some(KeyFormatType::Pkcs12Legacy)
        }
        #[cfg(not(feature = "non-fips"))]
        {
            false
        }
    };

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
        Box::pin(post_process_active_private_key(
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
        ))
        .await?;
    }
    // in the case of a PKCS#12, the private key must be packaged with the certificate
    if is_pkcs12 {
        Box::pin(build_pkcs12_for_private_key(
            kms,
            operation_type,
            user,
            request,
            owm,
        ))
        .await?;
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
) -> KResult<()> {
    trace!("key_format_type: {key_format_type:?}",);
    // First perform any necessary unwrapping to the expected type
    unwrap_if_requested(
        object_with_metadata,
        key_wrap_type,
        kms,
        user,
        ObjectType::PrivateKey,
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
        return Box::pin(process_covercrypt_key(
            object,
            key_wrapping_specification,
            key_format_type,
            kms,
            user,
        ))
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

    // Special-case TransparentDSAPrivateKey: we do not need (nor want) an OpenSSL round-trip
    // if the caller either requested no specific format OR explicitly requested the same
    // TransparentDSAPrivateKey format. This preserves the original key material as registered
    // or created (test vectors BL-M-13-21 style) and avoids unsupported conversions.
    let is_transparent_dsa = matches!(
        object.key_block(),
        Ok(KeyBlock {
            key_format_type: KeyFormatType::TransparentDSAPrivateKey,
            ..
        })
    );
    let requesting_same_transparent = matches!(
        key_format_type,
        Some(KeyFormatType::TransparentDSAPrivateKey) | None
    );
    if is_transparent_dsa && requesting_same_transparent {
        // Still honor wrapping if specified
        if let Some(kws) = key_wrapping_specification {
            if !matches!(
                key_format_type,
                None | Some(KeyFormatType::TransparentDSAPrivateKey)
            ) {
                kms_bail!("export: incompatible key format request for TransparentDSAPrivateKey")
            }
            // Wrap the existing object in-place
            unwrap_if_requested(
                object_with_metadata,
                key_wrap_type,
                kms,
                user,
                ObjectType::PrivateKey,
            )
            .await?; // ensure unwrapped first
            let mut cloned = object_with_metadata.object().clone();
            wrap_object(&mut cloned, kws, kms, user).await?;
            *object_with_metadata.object_mut() = cloned;
        } else {
            // Just ensure unwrapped if requested (normal path); no format conversion applied
            unwrap_if_requested(
                object_with_metadata,
                key_wrap_type,
                kms,
                user,
                ObjectType::PrivateKey,
            )
            .await?;
        }
        return Ok(());
    }
    // If it's a TransparentDSAPrivateKey and a different format was requested, return NotSupported explicitly.
    if is_transparent_dsa && !requesting_same_transparent {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Operation_Not_Supported,
            "DSA format conversion not supported".to_owned(),
        ));
    }

    // parse the key to an openssl object for all other private key formats
    let openssl_key = kmip_private_key_to_openssl(object)
        .context("export: unable to parse the private key to openssl")?;

    // Sanity check: verify RSA private key integrity if it's an RSA key
    if openssl_key.id() == openssl::pkey::Id::RSA {
        openssl_key
            .rsa()
            .context("export: failed to extract RSA key for validation")?
            .check_key()
            .context("export: RSA private key validation failed - key is mathematically invalid")?;
    }

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

        // Merge the correct cryptographic attributes in the attributes if present
        if let Ok(obj_attrs) = object.attributes() {
            attributes.merge(obj_attrs, true);
        }

        // Get the key block
        let key_block = object.key_block_mut()?;
        // add the attributes back; handle missing attribute container gracefully
        match key_block.key_value.as_mut() {
            Some(KeyValue::Structure {
                attributes: attrs, ..
            }) => {
                *attrs = Some(attributes.clone());
            }
            Some(KeyValue::ByteString(bytes)) => {
                // Preserve existing key material and create a structured KeyValue with attributes
                let km = KeyMaterial::ByteString(bytes.clone());
                key_block.key_value = Some(KeyValue::Structure {
                    key_material: km,
                    attributes: Some(attributes.clone()),
                });
            }
            None => {
                // No key value present: create an empty structure with attributes
                key_block.key_value = Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(Zeroizing::from(vec![])),
                    attributes: Some(attributes.clone()),
                });
            }
        }

        // wrap the key
        Box::pin(wrap_object(
            &mut object,
            key_wrapping_specification,
            kms,
            user,
        ))
        .await?;
        // reassign the wrapped key
        object_with_metadata.set_object(object);
        return Ok(());
    }

    // No wrapping requested: export the private key to the requested format
    if let Some(key_format_type) = key_format_type {
        debug!("exporting private key with format: {:?}", key_format_type);
        #[cfg(feature = "non-fips")]
        let supported_formats = [
            KeyFormatType::PKCS1,
            KeyFormatType::PKCS8,
            KeyFormatType::TransparentECPrivateKey,
            KeyFormatType::TransparentRSAPrivateKey,
            KeyFormatType::ECPrivateKey,
            KeyFormatType::PKCS12,
            #[cfg(feature = "non-fips")]
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

    // add the attributes back; handle missing attribute container gracefully
    match key_block.key_value.as_mut() {
        Some(KeyValue::Structure {
            attributes: attrs, ..
        }) => {
            *attrs = Some(attributes.clone());
        }
        Some(KeyValue::ByteString(bytes)) => {
            let km = KeyMaterial::ByteString(bytes.clone());
            key_block.key_value = Some(KeyValue::Structure {
                key_material: km,
                attributes: Some(attributes.clone()),
            });
        }
        None => {
            key_block.key_value = Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::from(vec![])),
                attributes: Some(attributes.clone()),
            });
        }
    }

    Ok(())
}

#[expect(clippy::ref_option)]
async fn process_public_key(
    object_with_metadata: &mut ObjectWithMetadata,
    key_format_type: &Option<KeyFormatType>,
    key_wrap_type: &Option<KeyWrapType>,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    kms: &KMS,
    user: &str,
) -> KResult<()> {
    // perform any necessary unwrapping
    unwrap_if_requested(
        object_with_metadata,
        key_wrap_type,
        kms,
        user,
        ObjectType::PublicKey,
    )
    .await?;

    // make a copy of the existing attributes
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
            return Box::pin(process_covercrypt_key(
                object,
                key_wrapping_specification,
                key_format_type,
                kms,
                user,
            ))
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
        Box::pin(wrap_object(
            &mut object,
            key_wrapping_specification,
            kms,
            user,
        ))
        .await?;
        // reassign the wrapped key
        *object_with_metadata.object_mut() = object;
        return Ok(());
    }

    // No wrapping requested: export the private key to the requested format
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

    object_type: ObjectType,
) -> Result<(), KmsError> {
    let mut key_wrap_type = *key_wrap_type;
    if key_wrap_type.is_none() {
        if let Some(defaults) = &kms.params.default_unwrap_types {
            if defaults.contains(&object_type) {
                key_wrap_type = Some(KeyWrapType::NotWrapped);
                debug!("Setting key_wrap_type to NotWrapped due to default_unwrap_types");
            }
        }
    }
    debug!("Key wrap type: {:?}", key_wrap_type);
    if let Some(key_wrap_type) = key_wrap_type {
        if key_wrap_type == KeyWrapType::NotWrapped {
            let mut object = kms
                .get_unwrapped(
                    object_with_metadata.id(),
                    object_with_metadata.object(),
                    user,
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

#[expect(clippy::ref_option)]
async fn process_covercrypt_key(
    covercrypt_key: &mut Object,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    key_format_type: &Option<KeyFormatType>,
    kms: &KMS,
    user: &str,
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
        Box::pin(wrap_object(
            covercrypt_key,
            key_wrapping_specification,
            kms,
            user,
        ))
        .await?;
    }
    Ok(())
}

pub(super) fn openssl_private_key_to_kmip_default_format(
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

pub(super) fn openssl_public_key_to_kmip_default_format(
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

#[expect(clippy::ref_option)]
async fn process_symmetric_key(
    object_with_metadata: &mut ObjectWithMetadata,
    key_format_type: &Option<KeyFormatType>,
    key_wrap_type: &Option<KeyWrapType>,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    kms: &KMS,
    user: &str,
) -> KResult<()> {
    trace!(
        "process_symmetric_key: object_with_metadata: {}",
        object_with_metadata
    );

    trace!(target: "kmip", "[diag-process_symmetric_key] enter uid={} requested_format={:?} wrap_type={:?}",
        object_with_metadata.id(), key_format_type, key_wrap_type);

    // First check is any unwrapping needs to be done
    unwrap_if_requested(
        object_with_metadata,
        key_wrap_type,
        kms,
        user,
        ObjectType::SymmetricKey,
    )
    .await?;

    // Capture id early to avoid borrow checker conflicts in trace statements
    let obj_id = object_with_metadata.id().to_owned();
    // let object = object_with_metadata.object_mut();
    // let key_block = object.key_block_mut()?;
    // Check whether the stored object is wrapped without taking a mutable borrow.
    let is_wrapped = object_with_metadata
        .object()
        .key_block()?
        .key_wrapping_data
        .is_some();

    // trace!(target: "kmip", "[diag-process_symmetric_key] key_block initial format={:?} wrapped={} uid={}", key_block.key_format_type, key_block.key_wrapping_data.is_some(), obj_id);

    // If the key is still wrapped then historically we rejected any requested KeyFormatType.
    // Allow the client to request `Raw` but, in order to provide actual raw key bytes (so the
    // KEK can be used to wrap another object), attempt to obtain the unwrapped key from the
    // KMS before returning. If the request explicitly asks for other formats, keep rejecting
    // them for wrapped objects.
    if is_wrapped {
        if let Some(req_fmt) = key_format_type {
            if matches!(req_fmt, KeyFormatType::Raw) {
                // Try to unwrap the stored wrapped key so callers requesting Raw actually get the
                // underlying key bytes. This mirrors the behavior expected when the key must be
                // unwrapped to be used as a KEK to wrap another key.
                let mut unwrapped = kms
                    .get_unwrapped(
                        object_with_metadata.id(),
                        object_with_metadata.object(),
                        user,
                    )
                    .await?;

                // If the unwrapped object lost attributes in the KeyValue::Structure, restore
                // them from the object metadata so downstream attribute accessors succeed.
                if let Ok(kb) = unwrapped.key_block_mut() {
                    if let Some(KeyValue::Structure {
                        attributes: attrs, ..
                    }) = kb.key_value.as_mut()
                    {
                        if attrs.is_none() {
                            *attrs = Some(object_with_metadata.attributes().clone());
                        }
                    }
                }

                // Replace the object with the unwrapped representation and continue processing
                // as an unwrapped symmetric key (so the normal export flow will return raw
                // key bytes).
                object_with_metadata.set_object(unwrapped);
            } else {
                // any other requested format remains unsupported for wrapped objects
                kms_bail!(
                    "export: unable to export a wrapped symmetric key with a requested Key Format \
                     Type. It must be the default or Raw"
                )
            }
        } else {
            // No specific KeyFormatType requested — export the wrapped object as registered
            return Ok(());
        }
    }

    // we have an unwrapped key, convert it to the pivotal format first,
    // which is getting the key bytes

    // Obtain mutable access to the (now guaranteed unwrapped) object and key block.
    let object = object_with_metadata.object_mut();
    let key_block = object.key_block_mut()?;

    // We have an unwrapped key, collect the key bytes and a copy of nested attributes
    let (key_bytes, mut nested_attrs) = if let Some(KeyValue::Structure {
        key_material,
        attributes,
    }) = key_block.key_value.as_ref()
    {
        match key_material {
            KeyMaterial::ByteString(b) => (b.clone(), attributes.clone()),
            KeyMaterial::TransparentSymmetricKey { key } => (key.clone(), attributes.clone()),
            _ => kms_bail!("export: unsupported key material"),
        }
    } else {
        trace!(target: "kmip", "[diag-process_symmetric_key] missing key_value structure uid={}", object_with_metadata.id());
        return Err(KmsError::Default(
            "process_symmetric_key: key value not found in key".to_owned(),
        ));
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
            attributes: nested_attrs.clone(),
        });
        key_block.key_format_type = KeyFormatType::Raw;
        if let Some(inner) = nested_attrs.as_mut() {
            inner.key_format_type = Some(KeyFormatType::Raw);
        }
        // wrap the key
        Box::pin(wrap_object(object, key_wrapping_specification, kms, user)).await?;
        return Ok(());
    }

    // The key  is not wrapped => export to desired format
    match key_format_type {
        Some(KeyFormatType::TransparentSymmetricKey) => {
            key_block.key_value = Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentSymmetricKey { key: key_bytes },
                attributes: nested_attrs.clone(),
            });
            key_block.key_format_type = KeyFormatType::TransparentSymmetricKey;
            trace!(target: "kmip", "[diag-process_symmetric_key] set TransparentSymmetricKey uid={}", obj_id);
        }
        None | Some(KeyFormatType::Raw) => {
            key_block.key_value = Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(key_bytes),
                attributes: nested_attrs.clone(),
            });
            key_block.key_format_type = KeyFormatType::Raw;
            if let Some(inner) = nested_attrs.as_mut() {
                inner.key_format_type = Some(KeyFormatType::Raw);
            }
            trace!(target: "kmip", "[diag-process_symmetric_key] set Raw uid={}", obj_id);
        }
        _ => kms_bail!(
            "export: unsupported requested Key Format Type for a symmetric key: {:?}",
            key_format_type
        ),
    }

    trace!(target: "kmip", "[diag-process_symmetric_key] exit uid={} final_format={:?}", obj_id, key_block.key_format_type);

    Ok(())
}

async fn build_pkcs12_for_private_key(
    kms: &KMS,
    operation_type: KmipOperation,
    user: &str,

    request: &Export,
    private_key_owm: &mut ObjectWithMetadata,
) -> Result<(), KmsError> {
    trace!(
        "build_pkcs12_for_private_key: {} with format: {:?}",
        private_key_owm.id(),
        request.key_format_type
    );

    let mut cert_owm =
        retrieve_certificate_for_private_key(private_key_owm, operation_type, kms, user).await?;
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
        cert_owm = Box::pin(retrieve_object_for_operation(
            &parent_id.to_string(),
            operation_type,
            kms,
            user,
        ))
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
        #[cfg(feature = "non-fips")]
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
    let public_key_owm = Box::pin(retrieve_object_for_operation(
        &public_key_id.to_string(),
        operation_type,
        kms,
        user,
    ))
    .await?;
    let private_key_id = public_key_owm
        .attributes()
        .get_link(LinkType::PrivateKeyLink);
    if let Some(private_key_id) = private_key_id {
        let private_key_owm = Box::pin(retrieve_object_for_operation(
            &private_key_id.to_string(),
            operation_type,
            kms,
            user,
        ))
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
            cert_owm = Box::pin(retrieve_object_for_operation(
                &parent_id.to_string(),
                operation_type,
                kms,
                user,
            ))
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

#[expect(clippy::ref_option)]
async fn process_secret_data(
    object_with_metadata: &mut ObjectWithMetadata,
    key_format_type: &Option<KeyFormatType>,
    key_wrap_type: &Option<KeyWrapType>,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    kms: &KMS,
    user: &str,
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
        ObjectType::SecretData,
    )
    .await?;

    let object = object_with_metadata.object_mut();
    let key_block = object.key_block_mut()?;

    // If the key is still wrapped the export KeyFormatType must be the default (none)
    if key_block.key_wrapping_data.is_some() {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to export a wrapped secret data with a requested Key Format Type. \
                 It must be the default"
            )
        }
        // The key is wrapped and as expected the requested Key Format Type is the default (none)
        // => The key is exported as such
        return Ok(());
    }

    // we have an unwrapped key, convert it to the pivotal format first,
    // which is getting the key bytes and a copy of nested attributes
    let (key_bytes, mut nested_attrs) = match key_block.key_value.as_ref() {
        Some(KeyValue::Structure {
            key_material,
            attributes,
        }) => match key_material {
            KeyMaterial::ByteString(b) => (b.clone(), attributes.clone()),
            _ => kms_bail!("export: unsupported key material"),
        },
        _ => {
            return Err(KmsError::Default(
                "process_secret_data: key value not found in key".to_owned(),
            ));
        }
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
            attributes: nested_attrs.clone(),
        });
        key_block.key_format_type = KeyFormatType::Raw;
        if let Some(inner) = nested_attrs.as_mut() {
            inner.key_format_type = Some(KeyFormatType::Raw);
        }
        // wrap the key
        Box::pin(wrap_object(object, key_wrapping_specification, kms, user)).await?;
        return Ok(());
    }

    // The key is not wrapped => export to desired format
    match key_format_type {
        // No explicit format requested: preserve the stored KeyFormatType (e.g., Opaque vs Raw)
        None => {
            // Ensure nested Attributes reflect the current KeyBlock format for consistency
            let current_fmt = key_block.key_format_type;
            if let Some(inner) = nested_attrs.as_mut() {
                inner.key_format_type = Some(current_fmt);
            }
            // Keep existing key_material as-is (already ByteString) and do not rewrite format
            key_block.key_value = Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(key_bytes),
                attributes: nested_attrs.clone(),
            });
        }
        Some(KeyFormatType::Raw) => {
            key_block.key_value = Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(key_bytes),
                attributes: nested_attrs.clone(),
            });
            key_block.key_format_type = KeyFormatType::Raw;
            if let Some(inner) = nested_attrs.as_mut() {
                inner.key_format_type = Some(KeyFormatType::Raw);
            }
        }
        // Support explicit Opaque for SecretData (SASED vectors expect Opaque to be retained)
        Some(KeyFormatType::Opaque) => {
            key_block.key_value = Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(key_bytes),
                attributes: nested_attrs.clone(),
            });
            key_block.key_format_type = KeyFormatType::Opaque;
            if let Some(inner) = nested_attrs.as_mut() {
                inner.key_format_type = Some(KeyFormatType::Opaque);
            }
        }
        _ => kms_bail!(
            "export: unsupported requested Key Format Type for a secret data: {:?}",
            key_format_type
        ),
    }

    Ok(())
}
