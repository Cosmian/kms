use std::{collections::HashSet, sync::Arc};

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::pqc::{
    pqc_private_key_pkcs8_to_raw, pqc_public_key_spki_to_raw,
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        KmipError,
        kmip_0::kmip_types::{
            CertificateType, CryptographicUsageMask, ErrorReason, KeyWrapType, State,
        },
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingSpecification},
            kmip_objects::{Certificate, Object, ObjectType, PrivateKey},
            kmip_operations::{Export, ExportResponse},
            kmip_types::{
                CryptographicAlgorithm, KeyCompressionType, KeyFormatType, LinkType,
                UniqueIdentifier,
            },
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

use super::{attributes::collect_attributes, pgp_ops};
use crate::{
    core::{
        KMS,
        certificate::{
            linked_id_str, retrieve_certificate_for_private_key,
            retrieve_private_key_for_certificate,
        },
        retrieve_object_utils::retrieve_object_for_operation,
        uid_utils::{ObjectHandle, from_request},
        wrapping::wrap_object,
    },
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::{KResult, KResultHelper},
};

/// Validate that the object may be exported/retrieved given its Sensitive,
/// Extractable, and `NeverExtractable` attributes.
///
/// Per KMIP 1.4 §3.48 / 2.1 §4.54 (Sensitive): sensitive objects cannot leave in plaintext.
/// Per KMIP 1.4 §3.50 / 2.1 §4.23 (Extractable): non-extractable keys cannot be exported
/// in any form (plaintext or encrypted).
fn check_extractable_and_sensitive(
    owm: &ObjectWithMetadata,
    key_wrapping_specification: &Option<KeyWrappingSpecification>,
    is_pkcs12: bool,
) -> KResult<()> {
    // Extractable=false or NeverExtractable=true (defensive latch check) forbids export completely.
    if owm.attributes().extractable == Some(false)
        || owm.attributes().never_extractable == Some(true)
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Not_Extractable,
            "DENIED".to_owned(),
        ));
    }

    // Sensitive objects cannot be returned without wrapping.
    // For PKCS#12 export, the password is recovered from the key wrapping spec's
    // encryption_key_information. A dummy wrapping spec with no password would yield
    // an empty password and return sensitive key material unprotected.
    // The export path never wraps PGP keys, Opaque Objects or Split Keys, so a wrapping
    // specification does not protect them.
    let unwrappable = matches!(
        owm.object().object_type(),
        ObjectType::PGPKey | ObjectType::OpaqueObject | ObjectType::SplitKey
    );
    let is_wrapped = if is_pkcs12 {
        key_wrapping_specification
            .as_ref()
            .and_then(|kws| kws.encryption_key_information.as_ref())
            .is_some_and(|eki| !eki.unique_identifier.to_string().is_empty())
    } else {
        key_wrapping_specification.is_some() && !unwrappable
    };

    // A sensitive HSM key is never readable by the KMS (the HSM refuses CKA_VALUE and the object
    // is an empty stub) and the KMS never calls C_WrapKey, so wrapping cannot get it out either.
    let is_hsm = ObjectHandle::from(owm.id()).is_hsm();
    if owm.attributes().sensitive == Some(true) && (!is_wrapped || is_hsm) {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Sensitive,
            "DENIED".to_owned(),
        ));
    }

    // Refuse rather than silently return plaintext when wrapping was requested.
    if unwrappable && key_wrapping_specification.is_some() {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Key_Wrap_Type_Not_Supported,
            format!(
                "export: key wrapping is not supported for objects of type {}",
                owm.object().object_type()
            ),
        ));
    }

    Ok(())
}

/// Export an object
///
/// This function is used by the KMIP Export and Get operations
pub(crate) async fn export_get(
    kms: &KMS,
    request: impl Into<Export>,
    operation_type: KmipOperation,
    user: &UserId,
) -> KResult<ExportResponse> {
    let request: Export = request.into();
    if request
        .key_compression_type
        .is_some_and(|compression| compression != KeyCompressionType::ECPublicKeyTypeUncompressed)
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Key_Compression_Type_Not_Supported,
            "Key Compression Type is not supported".to_owned(),
        ));
    }

    let object_handle = from_request(request.unique_identifier.as_ref(), "Export")?;
    let owm = Box::pin(retrieve_object_for_operation(
        object_handle,
        operation_type,
        kms,
        user,
    ))
    .await?;
    let mut owm = Arc::unwrap_or_clone(owm);

    // Log basic object metadata before any processing
    trace!(target: "kmip", "retrieved object uid={} type={:?} state={:?} key_fmt={:?}",
        owm.id(), owm.object().object_type(), owm.state(), owm.object().key_block().ok().map(|kb| kb.key_format_type));

    check_extractable_and_sensitive(&owm, &request.key_wrapping_specification, false)?;

    // Revoked (Deactivated / Compromised) objects must NOT be accessible via Get (without
    // allow_revoked). The client uses Export with allow_revoked=true when retrieval of a revoked
    // object is explicitly requested. Enforce denial only for Get so that Export path continues
    if operation_type == KmipOperation::Get && matches!(owm.state(), State::Deactivated) {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Permission_Denied,
            "DENIED".to_owned(),
        ));
    }

    let object_type = owm.object().object_type();
    let export = operation_type == KmipOperation::Export;

    // KMIP 2.1 §6.1.18: Export of a Destroyed object succeeds but returns no key material (handled
    // per object type below). Get of a Destroyed object fails with Object_Destroyed
    // (BL-M-8-21 expects ResultReason=ObjectDestroyed, message DENIED).
    if !export && matches!(owm.state(), State::Destroyed | State::Destroyed_Compromised) {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Object_Destroyed,
            "DENIED".to_owned(),
        ));
    }

    // KMIP 2.1 §6.1.18: the Export response carries "All of the object's Attributes": the set
    // Get Attributes reports (derived Digest, Short Unique Identifier, Sensitive/Extractable
    // defaults, ...), as it stood before this request served the object (Fresh).
    let export_attributes = if export {
        let mut collected = Box::pin(collect_attributes(kms, &owm, Vec::new())).await?;
        // Get Attributes leaves the tags out unless asked for; Export has always carried them
        // (the client's `--allow-revoked` export and TTLV export/import round-trip rely on it).
        let tags = kms.database.retrieve_tags(owm.id()).await?;
        collected.set_tags(kms.vendor_id(), tags)?;
        Some((owm.id().to_owned(), collected))
    } else {
        None
    };
    // The collected set describes the requested object; a PKCS#12 export of a certificate
    // returns its private key instead, with that key's attributes.
    let response_attributes = |uid: &str, attributes: Attributes| match export_attributes {
        Some((id, collected)) if id == uid => collected,
        _ => attributes,
    };

    // KMIP 2.1 §4.27-§4.28: an object registered without its Key Value (Key Value Present
    // false) is returned as registered; there is no key material to convert or wrap.
    if owm
        .object()
        .key_block()
        .is_ok_and(|key_block| key_block.key_value.is_none())
    {
        if request.key_format_type.is_some() || request.key_wrapping_specification.is_some() {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Key_Value_Not_Present,
                "the object was registered without its Key Value".to_owned(),
            ));
        }
        let (uid, object, attributes) = owm.into_parts();
        return Ok(ExportResponse {
            object_type: object.object_type(),
            attributes: response_attributes(&uid, attributes),
            unique_identifier: UniqueIdentifier::TextString(uid),
            object,
        });
    }

    // Snapshot the original DB-form object before any response-oriented processing.
    // Notice `owm` returned by `retrieve_object_for_operation` may have already been
    // auto-unwrapped if `default_unwrap_types` is configured, so we fetch the raw DB form
    // (from database / cache, which is an Arc peek) to guarantee that any Fresh writeback
    // never accidentally persists an unwrapped plaintext key to storage (COSMIAN-2026-031 / COSMIAN-2026-015).
    let mut original_object: Option<Arc<ObjectWithMetadata>> = if owm.attributes().fresh
        != Some(false)
        && matches!(
            object_type,
            ObjectType::PrivateKey | ObjectType::SymmetricKey
        ) {
        kms.database.retrieve_object_arc(owm.id()).await?
    } else {
        None
    };
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
                        persist_fresh_false(kms, user, &mut owm, original_object.take()).await?;
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
                trace!(target: "kmip", "processing symmetric key uid={} state={:?} requested_format={:?}", owm.id(), owm.state(), request.key_format_type);
                Box::pin(process_symmetric_key(
                    &mut owm,
                    &request.key_format_type,
                    &request.key_wrap_type,
                    &request.key_wrapping_specification,
                    kms,
                    user,
                ))
                .await?;
                trace!(target: "kmip", "post-process symmetric key uid={} final_format={:?}", owm.id(), owm.object().key_block().ok().map(|kb| kb.key_format_type));

                // KMIP Fresh semantics for symmetric keys: once the key material has been
                // returned unwrapped, Fresh should flip to false and be persisted so that
                // subsequent GetAttributes reflects it (e.g., TL-M-3-14 request[0] then request[2]).
                // Note: Get responses may omit Attributes, so key-block inner attributes may be absent.
                if owm.attributes().fresh != Some(false) {
                    let key_returned_unwrapped = request
                        .key_wrap_type
                        .is_none_or(|kwt| kwt == KeyWrapType::NotWrapped)
                        && request.key_wrapping_specification.is_none();
                    if key_returned_unwrapped {
                        persist_fresh_false(kms, user, &mut owm, original_object.take()).await?;
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
                        object_handle,
                        operation_type,
                        kms,
                        user,
                    )
                    .await?;
                    check_extractable_and_sensitive(
                        &owm,
                        &request.key_wrapping_specification,
                        true,
                    )?;
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
                    return Err(KmsError::Kmip21Error(
                        ErrorReason::Key_Format_Type_Not_Supported,
                        format!(
                            "export: unsupported Key Format Type for a certificate: {key_format_type:?}"
                        ),
                    ));
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
        ObjectType::PGPKey => pgp_ops::pgp_export_convert(&mut owm, request.key_format_type)?,
        ObjectType::OpaqueObject | ObjectType::SplitKey => {
            // Opaque Objects and SplitKey shares are returned as-is. KMIP does not define
            // alternate export formats for these types; no wrapping/unwrapping semantics apply.
        }
        ObjectType::CertificateRequest => {
            kms_bail!(
                "export: unsupported object type: {:?}",
                owm.object().object_type()
            )
        }
    }

    info!(
        uid = owm.id(),
        user = user.as_str(),
        "Exported object of type: {}",
        owm.object().object_type()
    );

    let (uid, object, attributes) = owm.into_parts();
    Ok(ExportResponse {
        object_type: object.object_type(),
        attributes: response_attributes(&uid, attributes),
        unique_identifier: UniqueIdentifier::TextString(uid),
        object,
    })
}
/// Post-process a private key
///
/// This function is used to export a private key
/// It will wrap or unwrap the key if necessary and convert it to the requested format.
async fn post_process_private_key(
    kms: &KMS,
    operation_type: KmipOperation,
    user: &UserId,

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
    if is_pkcs12 {
        check_extractable_and_sensitive(owm, &request.key_wrapping_specification, true)?;
    }
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
    user: &UserId,
) -> KResult<()> {
    trace!("key_format_type: {key_format_type:?}",);
    // First perform any necessary unwrapping to the expected type
    Box::pin(unwrap_if_requested(
        object_with_metadata,
        key_wrap_type,
        kms,
        user,
        ObjectType::PrivateKey,
    ))
    .await?;

    let owm_attributes = object_with_metadata.attributes().clone();

    // If the key is still wrapped, check constraints and optionally unwrap for re-wrapping.
    if object_with_metadata.object().is_wrapped() {
        if key_format_type.is_some() {
            kms_bail!(
                "export: unable to export a wrapped key with a requested Key Format Type. It must \
                 be the default"
            )
        }
        if key_wrapping_specification.is_none() {
            // No re-wrapping requested: export the key as-is (still wrapped)
            return Ok(());
        }
        // A re-wrapping specification is present (e.g. CSE key): unwrap the
        // current wrapping (KEK) first so the key can be re-wrapped below.
        let unwrapped = Box::pin(kms.get_unwrapped(
            object_with_metadata.id(),
            object_with_metadata.object(),
            user,
        ))
        .await?;
        object_with_metadata.set_object(unwrapped);
    }

    let object = object_with_metadata.object_mut();
    let key_block = object.key_block_mut()?;

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

    // PQC keys are stored as PKCS#8 (ML-KEM, ML-DSA, SLH-DSA) or Raw
    // (hybrid KEMs) and do not support an OpenSSL round-trip.
    // PKCS#8 → Raw conversion is supported; return as-is otherwise.
    #[cfg(feature = "non-fips")]
    if is_pqc_algorithm(key_block.cryptographic_algorithm) {
        let stored_fmt = key_block.key_format_type;
        // Convert PKCS#8 → Raw when requested; any other format must be the stored one
        // (these keys have no OpenSSL round-trip)
        if let Some(requested) = key_format_type {
            if *requested == KeyFormatType::Raw && stored_fmt == KeyFormatType::PKCS8 {
                let key_bytes = key_block.key_bytes()?;
                let raw_bytes = pqc_private_key_pkcs8_to_raw(&key_bytes).map_err(|e| {
                    KmsError::CryptographicError(format!(
                        "export: failed to convert PQC private key from PKCS#8 to Raw: {e}"
                    ))
                })?;
                key_block.key_format_type = KeyFormatType::Raw;
                if let Some(KeyValue::Structure {
                    ref mut key_material,
                    ..
                }) = key_block.key_value
                {
                    *key_material = KeyMaterial::ByteString(Zeroizing::from(raw_bytes));
                }
            } else if *requested != stored_fmt {
                kms_bail!(
                    "export: PQC key stored as {stored_fmt:?} cannot be converted to \
                     {requested:?}"
                )
            }
        }
        if let Some(kws) = key_wrapping_specification {
            let mut cloned = object_with_metadata.object().clone();
            Box::pin(wrap_object(&mut cloned, kws, kms, user)).await?;
            *object_with_metadata.object_mut() = cloned;
        }
        return Ok(());
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
    // Strip WrappingKeyLink: it belongs to the server-side metadata (tracking the stored
    // wrapping relationship), not to the exported key material. Without this, a key that
    // was imported-as-wrapped and later exported-with-unwrap would carry a stale
    // WrappingKeyLink in its embedded key_value.attributes.
    attributes.remove_link(LinkType::WrappingKeyLink);

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
            Box::pin(unwrap_if_requested(
                object_with_metadata,
                key_wrap_type,
                kms,
                user,
                ObjectType::PrivateKey,
            ))
            .await?; // ensure unwrapped first
            let mut cloned = object_with_metadata.object().clone();
            wrap_object(&mut cloned, kws, kms, user).await?;
            *object_with_metadata.object_mut() = cloned;
        } else {
            // Just ensure unwrapped if requested (normal path); no format conversion applied
            Box::pin(unwrap_if_requested(
                object_with_metadata,
                key_wrap_type,
                kms,
                user,
                ObjectType::PrivateKey,
            ))
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

    if let Some(key_wrapping_specification) = key_wrapping_specification {
        // The Key Format Type designates the format of the key before it is wrapped
        // (KMIP 2.1 §6.1.19: wrapped keys may be returned in any supported format)
        let mut object = private_key_object(
            &openssl_key,
            *key_format_type,
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
    object_with_metadata.set_object(private_key_object(
        &openssl_key,
        *key_format_type,
        attributes.cryptographic_usage_mask,
    )?);
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
    user: &UserId,
) -> KResult<()> {
    // perform any necessary unwrapping
    Box::pin(unwrap_if_requested(
        object_with_metadata,
        key_wrap_type,
        kms,
        user,
        ObjectType::PublicKey,
    ))
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

        // PQC public keys: skip the OpenSSL round-trip, same rationale as private keys.
        #[cfg(feature = "non-fips")]
        if is_pqc_algorithm(key_block.cryptographic_algorithm) {
            let stored_fmt = key_block.key_format_type;
            // Convert SPKI (stored as PKCS8 format type) → Raw when requested; any other format
            // must be the stored one (these keys have no OpenSSL round-trip)
            if let Some(requested) = key_format_type {
                if *requested == KeyFormatType::Raw && stored_fmt == KeyFormatType::PKCS8 {
                    let key_bytes = key_block.key_bytes()?;
                    let raw_bytes = pqc_public_key_spki_to_raw(&key_bytes).map_err(|e| {
                        KmsError::CryptographicError(format!(
                            "export: failed to convert PQC public key from SPKI to Raw: {e}"
                        ))
                    })?;
                    // Drop immutable borrow, re-acquire mutably
                    let key_block_mut = object_with_metadata.object_mut().key_block_mut()?;
                    key_block_mut.key_format_type = KeyFormatType::Raw;
                    if let Some(KeyValue::Structure {
                        ref mut key_material,
                        ..
                    }) = key_block_mut.key_value
                    {
                        *key_material = KeyMaterial::ByteString(Zeroizing::from(raw_bytes));
                    }
                } else if *requested != stored_fmt {
                    kms_bail!(
                        "export: PQC key stored as {stored_fmt:?} cannot be converted to \
                         {requested:?}"
                    )
                }
            }
            if let Some(kws) = key_wrapping_specification {
                let mut cloned = object_with_metadata.object().clone();
                Box::pin(wrap_object(&mut cloned, kws, kms, user)).await?;
                *object_with_metadata.object_mut() = cloned;
            }
            return Ok(());
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
    // Strip WrappingKeyLink from the exported public key attributes (same rationale as
    // post_process_active_private_key: server-side metadata, not part of exported material).
    attributes.remove_link(LinkType::WrappingKeyLink);

    // parse the key to an openssl object
    let openssl_key = kmip_public_key_to_openssl(object_with_metadata.object())
        .context("export: unable to parse the private key to openssl")?;

    if let Some(key_wrapping_specification) = key_wrapping_specification {
        // The Key Format Type designates the format of the key before it is wrapped
        let mut object = public_key_object(
            &openssl_key,
            *key_format_type,
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

    // No wrapping requested: export the public key to the requested format
    object_with_metadata.set_object(public_key_object(
        &openssl_key,
        *key_format_type,
        attributes.cryptographic_usage_mask,
    )?);

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

/// Whether the format is the non-standard legacy PKCS#12 (non-FIPS builds only).
#[cfg(feature = "non-fips")]
const fn is_legacy_pkcs12(key_format_type: KeyFormatType) -> bool {
    matches!(key_format_type, KeyFormatType::Pkcs12Legacy)
}

/// The legacy PKCS#12 format does not exist in FIPS builds.
#[cfg(not(feature = "non-fips"))]
const fn is_legacy_pkcs12(_key_format_type: KeyFormatType) -> bool {
    false
}

/// The private key in the requested Key Format Type, the default format when none is requested.
fn private_key_object(
    openssl_key: &PKey<Private>,
    key_format_type: Option<KeyFormatType>,
    cryptographic_usage_mask: Option<CryptographicUsageMask>,
) -> KResult<Object> {
    let Some(key_format_type) = key_format_type else {
        return openssl_private_key_to_kmip_default_format(openssl_key, cryptographic_usage_mask);
    };
    debug!("exporting private key with format: {:?}", key_format_type);
    let supported = matches!(
        key_format_type,
        KeyFormatType::PKCS1
            | KeyFormatType::PKCS8
            | KeyFormatType::TransparentECPrivateKey
            | KeyFormatType::TransparentRSAPrivateKey
            | KeyFormatType::ECPrivateKey
            | KeyFormatType::PKCS12
    ) || is_legacy_pkcs12(key_format_type);
    if !supported {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Key_Format_Type_Not_Supported,
            format!("export: unsupported Key Format Type: {key_format_type:?} for a private key"),
        ));
    }
    Ok(openssl_private_key_to_kmip(
        openssl_key,
        key_format_type,
        cryptographic_usage_mask,
    )?)
}

/// The public key in the requested Key Format Type, the default format when none is requested.
fn public_key_object(
    openssl_key: &PKey<Public>,
    key_format_type: Option<KeyFormatType>,
    cryptographic_usage_mask: Option<CryptographicUsageMask>,
) -> KResult<Object> {
    let Some(key_format_type) = key_format_type else {
        return openssl_public_key_to_kmip_default_format(openssl_key, cryptographic_usage_mask);
    };
    if !matches!(
        key_format_type,
        KeyFormatType::PKCS1
            | KeyFormatType::PKCS8
            | KeyFormatType::TransparentECPublicKey
            | KeyFormatType::TransparentRSAPublicKey
    ) {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Key_Format_Type_Not_Supported,
            format!("export: unsupported Key Format Type: {key_format_type:?}"),
        ));
    }
    Ok(openssl_public_key_to_kmip(
        openssl_key,
        key_format_type,
        cryptographic_usage_mask,
    )?)
}

async fn unwrap_if_requested(
    object_with_metadata: &mut ObjectWithMetadata,
    key_wrap_type: &Option<KeyWrapType>,
    kms: &KMS,
    user: &UserId,

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
            let mut object = Box::pin(kms.get_unwrapped(
                object_with_metadata.id(),
                object_with_metadata.object(),
                user,
            ))
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
    user: &UserId,
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

/// Returns `true` for algorithms whose keys have no OpenSSL representation and must skip the
/// OpenSSL round-trip on export: PQC (ML-KEM, ML-DSA, Hybrid KEM, SLH-DSA) and `ConfigurableKEM`.
#[cfg(feature = "non-fips")]
const fn is_pqc_algorithm(algo: Option<CryptographicAlgorithm>) -> bool {
    matches!(
        algo,
        Some(
            CryptographicAlgorithm::MLKEM_512
                | CryptographicAlgorithm::MLKEM_768
                | CryptographicAlgorithm::MLKEM_1024
                | CryptographicAlgorithm::MLDSA_44
                | CryptographicAlgorithm::MLDSA_65
                | CryptographicAlgorithm::MLDSA_87
                | CryptographicAlgorithm::ConfigurableKEM
                | CryptographicAlgorithm::X25519MLKEM768
                | CryptographicAlgorithm::X448MLKEM1024
                | CryptographicAlgorithm::SLHDSA_SHA2_128s
                | CryptographicAlgorithm::SLHDSA_SHA2_128f
                | CryptographicAlgorithm::SLHDSA_SHA2_192s
                | CryptographicAlgorithm::SLHDSA_SHA2_192f
                | CryptographicAlgorithm::SLHDSA_SHA2_256s
                | CryptographicAlgorithm::SLHDSA_SHA2_256f
                | CryptographicAlgorithm::SLHDSA_SHAKE_128s
                | CryptographicAlgorithm::SLHDSA_SHAKE_128f
                | CryptographicAlgorithm::SLHDSA_SHAKE_192s
                | CryptographicAlgorithm::SLHDSA_SHAKE_192f
                | CryptographicAlgorithm::SLHDSA_SHAKE_256s
                | CryptographicAlgorithm::SLHDSA_SHAKE_256f
        )
    )
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
    user: &UserId,
) -> KResult<()> {
    trace!(target: "kmip", "process_symmetric_key enter uid={} requested_format={:?} wrap_type={:?}",
        object_with_metadata.id(), key_format_type, key_wrap_type);

    // First check is any unwrapping needs to be done
    Box::pin(unwrap_if_requested(
        object_with_metadata,
        key_wrap_type,
        kms,
        user,
        ObjectType::SymmetricKey,
    ))
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

    // trace!(target: "kmip", "process_symmetric_key key_block initial format={:?} wrapped={} uid={}", key_block.key_format_type, key_block.key_wrapping_data.is_some(), obj_id);

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
                let mut unwrapped = Box::pin(kms.get_unwrapped(
                    object_with_metadata.id(),
                    object_with_metadata.object(),
                    user,
                ))
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
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Key_Format_Type_Not_Supported,
                    "export: a wrapped symmetric key requires the default or Raw Key Format Type"
                        .to_owned(),
                ));
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

    // We have an unwrapped key, collect the key bytes and a copy of nested attributes.
    // Use take() since key_value is unconditionally overwritten below.
    let (key_bytes, mut nested_attrs) = if let Some(KeyValue::Structure {
        key_material,
        attributes,
    }) = key_block.key_value.take()
    {
        match key_material {
            KeyMaterial::ByteString(b) => (b, attributes),
            KeyMaterial::TransparentSymmetricKey { key } => (key, attributes),
            _ => kms_bail!("export: unsupported key material"),
        }
    } else {
        trace!(target: "kmip", "process_symmetric_key missing key_value structure uid={}", object_with_metadata.id());
        return Err(KmsError::Default(
            "process_symmetric_key: key value not found in key".to_owned(),
        ));
    };
    // Wrapping is only available for KeyFormatType being the default (i.e. None)
    if let Some(key_wrapping_specification) = key_wrapping_specification {
        if key_format_type.is_some() {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Key_Format_Type_Not_Supported,
                "export: a wrapped symmetric key requires the default Key Format Type".to_owned(),
            ));
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
            trace!(target: "kmip", "process_symmetric_key set TransparentSymmetricKey uid={}", obj_id);
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
            trace!(target: "kmip", "process_symmetric_key set Raw uid={}", obj_id);
        }
        _ => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Key_Format_Type_Not_Supported,
                format!(
                    "export: unsupported requested Key Format Type for a symmetric key: {key_format_type:?}"
                ),
            ));
        }
    }

    trace!(target: "kmip", "process_symmetric_key exit uid={} final_format={:?}", obj_id, key_block.key_format_type);

    Ok(())
}

async fn build_pkcs12_for_private_key(
    kms: &KMS,
    operation_type: KmipOperation,
    user: &UserId,

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

    let mut chain: Stack<X509> = Stack::new()?;
    append_certificate_chain(&mut cert_owm, &mut chain, operation_type, kms, user).await?;

    // recover the password: the Key Wrapping Specification designates it, else the
    // PKCS#12 Password Link of the private key (KMIP 2.1 §6.1.19)
    let password_id = request
        .key_wrapping_specification
        .as_ref()
        .and_then(|kws| kws.encryption_key_information.as_ref())
        .map(|eki| eki.unique_identifier.to_string())
        .or_else(|| {
            private_key_owm
                .attributes()
                .get_link(LinkType::PKCS12PasswordLink)
                .map(|link| link.to_string())
        });
    let password = match password_id {
        Some(id) => resolve_pkcs12_password(kms, user, &id).await?,
        None => Zeroizing::new(String::new()),
    };
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

/// The password of a PKCS#12 container designated by `identifier`.
///
/// KMIP 2.1 §6.1.19: the container is protected by the Secret Data object designated by the
/// PKCS#12 Password Link; `Bad Password` (Table 'Result Reason') when that object is not an
/// Active Secret Data. An identifier that designates no accessible object is taken as the
/// literal password, the historical Cosmian convention.
pub(crate) async fn resolve_pkcs12_password(
    kms: &KMS,
    user: &UserId,
    identifier: &str,
) -> KResult<Zeroizing<String>> {
    let bad_password = |reason: &str| {
        KmsError::Kmip21Error(
            ErrorReason::Bad_Password,
            format!("PKCS#12 password object {identifier}: {reason}"),
        )
    };
    // `Uid`: a password is never a tag query nor an HSM identifier
    let owm = match retrieve_object_for_operation(
        ObjectHandle::Uid(identifier),
        KmipOperation::Get,
        kms,
        user,
    )
    .await
    {
        Ok(owm) => owm,
        Err(KmsError::Kmip21Error(ErrorReason::Object_Not_Found, _)) => {
            return Ok(Zeroizing::new(identifier.to_owned()));
        }
        Err(e) => return Err(e),
    };
    let Object::SecretData(secret_data) = owm.object() else {
        return Err(bad_password("not a Secret Data object"));
    };
    if owm.effective_state() != State::Active {
        return Err(bad_password("not Active"));
    }
    let bytes = secret_data.key_block.key_bytes()?;
    String::from_utf8(bytes.to_vec())
        .map(Zeroizing::new)
        .map_err(|_e| bad_password("not a UTF-8 password"))
}

/// Upper bound for a certificate chain, including its leaf certificate.
const MAX_CERTIFICATE_CHAIN_CERTIFICATES: usize = 100;

/// Record the next certificate chain link and reject cyclic or oversized chains.
fn register_certificate_chain_parent(
    certificate_ids: &mut HashSet<String>,
    certificate_id: &str,
    parent_id: &str,
) -> KResult<bool> {
    if parent_id == certificate_id {
        return Ok(false);
    }
    if !certificate_ids.insert(parent_id.to_owned()) {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            "certificate chain contains a cycle".to_owned(),
        ));
    }
    if certificate_ids.len() > MAX_CERTIFICATE_CHAIN_CERTIFICATES {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            format!("certificate chain exceeds {MAX_CERTIFICATE_CHAIN_CERTIFICATES} certificates"),
        ));
    }
    Ok(true)
}

/// Retrieve each parent certificate once, rejecting cyclic and oversized chains.
async fn append_certificate_chain(
    certificate: &mut ObjectWithMetadata,
    chain: &mut Stack<X509>,
    operation_type: KmipOperation,
    kms: &KMS,
    user: &UserId,
) -> KResult<()> {
    let mut certificate_ids = HashSet::from([certificate.id().to_owned()]);
    while let Some(parent_id) = certificate.attributes().get_link(LinkType::CertificateLink) {
        let parent_id = linked_id_str(&parent_id);
        if !register_certificate_chain_parent(
            &mut certificate_ids,
            certificate.id(),
            parent_id.as_ref(),
        )? {
            break;
        }
        trace!("certificate parent id is: {parent_id}");
        let parent_certificate = Box::pin(retrieve_object_for_operation(
            ObjectHandle::from(&*parent_id),
            operation_type,
            kms,
            user,
        ))
        .await?;
        *certificate = Arc::unwrap_or_clone(parent_certificate);
        chain.push(kmip_certificate_to_openssl(certificate.object())?)?;
    }
    Ok(())
}

async fn post_process_pkcs7(
    kms: &KMS,
    operation_type: KmipOperation,
    user: &UserId,
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
    let public_key_id_str = linked_id_str(&public_key_id);
    let public_key_owm = Box::pin(retrieve_object_for_operation(
        ObjectHandle::from(&*public_key_id_str),
        operation_type,
        kms,
        user,
    ))
    .await?;
    let private_key_id = public_key_owm
        .attributes()
        .get_link(LinkType::PrivateKeyLink);
    if let Some(private_key_id) = private_key_id {
        let private_key_id_str = linked_id_str(&private_key_id);
        let private_key_owm = Box::pin(retrieve_object_for_operation(
            ObjectHandle::from(&*private_key_id_str),
            operation_type,
            kms,
            user,
        ))
        .await?;
        let private_key_object = if private_key_owm.object().is_wrapped() {
            Box::pin(kms.get_unwrapped(private_key_owm.id(), private_key_owm.object(), user))
                .await
                .context("export pkcs7: unable to unwrap the private key")?
        } else {
            private_key_owm.object().clone()
        };
        let pkey = kmip_private_key_to_openssl(&private_key_object)
            .context("export: unable to parse the private key to openssl")?;

        // Create the PKCS7 structure
        let mut chain: Stack<X509> = Stack::new()?;

        append_certificate_chain(&mut cert_owm, &mut chain, operation_type, kms, user).await?;

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
    user: &UserId,
) -> KResult<()> {
    // First check is any unwrapping needs to be done
    Box::pin(unwrap_if_requested(
        object_with_metadata,
        key_wrap_type,
        kms,
        user,
        ObjectType::SecretData,
    ))
    .await?;

    let object = object_with_metadata.object_mut();
    let key_block = object.key_block_mut()?;

    // If the key is still wrapped the export KeyFormatType must be the default (none)
    if key_block.key_wrapping_data.is_some() {
        if key_format_type.is_some() {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Key_Format_Type_Not_Supported,
                "export: a wrapped secret data requires the default Key Format Type".to_owned(),
            ));
        }
        // The key is wrapped and as expected the requested Key Format Type is the default (none)
        // => The key is exported as such
        return Ok(());
    }

    // we have an unwrapped key, convert it to the pivotal format first,
    // which is getting the key bytes and a copy of nested attributes.
    // Use take() since key_value is unconditionally overwritten below.
    let (key_bytes, mut nested_attrs) = match key_block.key_value.take() {
        Some(KeyValue::Structure {
            key_material,
            attributes,
        }) => match key_material {
            KeyMaterial::ByteString(b) => (b, attributes),
            _ => kms_bail!("export: unsupported key material"),
        },
        _ => {
            return Err(KmsError::Default(
                "process_secret_data: key value not found in key".to_owned(),
            ));
        }
    };

    if let Some(key_wrapping_specification) = key_wrapping_specification {
        if key_format_type.is_some() {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Key_Format_Type_Not_Supported,
                "export: a wrapped secret data requires the default Key Format Type".to_owned(),
            ));
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
        _ => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Key_Format_Type_Not_Supported,
                format!(
                    "export: unsupported requested Key Format Type for a secret data: {key_format_type:?}"
                ),
            ));
        }
    }
    Ok(())
}

/// Flip `Fresh = false` in storage and in-memory while preserving key wrapping (COSMIAN-2026-031).
/// Fails closed if the original DB object snapshot is missing to prevent persisting auto-unwrapped keys.
async fn persist_fresh_false(
    kms: &KMS,
    user: &UserId,
    owm: &mut ObjectWithMetadata,
    original_object: Option<Arc<ObjectWithMetadata>>,
) -> KResult<()> {
    let mut updated_attrs = owm.attributes().clone();
    updated_attrs.fresh = Some(false);
    let uid = owm.id().to_owned();

    // Fail closed: require original stored DB snapshot so unwrapped keys are never persisted.
    let original = original_object.ok_or_else(|| {
        KmsError::ServerError(format!(
            "Missing original DB snapshot for object {uid} during Fresh write-back"
        ))
    })?;
    let mut obj = original.object().clone();

    if let Ok(kb_mut) = obj.key_block_mut() {
        if let Some(KeyValue::Structure { attributes, .. }) = kb_mut.key_value.as_mut() {
            if let Some(inner) = attributes.as_mut() {
                inner.fresh = Some(false);
            }
        }
    }

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

    let attrs_mut = owm.attributes_mut();
    attrs_mut.fresh = Some(false);
    if let Ok(kb_mut) = owm.object_mut().key_block_mut() {
        if let Some(KeyValue::Structure { attributes, .. }) = kb_mut.key_value.as_mut() {
            if let Some(inner) = attributes.as_mut() {
                inner.fresh = Some(false);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::ErrorReason,
        kmip_2_1::{
            kmip_operations::Get,
            kmip_types::{KeyCompressionType, UniqueIdentifier},
        },
    };

    use super::register_certificate_chain_parent;
    use crate::{
        error::KmsError, middlewares::UserId, result::KResult, tests::test_utils::test_kms,
    };

    #[tokio::test]
    async fn rejects_requested_key_compression() -> KResult<()> {
        let kms = test_kms().await?;
        let Err(error) = kms
            .get(
                Get {
                    unique_identifier: Some(UniqueIdentifier::TextString("unused".to_owned())),
                    key_compression_type: Some(
                        KeyCompressionType::ECPublicKeyTypeX962CompressedPrime,
                    ),
                    ..Get::default()
                },
                &UserId::from("compression@example.com"),
            )
            .await
        else {
            return Err(KmsError::Default(
                "key compression request unexpectedly succeeded".to_owned(),
            ));
        };

        if !matches!(
            error,
            KmsError::Kmip21Error(ErrorReason::Key_Compression_Type_Not_Supported, _)
        ) {
            return Err(KmsError::Default(
                "key compression request returned the wrong KMIP error reason".to_owned(),
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn accepts_uncompressed_key_compression() -> KResult<()> {
        let kms = test_kms().await?;
        let result = kms
            .get(
                Get {
                    unique_identifier: Some(UniqueIdentifier::TextString("unused".to_owned())),
                    key_compression_type: Some(KeyCompressionType::ECPublicKeyTypeUncompressed),
                    ..Get::default()
                },
                &UserId::from("compression@example.com"),
            )
            .await;
        if !matches!(
            result,
            Err(KmsError::Kmip21Error(ErrorReason::Object_Not_Found, _))
        ) {
            return Err(KmsError::Default(
                "uncompressed Key Compression Type was rejected before object lookup".to_owned(),
            ));
        }
        Ok(())
    }

    #[test]
    fn certificate_chain_cycle_is_rejected() -> KResult<()> {
        let mut certificate_ids = HashSet::from(["leaf".to_owned()]);
        if !register_certificate_chain_parent(&mut certificate_ids, "leaf", "issuer")? {
            return Err(KmsError::Default(
                "issuer link unexpectedly ended the certificate chain".to_owned(),
            ));
        }
        let cycle = register_certificate_chain_parent(&mut certificate_ids, "issuer", "leaf");
        if !matches!(
            cycle,
            Err(KmsError::Kmip21Error(ErrorReason::Invalid_Field, _))
        ) {
            return Err(KmsError::Default(
                "certificate chain cycle was not rejected".to_owned(),
            ));
        }
        if register_certificate_chain_parent(&mut certificate_ids, "issuer", "issuer")? {
            return Err(KmsError::Default(
                "self-signed certificate link did not end the chain".to_owned(),
            ));
        }
        Ok(())
    }

    /// KMIP 2.1 §6.1.19: the PKCS#12 password is the Active Secret Data designated by the link;
    /// an identifier that designates nothing is the literal password (historical convention).
    #[tokio::test]
    async fn pkcs12_password_is_the_linked_active_secret_data() -> KResult<()> {
        use cosmian_kms_server_database::reexport::cosmian_kmip::{
            kmip_0::kmip_types::SecretDataType,
            kmip_2_1::{
                kmip_attributes::Attributes,
                kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
                kmip_objects::{Object, ObjectType, SecretData},
                kmip_operations::{Activate, Register},
                kmip_types::KeyFormatType,
            },
        };
        use zeroize::Zeroizing;

        use super::resolve_pkcs12_password;

        let kms = test_kms().await?;
        let user = UserId::from("pkcs12-password@example.com");
        if resolve_pkcs12_password(&kms, &user, "[literal")
            .await?
            .as_str()
            != "[literal"
        {
            return Err(KmsError::Default("literal password was altered".to_owned()));
        }

        let uid = kms
            .register(
                Register {
                    object_type: ObjectType::SecretData,
                    attributes: Attributes::default(),
                    object: Object::SecretData(SecretData {
                        secret_data_type: SecretDataType::Password,
                        key_block: KeyBlock {
                            key_format_type: KeyFormatType::Raw,
                            key_compression_type: None,
                            key_value: Some(KeyValue::Structure {
                                key_material: KeyMaterial::ByteString(Zeroizing::from(
                                    b"s3cret".to_vec(),
                                )),
                                attributes: None,
                            }),
                            cryptographic_algorithm: None,
                            cryptographic_length: None,
                            key_wrapping_data: None,
                        },
                    }),
                    protection_storage_masks: None,
                },
                &user,
            )
            .await?
            .unique_identifier
            .to_string();

        let pre_active = resolve_pkcs12_password(&kms, &user, &uid).await;
        if !matches!(
            pre_active,
            Err(KmsError::Kmip21Error(ErrorReason::Bad_Password, _))
        ) {
            return Err(KmsError::Default(
                "a Pre-Active Secret Data was accepted as PKCS#12 password".to_owned(),
            ));
        }

        kms.activate(
            Activate {
                unique_identifier: UniqueIdentifier::TextString(uid.clone()),
            },
            &user,
        )
        .await?;
        if resolve_pkcs12_password(&kms, &user, &uid).await?.as_str() != "s3cret" {
            return Err(KmsError::Default(
                "linked Secret Data was not used as the password".to_owned(),
            ));
        }
        Ok(())
    }

    /// KMIP 2.1 §6.1.19: a key registered in a format is returned in it, possibly wrapped: the
    /// Key Format Type is the format of the key before wrapping.
    #[tokio::test]
    async fn export_wraps_keys_in_the_requested_key_format() -> KResult<()> {
        use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
            extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
            kmip_data_structures::KeyWrappingSpecification,
            kmip_operations::Export,
            kmip_types::{
                CryptographicAlgorithm, EncodingOption, EncryptionKeyInformation, KeyFormatType,
                RecommendedCurve, WrappingMethod,
            },
            requests::{create_ec_key_pair_request, symmetric_key_create_request},
        };

        let kms = test_kms().await?;
        let user = UserId::from("wrap-format@example.com");
        let wrapping_key = kms
            .create(
                symmetric_key_create_request(
                    VENDOR_ID_COSMIAN,
                    None,
                    256,
                    CryptographicAlgorithm::AES,
                    EMPTY_TAGS,
                    false,
                    None,
                )?,
                &user,
            )
            .await?
            .unique_identifier;
        let pair = kms
            .create_key_pair(
                create_ec_key_pair_request(
                    VENDOR_ID_COSMIAN,
                    None,
                    EMPTY_TAGS,
                    RecommendedCurve::P256,
                    false,
                    None,
                )?,
                &user,
            )
            .await?;
        for uid in [
            pair.private_key_unique_identifier,
            pair.public_key_unique_identifier,
        ] {
            let exported = kms
                .export(
                    Export::new(
                        uid,
                        false,
                        Some(KeyWrappingSpecification {
                            wrapping_method: WrappingMethod::Encrypt,
                            encryption_key_information: Some(EncryptionKeyInformation {
                                unique_identifier: wrapping_key.clone(),
                                cryptographic_parameters: None,
                            }),
                            encoding_option: Some(EncodingOption::TTLVEncoding),
                            ..KeyWrappingSpecification::default()
                        }),
                        Some(KeyFormatType::PKCS8),
                    ),
                    &user,
                )
                .await?;
            let key_block = exported.object.key_block()?;
            if !exported.object.is_wrapped() || key_block.key_format_type != KeyFormatType::PKCS8 {
                return Err(KmsError::Default(format!(
                    "expected a wrapped PKCS#8 key, got {:?} wrapped={}",
                    key_block.key_format_type,
                    exported.object.is_wrapped()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "non-fips"))]
#[allow(clippy::panic_in_result_fn)] // tests: a panic is the failure signal
mod pgp_export_tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::ErrorReason,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_data_structures::KeyWrappingSpecification,
            kmip_objects::ObjectType,
            kmip_operations::{Create, Get},
            kmip_types::{
                CryptographicAlgorithm, EncryptionKeyInformation, UniqueIdentifier, WrappingMethod,
            },
        },
    };

    use crate::{
        error::KmsError, middlewares::UserId, result::KResult, tests::test_utils::test_kms,
    };

    fn get_request(uid: &str, key_wrapping_specification: Option<KeyWrappingSpecification>) -> Get {
        Get {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            key_wrapping_specification,
            key_compression_type: None,
            key_format_type: None,
            key_wrap_type: None,
        }
    }

    /// A wrapping specification is not protection when the export path never wraps the object:
    /// a Sensitive PGP key must not leave in plaintext with a dummy wrapping specification.
    #[tokio::test]
    async fn test_sensitive_pgp_key_export_ignores_dummy_wrapping() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from("pgp_export_owner");
        let dummy_wrapping = KeyWrappingSpecification {
            wrapping_method: WrappingMethod::Encrypt,
            encryption_key_information: Some(EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString("does-not-exist".to_owned()),
                cryptographic_parameters: None,
            }),
            ..KeyWrappingSpecification::default()
        };

        for sensitive in [true, false] {
            let create = Create {
                object_type: ObjectType::PGPKey,
                attributes: Attributes {
                    object_type: Some(ObjectType::PGPKey),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::Ed25519),
                    sensitive: Some(sensitive),
                    ..Attributes::default()
                },
                protection_storage_masks: None,
            };
            let uid = kms
                .create(create, &owner)
                .await?
                .unique_identifier
                .to_string();

            let dummy_wrapped = kms
                .get(get_request(&uid, Some(dummy_wrapping.clone())), &owner)
                .await;
            let expected = if sensitive {
                ErrorReason::Sensitive
            } else {
                ErrorReason::Key_Wrap_Type_Not_Supported
            };
            assert!(
                matches!(&dummy_wrapped, Err(KmsError::Kmip21Error(reason, _)) if *reason == expected),
                "sensitive={sensitive}: {dummy_wrapped:?}"
            );

            let plain = kms.get(get_request(&uid, None), &owner).await;
            if sensitive {
                assert!(matches!(
                    plain,
                    Err(KmsError::Kmip21Error(ErrorReason::Sensitive, _))
                ));
            } else {
                plain?;
            }
        }
        Ok(())
    }
}
