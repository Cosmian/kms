#[cfg(feature = "non-fips")]
mod imp {
    use std::collections::HashSet;

    use cosmian_kms_server_database::reexport::{
        cosmian_kmip::{
            kmip_0::kmip_types::CryptographicUsageMask,
            kmip_2_1::{
                extra::{VENDOR_ATTR_PGP_USER_ID, tagging::SYSTEM_TAG_PGP_KEY},
                kmip_attributes::Attributes,
                kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
                kmip_objects::{Object, ObjectType, PGPKey},
                kmip_operations::{
                    Create, Decrypt, DecryptResponse, Encrypt, EncryptResponse, Sign, SignResponse,
                    SignatureVerify, SignatureVerifyResponse,
                },
                kmip_types::{
                    CryptographicAlgorithm, KeyFormatType, UniqueIdentifier, ValidityIndicator,
                    VendorAttributeValue,
                },
            },
        },
        cosmian_kms_crypto::crypto::openpgp::{
            PgpKeyProfile, generate_openpgp_secret_key, openpgp_decrypt, openpgp_encrypt,
            openpgp_key_metadata, openpgp_normalize, openpgp_public_from_secret,
            openpgp_sign_detached, openpgp_verify_detached,
        },
        cosmian_kms_interfaces::ObjectWithMetadata,
    };
    use uuid::Uuid;

    use crate::{error::KmsError, kms_bail, result::KResult};

    pub(crate) fn create_pgp_key_and_tags(
        vendor_id: &str,
        request: &Create,
    ) -> KResult<(Option<String>, Object, HashSet<String>)> {
        let profile = match request.attributes.cryptographic_algorithm {
            Some(CryptographicAlgorithm::RSA) => {
                let bits = match request.attributes.cryptographic_length {
                    Some(b @ (2048 | 3072 | 4096)) => b.cast_unsigned(),
                    Some(other) => {
                        return Err(KmsError::InvalidRequest(format!(
                            "OpenPGP RSA key length must be 2048, 3072, or 4096 (got {other})"
                        )));
                    }
                    None => 3072,
                };
                PgpKeyProfile::Rsa { bits }
            }
            Some(CryptographicAlgorithm::Ed25519) | None => PgpKeyProfile::Ed25519,
            Some(other) => {
                return Err(KmsError::NotSupported(format!(
                    "OpenPGP key creation is not supported for algorithm: {other:?}"
                )));
            }
        };

        let uid = match &request.attributes.unique_identifier {
            Some(UniqueIdentifier::TextString(s)) if !s.is_empty() => s.clone(),
            _ => Uuid::new_v4().to_string(),
        };

        let user_id = if let Some(VendorAttributeValue::TextString(user_id_str)) = request
            .attributes
            .get_vendor_attribute_value(vendor_id, VENDOR_ATTR_PGP_USER_ID)
        {
            user_id_str.clone()
        } else if let Some(first_name) = request
            .attributes
            .name
            .as_ref()
            .and_then(|names| names.first())
        {
            first_name.name_value.clone()
        } else {
            format!("Cosmian KMS <{uid}@kms.cosmian.com>")
        };

        let armored_secret = generate_openpgp_secret_key(profile, &user_id)
            .map_err(|e| KmsError::Default(e.to_string()))?;

        let (alg, len, version) =
            openpgp_key_metadata(&armored_secret).map_err(|e| KmsError::Default(e.to_string()))?;

        let mut tags = request.attributes.get_tags(vendor_id);
        tags.insert(SYSTEM_TAG_PGP_KEY.to_owned());

        let mut attributes = request.attributes.clone();
        attributes.object_type = Some(ObjectType::PGPKey);
        attributes.key_format_type = Some(KeyFormatType::OpenPgpSecretKey);
        attributes.cryptographic_algorithm = alg;
        attributes.cryptographic_length = len;
        if attributes.cryptographic_usage_mask.is_none() {
            attributes.cryptographic_usage_mask = Some(
                CryptographicUsageMask::Sign
                    | CryptographicUsageMask::Verify
                    | CryptographicUsageMask::Encrypt
                    | CryptographicUsageMask::Decrypt,
            );
        }
        attributes.unique_identifier = Some(UniqueIdentifier::TextString(uid.clone()));
        attributes.set_tags(vendor_id, tags.clone())?;

        let object = Object::PGPKey(PGPKey {
            pgp_key_version: version,
            key_block: KeyBlock {
                key_format_type: KeyFormatType::OpenPgpSecretKey,
                key_compression_type: None,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(armored_secret),
                    attributes: Some(attributes),
                }),
                cryptographic_algorithm: alg,
                cryptographic_length: len,
                key_wrapping_data: None,
            },
        });

        Ok((Some(uid), object, tags))
    }

    pub(crate) fn pgp_export_convert(
        owm: &mut ObjectWithMetadata,
        key_format_type: Option<KeyFormatType>,
    ) -> KResult<()> {
        let object = owm.object_mut();
        let key_block = object.key_block_mut()?;

        if key_block.key_wrapping_data.is_some() {
            if key_format_type.is_some() {
                kms_bail!(
                    "export: unable to export a wrapped OpenPGP key with a requested Key Format \
                     Type. It must be the default"
                );
            }
            return Ok(());
        }

        let stored_format = key_block.key_format_type;
        let (bytes, mut nested_attrs) = match &key_block.key_value {
            Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(b),
                attributes,
            }) => (b.clone(), attributes.clone()),
            _ => kms_bail!("export: unsupported key material"),
        };

        match key_format_type {
            None | Some(KeyFormatType::Raw) => {
                if let Some(inner) = &mut nested_attrs {
                    inner.key_format_type = Some(stored_format);
                }
                key_block.key_value = Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(bytes),
                    attributes: nested_attrs,
                });
            }
            Some(fmt) if fmt == stored_format => {
                if let Some(inner) = &mut nested_attrs {
                    inner.key_format_type = Some(stored_format);
                }
                key_block.key_value = Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(bytes),
                    attributes: nested_attrs,
                });
            }
            Some(KeyFormatType::OpenPgpPublicKey)
                if stored_format == KeyFormatType::OpenPgpSecretKey =>
            {
                let pub_armored = openpgp_public_from_secret(&bytes)
                    .map_err(|e| KmsError::Default(e.to_string()))?;
                if let Some(inner) = &mut nested_attrs {
                    inner.key_format_type = Some(KeyFormatType::OpenPgpPublicKey);
                }
                key_block.key_format_type = KeyFormatType::OpenPgpPublicKey;
                key_block.key_value = Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(zeroize::Zeroizing::new(pub_armored)),
                    attributes: nested_attrs,
                });
            }
            Some(KeyFormatType::OpenPgpSecretKey)
                if stored_format == KeyFormatType::OpenPgpPublicKey =>
            {
                return Err(KmsError::NotSupported(
                    "export: an OpenPGP public key cannot be exported as a secret key".to_owned(),
                ));
            }
            Some(other) => {
                kms_bail!("export: unsupported Key Format Type for an OpenPGP key: {other:?}");
            }
        }

        Ok(())
    }

    pub(crate) fn pgp_normalize_for_import(
        object: &mut Object,
        attributes: &mut Attributes,
    ) -> KResult<()> {
        let key_block = object.key_block_mut()?;
        let raw_bytes = match &key_block.key_value {
            Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(b),
                ..
            }) => b.clone(),
            _ => kms_bail!("import: OpenPGP key requires ByteString key material"),
        };

        let (armored, is_secret) =
            openpgp_normalize(&raw_bytes).map_err(|e| KmsError::Default(e.to_string()))?;

        let (alg, len, version) =
            openpgp_key_metadata(&armored).map_err(|e| KmsError::Default(e.to_string()))?;

        let fmt = if is_secret {
            KeyFormatType::OpenPgpSecretKey
        } else {
            KeyFormatType::OpenPgpPublicKey
        };

        key_block.key_format_type = fmt;
        key_block.cryptographic_algorithm = alg;
        key_block.cryptographic_length = len;

        attributes.object_type = Some(ObjectType::PGPKey);
        attributes.key_format_type = Some(fmt);
        attributes.cryptographic_algorithm = alg;
        attributes.cryptographic_length = len;
        if attributes.cryptographic_usage_mask.is_none() {
            attributes.cryptographic_usage_mask = Some(if is_secret {
                CryptographicUsageMask::Sign
                    | CryptographicUsageMask::Verify
                    | CryptographicUsageMask::Encrypt
                    | CryptographicUsageMask::Decrypt
            } else {
                CryptographicUsageMask::Verify | CryptographicUsageMask::Encrypt
            });
        }

        key_block.key_value = Some(KeyValue::Structure {
            key_material: KeyMaterial::ByteString(armored),
            attributes: Some(attributes.clone()),
        });

        if let Object::PGPKey(pgp) = object {
            pgp.pgp_key_version = version;
        }

        Ok(())
    }

    pub(crate) fn pgp_encrypt(
        owm: &ObjectWithMetadata,
        request: &Encrypt,
    ) -> KResult<EncryptResponse> {
        let data = request.data.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
        })?;

        let key_block = owm.object().key_block()?;
        let Some(KeyValue::Structure {
            key_material: KeyMaterial::ByteString(bytes),
            ..
        }) = &key_block.key_value
        else {
            kms_bail!("Encrypt: invalid key material structure");
        };

        let ciphertext =
            openpgp_encrypt(bytes, data).map_err(|e| KmsError::Default(e.to_string()))?;

        Ok(EncryptResponse {
            unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
            data: Some(ciphertext),
            i_v_counter_nonce: None,
            correlation_value: None,
            authenticated_encryption_tag: None,
        })
    }

    pub(crate) fn pgp_decrypt(
        owm: &ObjectWithMetadata,
        request: &Decrypt,
    ) -> KResult<DecryptResponse> {
        let key_block = owm.object().key_block()?;
        if key_block.key_format_type != KeyFormatType::OpenPgpSecretKey {
            return Err(KmsError::NotSupported(
                "decrypt: an OpenPGP public key cannot decrypt".to_owned(),
            ));
        }

        let data = request.data.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("Decrypt: data to decrypt must be provided".to_owned())
        })?;

        let Some(KeyValue::Structure {
            key_material: KeyMaterial::ByteString(bytes),
            ..
        }) = &key_block.key_value
        else {
            kms_bail!("Decrypt: invalid key material structure");
        };

        let plaintext =
            openpgp_decrypt(bytes, data).map_err(|e| KmsError::Default(e.to_string()))?;

        Ok(DecryptResponse {
            unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
            data: Some(plaintext),
            correlation_value: None,
        })
    }

    pub(crate) fn pgp_sign(owm: &ObjectWithMetadata, request: &Sign) -> KResult<SignResponse> {
        let key_block = owm.object().key_block()?;
        if key_block.key_format_type != KeyFormatType::OpenPgpSecretKey {
            return Err(KmsError::NotSupported(
                "sign: an OpenPGP public key cannot sign".to_owned(),
            ));
        }

        if request.digested_data.is_some() {
            return Err(KmsError::NotSupported(
                "Sign: OpenPGP signatures require the full data, not a digest".to_owned(),
            ));
        }

        if request.init_indicator == Some(true) || request.correlation_value.is_some() {
            return Err(KmsError::NotSupported(
                "Sign: streaming is not supported for OpenPGP keys".to_owned(),
            ));
        }

        let data = request.data.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("Sign: data to sign must be provided".to_owned())
        })?;

        let Some(KeyValue::Structure {
            key_material: KeyMaterial::ByteString(bytes),
            ..
        }) = &key_block.key_value
        else {
            kms_bail!("Sign: invalid key material structure");
        };

        let sig =
            openpgp_sign_detached(bytes, data).map_err(|e| KmsError::Default(e.to_string()))?;

        Ok(SignResponse {
            unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
            signature_data: Some(sig),
            correlation_value: None,
        })
    }

    pub(crate) fn pgp_signature_verify(
        owm: &ObjectWithMetadata,
        request: &SignatureVerify,
    ) -> KResult<SignatureVerifyResponse> {
        if request.digested_data.is_some() {
            return Err(KmsError::NotSupported(
                "SignatureVerify: OpenPGP signatures require the full data, not a digest"
                    .to_owned(),
            ));
        }

        if request.init_indicator == Some(true) || request.correlation_value.is_some() {
            return Err(KmsError::NotSupported(
                "SignatureVerify: streaming is not supported for OpenPGP keys".to_owned(),
            ));
        }

        let data = request.data.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("SignatureVerify: data must be provided".to_owned())
        })?;

        let sig = request.signature_data.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("SignatureVerify: signature_data must be provided".to_owned())
        })?;

        let key_block = owm.object().key_block()?;
        let Some(KeyValue::Structure {
            key_material: KeyMaterial::ByteString(bytes),
            ..
        }) = &key_block.key_value
        else {
            kms_bail!("SignatureVerify: invalid key material structure");
        };

        let is_valid = openpgp_verify_detached(bytes, data, sig)
            .map_err(|e| KmsError::Default(e.to_string()))?;

        let validity_indicator = if is_valid {
            ValidityIndicator::Valid
        } else {
            ValidityIndicator::Invalid
        };

        Ok(SignatureVerifyResponse {
            unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
            validity_indicator: Some(validity_indicator),
            data: None,
            correlation_value: None,
        })
    }
}

#[cfg(not(feature = "non-fips"))]
mod imp {
    use std::collections::HashSet;

    use cosmian_kms_server_database::reexport::{
        cosmian_kmip::kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_objects::Object,
            kmip_operations::{
                Create, Decrypt, DecryptResponse, Encrypt, EncryptResponse, Sign, SignResponse,
                SignatureVerify, SignatureVerifyResponse,
            },
            kmip_types::KeyFormatType,
        },
        cosmian_kms_interfaces::ObjectWithMetadata,
    };

    use crate::{error::KmsError, result::KResult};

    pub(crate) fn create_pgp_key_and_tags(
        _vendor_id: &str,
        _request: &Create,
    ) -> KResult<(Option<String>, Object, HashSet<String>)> {
        Err(KmsError::NotSupported(
            "OpenPGP (PGP Key) support requires a non-FIPS build".to_owned(),
        ))
    }

    pub(crate) fn pgp_export_convert(
        _owm: &mut ObjectWithMetadata,
        _key_format_type: Option<KeyFormatType>,
    ) -> KResult<()> {
        Err(KmsError::NotSupported(
            "OpenPGP (PGP Key) support requires a non-FIPS build".to_owned(),
        ))
    }

    pub(crate) fn pgp_normalize_for_import(
        _object: &mut Object,
        _attributes: &mut Attributes,
    ) -> KResult<()> {
        Err(KmsError::NotSupported(
            "OpenPGP (PGP Key) support requires a non-FIPS build".to_owned(),
        ))
    }

    pub(crate) fn pgp_encrypt(
        _owm: &ObjectWithMetadata,
        _request: &Encrypt,
    ) -> KResult<EncryptResponse> {
        Err(KmsError::NotSupported(
            "OpenPGP (PGP Key) support requires a non-FIPS build".to_owned(),
        ))
    }

    pub(crate) fn pgp_decrypt(
        _owm: &ObjectWithMetadata,
        _request: &Decrypt,
    ) -> KResult<DecryptResponse> {
        Err(KmsError::NotSupported(
            "OpenPGP (PGP Key) support requires a non-FIPS build".to_owned(),
        ))
    }

    pub(crate) fn pgp_sign(_owm: &ObjectWithMetadata, _request: &Sign) -> KResult<SignResponse> {
        Err(KmsError::NotSupported(
            "OpenPGP (PGP Key) support requires a non-FIPS build".to_owned(),
        ))
    }

    pub(crate) fn pgp_signature_verify(
        _owm: &ObjectWithMetadata,
        _request: &SignatureVerify,
    ) -> KResult<SignatureVerifyResponse> {
        Err(KmsError::NotSupported(
            "OpenPGP (PGP Key) support requires a non-FIPS build".to_owned(),
        ))
    }
}

pub(crate) use imp::{
    create_pgp_key_and_tags, pgp_decrypt, pgp_encrypt, pgp_export_convert,
    pgp_normalize_for_import, pgp_sign, pgp_signature_verify,
};
