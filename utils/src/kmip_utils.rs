use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_operations::ErrorReason,
        kmip_types::{Attributes, LinkType, LinkedObjectIdentifier},
    },
};

/// Extract the attributes from the given `KeyBlock`
/// Return an empty set of attributes if none are available
pub fn attributes_from_key_block(
    object_type: ObjectType,
    key_block: &KeyBlock,
) -> Result<Attributes, KmipError> {
    let (_, attributes) = key_block.key_value.plaintext().ok_or_else(|| {
        KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Attribute,
            "The key does not contain attributes".to_string(),
        )
    })?;
    let attributes = match attributes {
        Some(attrs) => {
            let mut a = attrs.clone();
            a.object_type = object_type;
            a
        }
        None => Attributes::new(object_type),
    };
    Ok(attributes)
}

/// Extract the attributes from the given `Object` which must have a `KeyBlock` of `PlnText` value
/// Return an empty set of attributes if none are available
pub fn attributes_from_object(
    object_type: ObjectType,
    object: &Object,
) -> Result<Attributes, KmipError> {
    attributes_from_key_block(
        object_type,
        object.key_block().map_err(|e| {
            KmipError::InvalidKmipValue(ErrorReason::Illegal_Object_Type, e.to_string())
        })?,
    )
}

/// Extract the Key bytes from the given `KeyBlock`
pub fn key_bytes_and_attributes_from_key_block(
    key_block: &KeyBlock,
    uid: &str,
) -> Result<(Vec<u8>, Option<Attributes>), KmipError> {
    match &key_block.key_value {
        KeyValue::PlainText {
            key_material,
            attributes,
        } => {
            let key = match key_material {
                KeyMaterial::TransparentSymmetricKey { key } => Ok(key.clone()),
                KeyMaterial::ByteString(v) => Ok(v.clone()),
                other => Err(KmipError::InvalidKmipValue(
                    ErrorReason::Invalid_Data_Type,
                    format!(
                        "The key at uid: {} has an invalid key material: {:?}",
                        uid, other,
                    ),
                )),
            };
            let attributes = attributes.clone();
            Ok((key?, attributes))
        }
        KeyValue::Wrapped(wrapped) => Ok((wrapped.clone(), None)),
    }
}

/// Get public key uid from private key uid
pub fn public_key_unique_identifier_from_private_key(
    private_key: &Object,
) -> Result<String, KmipError> {
    let key_block = match private_key {
        Object::PrivateKey { key_block } => key_block,
        _ => {
            return Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Object_Type,
                "KmipError KMIP Private Key".to_owned(),
            ))
        }
    };
    let mut attributes = key_block.key_value.attributes()?.clone();
    attributes.set_object_type(ObjectType::PublicKey);
    if attributes.link.len() != 1 {
        return Err(KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Object_Type,
            "Invalid public key. Should at least contain the link to private key".to_string(),
        ))
    }
    let link = attributes.link[0].clone();

    if link.link_type != LinkType::PublicKeyLink {
        return Err(KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Object_Type,
            "Private key MUST contain a public key link".to_string(),
        ))
    }
    Ok(match link.linked_object_identifier {
        LinkedObjectIdentifier::TextString(s) => s,
        LinkedObjectIdentifier::Enumeration(_) => {
            return Err(KmipError::NotSupported(
                "Enumeration not yet supported".to_owned(),
            ))
        }
        LinkedObjectIdentifier::Index(_) => {
            return Err(KmipError::NotSupported(
                "Index not yet supported".to_owned(),
            ))
        }
    })
}
