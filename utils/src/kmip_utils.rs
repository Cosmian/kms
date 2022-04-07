use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_operations::ErrorReason,
    kmip_types::{Attributes, LinkType, LinkedObjectIdentifier},
};

use crate::{
    error::LibError,
    lib_ensure, lib_error,
    result::{LibResult, LibResultHelper},
};

/// Extract the attributes from the given `KeyBlock`
/// Return an empty set of attributes if none are available
pub fn attributes_from_key_block(
    object_type: ObjectType,
    key_block: &KeyBlock,
) -> Result<Attributes, LibError> {
    let (_, attributes) = key_block.key_value.plaintext().ok_or_else(|| {
        LibError::InvalidKmipObject(
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
) -> Result<Attributes, LibError> {
    attributes_from_key_block(
        object_type,
        object.key_block().map_err(|e| {
            LibError::InvalidKmipValue(ErrorReason::Illegal_Object_Type, e.to_string())
        })?,
    )
}

/// Extract the Key bytes from the given `KeyBlock`
pub fn key_bytes_and_attributes_from_key_block(
    key_block: &KeyBlock,
    uid: &str,
) -> LibResult<(Vec<u8>, Option<Attributes>)> {
    match &key_block.key_value {
        KeyValue::PlainText {
            key_material,
            attributes,
        } => {
            let key = match key_material {
                KeyMaterial::TransparentSymmetricKey { key } => Ok(key.clone()),
                KeyMaterial::ByteString(v) => Ok(v.clone()),
                other => Err(lib_error!(
                    "The key at uid: {} has an invalid key material: {:?}",
                    uid,
                    other
                ))
                .reason(ErrorReason::Invalid_Data_Type),
            };
            let attributes = attributes.clone();
            Ok((key?, attributes))
        }
        KeyValue::Wrapped(wrapped) => Ok((wrapped.clone(), None)),
    }
}

/// Get public key uid from private key uid
pub fn public_key_unique_identifier_from_private_key(private_key: &Object) -> LibResult<String> {
    let key_block = match private_key {
        Object::PrivateKey { key_block } => key_block,
        _ => return Err(LibError::Error("Expected a KMIP Private Key".to_owned())),
    };
    let mut attributes = key_block.key_value.attributes()?.clone();
    attributes.set_object_type(ObjectType::PublicKey);
    lib_ensure!(
        attributes.link.len() == 1,
        "Invalid public key. Should at least contain the link to private key"
    );
    let link = attributes.link[0].clone();
    lib_ensure!(
        link.link_type == LinkType::PublicKeyLink,
        "Private key MUST contain a public key link"
    );
    Ok(match link.linked_object_identifier {
        LinkedObjectIdentifier::TextString(s) => s,
        LinkedObjectIdentifier::Enumeration(_) => {
            return Err(LibError::Error("Enumeration not yet supported".to_owned()))
        }
        LinkedObjectIdentifier::Index(_) => {
            return Err(LibError::Error("Index not yet supported".to_owned()))
        }
    })
}
