use crate::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::Import,
    kmip_types::{Attributes, KeyWrapType, UniqueIdentifier},
};

/// Build an ` Import ` request for a generic Object
#[must_use]
pub fn build_import_object_request(
    object: Object,
    object_type: ObjectType,
    attributes: Attributes,
    unique_identifier: &str,
    replace_existing: Option<bool>,
) -> Import {
    let key_wrap_type = if object.key_wrapping_data().is_some() {
        Some(KeyWrapType::AsRegistered)
    } else {
        None
    };

    // build the import request and run it
    Import {
        unique_identifier: UniqueIdentifier::TextString(unique_identifier.to_owned()),
        object_type,
        replace_existing,
        key_wrap_type,
        attributes,
        object,
    }
}
