use cosmian_logger::trace;

use crate::{
    error::result::KmipResult,
    kmip_0::kmip_types::KeyWrapType,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::{Object, ObjectType},
        kmip_operations::Import,
        kmip_types::UniqueIdentifier,
    },
    time_normalize,
};

/// Build an ` Import ` request for a generic Object
pub fn import_object_request<T: IntoIterator<Item = impl AsRef<str>>>(
    unique_identifier: Option<String>,
    object: Object,
    attributes: Option<Attributes>,
    unwrap: bool,
    replace_existing: bool,
    tags: T,
) -> KmipResult<Import> {
    let unique_identifier = UniqueIdentifier::TextString(unique_identifier.unwrap_or_default());
    trace!("unique_identifier: {unique_identifier}");
    let object_type = object.object_type();

    let (key_wrap_type, mut attributes) = if object_type == ObjectType::Certificate {
        // add the tags to the attributes
        let attributes = attributes.unwrap_or_default();
        (None, attributes)
    } else {
        // unwrap the key if needed
        let key_wrap_type = object.key_wrapping_data().map(|_| {
            if unwrap {
                KeyWrapType::NotWrapped
            } else {
                KeyWrapType::AsRegistered
            }
        });
        // add the tags to the attributes
        let attributes =
            attributes.unwrap_or_else(|| object.attributes().cloned().unwrap_or_default());
        (key_wrap_type, attributes)
    };
    attributes.activation_date = Some(time_normalize()?);

    trace!("key_wrap_type: {key_wrap_type:?}, attributes: {attributes}");

    attributes.set_tags(tags).unwrap_or_default();

    Ok(Import {
        unique_identifier,
        object,
        object_type,
        replace_existing: Some(replace_existing),
        key_wrap_type,
        attributes,
    })
}
