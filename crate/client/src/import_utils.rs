use tracing::trace;

use crate::{
    cosmian_kmip::kmip::{
        kmip_objects::{Object, ObjectType},
        kmip_operations::Import,
        kmip_types::{Attributes, KeyWrapType, UniqueIdentifier},
    },
    KmsClient, KmsClientError,
};

/// Import an Object into the KMS
///
/// If the `import_attributes` are not specified,
/// the attributes of the object are used, if any.
pub async fn import_object<'a, T: IntoIterator<Item = impl AsRef<str>>>(
    kms_rest_client: &KmsClient,
    object_id: Option<String>,
    object: Object,
    import_attributes: Option<Attributes>,
    unwrap: bool,
    replace_existing: bool,
    tags: T,
) -> Result<String, KmsClientError> {
    trace!("Entering import_object");
    // an empty uid will have the server generate if for us
    let unique_identifier = object_id.clone().unwrap_or_default();

    trace!("import_object: unique_identifier: {unique_identifier}");
    // cache the object type
    let object_type = object.object_type();
    trace!("import_object: object: {object}");

    let (key_wrap_type, mut attributes) = if object_type == ObjectType::Certificate {
        // add the tags to the attributes
        let attributes = import_attributes.unwrap_or_default();
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
        let attributes = import_attributes.map_or_else(
            || object.attributes().cloned().unwrap_or_default(),
            |attributes| attributes,
        );
        (key_wrap_type, attributes)
    };

    trace!("import_object: key_wrap_type: {key_wrap_type:?}, attributes: {attributes:?}");

    // set the new tags
    attributes.set_tags(tags)?;

    // if the key must be wrapped, wrap it
    let import = Import {
        unique_identifier: UniqueIdentifier::TextString(unique_identifier),
        object_type,
        replace_existing: Some(replace_existing),
        key_wrap_type,
        attributes,
        object,
    };

    // send the import request
    let response = kms_rest_client.import(import).await?;

    // return the unique identifier
    Ok(response.unique_identifier.to_string())
}
