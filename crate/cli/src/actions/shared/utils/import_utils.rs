use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::Import,
    kmip_types::{Attributes, KeyWrapType},
};
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::tagging::set_tags;
use tracing::trace;
use uuid::Uuid;

use crate::error::{result::CliResultHelper, CliError};

pub async fn import_object<'a, T: IntoIterator<Item = impl AsRef<str>>>(
    kms_rest_client: &KmsRestClient,
    object_id: Option<String>,
    object: Object,
    unwrap: bool,
    replace_existing: bool,
    tags: T,
) -> Result<String, CliError> {
    trace!("Entering import_object");
    // generate a unique id if not specified
    let unique_identifier = object_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    trace!("import_object: unique_identifier");
    // cache the object type
    let object_type = object.object_type();
    trace!("object_type: {object_type:?}");

    let (key_wrap_type, mut attributes) = match object_type {
        ObjectType::Certificate => {
            // add the tags to the attributes
            let attributes = Attributes::default();

            (None, attributes)
        } // no wrapping for certificate
        _ => {
            // unwrap the key if needed
            let key_wrap_type = object.key_wrapping_data().map(|_| {
                if unwrap {
                    KeyWrapType::NotWrapped
                } else {
                    KeyWrapType::AsRegistered
                }
            });
            // add the tags to the attributes
            let attributes = object.attributes().cloned()?;

            (key_wrap_type, attributes)
        }
    };

    // set the new tags
    set_tags(&mut attributes, tags)?;

    // if the key must be wrapped, wrap it
    let import = Import {
        unique_identifier,
        object_type,
        replace_existing: Some(replace_existing),
        key_wrap_type,
        attributes,
        object,
        key_wrapping_data: None,
    };

    // send the import request
    let response = kms_rest_client
        .import(import)
        .await
        .with_context(|| "cannot connect to the kms server")?;

    Ok(response.unique_identifier)
}
