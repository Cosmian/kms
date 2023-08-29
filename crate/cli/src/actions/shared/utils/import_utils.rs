use cosmian_kmip::kmip::{kmip_objects::Object, kmip_operations::Import, kmip_types::KeyWrapType};
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::tagging::set_tags;
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
    // unwrap the key if needed
    let key_wrap_type = object.key_wrapping_data().map(|_| {
        if unwrap {
            KeyWrapType::NotWrapped
        } else {
            KeyWrapType::AsRegistered
        }
    });

    // cache the object type
    let object_type = object.object_type();

    // generate a unique id if not specified
    let unique_identifier = object_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // add the tags to the attributes
    let mut attributes = object.attributes().cloned()?;
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
    };
    // send the import request
    let response = kms_rest_client
        .import(import)
        .await
        .with_context(|| "cannot connect to the kms server")?;

    Ok(response.unique_identifier)
}
