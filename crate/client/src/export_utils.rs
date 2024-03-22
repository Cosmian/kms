use cosmian_kmip::kmip::{
    kmip_operations::{GetAttributes, Operation},
    kmip_types::AttributeReference,
};

use crate::{
    batch_utils::batch_operations,
    client_bail,
    cosmian_kmip::kmip::{
        kmip_data_structures::KeyWrappingSpecification,
        kmip_objects::Object,
        kmip_operations::{Export, Get},
        kmip_types::{
            Attributes, EncryptionKeyInformation, KeyFormatType, UniqueIdentifier, WrappingMethod,
        },
    },
    ClientError, ClientResultHelper, KmsClient,
};

fn export_request(
    object_id_or_tags: &str,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    key_format_type: Option<KeyFormatType>,
) -> Export {
    let key_wrapping_specification = key_wrapping_specification(unwrap, wrapping_key_id);
    Export::new(
        UniqueIdentifier::TextString(object_id_or_tags.to_string()),
        unwrap,
        key_wrapping_specification,
        key_format_type,
    )
}

fn get_request(
    object_id_or_tags: &str,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    key_format_type: Option<KeyFormatType>,
) -> Get {
    let key_wrapping_specification = key_wrapping_specification(unwrap, wrapping_key_id);
    Get::new(
        UniqueIdentifier::TextString(object_id_or_tags.to_string()),
        unwrap,
        key_wrapping_specification,
        key_format_type,
    )
}

/// Determine the `KeyWrappingSpecification`
fn key_wrapping_specification(
    unwrap: bool,
    wrapping_key_id: Option<&str>,
) -> Option<KeyWrappingSpecification> {
    let key_wrapping_specification: Option<KeyWrappingSpecification> = if unwrap {
        None
    } else {
        wrapping_key_id.map(|id| KeyWrappingSpecification {
            wrapping_method: WrappingMethod::Encrypt,
            encryption_key_information: Some(EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString(id.to_string()),
                cryptographic_parameters: None,
            }),
            ..KeyWrappingSpecification::default()
        })
    };
    key_wrapping_specification
}

/// Export an Object from the KMS
///
/// # Arguments
///  * `kms_rest_client` - The KMS client connector
///  * `object_id_or_tags` - The KMS object id or tags
///  * `unwrap` - Unwrap the object if it is wrapped
///  * `wrapping_key_id` - The wrapping key id to wrap the key, may be the PKCS#12 password
///  * `allow_revoked` - Allow the export of a revoked object
///
///  `wrapping_key_id` is ignored if `unwrap` is true
///
/// # Returns
/// * The exported object and the Export attributes (None for Get)
///
/// # Errors
/// * If the KMS cannot be reached
/// * If the object cannot be exported
/// * If the object cannot be written to a file
pub async fn export_object(
    kms_rest_client: &KmsClient,
    object_id_or_tags: &str,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    allow_revoked: bool,
    key_format_type: Option<KeyFormatType>,
) -> Result<(Object, Option<Attributes>), ClientError> {
    let (object, object_type, attributes) = if allow_revoked {
        //use the KMIP export function to get revoked objects
        let export_response = kms_rest_client
            .export(export_request(
                object_id_or_tags,
                unwrap,
                wrapping_key_id,
                key_format_type,
            ))
            .await
            .with_context(|| "Export")?;
        (
            export_response.object,
            export_response.object_type,
            Some(export_response.attributes),
        )
    } else {
        // Query the KMS with your kmip data and get the key pair ids
        let get_response = kms_rest_client
            .get(get_request(
                object_id_or_tags,
                unwrap,
                wrapping_key_id,
                key_format_type,
            ))
            .await
            .with_context(|| "Get")?;
        (get_response.object, get_response.object_type, None)
    };
    // Return the object after post fixing the object type
    Ok((Object::post_fix(object_type, object), attributes))
}

/// Export a batch of Objects from the KMS
/// The objects are exported in a single request and the response is a list of results.
/// The objects are exported in the order they are provided.
/// If the object was successfully exported, the result is the exported object and the object attributes augmented with the tags
/// If the object export failed, the result is an error message.
///
/// # Arguments
/// * `kms_rest_client` - The KMS client connector
/// * `object_ids_or_tags` - The KMS object ids or tags
/// * `unwrap` - Unwrap the object if it is wrapped
/// * `wrapping_key_id` - The wrapping key id to wrap the key, may be the PKCS#12 password
/// * `allow_revoked` - Allow the export of a revoked object
/// * `key_format_type` - The key format type
pub async fn batch_export_objects(
    kms_rest_client: &KmsClient,
    object_ids_or_tags: Vec<String>,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    allow_revoked: bool,
    key_format_type: Option<KeyFormatType>,
) -> Result<Vec<Result<(Object, Attributes), String>>, ClientError> {
    if allow_revoked {
        batch_export(
            kms_rest_client,
            object_ids_or_tags,
            unwrap,
            wrapping_key_id,
            key_format_type,
        )
        .await
    } else {
        batch_get(
            kms_rest_client,
            object_ids_or_tags,
            unwrap,
            wrapping_key_id,
            key_format_type,
        )
        .await
    }
}

async fn batch_get(
    kms_rest_client: &KmsClient,
    object_ids_or_tags: Vec<String>,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    key_format_type: Option<KeyFormatType>,
) -> Result<Vec<Result<(Object, Attributes), String>>, ClientError> {
    let operations = object_ids_or_tags
        .into_iter()
        .flat_map(|id| {
            // Get  does not return (external) attributes, so we need to do a GetAttributes
            vec![
                Operation::Get(get_request(&id, unwrap, wrapping_key_id, key_format_type)),
                Operation::GetAttributes(GetAttributes {
                    unique_identifier: Some(UniqueIdentifier::TextString(id.to_string())),
                    attribute_references: None, //all attributes
                }),
            ]
        })
        .collect();
    let responses = batch_operations(kms_rest_client, operations).await?;
    let mut results = vec![];

    for response in responses.chunks(2) {
        match response {
            [
                Ok(Operation::GetResponse(get)),
                Ok(Operation::GetAttributesResponse(atts)),
            ] => {
                let object = Object::post_fix(get.object_type, get.object.clone());
                results.push(Ok((object, atts.attributes.clone())));
            }
            [Err(e), _] => results.push(Err(e.to_string())),
            [_, Err(e)] => results.push(Err(e.to_string())),
            e => client_bail!(
                "Unexpected response from KMS, returning a sequence of non matching operations: \
                 {e:?}"
            ),
        }
    }
    Ok(results)
}

async fn batch_export(
    kms_rest_client: &KmsClient,
    object_ids_or_tags: Vec<String>,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    key_format_type: Option<KeyFormatType>,
) -> Result<Vec<Result<(Object, Attributes), String>>, ClientError> {
    let operations = object_ids_or_tags
        .into_iter()
        .flat_map(|id| {
            // Export does not return the tags (external attributes), so we need to do a GetAttributes
            vec![
                Operation::Export(export_request(
                    &id,
                    unwrap,
                    wrapping_key_id,
                    key_format_type,
                )),
                Operation::GetAttributes(GetAttributes {
                    unique_identifier: Some(UniqueIdentifier::TextString(id.to_string())),
                    attribute_references: Some(vec![AttributeReference::tags_reference()]), //tags
                }),
            ]
        })
        .collect();
    let responses = batch_operations(kms_rest_client, operations).await?;
    let mut results = vec![];

    for response in responses.chunks(2) {
        match response {
            [
                Ok(Operation::ExportResponse(export_response)),
                Ok(Operation::GetAttributesResponse(atts)),
            ] => {
                let object =
                    Object::post_fix(export_response.object_type, export_response.object.clone());
                let mut attributes = export_response.attributes.clone();
                let _ = attributes.set_tags(atts.attributes.get_tags());
                results.push(Ok((object, atts.attributes.clone())));
            }
            [Err(e), _] => results.push(Err(e.to_string())),
            [_, Err(e)] => results.push(Err(e.to_string())),
            e => client_bail!(
                "Unexpected response from KMS, returning a sequence of non matching operations: \
                 {e:?}"
            ),
        }
    }
    Ok(results)
}
