use cosmian_kms_client::{
    cosmian_kmip::kmip::{
        kmip_data_structures::KeyWrappingSpecification,
        kmip_objects::Object,
        kmip_operations::{Export, Get},
        kmip_types::{
            Attributes, EncryptionKeyInformation, KeyFormatType, UniqueIdentifier, WrappingMethod,
        },
    },
    KmsRestClient,
};

use crate::{batch_utils::batch_operations, ClientError, KmsRestClient, RestClientResultHelper};

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

/// Determine the KeyWrappingSpecification
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
    kms_rest_client: &KmsRestClient,
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
/// If the object was successfully exported, the result is the exported object and the object attributes.
/// In the case of a query for non-revoked objects, the attributes are tentatively extracted from the object.
/// If the object export failed, the result is an error message.
pub async fn batch_export_objects(
    kms_rest_client: &KmsRestClient,
    object_ids_or_tags: Vec<String>,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    allow_revoked: bool,
    key_format_type: Option<KeyFormatType>,
) -> Result<Vec<Result<(Object, Attributes), String>>, ClientError> {
    let operations = object_ids_or_tags
        .into_iter()
        .map(|id| {
            if allow_revoked {
                Operation::Export(export_request(
                    &id,
                    unwrap,
                    wrapping_key_id,
                    key_format_type,
                ))
            } else {
                Operation::Get(get_request(&id, unwrap, wrapping_key_id, key_format_type))
            }
        })
        .collect();
    let response = batch_operations(kms_rest_client, operations).await?;
    Ok(response
        .into_iter()
        .map(|result| {
            result.and_then(|item| match item.operation_enum() {
                Operation::ExportResponse(export) => Ok((
                    Object::post_fix(export.object_type, export.object),
                    export.attributes,
                )),
                Operation::GetResponse(get) => {
                    let object = Object::post_fix(get.object_type, get.object);
                    // the Get operation does not return attributes, try to get them from the object
                    let attributes = object.attributes().cloned().unwrap_or_default();
                    Ok((object, attributes))
                }
                _ => unreachable!(),
            })
        })
        .collect())
}
