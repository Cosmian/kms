use cosmian_kms_client_utils::{
    export_utils::{export_request, get_request},
    reexport::cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_operations::{GetAttributes, Operation},
        kmip_types::{AttributeReference, CryptographicParameters},
    },
};

use crate::{
    KmsClient, KmsClientError,
    batch_utils::batch_operations,
    cosmian_kmip::kmip_2_1::{
        kmip_objects::Object,
        kmip_types::{KeyFormatType, UniqueIdentifier},
    },
    error::result::{KmsClientResult, KmsClientResultHelper},
};

#[derive(Default)]
pub struct ExportObjectParams<'a> {
    ///  Unwrap the object if it is wrapped
    pub unwrap: bool,
    ///  The wrapping key id to wrap the key, may be the PKCS#12 password. `wrapping_key_id` is ignored if `unwrap` is true
    pub wrapping_key_id: Option<&'a str>,
    /// `allow_revoked` - Allow the export of a revoked object
    pub allow_revoked: bool,
    /// `key_format_type` - The key format for export
    pub key_format_type: Option<KeyFormatType>,
    /// `encode_to_ttlv` - if wrapping, Encode the Key Material to JSON TTLV before wrapping
    pub encode_to_ttlv: bool,
    /// `cryptographic_parameters` - The cryptographic parameters for wrapping
    pub wrapping_cryptographic_parameters: Option<CryptographicParameters>,
    /// `authenticated_encryption_additional_data` - Wrapping using GCM mode, additional data used for encryption
    pub authenticated_encryption_additional_data: Option<String>,
}

impl ExportObjectParams<'_> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            unwrap: false,
            wrapping_key_id: None,
            allow_revoked: false,
            key_format_type: None,
            encode_to_ttlv: false,
            wrapping_cryptographic_parameters: None,
            authenticated_encryption_additional_data: None,
        }
    }
}

/// Export an Object from the KMS
///
/// # Arguments
///  * `kms_rest_client` - The KMS client connector
///  * `object_id_or_tags` - The KMS object id or tags
///  * `params` - Export parameters
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
    params: ExportObjectParams<'_>,
) -> Result<(UniqueIdentifier, Object, Option<Attributes>), KmsClientError> {
    let (id, object, _, attributes) = if params.allow_revoked {
        // use the KMIP export function to get revoked objects
        let export_response = kms_rest_client
            .export(export_request(
                object_id_or_tags,
                params.unwrap,
                params.wrapping_key_id,
                params.key_format_type,
                params.encode_to_ttlv,
                params.wrapping_cryptographic_parameters,
                params.authenticated_encryption_additional_data,
            ))
            .await
            .with_context(|| "Export")?;
        (
            export_response.unique_identifier,
            export_response.object,
            export_response.object_type,
            Some(export_response.attributes),
        )
    } else {
        // Query the KMS with your kmip data and get the key pair ids
        let get_response = kms_rest_client
            .get(get_request(
                object_id_or_tags,
                params.unwrap,
                params.wrapping_key_id,
                params.key_format_type,
                params.encode_to_ttlv,
                params.wrapping_cryptographic_parameters,
                params.authenticated_encryption_additional_data,
            ))
            .await
            .with_context(|| "Get")?;
        (
            get_response.unique_identifier,
            get_response.object,
            get_response.object_type,
            None,
        )
    };
    // Return the object after post fixing the object type
    Ok((id, object, attributes))
}

/// Export a batch of Objects from the KMS
///
/// The objects are exported in a single request and the response is a list of results.
/// The objects are exported in the order they are provided.
/// If the object was successfully exported, the result is the exported object and the object attributes augmented with the tags
/// If the object export failed, the result is an error message.
///
/// # Arguments
/// * `kms_rest_client` - The KMS client connector
/// * `object_ids_or_tags` - The KMS object ids or tags
/// * `params` - Export parameters
/// # Errors
/// * If the KMS cannot be reached
pub async fn batch_export_objects(
    kms_rest_client: &KmsClient,
    object_ids_or_tags: Vec<String>,
    params: ExportObjectParams<'_>,
) -> Result<Vec<(UniqueIdentifier, Object, Attributes)>, KmsClientError> {
    if params.allow_revoked {
        batch_export(kms_rest_client, object_ids_or_tags, &params).await
    } else {
        batch_get(kms_rest_client, object_ids_or_tags, &params).await
    }
}

async fn batch_get(
    kms_rest_client: &KmsClient,
    object_ids_or_tags: Vec<String>,
    params: &ExportObjectParams<'_>,
) -> KmsClientResult<Vec<(UniqueIdentifier, Object, Attributes)>> {
    let operations = object_ids_or_tags
        .into_iter()
        .flat_map(|id| {
            // Get  does not return (external) attributes, so we need to do a GetAttributes
            vec![
                Operation::Get(get_request(
                    &id,
                    params.unwrap,
                    params.wrapping_key_id,
                    params.key_format_type,
                    params.encode_to_ttlv,
                    params.wrapping_cryptographic_parameters.clone(),
                    params.authenticated_encryption_additional_data.clone(),
                )),
                Operation::GetAttributes(GetAttributes {
                    unique_identifier: Some(UniqueIdentifier::TextString(id.clone())),
                    attribute_reference: None, // all attributes
                }),
            ]
        })
        .collect();
    let responses = batch_operations(kms_rest_client, operations).await?;
    let mut results = Vec::with_capacity(responses.len());

    for response in responses.chunks(2) {
        match response {
            [
                Operation::GetResponse(get),
                Operation::GetAttributesResponse(get_attributes_response),
            ] => {
                let object = get.object.clone();
                results.push((
                    get.unique_identifier.clone(),
                    object,
                    get_attributes_response.attributes.clone(),
                ));
            }
            operations => {
                let mut errors = String::new();
                for op in operations {
                    errors = format!("{errors}, Unexpected operation {op}\n");
                }
                return Err(KmsClientError::Default(format!(
                    "Unexpected response from KMS, returning a sequence of non matching \
                     operations: {errors}",
                )));
            }
        }
    }
    Ok(results)
}

async fn batch_export(
    kms_rest_client: &KmsClient,
    object_ids_or_tags: Vec<String>,
    params: &ExportObjectParams<'_>,
) -> KmsClientResult<Vec<(UniqueIdentifier, Object, Attributes)>> {
    let operations = object_ids_or_tags
        .into_iter()
        .flat_map(|id| {
            // Export does not return the tags (external attributes), so we need to do a GetAttributes
            vec![
                Operation::Export(export_request(
                    &id,
                    params.unwrap,
                    params.wrapping_key_id,
                    params.key_format_type,
                    params.encode_to_ttlv,
                    params.wrapping_cryptographic_parameters.clone(),
                    params.authenticated_encryption_additional_data.clone(),
                )),
                Operation::GetAttributes(GetAttributes {
                    unique_identifier: Some(UniqueIdentifier::TextString(id.clone())),
                    attribute_reference: Some(vec![AttributeReference::tags_reference()]), // tags
                }),
            ]
        })
        .collect();
    let responses = batch_operations(kms_rest_client, operations).await?;
    let mut results = vec![];

    for response in responses.chunks(2) {
        match response {
            [
                Operation::ExportResponse(export_response),
                Operation::GetAttributesResponse(get_attributes_response),
            ] => {
                let object = export_response.object.clone();
                let mut attributes = export_response.attributes.clone();
                attributes.set_tags(get_attributes_response.attributes.get_tags())?;
                results.push((
                    get_attributes_response.unique_identifier.clone(),
                    object,
                    get_attributes_response.attributes.clone(),
                ));
            }
            operations => {
                let mut errors = String::new();
                for op in operations {
                    errors = format!("{errors}, Unexpected operation {op}\n");
                }
                return Err(KmsClientError::Default(format!(
                    "Unexpected response from KMS, returning a sequence of non matching \
                     operations: {errors}",
                )));
            }
        }
    }
    Ok(results)
}
