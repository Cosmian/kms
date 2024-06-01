use cosmian_kmip::kmip::{
    kmip_operations::{GetAttributes, Operation},
    kmip_types::{AttributeReference, CryptographicParameters, EncodingOption},
};

use crate::{
    batch_utils::batch_operations,
    cosmian_kmip::kmip::{
        kmip_data_structures::KeyWrappingSpecification,
        kmip_objects::Object,
        kmip_operations::{Export, Get},
        kmip_types::{
            Attributes, EncryptionKeyInformation, KeyFormatType, UniqueIdentifier, WrappingMethod,
        },
    },
    error::result::ClientResult,
    ClientError, ClientResultHelper, KmsClient,
};

fn export_request(
    object_id_or_tags: &str,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    key_format_type: Option<KeyFormatType>,
    encoding_to_ttlv: bool,
    wrapping_cryptographic_parameters: Option<CryptographicParameters>,
    authenticated_encryption_additional_data: Option<String>,
) -> Export {
    Export::new(
        UniqueIdentifier::TextString(object_id_or_tags.to_string()),
        unwrap,
        wrapping_key_id.map(|wrapping_key_id| {
            key_wrapping_specification(
                wrapping_key_id,
                wrapping_cryptographic_parameters,
                authenticated_encryption_additional_data,
                encoding_to_ttlv,
            )
        }),
        key_format_type,
    )
}

fn get_request(
    object_id_or_tags: &str,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    key_format_type: Option<KeyFormatType>,
    encoding_to_ttlv: bool,
    wrapping_cryptographic_parameters: Option<CryptographicParameters>,
    authenticated_encryption_additional_data: Option<String>,
) -> Get {
    Get::new(
        UniqueIdentifier::TextString(object_id_or_tags.to_string()),
        unwrap,
        wrapping_key_id.map(|wrapping_key_id| {
            key_wrapping_specification(
                wrapping_key_id,
                wrapping_cryptographic_parameters,
                authenticated_encryption_additional_data,
                encoding_to_ttlv,
            )
        }),
        key_format_type,
    )
}

/// Determine the `KeyWrappingSpecification`
fn key_wrapping_specification(
    wrapping_key_id: &str,
    cryptographic_parameters: Option<CryptographicParameters>,
    authenticated_encryption_additional_data: Option<String>,
    encode_to_ttlv: bool,
) -> KeyWrappingSpecification {
    KeyWrappingSpecification {
        wrapping_method: WrappingMethod::Encrypt,
        encryption_key_information: Some(EncryptionKeyInformation {
            unique_identifier: UniqueIdentifier::TextString(wrapping_key_id.to_string()),
            cryptographic_parameters,
        }),
        attribute_name: authenticated_encryption_additional_data.map(|data| vec![data]),
        encoding_option: Some(if encode_to_ttlv {
            EncodingOption::TTLVEncoding
        } else {
            EncodingOption::NoEncoding
        }),
        ..KeyWrappingSpecification::default()
    }
}

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

impl<'a> ExportObjectParams<'a> {
    #[must_use]
    pub fn new() -> Self {
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
) -> Result<(UniqueIdentifier, Object, Option<Attributes>), ClientError> {
    let (id, object, object_type, attributes) = if params.allow_revoked {
        //use the KMIP export function to get revoked objects
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
    Ok((id, Object::post_fix(object_type, object), attributes))
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
/// * `params` - Export parameters
pub async fn batch_export_objects(
    kms_rest_client: &KmsClient,
    object_ids_or_tags: Vec<String>,
    params: ExportObjectParams<'_>,
) -> Result<Vec<(UniqueIdentifier, Object, Attributes)>, ClientError> {
    if params.allow_revoked {
        batch_export(
            kms_rest_client,
            object_ids_or_tags,
            params.unwrap,
            params.wrapping_key_id,
            params.key_format_type,
            params.encode_to_ttlv,
            params.wrapping_cryptographic_parameters,
            params.authenticated_encryption_additional_data,
        )
        .await
    } else {
        batch_get(
            kms_rest_client,
            object_ids_or_tags,
            params.unwrap,
            params.wrapping_key_id,
            params.key_format_type,
            params.encode_to_ttlv,
            params.wrapping_cryptographic_parameters,
            params.authenticated_encryption_additional_data,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn batch_get(
    kms_rest_client: &KmsClient,
    object_ids_or_tags: Vec<String>,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    key_format_type: Option<KeyFormatType>,
    encode_to_ttlv: bool,
    wrapping_cryptographic_parameters: Option<CryptographicParameters>,
    authenticated_encryption_additional_data: Option<String>,
) -> ClientResult<Vec<(UniqueIdentifier, Object, Attributes)>> {
    let operations = object_ids_or_tags
        .into_iter()
        .flat_map(|id| {
            // Get  does not return (external) attributes, so we need to do a GetAttributes
            vec![
                Operation::Get(get_request(
                    &id,
                    unwrap,
                    wrapping_key_id,
                    key_format_type,
                    encode_to_ttlv,
                    wrapping_cryptographic_parameters.clone(),
                    authenticated_encryption_additional_data.clone(),
                )),
                Operation::GetAttributes(GetAttributes {
                    unique_identifier: Some(UniqueIdentifier::TextString(id.to_string())),
                    attribute_references: None, //all attributes
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
                let object = Object::post_fix(get.object_type, get.object.clone());
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
                return Err(ClientError::Default(format!(
                    "Unexpected response from KMS, returning a sequence of non matching \
                     operations: {errors}",
                )))
            }
        }
    }
    Ok(results)
}

#[allow(clippy::too_many_arguments)]
async fn batch_export(
    kms_rest_client: &KmsClient,
    object_ids_or_tags: Vec<String>,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    key_format_type: Option<KeyFormatType>,
    encode_to_ttlv: bool,
    wrapping_cryptographic_parameters: Option<CryptographicParameters>,
    authenticated_encryption_additional_data: Option<String>,
) -> ClientResult<Vec<(UniqueIdentifier, Object, Attributes)>> {
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
                    encode_to_ttlv,
                    wrapping_cryptographic_parameters.clone(),
                    authenticated_encryption_additional_data.clone(),
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
                Operation::ExportResponse(export_response),
                Operation::GetAttributesResponse(get_attributes_response),
            ] => {
                let object =
                    Object::post_fix(export_response.object_type, export_response.object.clone());
                let mut attributes = export_response.attributes.clone();
                let _ = attributes.set_tags(get_attributes_response.attributes.get_tags());
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
                return Err(ClientError::Default(format!(
                    "Unexpected response from KMS, returning a sequence of non matching \
                     operations: {errors}",
                )))
            }
        }
    }
    Ok(results)
}
