use cosmian_kmip::kmip::{
    kmip_operations::{GetAttributes, Operation},
    kmip_types::{AttributeReference, BlockCipherMode, CryptographicParameters, EncodingOption},
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
    block_cipher_mode: Option<BlockCipherMode>,
    authenticated_encryption_additional_data: Option<String>,
) -> Export {
    let key_wrapping_specification = key_wrapping_specification(
        unwrap,
        wrapping_key_id,
        block_cipher_mode,
        authenticated_encryption_additional_data,
    );
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
    block_cipher_mode: Option<BlockCipherMode>,
    authenticated_encryption_additional_data: Option<String>,
) -> Get {
    let key_wrapping_specification = key_wrapping_specification(
        unwrap,
        wrapping_key_id,
        block_cipher_mode,
        authenticated_encryption_additional_data,
    );
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
    block_cipher_mode: Option<BlockCipherMode>,
    authenticated_encryption_additional_data: Option<String>,
) -> Option<KeyWrappingSpecification> {
    let key_wrapping_specification: Option<KeyWrappingSpecification> = if unwrap {
        None
    } else if block_cipher_mode == Some(BlockCipherMode::GCM) {
        wrapping_key_id.map(|id| KeyWrappingSpecification {
            wrapping_method: WrappingMethod::Encrypt,
            encryption_key_information: Some(EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString(id.to_string()),
                cryptographic_parameters: Some(Box::new(CryptographicParameters {
                    block_cipher_mode,
                    ..CryptographicParameters::default()
                })),
            }),
            attribute_name: authenticated_encryption_additional_data.map(|data| vec![data]),
            encoding_option: Some(EncodingOption::NoEncoding),
            ..KeyWrappingSpecification::default()
        })
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
    /// `block_cipher_mode` - If wrapping with symmetric key, how to wrap key, using RFC5649 (`NistKeyWrap`) or AES256GCM (GCM)
    pub block_cipher_mode: Option<BlockCipherMode>,
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
            block_cipher_mode: None,
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
) -> Result<(Object, Option<Attributes>), ClientError> {
    let (object, object_type, attributes) = if params.allow_revoked {
        //use the KMIP export function to get revoked objects
        let export_response = kms_rest_client
            .export(export_request(
                object_id_or_tags,
                params.unwrap,
                params.wrapping_key_id,
                params.key_format_type,
                params.block_cipher_mode,
                params.authenticated_encryption_additional_data,
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
                params.unwrap,
                params.wrapping_key_id,
                params.key_format_type,
                params.block_cipher_mode,
                params.authenticated_encryption_additional_data,
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
/// * `params` - Export parameters
pub async fn batch_export_objects(
    kms_rest_client: &KmsClient,
    object_ids_or_tags: Vec<String>,
    params: ExportObjectParams<'_>,
) -> Result<Vec<(Object, Attributes)>, ClientError> {
    if params.allow_revoked {
        batch_export(
            kms_rest_client,
            object_ids_or_tags,
            params.unwrap,
            params.wrapping_key_id,
            params.key_format_type,
            params.block_cipher_mode,
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
            params.block_cipher_mode,
            params.authenticated_encryption_additional_data,
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
    block_cipher_mode: Option<BlockCipherMode>,
    authenticated_encryption_additional_data: Option<String>,
) -> ClientResult<Vec<(Object, Attributes)>> {
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
                    block_cipher_mode,
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
    let mut results = vec![];

    for response in responses.chunks(2) {
        match response {
            [
                Operation::GetResponse(get),
                Operation::GetAttributesResponse(get_attributes_response),
            ] => {
                let object = Object::post_fix(get.object_type, get.object.clone());
                results.push((object, get_attributes_response.attributes.clone()));
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

async fn batch_export(
    kms_rest_client: &KmsClient,
    object_ids_or_tags: Vec<String>,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    key_format_type: Option<KeyFormatType>,
    block_cipher_mode: Option<BlockCipherMode>,
    authenticated_encryption_additional_data: Option<String>,
) -> ClientResult<Vec<(Object, Attributes)>> {
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
                    block_cipher_mode,
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
                results.push((object, get_attributes_response.attributes.clone()));
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
