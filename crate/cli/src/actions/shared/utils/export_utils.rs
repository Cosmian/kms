use cosmian_kmip::kmip::{
    kmip_data_structures::KeyWrappingData,
    kmip_objects::Object,
    kmip_operations::{Export, Get},
    kmip_types::{EncryptionKeyInformation, WrappingMethod},
};
use cosmian_kms_client::KmsRestClient;

use crate::error::{result::CliResultHelper, CliError};

/// Export an Object from the KMS
///
/// # Arguments
///  * `client_connector` - The KMS client connector
///  * `object_id` - The KMS object id
///  * `unwrap` - Unwrap the object if it is wrapped
///  * `wrapping_key_id` - The wrapping key id to wrap the key
///  * `allow_revoked` - Allow the export of a revoked object
///
///  `wrapping_key_id` is ignored if `unwrap` is true
///
/// # Returns
/// * The exported object
///
/// # Errors
/// * If the KMS cannot be reached
/// * If the object cannot be exported
/// * If the object cannot be written to a file
pub async fn export_object(
    client_connector: &KmsRestClient,
    object_id: &str,
    unwrap: bool,
    wrapping_key_id: Option<&str>,
    allow_revoked: bool,
) -> Result<Object, CliError> {
    // If an unwrapping key is specified, generate the key (un)wrapping data
    let key_wrapping_data: Option<KeyWrappingData> = if unwrap {
        None
    } else {
        wrapping_key_id.map(|id| KeyWrappingData {
            wrapping_method: WrappingMethod::Encrypt,
            encryption_key_information: Some(EncryptionKeyInformation {
                unique_identifier: id.to_string(),
                cryptographic_parameters: None,
            }),
            mac_or_signature_key_information: None,
            mac_or_signature: None,
            iv_counter_nonce: None,
            encoding_option: None,
        })
    };
    let (object, object_type) = if allow_revoked {
        //use the KMIP export function to get revoked objects
        let export_response = client_connector
            .export(Export::new(object_id, unwrap, key_wrapping_data))
            .await
            .with_context(|| "export")?;
        (export_response.object, export_response.object_type)
    } else {
        // Query the KMS with your kmip data and get the key pair ids
        let get_response = client_connector
            .get(Get::new(object_id, unwrap, key_wrapping_data))
            .await
            .with_context(|| "export")?;
        (get_response.object, get_response.object_type)
    };
    // Return the object after post fixing the object type
    Ok(Object::post_fix(object_type, object))
}
