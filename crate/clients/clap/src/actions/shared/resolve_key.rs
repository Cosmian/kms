use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose};
use cosmian_kms_client::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
use cosmian_kms_client::export_object;
use cosmian_kms_client::{
    ExportObjectParams, KmsClient,
    kmip_2_1::{
        kmip_attributes::Attributes, kmip_objects::Object,
        requests::create_symmetric_key_kmip_object,
    },
    read_object_from_json_ttlv_file,
};

use crate::error::result::{KmsCliResult, KmsCliResultHelper};

/// Resolve a wrapping/unwrapping key from one of the common key source options:
/// - base64-encoded key bytes → AES symmetric key object
/// - key ID in the KMS → export the key
/// - KMIP JSON TTLV file → read the key
///
/// Returns `None` if no source is provided.
pub(crate) async fn resolve_key_from_options(
    kms_rest_client: &KmsClient,
    key_b64: Option<&str>,
    key_id: Option<&str>,
    key_file: Option<&PathBuf>,
) -> KmsCliResult<Option<Object>> {
    let vendor_id = kms_rest_client.config.vendor_id.as_str();

    if let Some(b64) = key_b64 {
        let key_bytes = general_purpose::STANDARD
            .decode(b64)
            .with_context(|| "failed decoding the key from base64")?;
        let object = create_symmetric_key_kmip_object(
            vendor_id,
            &key_bytes,
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Default::default()
            },
        )?;
        return Ok(Some(object));
    }

    if let Some(key_id) = key_id {
        let (_, object, _) =
            export_object(kms_rest_client, key_id, ExportObjectParams::default()).await?;
        return Ok(Some(object));
    }

    if let Some(key_file) = key_file {
        let object = read_object_from_json_ttlv_file(key_file)?;
        return Ok(Some(object));
    }

    Ok(None)
}
