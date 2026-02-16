//! Shared utility functions for route handlers
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::KeyWrapType,
    kmip_2_1::{
        kmip_data_structures::KeyMaterial,
        kmip_operations::Get,
        kmip_types::{KeyFormatType, UniqueIdentifier},
    },
};
use cosmian_logger::trace;

use crate::{core::KMS, error::KmsError, result::KResult};

/// Extract RSA public key metadata (modulus and exponent)
pub(crate) async fn get_rsa_key_metadata_from_public_key(
    kms: &KMS,
    key_name: &str,
    user: &str,
) -> KResult<(Box<num_bigint_dig::BigInt>, Box<num_bigint_dig::BigInt>)> {
    let public_key_name = format!("{key_name}_pk");
    trace!(
        "Fetching public key: {public_key_name} and attempting to extract RSA modulus and public exponent from key material"
    );
    let public_key_response = kms
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(public_key_name.clone())),
                key_format_type: Some(KeyFormatType::TransparentRSAPublicKey),
                key_wrap_type: Some(KeyWrapType::NotWrapped),
                ..Default::default()
            },
            user,
        )
        .await
        .map_err(|e| {
            KmsError::ServerError(format!(
                "Failed to retrieve public key {public_key_name}: {e}"
            ))
        })?;

    let pub_key_block = public_key_response.object.key_block()?;
    let key_material = pub_key_block.key_material()?;

    match key_material {
        KeyMaterial::TransparentRSAPublicKey {
            modulus,
            public_exponent,
        } => Ok((modulus.clone(), public_exponent.clone())), // no escape from this clone if we want to refactor
        _ => Err(KmsError::ServerError(
            "Public key does not contain RSA public key material".to_owned(),
        )),
    }
}
