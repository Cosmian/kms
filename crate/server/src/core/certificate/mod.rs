use cosmian_crypto_core::{Ed25519PublicKey, FixedSizeCBytes};
use cosmian_kmip::kmip::kmip_operations::Get;
use cosmian_kms_utils::access::ExtraDatabaseParams;
use tracing::trace;

use super::KMS;
use crate::{error::KmsError, result::KResult};

pub(crate) mod ca_signing_key;
pub(crate) mod create_leaf_certificate;
pub(crate) mod create_subca_certificate;

async fn get_key_bytes<const LENGTH: usize>(
    uid: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<[u8; LENGTH]> {
    let get_response = kms.get(Get::from(uid), owner, params).await?;
    let bytes = &get_response.object.key_block()?.key_bytes()?;
    let fixed_size_array: [u8; LENGTH] = bytes[..].try_into()?;
    Ok(fixed_size_array)
}

async fn build_public_key(
    public_key_uid: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Ed25519PublicKey> {
    trace!("Creating key pair for new certificate");
    let public_key_bytes = get_key_bytes(public_key_uid, kms, owner, params).await?;
    let public_key = Ed25519PublicKey::try_from_bytes(public_key_bytes).map_err(|e| {
        KmsError::ConversionError(format!("X25519 Public key from bytes failed: {}", e))
    })?;

    Ok(public_key)
}
