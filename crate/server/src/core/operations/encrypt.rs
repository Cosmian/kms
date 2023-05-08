use cosmian_kmip::kmip::kmip_operations::{Encrypt, EncryptResponse};
use cosmian_kms_utils::types::ExtraDatabaseParams;
use tracing::trace;

use crate::{core::KMS, error::KmsError, result::KResult};

pub async fn encrypt(
    kms: &KMS,
    request: Encrypt,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<EncryptResponse> {
    // 1 - check correlation //TODO
    // 2b - if correlation pull encrypt oracle from cache
    // 2a - if no correlation, create encrypt oracle
    // 3 - call EncryptOracle.encrypt
    trace!("encrypt : {}", serde_json::to_string(&request)?);

    let uid = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;
    kms.get_encryption_system(uid, owner, params)
        .await?
        .encrypt(&request)
        .map_err(Into::into)
}
