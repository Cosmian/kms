use cosmian_kmip::kmip::kmip_operations::{Decrypt, DecryptResponse};
use cosmian_kms_utils::access::ExtraDatabaseParams;
use tracing::trace;

use crate::{core::KMS, error::KmsError, result::KResult};

pub async fn decrypt(
    kms: &KMS,
    request: Decrypt,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<DecryptResponse> {
    trace!("Decrypt: {:?}", &request.unique_identifier);
    let uid = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;
    kms.get_decryption_system(Default::default(), uid, owner, params)
        .await?
        .decrypt(&request)
        .map_err(Into::into)
}
