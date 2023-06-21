use cosmian_kmip::kmip::kmip_operations::{Decrypt, DecryptResponse};
use cosmian_kms_utils::{access::ExtraDatabaseParams, crypto::error::result::CryptoResultHelper};
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

    // check if the uid is actually a set of tags
    if uid.starts_with("[") {
        let tags: Vec<String> = serde_json::from_str(uid).context_with(|| format!())?;
        return kms
            .get_decryption_system_by_tags(Default::default(), owner, tags, params)
            .await?
            .decrypt(&request)
            .map_err(Into::into)
    }

    kms.get_decryption_system(Default::default(), uid, owner, params)
        .await?
        .decrypt(&request)
        .map_err(Into::into)
}
