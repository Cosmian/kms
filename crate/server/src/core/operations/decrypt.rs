use cosmian_kmip::kmip::kmip_operations::{Decrypt, DecryptResponse};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationTypes};
use tracing::trace;

use crate::{
    core::{operations::uids::uid_from_identifier_tags, KMS},
    error::KmsError,
    result::KResult,
};

pub async fn decrypt(
    kms: &KMS,
    request: Decrypt,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<DecryptResponse> {
    trace!("Decrypt: {:?}", &request.unique_identifier);

    // there must be an identifier
    let identifier = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // retrieve from tags or use passed identifier
    let uid = uid_from_identifier_tags(
        kms,
        &identifier,
        user,
        ObjectOperationTypes::Decrypt,
        params,
    )
    .await?
    .unwrap_or(identifier);

    // decrypt
    kms.get_decryption_system(Default::default(), &uid, user, params)
        .await?
        .decrypt(&request)
        .map_err(Into::into)
}
