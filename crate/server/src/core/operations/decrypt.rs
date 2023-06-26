use cosmian_kmip::kmip::{
    kmip_operations::{Decrypt, DecryptResponse},
    kmip_types::StateEnumeration,
};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, ObjectOperationTypes},
    crypto::error::result::CryptoResultHelper,
};
use tracing::trace;

use crate::{core::KMS, error::KmsError, kms_bail, result::KResult};

pub async fn decrypt(
    kms: &KMS,
    request: Decrypt,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<DecryptResponse> {
    trace!("Decrypt: {:?}", &request.unique_identifier);
    let mut uid = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // check if the uid is actually a set of tags
    if uid.starts_with('[') {
        let tags: Vec<String> =
            serde_json::from_str(&uid).with_context(|| format!("Invalid tags: {uid}"))?;
        let res = kms
            .db
            .find_from_tags(&tags, Some(user.to_owned()), params)
            .await?
            .into_iter()
            .filter(|(_unique_identifier, owner, state, permissions)| {
                owner == user
                    && (*state == StateEnumeration::Active
                        && permissions
                            .iter()
                            .any(|p| *p == ObjectOperationTypes::Decrypt))
            })
            .map(|(unique_identifier, _, _, _)| unique_identifier)
            .collect::<Vec<_>>();
        uid = match res.len() {
            0 => kms_bail!("No matching key for tags"),
            1 => res[0].clone(),
            _ => {
                kms_bail!("Multiple matching keys for tags")
            }
        };
    }

    kms.get_decryption_system(Default::default(), &uid, user, params)
        .await?
        .decrypt(&request)
        .map_err(Into::into)
}
