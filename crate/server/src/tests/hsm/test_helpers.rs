use log::info;
use crate::error::KmsError;
use crate::result::KResult;

pub(crate) fn get_hsm_password() -> KResult<String> {
    let user_password = option_env!("HSM_USER_PASSWORD")
        .ok_or_else(|| {
            KmsError::Default(
                "The user password for the HSM is not set. Please set the HSM_USER_PASSWORD \
                 environment variable"
                    .to_string(),
            )
        })?
        .to_string();
    Ok(user_password)
}

pub(crate) fn get_hsm_slot_id() -> KResult<usize> {
    let slot_id = option_env!("HSM_SLOT_ID")
        .ok_or_else(|| {
            KmsError::Default(
                "The slot id for the HSM was not provided. Please set the HSM_SLOT_ID \
                 environment variable"
                    .to_string(),
            )
        })?
        .to_string();
    Ok(slot_id.parse().unwrap())
}

pub(crate) fn get_hsm_model() -> Option<String> {
    let model = option_env!("HSM_MODEL");
    match model {
        Some(model) => Some(model.to_string()),
        None => {
            info!("No HSM model provide via environment variable 'HSM_MODEL'. Defaulting to utimaco");
            None
        },
    }
}