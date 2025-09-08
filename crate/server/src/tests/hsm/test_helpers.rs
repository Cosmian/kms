use log::info;
use crate::error::KmsError;
use crate::result::KResult;

pub(crate) fn get_hsm_password() -> KResult<String> {
    let user_password = option_env!("HSM_USER_PASSWORD")
        .ok_or_else(|| {
            KmsError::Default(
                "The user password for the HSM is not set. Please set the HSM_USER_PASSWORD \
                 environment variable"
                    .to_owned(),
            )
        })?
        .to_owned();
    Ok(user_password)
}

pub(crate) fn get_hsm_slot_id() -> KResult<usize> {
    let slot_id = option_env!("HSM_SLOT_ID")
        .ok_or_else(|| {
            KmsError::Default(
                "The slot id for the HSM was not provided. Please set the HSM_SLOT_ID \
                 environment variable"
                    .to_owned(),
            )
        })?
        .to_owned();
    slot_id.parse().map_err(|_e| {
        KmsError::Default(
            format!(
                "The HSM slot id '{slot_id}' could not be parsed. Please make sure the\
                 HSM_SLOT_ID environment variable is set to a valid slot id."
            )
        )
    })
}

pub(crate) fn get_hsm_model() -> Option<String> {
    let model = option_env!("HSM_MODEL");
    model.map_or_else(|| {
        info!("No HSM model provided via environment variable 'HSM_MODEL'. Defaulting to utimaco");
        None
    }, |model| Some(model.to_owned()))
}