use crate::{HError, HResult};

pub fn get_slot_id() -> HResult<usize> {
    let slot_id = option_env!("HSM_SLOT_ID")
        .ok_or_else(|| {
            HError::Default(
                "The slot ID for the HSM is not set. Please set the HSM_SLOT_ID environment \
                 variable"
                    .to_string(),
            )
        })?
        .to_string();
    Ok(slot_id.parse::<usize>().unwrap())
}

pub fn get_hsm_password() -> HResult<String> {
    let user_password = option_env!("HSM_USER_PASSWORD")
        .ok_or_else(|| {
            HError::Default(
                "The user password for the HSM is not set. Please set the HSM_USER_PASSWORD \
                 environment variable"
                    .to_string(),
            )
        })?
        .to_string();
    Ok(user_password)
}

pub fn get_hsm_slot_id() -> HResult<usize> {
    let slot_id = option_env!("HSM_SLOT_ID")
        .ok_or_else(|| {
            HError::Default(
                "The slot id for the HSM was not provided. Please set the HSM_SLOT_ID \
                 environment variable"
                    .to_string(),
            )
        })?
        .to_string();
    Ok(slot_id.parse().unwrap())
}