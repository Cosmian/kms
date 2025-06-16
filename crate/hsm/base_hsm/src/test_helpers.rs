use crate::{HError, HResult};

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
