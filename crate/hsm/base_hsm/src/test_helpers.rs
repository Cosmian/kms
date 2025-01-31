use std::{
    ptr,
    sync::{Arc, Once},
    thread,
};

use cosmian_kms_interfaces::KeyType;
use pkcs11_sys::{CK_RV, CK_VOID_PTR};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use crate::{ HError, HResult, HsmEncryptionAlgorithm, RsaKeySize, SlotManager};

static TRACING_INIT: Once = Once::new();
pub fn initialize_logging() {
    TRACING_INIT.call_once(|| {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::INFO) // Adjust the level as needed
            .with_writer(std::io::stdout)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Setting default subscriber failed");
    });
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
