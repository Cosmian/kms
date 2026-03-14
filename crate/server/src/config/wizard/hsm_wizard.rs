//! HSM configuration step of the KMS configuration wizard.

#![allow(unreachable_pub)]

use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};

use crate::{
    config::{HsmConfig, HsmModel},
    error::KmsError,
    result::KResult,
};

pub fn configure_hsm() -> KResult<HsmConfig> {
    let theme = ColorfulTheme::default();

    let enable: bool = Confirm::with_theme(&theme)
        .with_prompt("Enable Hardware Security Module (HSM) support?")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    if !enable {
        return Ok(HsmConfig::default());
    }

    let model_idx = Select::with_theme(&theme)
        .with_prompt("HSM model")
        .items(
            &HsmModel::VARIANTS
                .iter()
                .map(|v| v.as_str())
                .collect::<Vec<_>>(),
        )
        .default(0)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    let hsm_model = HsmModel::VARIANTS
        .get(model_idx)
        .ok_or_else(|| KmsError::ServerError("Invalid HSM model selection".to_owned()))?
        .as_str()
        .to_owned();

    let hsm_admin: String = Input::with_theme(&theme)
        .with_prompt("HSM admin username")
        .default("admin".to_owned())
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let mut hsm_slot: Vec<usize> = Vec::new();
    let mut hsm_password: Vec<String> = Vec::new();

    loop {
        let slot: String = Input::with_theme(&theme)
            .with_prompt("HSM slot number (leave blank to finish)")
            .allow_empty(true)
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        if slot.trim().is_empty() {
            break;
        }
        let slot_num: usize = slot
            .trim()
            .parse()
            .map_err(|e| KmsError::ServerError(format!("Invalid slot number '{slot}': {e}")))?;

        let password: String = dialoguer::Password::with_theme(&theme)
            .with_prompt(format!(
                "Password for slot {slot_num} (leave blank for none)"
            ))
            .allow_empty_password(true)
            .interact()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

        hsm_slot.push(slot_num);
        hsm_password.push(password);

        let add_more = Confirm::with_theme(&theme)
            .with_prompt("Add another HSM slot?")
            .default(false)
            .interact()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        if !add_more {
            break;
        }
    }

    Ok(HsmConfig {
        hsm_model,
        hsm_admin,
        hsm_slot,
        hsm_password,
    })
}
