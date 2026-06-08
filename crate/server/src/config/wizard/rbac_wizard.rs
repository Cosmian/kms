//! RBAC / OPA policy wizard step.

use std::path::PathBuf;

use dialoguer::{Confirm, Input, theme::ColorfulTheme};

use crate::{config::RbacConfig, error::KmsError, result::KResult};

/// Configure RBAC settings interactively.
///
/// Returns the populated `RbacConfig` struct.
pub(crate) fn configure_rbac() -> KResult<RbacConfig> {
    let theme = ColorfulTheme::default();

    let enabled = Confirm::with_theme(&theme)
        .with_prompt("Enable RBAC/OPA authorization? (roles, tenants, centralized policy)")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    if !enabled {
        println!("  ℹ  RBAC disabled — using legacy ownership + ACL grant model.");
        return Ok(RbacConfig::default());
    }

    println!("  ℹ  RBAC enabled — configuring policy bundle and claim mappings.");
    println!();

    // Bundle source
    let bundle_path: String = Input::with_theme(&theme)
        .with_prompt("Local policy bundle directory path (leave empty for remote URL)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let (rbac_bundle_path, rbac_bundle_url) = if bundle_path.is_empty() {
        let url: String = Input::with_theme(&theme)
            .with_prompt("Remote policy bundle URL")
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        (None, Some(url))
    } else {
        (Some(PathBuf::from(bundle_path)), None)
    };

    let poll_interval: u64 = Input::with_theme(&theme)
        .with_prompt("Bundle poll interval (seconds, for remote URL)")
        .default(300)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    // Claim mappings
    let role_claim: String = Input::with_theme(&theme)
        .with_prompt("JWT claim path for roles (dot-notation, e.g., 'realm_access.roles')")
        .default("roles".to_owned())
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let tenant_claim: String = Input::with_theme(&theme)
        .with_prompt("JWT claim path for tenant ID")
        .default("tenant_id".to_owned())
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    // Super-admins
    let super_admins_str: String = Input::with_theme(&theme)
        .with_prompt("Super-admin users (comma-separated, leave empty for none)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let rbac_super_admins = if super_admins_str.is_empty() {
        None
    } else {
        Some(
            super_admins_str
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect(),
        )
    };

    Ok(RbacConfig {
        rbac_enabled: true,
        rbac_bundle_path,
        rbac_bundle_url,
        rbac_bundle_poll_interval_secs: poll_interval,
        rbac_role_claim: role_claim,
        rbac_tenant_claim: tenant_claim,
        rbac_super_admins,
    })
}
