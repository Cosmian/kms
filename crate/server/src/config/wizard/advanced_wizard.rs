//! Advanced / miscellaneous configuration step of the KMS configuration wizard.
//!
//! Covers: workspace paths, key management, Microsoft DKE, KMS public URL, KMIP
//! policy, Google CSE, Azure EKM, AWS XKS, and UI settings.

#![allow(unreachable_pub)]

use std::path::PathBuf;

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType;
use dialoguer::{Confirm, Input, MultiSelect, Select, theme::ColorfulTheme};
use strum::IntoEnumIterator;

use crate::{
    config::{
        AzureEkmConfig, GoogleCseConfig, KmipPolicyConfig, KmipPolicyId, UiConfig, WorkspaceConfig,
    },
    error::KmsError,
    result::KResult,
    routes::aws_xks::AwsXksConfig,
};

pub struct AdvancedConfig {
    pub workspace: WorkspaceConfig,
    pub key_encryption_key: Option<String>,
    pub default_unwrap_type: Option<Vec<String>>,
    pub privileged_users: Option<Vec<String>>,
    pub ms_dke_service_url: Option<String>,
    pub kms_public_url: Option<String>,
    pub kmip_policy: KmipPolicyConfig,
    pub google_cse_config: GoogleCseConfig,
    pub azure_ekm_config: AzureEkmConfig,
    pub aws_xks_config: AwsXksConfig,
    pub ui_config: UiConfig,
}

pub fn configure_advanced(mut ui: UiConfig) -> KResult<AdvancedConfig> {
    let theme = ColorfulTheme::default();

    // ── Workspace ─────────────────────────────────────────────────────────────
    let root_data_path: String = Input::with_theme(&theme)
        .with_prompt("KMS data root directory")
        .default("./cosmian-kms".to_owned())
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let tmp_path: String = Input::with_theme(&theme)
        .with_prompt("Temporary data directory")
        .default("/tmp".to_owned())
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let workspace = WorkspaceConfig {
        root_data_path: PathBuf::from(root_data_path),
        tmp_path: PathBuf::from(tmp_path),
    };

    // ── Key Management ────────────────────────────────────────────────────────
    let kek: String = Input::with_theme(&theme)
        .with_prompt(
            "Key Encryption Key (KEK) ID to wrap all keys at rest \
             (leave blank to disable)",
        )
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    let key_encryption_key = if kek.trim().is_empty() {
        None
    } else {
        Some(kek)
    };

    let mut unwrap_type_labels: Vec<&str> = vec!["All"];
    unwrap_type_labels.extend(ObjectType::iter().map(|t| -> &'static str { t.into() }));
    let selected_unwrap = MultiSelect::with_theme(&theme)
        .with_prompt(
            "Object types to auto-unwrap when retrieved \
             (space to toggle, enter to confirm; select none to disable)",
        )
        .items(&unwrap_type_labels)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    let default_unwrap_type = if selected_unwrap.is_empty() {
        None
    } else {
        Some(
            selected_unwrap
                .iter()
                .filter_map(|&i| unwrap_type_labels.get(i).copied())
                .map(ToOwned::to_owned)
                .collect(),
        )
    };

    let privileged_str: String = Input::with_theme(&theme)
        .with_prompt(
            "Privileged users who can create/import objects \
             (comma-separated, leave blank to skip)",
        )
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    let privileged_users = if privileged_str.trim().is_empty() {
        None
    } else {
        Some(
            privileged_str
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect(),
        )
    };

    // ── Microsoft DKE & Public URL ────────────────────────────────────────────
    let ms_dke: String = Input::with_theme(&theme)
        .with_prompt(
            "Microsoft DKE service URL (leave blank to disable, \
             e.g. https://cse.my_domain.com/ms_dke)",
        )
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    let ms_dke_service_url = if ms_dke.trim().is_empty() {
        None
    } else {
        Some(ms_dke)
    };

    let public_url: String = Input::with_theme(&theme)
        .with_prompt(
            "KMS public URL (required for Google CSE / UI auth flows; leave blank to skip)",
        )
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    let kms_public_url = if public_url.trim().is_empty() {
        None
    } else {
        Some(public_url)
    };

    // ── KMIP Policy ───────────────────────────────────────────────────────────
    let mut policy_items: Vec<&str> = vec!["(disabled)"];
    policy_items.extend(KmipPolicyId::VARIANTS.iter().map(|v| v.as_str()));
    let policy_idx = Select::with_theme(&theme)
        .with_prompt("KMIP algorithm policy")
        .items(&policy_items)
        .default(0)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    let kmip_policy = KmipPolicyConfig {
        policy_id: if policy_idx == 0 {
            None
        } else {
            KmipPolicyId::VARIANTS
                .get(policy_idx - 1)
                .map(|v| v.as_str().to_owned())
        },
        allowlists: KmipPolicyConfig::unrestricted_allowlists(),
    };

    // ── Google CSE ────────────────────────────────────────────────────────────
    let google_cse_config = configure_google_cse(&theme)?;

    // ── Azure EKM ─────────────────────────────────────────────────────────────
    let azure_ekm_config = configure_azure_ekm(&theme)?;

    // ── AWS XKS ───────────────────────────────────────────────────────────────
    let aws_xks_config = configure_aws_xks(&theme)?;

    // ── UI dist path ──────────────────────────────────────────────────────────
    let ui_dist: String = Input::with_theme(&theme)
        .with_prompt("UI distribution folder path")
        .default(crate::config::get_default_ui_dist_path())
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    ui.ui_index_html_folder = Some(ui_dist);

    let session_salt: String = Input::with_theme(&theme)
        .with_prompt(
            "Session cookie salt (leave blank to auto-generate; \
             must match across load-balanced instances)",
        )
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    ui.ui_session_salt = if session_salt.trim().is_empty() {
        None
    } else {
        Some(session_salt)
    };

    Ok(AdvancedConfig {
        workspace,
        key_encryption_key,
        default_unwrap_type,
        privileged_users,
        ms_dke_service_url,
        kms_public_url,
        kmip_policy,
        google_cse_config,
        azure_ekm_config,
        aws_xks_config,
        ui_config: ui,
    })
}

fn configure_google_cse(theme: &ColorfulTheme) -> KResult<GoogleCseConfig> {
    let enable: bool = Confirm::with_theme(theme)
        .with_prompt("Enable Google Client-Side Encryption (CSE) endpoints?")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    if !enable {
        return Ok(GoogleCseConfig::default());
    }

    let disable_validation: bool = Confirm::with_theme(theme)
        .with_prompt("Disable Google CSE token validation? (not recommended for production)")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let whitelist_str: String = Input::with_theme(theme)
        .with_prompt(
            "CSE incoming URL whitelist for migration (comma-separated; leave blank to skip)",
        )
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    let google_cse_incoming_url_whitelist = if whitelist_str.trim().is_empty() {
        None
    } else {
        Some(
            whitelist_str
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect(),
        )
    };

    let migration_key: String = Input::with_theme(theme)
        .with_prompt("CSE migration key (PEM PKCS#8 RSA key; leave blank to auto-generate)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    Ok(GoogleCseConfig {
        google_cse_enable: true,
        google_cse_disable_tokens_validation: disable_validation,
        google_cse_incoming_url_whitelist,
        google_cse_migration_key: if migration_key.trim().is_empty() {
            None
        } else {
            Some(migration_key)
        },
    })
}

fn configure_azure_ekm(theme: &ColorfulTheme) -> KResult<AzureEkmConfig> {
    let enable: bool = Confirm::with_theme(theme)
        .with_prompt("Enable Azure EKM proxy endpoints?")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    if !enable {
        return Ok(AzureEkmConfig::default());
    }

    let path_prefix: String = Input::with_theme(theme)
        .with_prompt("Azure EKM path prefix (leave blank to skip)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let disable_client_auth: bool = Confirm::with_theme(theme)
        .with_prompt("⚠  Disable mTLS client auth? (testing only)")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let proxy_vendor: String = Input::with_theme(theme)
        .with_prompt("EKM proxy vendor name")
        .default("Cosmian".to_owned())
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let proxy_name: String = Input::with_theme(theme)
        .with_prompt("EKM proxy name")
        .default("EKM Proxy Service".to_owned())
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let ekm_vendor: String = Input::with_theme(theme)
        .with_prompt("EKMS vendor name")
        .default("Cosmian".to_owned())
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let ekm_product: String = Input::with_theme(theme)
        .with_prompt("EKMS product name and version")
        .default(format!("Cosmian KMS v{}", env!("CARGO_PKG_VERSION")))
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    Ok(AzureEkmConfig {
        azure_ekm_enable: true,
        azure_ekm_path_prefix: if path_prefix.trim().is_empty() {
            None
        } else {
            Some(path_prefix)
        },
        azure_ekm_disable_client_auth: disable_client_auth,
        azure_ekm_proxy_vendor: proxy_vendor,
        azure_ekm_proxy_name: proxy_name,
        azure_ekm_ekm_vendor: ekm_vendor,
        azure_ekm_ekm_product: ekm_product,
    })
}

fn configure_aws_xks(theme: &ColorfulTheme) -> KResult<AwsXksConfig> {
    let enable: bool = Confirm::with_theme(theme)
        .with_prompt("Enable AWS External Key Store (XKS) endpoints?")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    if !enable {
        return Ok(AwsXksConfig::default());
    }

    let region: String = Input::with_theme(theme)
        .with_prompt("AWS region (for SigV4 signing)")
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let service: String = Input::with_theme(theme)
        .with_prompt("AWS service name (for SigV4 signing)")
        .default("kms".to_owned())
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let access_key_id: String = Input::with_theme(theme)
        .with_prompt("AWS XKS SigV4 access key ID")
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let secret_access_key: String = dialoguer::Password::with_theme(theme)
        .with_prompt("AWS XKS SigV4 secret access key")
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    Ok(AwsXksConfig {
        aws_xks_enable: true,
        aws_xks_region: Some(region),
        aws_xks_service: Some(service),
        aws_xks_sigv4_access_key_id: Some(access_key_id),
        aws_xks_sigv4_secret_access_key: Some(secret_access_key),
    })
}
