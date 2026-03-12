//! Authentication configuration step of the KMS configuration wizard.
//!
//! Covers: API key, JWT / OIDC, client certificate (mTLS), default username and
//! UI OIDC settings.

#![allow(unreachable_pub, clippy::print_stdout)]

use dialoguer::{Confirm, Input, MultiSelect, theme::ColorfulTheme};

use crate::{
    config::{HttpConfig, IdpAuthConfig, OidcConfig, UiConfig},
    error::KmsError,
    result::KResult,
};

pub struct AuthWizardResult {
    #[allow(dead_code)]
    pub http_api_token: Option<String>,
    pub idp_auth: IdpAuthConfig,
    #[allow(dead_code)]
    pub ui_config_oidc: OidcConfig,
    pub default_username: String,
    pub force_default_username: bool,
}

pub fn configure_auth(http: &mut HttpConfig, ui: &mut UiConfig) -> KResult<AuthWizardResult> {
    let theme = ColorfulTheme::default();

    let auth_choices = &[
        "API Key (static token)",
        "JWT / OIDC (for programmatic clients)",
        "Client Certificate (mTLS – configure in TLS section)",
    ];

    let selected = MultiSelect::with_theme(&theme)
        .with_prompt(
            "Select authentication method(s) to enable \
             (space to toggle, enter to confirm)",
        )
        .items(auth_choices)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    // API key
    let api_token_id: Option<String> = if selected.contains(&0) {
        let token: String = Input::with_theme(&theme)
            .with_prompt("API token value (will be stored in config; keep it secret)")
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        Some(token)
    } else {
        None
    };
    http.api_token_id = api_token_id;

    // JWT / OIDC
    let mut jwt_providers: Vec<String> = Vec::new();
    let mut ui_oidc = OidcConfig::default();

    if selected.contains(&1) {
        println!("  Configure JWT/OIDC providers.");
        println!("  Format: ISSUER_URI[,JWKS_URI[,AUDIENCE1,AUDIENCE2,...]]");
        loop {
            let provider: String = Input::with_theme(&theme)
                .with_prompt("Provider config string (leave blank to stop)")
                .allow_empty(true)
                .interact_text()
                .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
            if provider.trim().is_empty() {
                break;
            }
            jwt_providers.push(provider);
            let add_more = Confirm::with_theme(&theme)
                .with_prompt("Add another JWT/OIDC provider?")
                .default(false)
                .interact()
                .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
            if !add_more {
                break;
            }
        }

        // UI OIDC
        let configure_ui_oidc = Confirm::with_theme(&theme)
            .with_prompt("Configure OIDC for the web UI?")
            .default(false)
            .interact()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

        if configure_ui_oidc {
            let client_id: String = Input::with_theme(&theme)
                .with_prompt("UI OIDC client ID")
                .interact_text()
                .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
            let client_secret: String = dialoguer::Password::with_theme(&theme)
                .with_prompt("UI OIDC client secret")
                .interact()
                .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
            let issuer_url: String = Input::with_theme(&theme)
                .with_prompt("UI OIDC issuer URL")
                .interact_text()
                .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
            let logout_url: String = Input::with_theme(&theme)
                .with_prompt("UI OIDC logout URL (optional, leave blank to skip)")
                .allow_empty(true)
                .interact_text()
                .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

            ui_oidc = OidcConfig {
                ui_oidc_client_id: Some(client_id),
                ui_oidc_client_secret: Some(client_secret),
                ui_oidc_issuer_url: Some(issuer_url),
                ui_oidc_logout_url: if logout_url.trim().is_empty() {
                    None
                } else {
                    Some(logout_url)
                },
            };
        }
    }

    if selected.contains(&2) {
        println!(
            "  Client certificate (mTLS) authentication is controlled by the \
             '--clients-ca-cert-file' option configured in the TLS section."
        );
    }

    // Default username
    let default_username: String = Input::with_theme(&theme)
        .with_prompt("Default username (used when no auth method resolves a user)")
        .default("admin".to_owned())
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let force_default_username: bool = Confirm::with_theme(&theme)
        .with_prompt("Force the default username even when an authentication method is provided?")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    ui.ui_oidc_auth = ui_oidc.clone();

    Ok(AuthWizardResult {
        http_api_token: None, // already set in http above
        idp_auth: IdpAuthConfig {
            jwt_auth_provider: if jwt_providers.is_empty() {
                None
            } else {
                Some(jwt_providers)
            },
        },
        ui_config_oidc: ui_oidc,
        default_username,
        force_default_username,
    })
}
