//! Authentication configuration step of the KMS configuration wizard.
//!
//! Covers: API key, JWT / OIDC, client certificate (mTLS), default username and
//! UI OIDC settings.

#![allow(unreachable_pub, clippy::print_stdout)]

use dialoguer::{Confirm, Input, MultiSelect, theme::ColorfulTheme};

use crate::{
    config::{AuthVerifierConfig, HttpConfig, IdpAuthConfig, OidcConfig, UiConfig},
    error::KmsError,
    result::KResult,
};

pub struct AuthWizardResult {
    #[allow(dead_code)]
    pub http_api_token: Option<String>,
    pub idp_auth: IdpAuthConfig,
    #[allow(dead_code)]
    pub auth_verifier: AuthVerifierConfig,
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
        "Auth Verifier server",
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
    let mut auth_verifier = AuthVerifierConfig::default();

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
        println!("  Configure the Auth Verifier server.");
        let server_url: String = Input::with_theme(&theme)
            .with_prompt("Auth Verifier server URL (e.g. https://auth.example.com)")
            .validate_with(|input: &String| -> Result<(), &str> {
                if input.trim().is_empty() {
                    Err("The Auth Verifier server URL cannot be blank")
                } else {
                    Ok(())
                }
            })
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        let server_url = server_url.trim().to_owned();
        let jwks_uri: String = Input::with_theme(&theme)
            .with_prompt("JWKS URI (leave blank to use <server_url>/.well-known/jwks.json)")
            .allow_empty(true)
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        let accept_invalid_certs: bool = Confirm::with_theme(&theme)
            .with_prompt("Accept invalid TLS certificates when fetching the JWKS? (dev/test only)")
            .default(false)
            .interact()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        let enable_ui_login: bool = Confirm::with_theme(&theme)
            .with_prompt("Enable the Web UI login form for the Auth Verifier server?")
            .default(false)
            .interact()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        let realm: Option<String> = if enable_ui_login {
            let realm: String = Input::with_theme(&theme)
                .with_prompt("Realm to authenticate the Web UI against")
                .interact_text()
                .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
            Some(realm)
        } else {
            None
        };
        auth_verifier = AuthVerifierConfig {
            auth_verifier_url: Some(server_url),
            auth_verifier_jwks_uri: if jwks_uri.trim().is_empty() {
                None
            } else {
                Some(jwks_uri)
            },
            auth_verifier_realm: realm,
            auth_verifier_accept_invalid_certs: accept_invalid_certs,
        };
    }

    if selected.contains(&3) {
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
        auth_verifier,
        ui_config_oidc: ui_oidc,
        default_username,
        force_default_username,
    })
}
