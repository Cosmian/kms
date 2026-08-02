use clap::Parser;
use cosmian_kms_client::{
    KmsClientConfig,
    reexport::cosmian_http_client::{
        CosmianAuthServerLoginConfig, CosmianLoginStep, LoginState, approle_login, cosmian_login,
    },
};
use dialoguer::{Input, Password};

use crate::error::{KmsCliError, result::KmsCliResult};

/// Read a secret interactively from the terminal without echoing it.
///
/// Used for passwords and `AppRole` secret IDs so they never appear in shell
/// history, `ps` output, or `/proc/*/cmdline`.
fn prompt_hidden(prompt: &str) -> KmsCliResult<String> {
    Password::new()
        .with_prompt(prompt)
        .allow_empty_password(true)
        .interact()
        .map_err(|e| {
            KmsCliError::Default(format!(
                "a secret is required but no interactive terminal is available: {e}"
            ))
        })
}

/// The credential produced by a successful [`LoginAction`], indicating which
/// configuration field the caller must persist.
#[derive(Debug, Clone)]
pub enum LoginCredential {
    /// A JWT/OAuth access token, stored in `http_config.access_token` and sent
    /// as an `Authorization: Bearer` header.
    AccessToken(String),
    /// A Vault-compatible token, stored in `http_config.vault_token` and sent
    /// as an `X-Vault-Token` header.
    VaultToken(String),
}

/// Login to the KMS server identity provider.
///
/// Two subcommands are available:
///
/// **oauth** — `OAuth2` / OIDC authorization-code flow (opens a browser window).
/// Requires an `oauth2_conf` section in the configuration file with fields:
/// - `client_id`, `client_secret`, `authorize_url`, `token_url`, `scopes`.
///   The callback URL must be whitelisted with value `http://localhost:17899/token`.
///
/// **cosmian** — Cosmian authentication server (HTTP Basic credentials).
/// Requires a `cosmian_conf` section in the configuration file with fields:
/// - `server_url`: base URL of the Cosmian authentication server.
/// - `realm`: realm to authenticate against (e.g. `"kms"`).
///   The endpoint called is `POST {server_url}/login?realm={realm}` with an
///   `Authorization: Basic <base64(username:password)>` header.
///
/// **approle** — Vault-compatible `AppRole` login (for automation / service
/// accounts). Exchanges a `role_id` (+ optional `secret_id`) for a
/// Vault-compatible token at `POST {server_url}/v1/auth/approle/login`, which
/// the KMS proxies to the auth-verifier. The token is stored and sent as an
/// `X-Vault-Token` header on subsequent requests.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct LoginAction {
    #[command(subcommand)]
    pub subcommand: LoginSubcommand,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum LoginSubcommand {
    /// Login using the `OAuth2` authorization code flow.
    Oauth,
    /// Login using Cosmian authentication server (HTTP Basic credentials).
    ///
    /// The configuration file must contain a `cosmian_conf` section with
    /// `server_url` and `realm`.  Credentials are transmitted via an
    /// `Authorization: Basic` header to `POST {server_url}/login?realm={realm}`.
    Cosmian {
        /// Username for HTTP Basic authentication.
        #[clap(long, short = 'u')]
        username: String,
        /// Password for HTTP Basic authentication.
        ///
        /// If omitted, the password is read interactively without echoing it to
        /// the terminal, avoiding exposure in shell history and process listings.
        #[clap(long, short = 'p')]
        password: Option<String>,
    },
    /// Login using a Vault-compatible `AppRole` identity.
    ///
    /// Exchanges the `role_id` (and optional `secret_id`) for a Vault token via
    /// the KMS `POST {server_url}/v1/auth/approle/login` endpoint. The resulting
    /// token is stored in `http_config.vault_token` and forwarded as an
    /// `X-Vault-Token` header. Intended for CI/CD pipelines and service accounts.
    Approle {
        /// The stable `role_id` of the `AppRole`.
        #[clap(long)]
        role_id: String,
        /// The `secret_id` credential. Omit for roles with `bind_secret_id = false`.
        ///
        /// If omitted for a role that requires it, you will be prompted to enter
        /// it interactively without echoing it to the terminal.
        #[clap(long)]
        secret_id: Option<String>,
    },
}

impl LoginAction {
    /// Process the login action
    ///
    /// # Errors
    /// - If the required configuration section is missing or invalid
    /// - If the authentication request fails
    #[expect(clippy::print_stdout)]
    pub async fn process(&self, config: KmsClientConfig) -> KmsCliResult<LoginCredential> {
        match &self.subcommand {
            LoginSubcommand::Oauth => {
                let login_config = config.http_config.oauth2_conf.as_ref().ok_or_else(|| {
                    KmsCliError::Default(format!(
                        "The `login oauth` command (only used for JWT authentication) requires an Identity \
                         Provider (IdP) that MUST be configured in the oauth2_conf object in {config:?}",
                    ))
                })?;

                let state = LoginState::try_from(login_config.clone())?;
                println!("Browse to: {}", state.auth_url);
                let access_token = state.finalize().await?;

                println!("\nSuccess! The access token was saved to the KMS client configuration.");

                Ok(LoginCredential::AccessToken(access_token))
            }
            LoginSubcommand::Cosmian { username, password } => {
                let cosmian_conf: &CosmianAuthServerLoginConfig =
                    config.http_config.cosmian_conf.as_ref().ok_or_else(|| {
                        KmsCliError::Default(
                            "The `login cosmian` command requires a `cosmian_conf` section in the \
                             KMS client configuration file with `server_url` and `realm` fields."
                                .to_owned(),
                        )
                    })?;

                // Read the password interactively (without echoing) when it was
                // not supplied on the command line, so it never appears in shell
                // history, `ps` output, or `/proc/*/cmdline`.
                let password = if let Some(password) = password {
                    password.clone()
                } else {
                    prompt_hidden("Password")?
                };

                let accept_invalid_certs = config.http_config.accept_invalid_certs;

                // First attempt: send without a TOTP code.
                let access_token = match cosmian_login(
                    cosmian_conf,
                    username,
                    &password,
                    accept_invalid_certs,
                    None,
                )
                .await?
                {
                    CosmianLoginStep::Authenticated(token) => token,
                    CosmianLoginStep::TotpRequired => {
                        // Prompt the user for their TOTP code, then re-submit.
                        let code: String = Input::new()
                            .with_prompt("TOTP code")
                            .interact_text()
                            .map_err(|e| {
                                KmsCliError::Default(format!(
                                    "Server requires TOTP but no interactive terminal is \
                                     available: {e}"
                                ))
                            })?;

                        match cosmian_login(
                            cosmian_conf,
                            username,
                            &password,
                            accept_invalid_certs,
                            Some(&code),
                        )
                        .await?
                        {
                            CosmianLoginStep::Authenticated(token) => token,
                            CosmianLoginStep::TotpRequired => {
                                return Err(KmsCliError::Default(
                                    "TOTP code rejected by the server. Check that your \
                                     authenticator app is synchronized."
                                        .to_owned(),
                                ));
                            }
                        }
                    }
                };

                println!("\nSuccess! The access token was saved to the KMS client configuration.");

                Ok(LoginCredential::AccessToken(access_token))
            }
            LoginSubcommand::Approle { role_id, secret_id } => {
                // Read the secret_id interactively (without echoing) when it was
                // not supplied on the command line, so it never appears in shell
                // history, `ps` output, or `/proc/*/cmdline`.
                let secret_id = if let Some(secret_id) = secret_id {
                    Some(secret_id.clone())
                } else {
                    let entered =
                        prompt_hidden("Secret ID (leave empty for a role without a secret_id)")?;
                    if entered.is_empty() {
                        None
                    } else {
                        Some(entered)
                    }
                };

                let vault_token =
                    approle_login(&config.http_config, role_id, secret_id.as_deref()).await?;

                println!("\nSuccess! The AppRole token was saved to the KMS client configuration.");

                Ok(LoginCredential::VaultToken(vault_token))
            }
        }
    }
}
