//! `ckms vault approle` sub-commands.
//!
//! Manage Vault-compatible `AppRole` identities in the Cosmian Authentication
//! Server (`auth-verifier`).
//!
//! ## Unauthenticated commands
//! - `login` — exchange `role_id` + `secret_id` for a Vault token.
//!
//! ## Admin commands (require `--admin-user` + `--admin-password`)
//! - `create-role` — create or update a role.
//! - `list-roles` — list all roles.
//! - `get-role-id` — retrieve the stable `role_id` for a role.
//! - `generate-secret-id` — generate a new secret ID.
//! - `destroy-secret-id` — invalidate a secret ID by accessor.
//! - `delete-role` — permanently delete a role.

use std::collections::HashMap;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use crate::{actions::console::Stdout, error::result::KmsCliResult};

// ── Wire types (mirrors auth_client dto/vault.rs) ────────────────────────────

#[derive(Serialize)]
struct AppRoleLoginRequest<'a> {
    role_id: &'a str,
    secret_id: &'a str,
}

#[derive(Serialize)]
struct AppRoleRoleRequest {
    secret_id_ttl: i64,
    token_ttl: i64,
    token_policies: Vec<String>,
    bind_secret_id: bool,
}

#[derive(Serialize)]
struct AppRoleSecretIdRequest {
    ttl: i64,
    num_uses: i64,
}

#[derive(Serialize)]
struct AppRoleDestroySecretIdRequest<'a> {
    secret_id_accessor: &'a str,
}

#[derive(Deserialize)]
struct VaultAuthResponse {
    auth: VaultAuth,
}

#[derive(Deserialize)]
struct VaultAuth {
    client_token: String,
    lease_duration: i64,
    policies: Vec<String>,
    #[allow(dead_code)]
    metadata: HashMap<String, String>,
}

#[derive(Deserialize)]
struct AppRoleRoleIdResponse {
    data: AppRoleRoleIdData,
}

#[derive(Deserialize)]
struct AppRoleRoleIdData {
    role_id: String,
}

#[derive(Deserialize)]
struct AppRoleSecretIdResponse {
    data: AppRoleSecretIdData,
}

#[derive(Deserialize)]
struct AppRoleSecretIdData {
    secret_id: String,
    secret_id_accessor: String,
}

#[derive(Deserialize)]
struct AppRoleListRolesResponse {
    data: AppRoleListData,
}

#[derive(Deserialize)]
struct AppRoleListData {
    keys: Vec<String>,
}

/// Minimal login request body for auth-verifier `/login` endpoint.
#[derive(Serialize)]
struct AuthVerifierLoginRequest {
    public_key_pem: Option<String>,
    totp_code: Option<String>,
}

// ── Admin helper ─────────────────────────────────────────────────────────────

/// Authenticate to the auth-verifier admin realm and return a cookie-aware
/// [`reqwest::Client`] ready for admin calls.
///
/// # Errors
/// Returns an error if the HTTP request fails or admin credentials are invalid.
async fn admin_client(
    auth_url: &str,
    admin_user: &str,
    admin_password: &str,
) -> KmsCliResult<reqwest::Client> {
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

    let login_url = format!("{auth_url}/login?realm=_");
    let resp = client
        .post(&login_url)
        .basic_auth(admin_user, Some(admin_password))
        .json(&AuthVerifierLoginRequest {
            public_key_pem: None,
            totp_code: None,
        })
        .send()
        .await
        .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(crate::error::KmsCliError::Default(format!(
            "Admin login failed (HTTP {status}): {body}"
        )));
    }
    Ok(client)
}

// ── Shared admin flags ────────────────────────────────────────────────────────

/// Shared flags for admin `AppRole` operations.
#[derive(Parser, Debug)]
pub(crate) struct AdminArgs {
    /// URL of the Cosmian Authentication Server (auth-verifier).
    ///
    /// Example: `https://auth.example.com:8443`
    #[clap(
        long,
        env = "CKMS_VAULT_AUTH_URL",
        help = "Base URL of the Cosmian Authentication Server"
    )]
    auth_verifier_url: String,

    /// Admin username for the `_` (admin) realm.
    #[clap(long, env = "CKMS_VAULT_ADMIN_USER", help = "Admin username")]
    admin_user: String,

    /// Admin password.
    #[clap(
        long,
        env = "CKMS_VAULT_ADMIN_PASSWORD",
        help = "Admin password",
        hide_env_values = true
    )]
    admin_password: String,
}

// ── Sub-commands ──────────────────────────────────────────────────────────────

/// Manage Vault-compatible `AppRole` identities in the Authentication Server.
#[derive(Subcommand, Debug)]
pub enum AppRoleCommands {
    /// Exchange a `role_id` + `secret_id` for a Vault token.
    ///
    /// This is the unauthenticated login step used by SPIRE agents.
    Login(AppRoleLoginCmd),
    /// Create or update an `AppRole` role.
    #[command(name = "create-role")]
    CreateRole(AppRoleCreateRoleCmd),
    /// List all `AppRole` roles.
    #[command(name = "list-roles")]
    ListRoles(AppRoleListRolesCmd),
    /// Retrieve the stable `role_id` for a role.
    #[command(name = "get-role-id")]
    GetRoleId(AppRoleGetRoleIdCmd),
    /// Generate a new secret ID for a role.
    #[command(name = "generate-secret-id")]
    GenerateSecretId(AppRoleGenerateSecretIdCmd),
    /// Destroy a secret ID by its accessor.
    #[command(name = "destroy-secret-id")]
    DestroySecretId(AppRoleDestroySecretIdCmd),
    /// Permanently delete an `AppRole` role.
    #[command(name = "delete-role")]
    DeleteRole(AppRoleDeleteRoleCmd),
}

impl AppRoleCommands {
    /// Dispatch the selected sub-command.
    ///
    /// # Errors
    /// Returns an error if the underlying HTTP call or response parsing fails.
    pub async fn process(&self) -> KmsCliResult<()> {
        match self {
            Self::Login(cmd) => cmd.process().await,
            Self::CreateRole(cmd) => cmd.process().await,
            Self::ListRoles(cmd) => cmd.process().await,
            Self::GetRoleId(cmd) => cmd.process().await,
            Self::GenerateSecretId(cmd) => cmd.process().await,
            Self::DestroySecretId(cmd) => cmd.process().await,
            Self::DeleteRole(cmd) => cmd.process().await,
        }
    }
}

// ── login ─────────────────────────────────────────────────────────────────────

/// Exchange a `role_id` + `secret_id` for a Vault token.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct AppRoleLoginCmd {
    /// URL of the Cosmian Authentication Server.
    #[clap(long, env = "CKMS_VAULT_AUTH_URL")]
    auth_verifier_url: String,

    /// Stable role identifier (UUID).
    #[clap(long)]
    role_id: String,

    /// Secret ID credential (single-use or limited-use).
    #[clap(long)]
    secret_id: String,
}

impl AppRoleLoginCmd {
    async fn process(&self) -> KmsCliResult<()> {
        let client = reqwest::Client::new();
        let url = format!("{}/v1/auth/approle/login", self.auth_verifier_url);
        let resp = client
            .post(&url)
            .json(&AppRoleLoginRequest {
                role_id: &self.role_id,
                secret_id: &self.secret_id,
            })
            .send()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(crate::error::KmsCliError::Default(format!(
                "Login failed (HTTP {status}): {body}"
            )));
        }

        let auth: VaultAuthResponse = resp
            .json()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        Stdout::new(&format!("client_token: {}", auth.auth.client_token)).write()?;
        Stdout::new(&format!("lease_duration: {}s", auth.auth.lease_duration)).write()?;
        Stdout::new(&format!("policies: {}", auth.auth.policies.join(", "))).write()?;
        Ok(())
    }
}

// ── create-role ───────────────────────────────────────────────────────────────

/// Create or update an `AppRole` role in the Authentication Server.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct AppRoleCreateRoleCmd {
    #[clap(flatten)]
    admin: AdminArgs,

    /// Name of the role to create or update.
    role_name: String,

    /// Token TTL in seconds (default: 3600).
    #[clap(long, default_value = "3600")]
    token_ttl: i64,

    /// Secret ID TTL in seconds (0 = no expiry; default: 0).
    #[clap(long, default_value = "0")]
    secret_id_ttl: i64,

    /// Comma-separated list of policies to attach to issued tokens.
    #[clap(long, value_delimiter = ',', default_value = "default")]
    token_policies: Vec<String>,

    /// Whether a `secret_id` is required for login (default: true).
    #[clap(long, default_value = "true")]
    bind_secret_id: bool,
}

impl AppRoleCreateRoleCmd {
    async fn process(&self) -> KmsCliResult<()> {
        let client = admin_client(
            &self.admin.auth_verifier_url,
            &self.admin.admin_user,
            &self.admin.admin_password,
        )
        .await?;

        let url = format!(
            "{}/v1/auth/approle/role/{}",
            self.admin.auth_verifier_url, self.role_name
        );
        let resp = client
            .post(&url)
            .json(&AppRoleRoleRequest {
                secret_id_ttl: self.secret_id_ttl,
                token_ttl: self.token_ttl,
                token_policies: self.token_policies.clone(),
                bind_secret_id: self.bind_secret_id,
            })
            .send()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(crate::error::KmsCliError::Default(format!(
                "Create role failed (HTTP {status}): {body}"
            )));
        }
        Stdout::new(&format!("Role '{}' created/updated.", self.role_name)).write()
    }
}

// ── list-roles ────────────────────────────────────────────────────────────────

/// List all `AppRole` roles.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct AppRoleListRolesCmd {
    #[clap(flatten)]
    admin: AdminArgs,
}

impl AppRoleListRolesCmd {
    async fn process(&self) -> KmsCliResult<()> {
        let client = admin_client(
            &self.admin.auth_verifier_url,
            &self.admin.admin_user,
            &self.admin.admin_password,
        )
        .await?;

        let url = format!(
            "{}/v1/auth/approle/role?list=true",
            self.admin.auth_verifier_url
        );
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(crate::error::KmsCliError::Default(format!(
                "List roles failed (HTTP {status}): {body}"
            )));
        }

        let list: AppRoleListRolesResponse = resp
            .json()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        if list.data.keys.is_empty() {
            Stdout::new("No roles found.").write()?;
        } else {
            for key in &list.data.keys {
                Stdout::new(key).write()?;
            }
        }
        Ok(())
    }
}

// ── get-role-id ───────────────────────────────────────────────────────────────

/// Retrieve the stable `role_id` for a named role.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct AppRoleGetRoleIdCmd {
    #[clap(flatten)]
    admin: AdminArgs,

    /// Name of the role.
    role_name: String,
}

impl AppRoleGetRoleIdCmd {
    async fn process(&self) -> KmsCliResult<()> {
        let client = admin_client(
            &self.admin.auth_verifier_url,
            &self.admin.admin_user,
            &self.admin.admin_password,
        )
        .await?;

        let url = format!(
            "{}/v1/auth/approle/role/{}/role-id",
            self.admin.auth_verifier_url, self.role_name
        );
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(crate::error::KmsCliError::Default(format!(
                "Get role-id failed (HTTP {status}): {body}"
            )));
        }

        let result: AppRoleRoleIdResponse = resp
            .json()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        Stdout::new(&result.data.role_id).write()
    }
}

// ── generate-secret-id ────────────────────────────────────────────────────────

/// Generate a new secret ID for a named role.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct AppRoleGenerateSecretIdCmd {
    #[clap(flatten)]
    admin: AdminArgs,

    /// Name of the role.
    role_name: String,

    /// TTL for this secret ID in seconds (0 = use role default).
    #[clap(long, default_value = "0")]
    ttl: i64,

    /// Maximum number of uses (0 = unlimited).
    #[clap(long, default_value = "0")]
    num_uses: i64,
}

impl AppRoleGenerateSecretIdCmd {
    async fn process(&self) -> KmsCliResult<()> {
        let client = admin_client(
            &self.admin.auth_verifier_url,
            &self.admin.admin_user,
            &self.admin.admin_password,
        )
        .await?;

        let url = format!(
            "{}/v1/auth/approle/role/{}/secret-id",
            self.admin.auth_verifier_url, self.role_name
        );
        let resp = client
            .post(&url)
            .json(&AppRoleSecretIdRequest {
                ttl: self.ttl,
                num_uses: self.num_uses,
            })
            .send()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(crate::error::KmsCliError::Default(format!(
                "Generate secret-id failed (HTTP {status}): {body}"
            )));
        }

        let result: AppRoleSecretIdResponse = resp
            .json()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        Stdout::new(&format!("secret_id: {}", result.data.secret_id)).write()?;
        Stdout::new(&format!(
            "secret_id_accessor: {}",
            result.data.secret_id_accessor
        ))
        .write()
    }
}

// ── destroy-secret-id ─────────────────────────────────────────────────────────

/// Destroy a secret ID by its accessor, invalidating it immediately.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct AppRoleDestroySecretIdCmd {
    #[clap(flatten)]
    admin: AdminArgs,

    /// Name of the role.
    role_name: String,

    /// Accessor string returned when the secret ID was generated.
    #[clap(long)]
    accessor: String,
}

impl AppRoleDestroySecretIdCmd {
    async fn process(&self) -> KmsCliResult<()> {
        let client = admin_client(
            &self.admin.auth_verifier_url,
            &self.admin.admin_user,
            &self.admin.admin_password,
        )
        .await?;

        let url = format!(
            "{}/v1/auth/approle/role/{}/secret-id/destroy",
            self.admin.auth_verifier_url, self.role_name
        );
        let resp = client
            .post(&url)
            .json(&AppRoleDestroySecretIdRequest {
                secret_id_accessor: &self.accessor,
            })
            .send()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(crate::error::KmsCliError::Default(format!(
                "Destroy secret-id failed (HTTP {status}): {body}"
            )));
        }
        Stdout::new("Secret ID destroyed.").write()
    }
}

// ── delete-role ───────────────────────────────────────────────────────────────

/// Permanently delete an `AppRole` role.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct AppRoleDeleteRoleCmd {
    #[clap(flatten)]
    admin: AdminArgs,

    /// Name of the role to delete.
    role_name: String,
}

impl AppRoleDeleteRoleCmd {
    async fn process(&self) -> KmsCliResult<()> {
        let client = admin_client(
            &self.admin.auth_verifier_url,
            &self.admin.admin_user,
            &self.admin.admin_password,
        )
        .await?;

        let url = format!(
            "{}/v1/auth/approle/role/{}",
            self.admin.auth_verifier_url, self.role_name
        );
        let resp = client
            .delete(&url)
            .send()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(crate::error::KmsCliError::Default(format!(
                "Delete role failed (HTTP {status}): {body}"
            )));
        }
        Stdout::new(&format!("Role '{}' deleted.", self.role_name)).write()
    }
}
