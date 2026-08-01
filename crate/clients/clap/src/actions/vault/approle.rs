//! `ckms vault approle` sub-commands.
//!
//! Manage Vault-compatible `AppRole` identities in the Cosmian Authentication
//! Server (`auth-verifier`).
//!
//! All sub-commands are **admin (management-plane)** operations: they require an
//! admin session cookie obtained from the auth-verifier's `/login?realm=_`, so
//! `--auth-verifier-url` must point **directly at the auth-verifier** (a separate
//! endpoint), not at the KMS. SPIRE performs the data-plane `AppRole` *login*
//! itself against the KMS `vault_addr`; there is no `login` sub-command here.
//!
//! ## Admin commands (require `--admin-user` + `--admin-password`)
//! - `create-role` — create or update a role.
//! - `list-roles` — list all roles.
//! - `get-role-id` — retrieve the stable `role_id` for a role.
//! - `generate-secret-id` — generate a new secret ID.
//! - `destroy-secret-id` — invalidate a secret ID by accessor.
//! - `delete-role` — permanently delete a role.

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use crate::{actions::console::Stdout, error::result::KmsCliResult};

// ── Wire types (mirrors auth_client dto/vault.rs) ────────────────────────────

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
async fn admin_client(admin: &AdminArgs) -> KmsCliResult<reqwest::Client> {
    let mut builder = reqwest::Client::builder().cookie_store(true);
    if admin.accept_invalid_certs {
        builder = builder.danger_accept_invalid_certs(true);
    } else if let Some(ca_path) = &admin.auth_verifier_ca_cert {
        let pem = std::fs::read(ca_path).map_err(|e| {
            crate::error::KmsCliError::Default(format!(
                "cannot read auth-verifier CA cert '{ca_path}': {e}"
            ))
        })?;
        let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
            crate::error::KmsCliError::Default(format!(
                "invalid auth-verifier CA cert '{ca_path}': {e}"
            ))
        })?;
        builder = builder.add_root_certificate(cert);
    }
    let client = builder
        .build()
        .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

    let login_url = format!("{}/login?realm=_", admin.auth_verifier_url);
    let resp = client
        .post(&login_url)
        .basic_auth(&admin.admin_user, Some(&admin.admin_password))
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

/// Build an auth-verifier `AppRole` **admin** endpoint URL.
///
/// The admin API is served **directly** by the auth-verifier under
/// `/auth/approle` — never under the KMS `/v1/auth/*` proxy, which only exposes
/// the data-plane login/token routes and cannot carry the admin session cookie.
/// `suffix` is appended verbatim, e.g. `"/role/my-role"` or `"/role?list=true"`.
fn approle_admin_url(auth_verifier_url: &str, suffix: &str) -> String {
    format!(
        "{}/auth/approle{suffix}",
        auth_verifier_url.trim_end_matches('/')
    )
}

/// Check a `reqwest::Response` for success, returning it as-is on success
/// or a [`KmsCliError`] with the operation name and response body on failure.
async fn check_approle_response(
    resp: reqwest::Response,
    operation: &str,
) -> KmsCliResult<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    Err(crate::error::KmsCliError::Default(format!(
        "{operation} failed (HTTP {status}): {body}"
    )))
}

// ── Shared admin flags ────────────────────────────────────────────────────────

/// Shared flags for admin `AppRole` operations.
#[derive(Parser, Debug)]
pub(crate) struct AdminArgs {
    /// URL of the Cosmian Authentication Server (auth-verifier), reached
    /// **directly** — NOT via the KMS proxy.
    ///
    /// Admin `AppRole` management needs an admin session cookie from the
    /// auth-verifier's `/login?realm=_`, which the KMS does not proxy, so this
    /// is the auth-verifier's own address (a separate endpoint; keep it on a
    /// limited-exposure network where possible). Example:
    /// `https://auth.example.com:8443`
    #[clap(
        long,
        env = "CKMS_VAULT_AUTH_URL",
        help = "Base URL of the Cosmian Authentication Server (auth-verifier, reached directly)"
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

    /// Path to a PEM CA certificate used to verify the auth-verifier's TLS
    /// certificate (e.g. a private/self-signed CA). Ignored when
    /// `--accept-invalid-certs` is set.
    #[clap(long, env = "CKMS_VAULT_AUTH_CA_CERT")]
    auth_verifier_ca_cert: Option<String>,

    /// Skip TLS certificate verification for the auth-verifier connection.
    /// Development/test only — never use against an untrusted network.
    #[clap(long, default_value = "false")]
    accept_invalid_certs: bool,
}

// ── Sub-commands ──────────────────────────────────────────────────────────────

/// Manage Vault-compatible `AppRole` identities in the Authentication Server.
#[derive(Subcommand, Debug)]
pub enum AppRoleCommands {
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
            Self::CreateRole(cmd) => cmd.process().await,
            Self::ListRoles(cmd) => cmd.process().await,
            Self::GetRoleId(cmd) => cmd.process().await,
            Self::GenerateSecretId(cmd) => cmd.process().await,
            Self::DestroySecretId(cmd) => cmd.process().await,
            Self::DeleteRole(cmd) => cmd.process().await,
        }
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
        let client = admin_client(&self.admin).await?;

        let url = approle_admin_url(
            &self.admin.auth_verifier_url,
            &format!("/role/{}", self.role_name),
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

        check_approle_response(resp, "Create role").await?;
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
        let client = admin_client(&self.admin).await?;

        let url = approle_admin_url(&self.admin.auth_verifier_url, "/role?list=true");
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        let resp = check_approle_response(resp, "List roles").await?;

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
        let client = admin_client(&self.admin).await?;

        let url = approle_admin_url(
            &self.admin.auth_verifier_url,
            &format!("/role/{}/role-id", self.role_name),
        );
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        let resp = check_approle_response(resp, "Get role-id").await?;

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
        let client = admin_client(&self.admin).await?;

        let url = approle_admin_url(
            &self.admin.auth_verifier_url,
            &format!("/role/{}/secret-id", self.role_name),
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

        let resp = check_approle_response(resp, "Generate secret-id").await?;

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
        let client = admin_client(&self.admin).await?;

        let url = approle_admin_url(
            &self.admin.auth_verifier_url,
            &format!("/role/{}/secret-id/destroy", self.role_name),
        );
        let resp = client
            .post(&url)
            .json(&AppRoleDestroySecretIdRequest {
                secret_id_accessor: &self.accessor,
            })
            .send()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        check_approle_response(resp, "Destroy secret-id").await?;
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
        let client = admin_client(&self.admin).await?;

        let url = approle_admin_url(
            &self.admin.auth_verifier_url,
            &format!("/role/{}", self.role_name),
        );
        let resp = client
            .delete(&url)
            .send()
            .await
            .map_err(|e| crate::error::KmsCliError::Default(e.to_string()))?;

        check_approle_response(resp, "Delete role").await?;
        Stdout::new(&format!("Role '{}' deleted.", self.role_name)).write()
    }
}

#[cfg(test)]
mod tests {
    use super::approle_admin_url;

    #[test]
    fn admin_url_targets_auth_verifier_without_v1_prefix() {
        // Admin AppRole CRUD must hit the auth-verifier's `/auth/approle/*`
        // routes directly — never the KMS `/v1/auth/*` proxy (which cannot carry
        // the admin session cookie). This guards against reintroducing the `/v1`
        // prefix that made the admin commands 404.
        let base = "https://auth.example.com:8443";
        let url = approle_admin_url(base, "/role/spire-server");
        assert_eq!(
            url,
            "https://auth.example.com:8443/auth/approle/role/spire-server"
        );
        assert!(
            !url.contains("/v1/"),
            "admin URL must not contain the KMS /v1 proxy prefix"
        );
    }

    #[test]
    fn admin_url_trims_trailing_slash() {
        let url = approle_admin_url("https://auth.example.com:8443/", "/role?list=true");
        assert_eq!(
            url,
            "https://auth.example.com:8443/auth/approle/role?list=true"
        );
    }
}
