//! Clap credential structs for secret URI backends.
//!
//! This file contains **only** clap structs — no logic, no HTTP calls.
//! The actual resolution is performed elsewhere once the config is loaded.

use clap::{Args, ValueEnum};

/// Selects which backend resolves `secret://` URIs in the KMS config file.
///
/// Pass via `--secret-backend <KIND>` or the `KMS_SECRET_BACKEND` env var.
/// The TOML config uses the neutral `secret://` scheme; which backend is
/// actually used is **never** revealed in the config file itself.
#[derive(Clone, Default, ValueEnum, Debug)]
pub enum SecretBackendKind {
    /// `HashiCorp` Vault KV-v2.
    /// Path format: `secret://<mount>/<path>[#<field>]`
    #[default]
    #[value(name = "vault")]
    Vault,
    /// AWS Systems Manager Parameter Store.
    /// Path format: `secret://<region>/<parameter-name>`
    #[value(name = "aws-ssm")]
    AwsSsm,
    /// Azure Key Vault.
    /// Path format: `secret://<vault-name>/secrets/<name>[/<version>]`
    #[value(name = "azure-kv")]
    AzureKv,
    /// Another Cosmian KMS server (KMIP Get).
    /// Path format: `secret://<host>[:<port>]/<object-id>`
    #[value(name = "cosmian-kms")]
    CosmianKms,
}

/// Credentials for the `HashiCorp` Vault KV-v2 backend.
///
/// Injected exclusively via clap (CLI flags or environment variables).
/// Never read from the TOML config file.
#[derive(Args, Clone, Default)]
pub struct VaultBackendConfig {
    /// Vault server URL (e.g. `https://vault.internal:8200`).
    ///
    /// Required when `secret://` URIs are resolved via the `vault` backend.
    #[clap(long, env = "VAULT_ADDR", default_value = "http://127.0.0.1:8200")]
    pub vault_addr: String,

    /// Vault token with `read` access on the target paths.
    ///
    /// Required when `secret://` URIs are resolved via the `vault` backend.
    #[clap(long, env = "VAULT_TOKEN", default_value = "")]
    pub vault_token: String,
}

/// Credentials for the AWS Systems Manager Parameter Store backend.
///
/// Injected exclusively via clap (CLI flags or environment variables).
/// Never read from the TOML config file.
#[derive(Args, Clone, Default)]
pub struct AwsSsmBackendConfig {
    /// AWS access key ID.
    ///
    /// Required when `secret://` URIs are resolved via the `aws-ssm` backend.
    #[clap(long, env = "AWS_ACCESS_KEY_ID", default_value = "")]
    pub aws_access_key_id: String,

    /// AWS secret access key.
    ///
    /// Required when `secret://` URIs are resolved via the `aws-ssm` backend.
    #[clap(long, env = "AWS_SECRET_ACCESS_KEY", default_value = "")]
    pub aws_secret_access_key: String,

    /// AWS session token (for temporary credentials / STS).
    #[clap(long, env = "AWS_SESSION_TOKEN")]
    pub aws_session_token: Option<String>,
}

/// Credentials for the Azure Key Vault backend.
///
/// Injected exclusively via clap (CLI flags or environment variables).
/// Never read from the TOML config file.
#[derive(Args, Clone, Default)]
pub struct AzureKvBackendConfig {
    /// Azure AD tenant ID.
    ///
    /// Required when `secret://` URIs are resolved via the `azure-kv` backend.
    #[clap(long, env = "AZURE_TENANT_ID", default_value = "")]
    pub azure_tenant_id: String,

    /// Azure service-principal application (client) ID.
    ///
    /// Required when `secret://` URIs are resolved via the `azure-kv` backend.
    #[clap(long, env = "AZURE_CLIENT_ID", default_value = "")]
    pub azure_client_id: String,

    /// Azure service-principal client secret.
    ///
    /// Required when `secret://` URIs are resolved via the `azure-kv` backend.
    #[clap(long, env = "AZURE_CLIENT_SECRET", default_value = "")]
    pub azure_client_secret: String,
}

/// Credentials for the Cosmian KMS secret backend.
///
/// Injected exclusively via clap (CLI flags or environment variables).
/// Never read from the TOML config file.
#[derive(Args, Clone, Default)]
pub struct CosmianKmsSecretConfig {
    /// Bearer token / API key for authenticating to the Cosmian KMS secret backend.
    #[clap(long, env = "COSMIAN_KMS_SECRET_TOKEN")]
    pub cosmian_kms_secret_token: Option<String>,

    /// Skip TLS certificate verification for the Cosmian KMS secret backend.
    ///
    /// **For development and testing only.** Never enable in production.
    #[clap(long, env = "COSMIAN_KMS_INSECURE_CERTS")]
    pub cosmian_kms_insecure_certs: bool,
}

/// Authentication credentials and backend selection for secret URI resolution.
///
/// These values are provided exclusively via clap (CLI flags or environment
/// variables) and are **never** read from the TOML config file, preventing
/// accidental secret exposure through configuration files.
#[derive(Args, Clone, Default)]
pub struct SecretBackendConfig {
    /// Secret backend to use for resolving `secret://` URIs in the config file.
    ///
    /// When set, all `secret://` values in the config file are resolved through
    /// the selected backend. Credentials must be provided via the corresponding
    /// flags or environment variables below.
    #[clap(long, env = "KMS_SECRET_BACKEND", value_enum)]
    pub backend: Option<SecretBackendKind>,

    #[command(flatten)]
    pub vault: VaultBackendConfig,

    #[command(flatten)]
    pub aws: AwsSsmBackendConfig,

    #[command(flatten)]
    pub azure: AzureKvBackendConfig,

    #[command(flatten)]
    pub cosmian_kms: CosmianKmsSecretConfig,
}
