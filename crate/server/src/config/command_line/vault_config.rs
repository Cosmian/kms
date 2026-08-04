// Field names intentionally share a `vault_` prefix for disambiguation in
// flat CLI / env-var namespaces.
#![allow(clippy::struct_field_names)]

use clap::Args;
use clap_config_fallback::ConfigArgs;
use serde::{Deserialize, Serialize};

/// Configuration for the Vault-compatible REST API.
///
/// When `vault_api_enabled = true`, the KMS exposes `/v1/transit/` and
/// `/v1/<vault_pki_mount>/` scopes that are compatible with the Vault
/// API. This is used by SPIRE and other Vault-aware tools.
#[derive(Args, ConfigArgs, Clone, Debug, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct VaultConfig {
    /// Enable the Vault-compatible `/v1/transit/` and `/v1/<vault_pki_mount>/` scopes.
    ///
    /// Defaults to `false`. Set to `true` to enable the Vault-compatible API.
    /// Requires `vault_auth_verifier_url` to be set.
    #[clap(long, env = "KMS_VAULT_API_ENABLED", default_value = "false")]
    pub vault_api_enabled: bool,

    /// Base URL of the auth-verifier server used to validate `X-Vault-Token` headers.
    ///
    /// Required when `vault_api_enabled = true`.
    /// Example: `https://auth.example.com`
    #[clap(long, env = "KMS_VAULT_AUTH_VERIFIER_URL")]
    pub vault_auth_verifier_url: Option<String>,

    /// Path to a PEM-encoded CA certificate used to verify the auth-verifier's TLS certificate.
    ///
    /// Optional. When set, the KMS will trust this CA when connecting to `vault_auth_verifier_url`.
    /// Useful when auth-verifier uses a self-signed or private CA certificate.
    #[clap(long, env = "KMS_VAULT_AUTH_VERIFIER_CA_CERT")]
    pub vault_auth_verifier_ca_cert: Option<String>,

    /// Skip TLS certificate verification when calling the auth-verifier.
    ///
    /// **Security warning**: only set this to `true` in test or development environments.
    /// In production, use `vault_auth_verifier_ca_cert` to provide the correct CA certificate.
    /// Defaults to `false`.
    #[clap(
        long,
        env = "KMS_VAULT_AUTH_VERIFIER_ACCEPT_INVALID_CERTS",
        default_value = "false"
    )]
    pub vault_auth_verifier_accept_invalid_certs: bool,

    /// Vault transit mount name used by the `/v1/<mount>/keys/…` routes.
    ///
    /// Transit keys are served at `/v1/<vault_transit_mount>/keys/<name>`.
    /// Defaults to `"transit"`.
    #[clap(
        long,
        env = "KMS_VAULT_TRANSIT_MOUNT",
        default_value = "transit",
        verbatim_doc_comment
    )]
    pub vault_transit_mount: String,

    /// Vault PKI mount name used by the `/v1/<mount>/root/sign-intermediate` route.
    ///
    /// Defaults to `"pki"`.
    #[clap(
        long,
        env = "KMS_VAULT_PKI_MOUNT",
        default_value = "pki",
        verbatim_doc_comment
    )]
    pub vault_pki_mount: String,

    /// KMIP label of the KMS key used as the intermediate CA signing key for the PKI engine.
    ///
    /// The key must already exist in the KMS (create with `ckms ec keys create --tag <label>`).
    /// Defaults to `"vault_pki_ca"`.
    #[clap(
        long,
        env = "KMS_VAULT_PKI_CA_KEY_LABEL",
        default_value = "vault_pki_ca",
        verbatim_doc_comment
    )]
    pub vault_pki_ca_key_label: String,

    /// Lifetime of vault token validation cache entries in seconds.
    ///
    /// Successful `lookup-self` responses from the auth-verifier are cached
    /// for this duration to reduce round-trips on every transit/PKI request.
    /// Set to `0` to disable caching. Defaults to `30`.
    #[clap(
        long,
        env = "KMS_VAULT_TOKEN_CACHE_TTL_SECS",
        default_value = "30",
        verbatim_doc_comment
    )]
    pub vault_token_cache_ttl_secs: u64,
}
