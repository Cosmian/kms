//! Secret URI backends — Clap credential structs, resolution logic, and
//! per-backend implementations.
//!
//! The TOML walker replaces every `secret://` value using the selected backend.
//! Credentials are passed via `SecretBackendConfig` (populated by clap/env).
//! Zero `std::env::var` calls in production code.

mod aws;
mod azure;
mod common;
mod cosmian_kms;
mod vault;

use clap::{Args, ValueEnum};

use crate::{error::KmsError, result::KResult};

// ─── Clap structs ───────────────────────────────────────────────────────────

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
#[derive(Args, Clone, Default)]
pub struct VaultBackendConfig {
    #[clap(long, env = "VAULT_ADDR", default_value = "http://127.0.0.1:8200")]
    pub vault_addr: String,
    #[clap(long, env = "VAULT_TOKEN", default_value = "")]
    pub vault_token: String,
}

/// Credentials for the AWS Systems Manager Parameter Store backend.
#[derive(Args, Clone, Default)]
pub struct AwsSsmBackendConfig {
    #[clap(long, env = "AWS_ACCESS_KEY_ID", default_value = "")]
    pub aws_access_key_id: String,
    #[clap(long, env = "AWS_SECRET_ACCESS_KEY", default_value = "")]
    pub aws_secret_access_key: String,
    #[clap(long, env = "AWS_SESSION_TOKEN")]
    pub aws_session_token: Option<String>,
}

/// Credentials for the Azure Key Vault backend.
#[derive(Args, Clone, Default)]
pub struct AzureKvBackendConfig {
    #[clap(long, env = "AZURE_TENANT_ID", default_value = "")]
    pub azure_tenant_id: String,
    #[clap(long, env = "AZURE_CLIENT_ID", default_value = "")]
    pub azure_client_id: String,
    #[clap(long, env = "AZURE_CLIENT_SECRET", default_value = "")]
    pub azure_client_secret: String,
}

/// Credentials for the Cosmian KMS secret backend.
#[derive(Args, Clone, Default)]
pub struct CosmianKmsSecretConfig {
    #[clap(long, env = "COSMIAN_KMS_SECRET_TOKEN")]
    pub cosmian_kms_secret_token: Option<String>,
    #[clap(long, env = "COSMIAN_KMS_INSECURE_CERTS")]
    pub cosmian_kms_insecure_certs: bool,
}

/// Authentication credentials and backend selection for secret URI resolution.
#[derive(Args, Clone, Default)]
pub struct SecretBackendConfig {
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

// ─── Trait ──────────────────────────────────────────────────────────────────

/// Each secret backend implements this single method.
pub(crate) trait SecretBackend {
    fn resolve(&self, uri: &str) -> KResult<String>;
}

// ─── TOML walker ────────────────────────────────────────────────────────────

/// Replace every TOML string starting with `secret://` using the active backend.
fn resolve_secret_uris(value: &mut toml::Value, backend: &dyn SecretBackend) -> KResult<()> {
    match value {
        toml::Value::String(s) => {
            if s.starts_with("secret://") {
                *s = backend.resolve(s)?;
            }
        }
        toml::Value::Table(map) => {
            for (_, v) in map.iter_mut() {
                resolve_secret_uris(v, backend)?;
            }
        }
        toml::Value::Array(arr) => {
            for v in arr {
                resolve_secret_uris(v, backend)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Entry point called from `load_from_args`.
/// Does nothing when `config.backend` is `None`.
pub(crate) fn resolve_config(value: &mut toml::Value, config: &SecretBackendConfig) -> KResult<()> {
    match &config.backend {
        None => Ok(()),
        Some(SecretBackendKind::Vault) => {
            resolve_secret_uris(value, &vault::VaultBackend::new(&config.vault))
        }
        Some(SecretBackendKind::AwsSsm) => {
            resolve_secret_uris(value, &aws::AwsSsmBackend::new(&config.aws))
        }
        Some(SecretBackendKind::AzureKv) => {
            resolve_secret_uris(value, &azure::AzureKvBackend::new(&config.azure))
        }
        Some(SecretBackendKind::CosmianKms) => resolve_secret_uris(
            value,
            &cosmian_kms::CosmianKmsBackend::new(&config.cosmian_kms),
        ),
    }
}

// ─── Integration tests ──────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// Helper: wrap a URI in a minimal TOML table and resolve it.
    fn resolve_single_uri(uri: &str, config: &SecretBackendConfig) -> KResult<String> {
        let mut value = toml::Value::Table(toml::map::Map::from_iter([(
            "test_field".to_owned(),
            toml::Value::String(uri.to_owned()),
        )]));
        resolve_config(&mut value, config)?;
        value
            .get("test_field")
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| KmsError::ServerError("test_field missing after resolve".to_owned()))
    }

    #[test]
    #[ignore = "Requires a running HashiCorp Vault and VAULT_ADDR/VAULT_TOKEN env vars"]
    fn test_secret_vault() {
        let uri = std::env::var("KMS_TEST_VAULT_URI")
            .expect("KMS_TEST_VAULT_URI must be set (e.g. vault://secret/kms-ci/db#password)");
        let expected =
            std::env::var("KMS_TEST_VAULT_EXPECTED").expect("KMS_TEST_VAULT_EXPECTED must be set");
        let vault_addr =
            std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_owned());
        let vault_token = std::env::var("VAULT_TOKEN").expect("VAULT_TOKEN must be set");

        // The bash script passes URIs as "vault://mount/path#field" but resolve_config
        // expects the neutral "secret://" scheme.
        let secret_uri = uri.replacen("vault://", "secret://", 1);

        let config = SecretBackendConfig {
            backend: Some(SecretBackendKind::Vault),
            vault: VaultBackendConfig {
                vault_addr,
                vault_token,
            },
            ..Default::default()
        };

        let resolved = resolve_single_uri(&secret_uri, &config)
            .expect("resolve_config should succeed for vault");
        assert_eq!(resolved, expected, "Vault secret mismatch");
    }

    #[test]
    #[ignore = "Requires AWS credentials and a SSM parameter created by CI"]
    fn test_secret_aws_ssm() {
        let uri = std::env::var("KMS_TEST_AWS_SSM_URI")
            .expect("KMS_TEST_AWS_SSM_URI must be set (e.g. aws-ssm://eu-west-1/kms/ci/test)");
        let expected = std::env::var("KMS_TEST_AWS_SSM_EXPECTED")
            .expect("KMS_TEST_AWS_SSM_EXPECTED must be set");
        let access_key_id =
            std::env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID must be set");
        let secret_access_key =
            std::env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY must be set");
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();

        // The bash script passes URIs as "aws-ssm://region/param" but resolve_config
        // expects the neutral "secret://" scheme.
        let secret_uri = uri.replacen("aws-ssm://", "secret://", 1);

        let config = SecretBackendConfig {
            backend: Some(SecretBackendKind::AwsSsm),
            aws: AwsSsmBackendConfig {
                aws_access_key_id: access_key_id,
                aws_secret_access_key: secret_access_key,
                aws_session_token: session_token,
            },
            ..Default::default()
        };

        let resolved = resolve_single_uri(&secret_uri, &config)
            .expect("resolve_config should succeed for aws-ssm");
        assert_eq!(resolved, expected, "AWS SSM secret mismatch");
    }

    #[test]
    #[ignore = "Requires Azure AD credentials and a Key Vault secret created by CI"]
    fn test_secret_azure_kv() {
        let uri = std::env::var("KMS_TEST_AZURE_KV_URI")
            .expect("KMS_TEST_AZURE_KV_URI must be set (e.g. azure-kv://myvault/secrets/myname)");
        let expected = std::env::var("KMS_TEST_AZURE_KV_EXPECTED")
            .expect("KMS_TEST_AZURE_KV_EXPECTED must be set");
        let tenant_id = std::env::var("AZURE_TENANT_ID").expect("AZURE_TENANT_ID must be set");
        let client_id = std::env::var("AZURE_CLIENT_ID").expect("AZURE_CLIENT_ID must be set");
        let client_secret =
            std::env::var("AZURE_CLIENT_SECRET").expect("AZURE_CLIENT_SECRET must be set");

        // The bash script passes URIs as "azure-kv://vault/secrets/name" but
        // resolve_config expects the neutral "secret://" scheme.
        let secret_uri = uri.replacen("azure-kv://", "secret://", 1);

        let config = SecretBackendConfig {
            backend: Some(SecretBackendKind::AzureKv),
            azure: AzureKvBackendConfig {
                azure_tenant_id: tenant_id,
                azure_client_id: client_id,
                azure_client_secret: client_secret,
            },
            ..Default::default()
        };

        let resolved = resolve_single_uri(&secret_uri, &config)
            .expect("resolve_config should succeed for azure-kv");
        assert_eq!(resolved, expected, "Azure KV secret mismatch");
    }

    #[test]
    #[ignore = "Requires a running Cosmian KMS server with a registered SecretData object"]
    fn test_secret_cosmian_kms() {
        let uri = std::env::var("KMS_TEST_COSMIAN_KMS_URI").expect(
            "KMS_TEST_COSMIAN_KMS_URI must be set (e.g. cosmian-kms://localhost:9998/<id>)",
        );
        let expected = std::env::var("KMS_TEST_COSMIAN_KMS_EXPECTED")
            .expect("KMS_TEST_COSMIAN_KMS_EXPECTED must be set");
        let token = std::env::var("COSMIAN_KMS_SECRET_TOKEN").ok();
        let insecure = std::env::var("COSMIAN_KMS_INSECURE_CERTS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        // The bash script passes URIs as "cosmian-kms://host:port/id" but
        // resolve_config expects the neutral "secret://" scheme.
        let secret_uri = uri.replacen("cosmian-kms://", "secret://", 1);

        let config = SecretBackendConfig {
            backend: Some(SecretBackendKind::CosmianKms),
            cosmian_kms: CosmianKmsSecretConfig {
                cosmian_kms_secret_token: token,
                cosmian_kms_insecure_certs: insecure,
            },
            ..Default::default()
        };

        let resolved = resolve_single_uri(&secret_uri, &config)
            .expect("resolve_config should succeed for cosmian-kms");
        assert_eq!(resolved, expected, "Cosmian KMS secret mismatch");
    }
}
