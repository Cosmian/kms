//! Phase-2 secret URI resolution backends.
//!
//! Any TOML string value that starts with a recognised scheme is replaced by the
//! secret it points to, fetched synchronously at startup.
//!
//! Supported schemes and their controlling feature flags:
//!
//! | Scheme        | Feature flag   | Required env vars                             |
//! |---------------|----------------|-----------------------------------------------|
//! | `vault://`    | `secret-vault` | `VAULT_ADDR`, `VAULT_TOKEN`                   |
//! | `aws-ssm://`  | `secret-aws`   | standard AWS credential chain                 |
//! | `azure-kv://` | `secret-azure` | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,         |
//! |               |                | `AZURE_CLIENT_SECRET`                         |
//!
//! **Usage in kms.toml / secrets.toml**
//!
//! ```toml
//! [db]
//! database_url         = "aws-ssm://eu-west-1/kms/prod/db-url"
//! redis_master_password = "vault://secret/kms/redis#password"
//!
//! [tls]
//! tls_p12_password = "azure-kv://my-vault/secrets/kms-tls"
//!
//! hsm_password = ["vault://secret/kms/hsm-slot1", "vault://secret/kms/hsm-slot2"]
//! ```
//!
//! Schemes can be mixed freely; each value is resolved independently.

#[cfg(any(
    feature = "secret-vault",
    feature = "secret-aws",
    feature = "secret-azure"
))]
use crate::error::KmsError;
use crate::result::KResult;

// ─────────────────────────────────────────────────────────────────────────────
// Trait
// ─────────────────────────────────────────────────────────────────────────────

/// A synchronous secret backend that knows how to resolve one URI scheme.
pub(super) trait SecretBackend {
    /// The URI scheme handled by this backend (without `://`).
    fn scheme(&self) -> &'static str;

    /// Fetch the secret identified by `uri` (e.g. `vault://secret/kms/foo`).
    fn resolve(&self, uri: &str) -> KResult<String>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Walk a toml::Value tree and resolve all string leaves
// ─────────────────────────────────────────────────────────────────────────────

/// Recursively walk `value` and replace every string that starts with a known
/// scheme by the resolved secret.
pub(super) fn resolve_secret_uris(
    value: &mut toml::Value,
    backends: &[Box<dyn SecretBackend>],
) -> KResult<()> {
    match value {
        toml::Value::String(s) => {
            for backend in backends {
                let prefix = format!("{}://", backend.scheme());
                if s.starts_with(&prefix) {
                    *s = backend.resolve(s)?;
                    break;
                }
            }
        }
        toml::Value::Table(map) => {
            for (_, v) in map.iter_mut() {
                resolve_secret_uris(v, backends)?;
            }
        }
        toml::Value::Array(arr) => {
            for v in arr {
                resolve_secret_uris(v, backends)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory — returns the list of enabled backends
// ─────────────────────────────────────────────────────────────────────────────

/// Build the list of all backends that are compiled in.
/// Returns an empty `Vec` when no feature flags are enabled, which means
/// `resolve_secret_uris` is a no-op and adds zero overhead at runtime.
pub(super) fn build_secret_backends() -> Vec<Box<dyn SecretBackend>> {
    #[allow(unused_mut)]
    let mut backends: Vec<Box<dyn SecretBackend>> = Vec::new();

    #[cfg(feature = "secret-vault")]
    backends.push(Box::new(vault::VaultBackend::new()));

    #[cfg(feature = "secret-aws")]
    backends.push(Box::new(aws::AwsSsmBackend::new()));

    #[cfg(feature = "secret-azure")]
    backends.push(Box::new(azure::AzureKvBackend::new()));

    backends
}

// ─────────────────────────────────────────────────────────────────────────────
// HashiCorp Vault — `vault://`
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "secret-vault")]
mod vault {
    use super::{KResult, KmsError, SecretBackend};

    /// HashiCorp Vault KV-v2 backend.
    ///
    /// URI format:  `vault://<mount>/<path>#<field>`
    ///   - `mount`  — KV-v2 mount point (e.g. `secret`)
    ///   - `path`   — secret path inside that mount (e.g. `kms/db`)
    ///   - `field`  — field name inside the secret data (default: `value`)
    ///
    /// Required env vars:
    ///   - `VAULT_ADDR`  — Vault server URL (e.g. `https://vault.internal:8200`)
    ///   - `VAULT_TOKEN` — Vault token with `read` permission on the path
    ///
    /// Example:
    ///   `vault://secret/kms/db#password`  →  reads field `password` from
    ///   `<VAULT_ADDR>/v1/secret/data/kms/db`.
    pub(super) struct VaultBackend {
        addr: String,
        token: String,
    }

    impl VaultBackend {
        pub(super) fn new() -> Self {
            Self {
                addr: std::env::var("VAULT_ADDR")
                    .unwrap_or_else(|_| "http://127.0.0.1:8200".to_owned()),
                token: std::env::var("VAULT_TOKEN").unwrap_or_default(),
            }
        }
    }

    impl SecretBackend for VaultBackend {
        fn scheme(&self) -> &'static str {
            "vault"
        }

        fn resolve(&self, uri: &str) -> KResult<String> {
            // Parse  vault://<mount>/<path...>#<field>
            let rest = uri
                .strip_prefix("vault://")
                .ok_or_else(|| KmsError::InvalidRequest(format!("Invalid vault URI: {uri}")))?;

            let (path_part, field) = rest
                .split_once('#')
                .map_or((rest, "value"), |(p, f)| (p, f));

            // Build the KV-v2 API URL: /v1/<mount>/data/<path>
            // The first segment is the mount; the rest is the secret path.
            let slash = path_part.find('/').ok_or_else(|| {
                KmsError::InvalidRequest(format!(
                    "vault URI must have the form vault://<mount>/<path>[#<field>], got: {uri}"
                ))
            })?;
            let mount = &path_part[..slash];
            let secret_path = &path_part[slash + 1..];
            let url = format!(
                "{}/v1/{mount}/data/{secret_path}",
                self.addr.trim_end_matches('/')
            );

            let token = self.token.clone();
            let uri_owned = uri.to_owned();
            let value: serde_json::Value = std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        KmsError::ServerError(format!(
                            "Failed to build tokio runtime for Vault: {e}"
                        ))
                    })?
                    .block_on(async move {
                        let client = reqwest::Client::new();
                        let resp = client
                            .get(&url)
                            .header("X-Vault-Token", &token)
                            .send()
                            .await
                            .map_err(|e| {
                                KmsError::ServerError(format!(
                                    "Vault request failed for {uri_owned}: {e}"
                                ))
                            })?;

                        if !resp.status().is_success() {
                            return Err(KmsError::ServerError(format!(
                                "Vault returned HTTP {} for {uri_owned}",
                                resp.status()
                            )));
                        }
                        resp.json::<serde_json::Value>().await.map_err(|e| {
                            KmsError::ServerError(format!(
                                "Failed to parse Vault response for {uri_owned}: {e}"
                            ))
                        })
                    })
            })
            .join()
            .map_err(|_| {
                KmsError::ServerError("Vault secret resolution thread panicked".to_owned())
            })??;

            value["data"]["data"][field]
                .as_str()
                .ok_or_else(|| {
                    KmsError::ServerError(format!(
                        "Field '{field}' not found in Vault secret at {uri}"
                    ))
                })
                .map(str::to_owned)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AWS Systems Manager Parameter Store — `aws-ssm://`
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "secret-aws")]
mod aws {
    use super::{KResult, KmsError, SecretBackend};

    /// AWS SSM Parameter Store backend.
    ///
    /// URI format: `aws-ssm://<region>/<parameter-name>`
    ///   - `region`         — AWS region (e.g. `eu-west-1`)
    ///   - `parameter-name` — SSM parameter name, leading `/` included
    ///                        (e.g. `/kms/prod/db-password`)
    ///
    /// Credentials are resolved via the standard AWS credential chain
    /// (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars, `~/.aws/credentials`,
    /// IAM instance profile, etc.).
    ///
    /// Example:
    ///   `aws-ssm://eu-west-1/kms/prod/db-password`
    pub(super) struct AwsSsmBackend;

    impl AwsSsmBackend {
        pub(super) fn new() -> Self {
            Self
        }
    }

    impl SecretBackend for AwsSsmBackend {
        fn scheme(&self) -> &'static str {
            "aws-ssm"
        }

        fn resolve(&self, uri: &str) -> KResult<String> {
            // Parse  aws-ssm://<region>/<param-name>
            let rest = uri
                .strip_prefix("aws-ssm://")
                .ok_or_else(|| KmsError::InvalidRequest(format!("Invalid aws-ssm URI: {uri}")))?;

            let slash = rest.find('/').ok_or_else(|| {
                KmsError::InvalidRequest(format!(
                    "aws-ssm URI must have the form aws-ssm://<region>/<param>, got: {uri}"
                ))
            })?;
            let region = &rest[..slash];
            // Parameter name starts with the '/', e.g. /kms/prod/db
            let param_name = &rest[slash..];

            let region_owned = region.to_owned();
            let param_name_owned = param_name.to_owned();
            let uri_owned = uri.to_owned();
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        KmsError::ServerError(format!(
                            "Failed to build tokio runtime for AWS SSM: {e}"
                        ))
                    })?
                    .block_on(async move {
                        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                            .region(aws_config::Region::new(region_owned))
                            .load()
                            .await;
                        let client = aws_sdk_ssm::Client::new(&config);
                        let resp = client
                            .get_parameter()
                            .name(param_name_owned)
                            .with_decryption(true)
                            .send()
                            .await
                            .map_err(|e| {
                                KmsError::ServerError(format!(
                                    "AWS SSM GetParameter failed for {uri_owned}: {e}"
                                ))
                            })?;
                        resp.parameter.and_then(|p| p.value).ok_or_else(|| {
                            KmsError::ServerError(format!(
                                "AWS SSM parameter has no value: {uri_owned}"
                            ))
                        })
                    })
            })
            .join()
            .map_err(|_| {
                KmsError::ServerError("AWS SSM secret resolution thread panicked".to_owned())
            })?
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Azure Key Vault — `azure-kv://`
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "secret-azure")]
mod azure {
    use super::{KResult, KmsError, SecretBackend};

    /// Azure Key Vault secrets backend.
    ///
    /// URI format: `azure-kv://<vault-name>/secrets/<secret-name>[/<version>]`
    ///   - `vault-name`   — Key Vault name (e.g. `my-vault`)
    ///   - `secret-name`  — secret name (e.g. `kms-tls-p12`)
    ///   - `version`      — optional secret version; omit for the latest
    ///
    /// Required env vars (service-principal auth):
    ///   - `AZURE_TENANT_ID`     — Azure AD tenant ID
    ///   - `AZURE_CLIENT_ID`     — service-principal application (client) ID
    ///   - `AZURE_CLIENT_SECRET` — service-principal secret
    ///
    /// Example:
    ///   `azure-kv://my-vault/secrets/kms-tls-p12`
    pub(super) struct AzureKvBackend {
        tenant_id: String,
        client_id: String,
        client_secret: String,
    }

    impl AzureKvBackend {
        pub(super) fn new() -> Self {
            Self {
                tenant_id: std::env::var("AZURE_TENANT_ID").unwrap_or_default(),
                client_id: std::env::var("AZURE_CLIENT_ID").unwrap_or_default(),
                client_secret: std::env::var("AZURE_CLIENT_SECRET").unwrap_or_default(),
            }
        }
    }

    impl SecretBackend for AzureKvBackend {
        fn scheme(&self) -> &'static str {
            "azure-kv"
        }

        fn resolve(&self, uri: &str) -> KResult<String> {
            // Parse  azure-kv://<vault-name>/secrets/<name>[/<version>]
            let rest = uri
                .strip_prefix("azure-kv://")
                .ok_or_else(|| KmsError::InvalidRequest(format!("Invalid azure-kv URI: {uri}")))?;

            let slash = rest.find('/').ok_or_else(|| {
                KmsError::InvalidRequest(format!(
                    "azure-kv URI must have the form azure-kv://<vault>/secrets/<name>, got: {uri}"
                ))
            })?;
            let vault_name = &rest[..slash];
            let secret_path = &rest[slash + 1..]; // e.g. "secrets/kms-tls" or "secrets/kms-tls/abc123"

            let kv_url =
                format!("https://{vault_name}.vault.azure.net/{secret_path}?api-version=7.4");

            let tenant_id = self.tenant_id.clone();
            let client_id = self.client_id.clone();
            let client_secret = self.client_secret.clone();
            let uri_owned = uri.to_owned();
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        KmsError::ServerError(format!(
                            "Failed to build tokio runtime for Azure KV: {e}"
                        ))
                    })?
                    .block_on(async move {
                        // Obtain Azure AD access token via client-credentials flow
                        let token_url = format!(
                            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                            tenant_id
                        );
                        let auth_client = reqwest::Client::new();
                        let token_resp = auth_client
                            .post(&token_url)
                            .form(&[
                                ("grant_type", "client_credentials"),
                                ("client_id", client_id.as_str()),
                                ("client_secret", client_secret.as_str()),
                                ("scope", "https://vault.azure.net/.default"),
                            ])
                            .send()
                            .await
                            .map_err(|e| {
                                KmsError::ServerError(format!(
                                    "Azure AD token request failed: {e}"
                                ))
                            })?;

                        if !token_resp.status().is_success() {
                            return Err(KmsError::ServerError(format!(
                                "Azure AD token endpoint returned HTTP {}",
                                token_resp.status()
                            )));
                        }

                        let token_body: serde_json::Value =
                            token_resp.json().await.map_err(|e| {
                                KmsError::ServerError(format!(
                                    "Failed to parse Azure AD token response: {e}"
                                ))
                            })?;

                        let token = token_body["access_token"]
                            .as_str()
                            .ok_or_else(|| {
                                KmsError::ServerError(
                                    "No access_token in Azure AD token response".to_owned(),
                                )
                            })?
                            .to_owned();

                        // Fetch the secret from Azure Key Vault
                        let kv_client = reqwest::Client::new();
                        let resp = kv_client
                            .get(&kv_url)
                            .bearer_auth(&token)
                            .send()
                            .await
                            .map_err(|e| {
                                KmsError::ServerError(format!(
                                    "Azure Key Vault request failed for {uri_owned}: {e}"
                                ))
                            })?;

                        if !resp.status().is_success() {
                            return Err(KmsError::ServerError(format!(
                                "Azure Key Vault returned HTTP {} for {uri_owned}",
                                resp.status()
                            )));
                        }

                        let body: serde_json::Value = resp.json().await.map_err(|e| {
                            KmsError::ServerError(format!(
                                "Failed to parse Azure Key Vault response for {uri_owned}: {e}"
                            ))
                        })?;

                        body["value"]
                            .as_str()
                            .ok_or_else(|| {
                                KmsError::ServerError(format!(
                                    "Field 'value' not found in Azure Key Vault secret at {uri_owned}"
                                ))
                            })
                            .map(str::to_owned)
                    })
            })
            .join()
            .map_err(|_| {
                KmsError::ServerError("Azure KV secret resolution thread panicked".to_owned())
            })?
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (always compiled — backends themselves are behind feature flags)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use toml::Value;

    use super::{KResult, SecretBackend, resolve_secret_uris};

    struct EchoBackend;
    impl SecretBackend for EchoBackend {
        fn scheme(&self) -> &'static str {
            "echo"
        }
        fn resolve(&self, uri: &str) -> KResult<String> {
            // Returns the path part after "echo://"
            Ok(uri.trim_start_matches("echo://").to_owned())
        }
    }

    fn echo_backends() -> Vec<Box<dyn SecretBackend>> {
        vec![Box::new(EchoBackend)]
    }

    #[test]
    fn resolves_string_value() {
        let mut v: Value = toml::from_str(r#"password = "echo://my-secret""#).unwrap();
        resolve_secret_uris(&mut v, &echo_backends()).unwrap();
        assert_eq!(v["password"].as_str().unwrap(), "my-secret");
    }

    #[test]
    fn resolves_nested_table() {
        let mut v: Value = toml::from_str(
            r#"
            [db]
            database_url = "echo://pg://user:pass@localhost/kms"
            "#,
        )
        .unwrap();
        resolve_secret_uris(&mut v, &echo_backends()).unwrap();
        assert_eq!(
            v["db"]["database_url"].as_str().unwrap(),
            "pg://user:pass@localhost/kms"
        );
    }

    #[test]
    fn resolves_array() {
        let mut v: Value =
            toml::from_str(r#"hsm_password = ["echo://slot1", "echo://slot2"]"#).unwrap();
        resolve_secret_uris(&mut v, &echo_backends()).unwrap();
        let arr = v["hsm_password"].as_array().unwrap();
        assert_eq!(arr[0].as_str().unwrap(), "slot1");
        assert_eq!(arr[1].as_str().unwrap(), "slot2");
    }

    #[test]
    fn leaves_non_matching_strings_unchanged() {
        let mut v: Value = toml::from_str(r#"port = "9998""#).unwrap();
        resolve_secret_uris(&mut v, &echo_backends()).unwrap();
        assert_eq!(v["port"].as_str().unwrap(), "9998");
    }

    #[test]
    fn no_backends_is_noop() {
        let mut v: Value = toml::from_str(r#"password = "echo://secret""#).unwrap();
        resolve_secret_uris(&mut v, &[]).unwrap();
        // Unchanged because no backend handles the scheme
        assert_eq!(v["password"].as_str().unwrap(), "echo://secret");
    }
}
