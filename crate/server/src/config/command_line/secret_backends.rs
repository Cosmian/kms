//! Phase-2 secret URI resolution backends.
//!
//! Any TOML string value that starts with a recognised scheme is replaced by the
//! secret it points to, fetched synchronously at startup.
//!
//! Supported schemes and their controlling feature flags:
//!
//! | Scheme             | Feature flag          | Required env vars / notes                  |
//! |--------------------|----------------------|--------------------------------------------|
//! | `vault://`         | `secret-vault`       | `VAULT_ADDR`, `VAULT_TOKEN`                |
//! | `aws-ssm://`       | `secret-aws`         | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
//! | `azure-kv://`      | `secret-azure`       | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,      |
//! |                    |                      | `AZURE_CLIENT_SECRET`                      |
//! | `cosmian-kms://`   | `secret-cosmian-kms` | `COSMIAN_KMS_TOKEN` (opt.),                |
//! |                    |                      | `COSMIAN_KMS_INSECURE_CERTS` (opt.)        |
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
//!
//! database_url = "cosmian-kms://kms.internal:9998/b4c2f00a-1234-5678-abcd-ef0123456789"
//! ```
//!
//! Schemes can be mixed freely; each value is resolved independently.

#[cfg(any(
    feature = "secret-vault",
    feature = "secret-aws",
    feature = "secret-azure",
    feature = "secret-cosmian-kms"
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
#[allow(clippy::vec_init_then_push)]
pub(super) fn build_secret_backends() -> Vec<Box<dyn SecretBackend>> {
    #[allow(unused_mut)]
    let mut backends: Vec<Box<dyn SecretBackend>> = Vec::new();

    #[cfg(feature = "secret-vault")]
    backends.push(Box::new(vault::VaultBackend::new()));

    #[cfg(feature = "secret-aws")]
    backends.push(Box::new(aws::AwsSsmBackend::new()));

    #[cfg(feature = "secret-azure")]
    #[allow(clippy::vec_init_then_push)]
    backends.push(Box::new(azure::AzureKvBackend::new()));

    #[cfg(feature = "secret-cosmian-kms")]
    backends.push(Box::new(cosmian_kms::CosmianKmsBackend::new()));

    backends
}

// ─────────────────────────────────────────────────────────────────────────────
// HashiCorp Vault — `vault://`
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "secret-vault")]
mod vault {
    use super::{KResult, KmsError, SecretBackend};

    /// `HashiCorp` Vault KV-v2 backend.
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
            .map_err(|_e| {
                KmsError::ServerError("Vault secret resolution thread panicked".to_owned())
            })??;

            value
                .get("data")
                .and_then(|d| d.get("data"))
                .and_then(|d| d.get(field))
                .and_then(serde_json::Value::as_str)
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
    use chrono::Utc;
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    use super::{KResult, KmsError, SecretBackend};

    type HmacSha256 = Hmac<Sha256>;

    /// AWS SSM Parameter Store backend.
    ///
    /// URI format: `aws-ssm://<region>/<parameter-name>`
    ///   - `region`         — AWS region (e.g. `eu-west-1`)
    ///   - `parameter-name` — SSM parameter name, leading `/` included
    ///     (e.g. `/kms/prod/db-password`)
    ///
    /// Credentials are resolved from the `AWS_ACCESS_KEY_ID` and
    /// `AWS_SECRET_ACCESS_KEY` environment variables (and optionally
    /// `AWS_SESSION_TOKEN`).
    ///
    /// Example:
    ///   `aws-ssm://eu-west-1/kms/prod/db-password`
    pub(super) struct AwsSsmBackend;

    impl AwsSsmBackend {
        pub(super) const fn new() -> Self {
            Self
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    fn sha256_hex(data: &[u8]) -> String {
        hex_encode(&Sha256::digest(data))
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> KResult<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| KmsError::ServerError(format!("HMAC key error: {e}")))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Build the `SigV4` signing key:
    /// `HMAC(HMAC(HMAC(HMAC("AWS4" + secret, date), region), service), "aws4_request")`
    fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> KResult<Vec<u8>> {
        let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes())?;
        let k_region = hmac_sha256(&k_date, region.as_bytes())?;
        let k_service = hmac_sha256(&k_region, service.as_bytes())?;
        hmac_sha256(&k_service, b"aws4_request")
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
            let region = rest[..slash].to_owned();
            // Parameter name starts with '/', e.g. /kms/prod/db
            let param_name = rest[slash..].to_owned();

            let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").map_err(|_e| {
                KmsError::ServerError(
                    "AWS_ACCESS_KEY_ID env var not set for secret-aws backend".to_owned(),
                )
            })?;
            let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").map_err(|_e| {
                KmsError::ServerError(
                    "AWS_SECRET_ACCESS_KEY env var not set for secret-aws backend".to_owned(),
                )
            })?;
            let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
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
                        call_ssm_get_parameter(
                            &region,
                            &param_name,
                            &access_key_id,
                            &secret_key,
                            session_token.as_deref(),
                            &uri_owned,
                        )
                        .await
                    })
            })
            .join()
            .map_err(|_e| {
                KmsError::ServerError("AWS SSM secret resolution thread panicked".to_owned())
            })?
        }
    }

    /// Make a SigV4-signed POST request to the AWS SSM `GetParameter` API using
    /// `reqwest` (native-TLS). No AWS SDK is required.
    async fn call_ssm_get_parameter(
        region: &str,
        param_name: &str,
        access_key_id: &str,
        secret_key: &str,
        session_token: Option<&str>,
        uri: &str,
    ) -> KResult<String> {
        let now = Utc::now();
        let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let host = format!("ssm.{region}.amazonaws.com");
        let service = "ssm";

        let body = serde_json::json!({"Name": param_name, "WithDecryption": true}).to_string();
        let payload_hash = sha256_hex(body.as_bytes());

        // Canonical headers must be sorted alphabetically by name (lowercased).
        // Without session token: content-type, host, x-amz-date, x-amz-target.
        // With session token: insert x-amz-security-token between x-amz-date and x-amz-target.
        let (canonical_headers, signed_headers) = session_token.map_or_else(
            || {
                (
                    format!(
                        "content-type:application/x-amz-json-1.1\nhost:{host}\nx-amz-date:{datetime}\nx-amz-target:AmazonSSM.GetParameter\n"
                    ),
                    "content-type;host;x-amz-date;x-amz-target".to_owned(),
                )
            },
            |token| {
                (
                    format!(
                        "content-type:application/x-amz-json-1.1\nhost:{host}\nx-amz-date:{datetime}\nx-amz-security-token:{token}\nx-amz-target:AmazonSSM.GetParameter\n"
                    ),
                    "content-type;host;x-amz-date;x-amz-security-token;x-amz-target".to_owned(),
                )
            },
        );

        let canonical_request =
            format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
        let credential_scope = format!("{date}/{region}/{service}/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );

        let key = signing_key(secret_key, &date, region, service)?;
        let signature = hex_encode(&hmac_sha256(&key, string_to_sign.as_bytes())?);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        );

        let endpoint = format!("https://{host}/");
        let client = reqwest::Client::new();
        let req_builder = client
            .post(&endpoint)
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Date", &datetime)
            .header("X-Amz-Target", "AmazonSSM.GetParameter")
            .header("Authorization", &authorization);
        let req_builder = if let Some(token) = session_token {
            req_builder.header("X-Amz-Security-Token", token)
        } else {
            req_builder
        };
        let resp =
            req_builder.body(body).send().await.map_err(|e| {
                KmsError::ServerError(format!("AWS SSM request failed for {uri}: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(KmsError::ServerError(format!(
                "AWS SSM returned HTTP {status} for {uri}: {body_text}"
            )));
        }

        let resp_body: serde_json::Value = resp.json().await.map_err(|e| {
            KmsError::ServerError(format!("Failed to parse AWS SSM response for {uri}: {e}"))
        })?;

        resp_body
            .get("Parameter")
            .and_then(|p| p.get("Value"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                KmsError::ServerError(format!(
                    "AWS SSM response missing Parameter.Value for {uri}"
                ))
            })
            .map(str::to_owned)
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
                            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
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

                        let token = token_body
                            .get("access_token")
                            .and_then(serde_json::Value::as_str)
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

                        body.get("value")
                            .and_then(serde_json::Value::as_str)
                            .ok_or_else(|| {
                                KmsError::ServerError(format!(
                                    "Field 'value' not found in Azure Key Vault secret at {uri_owned}"
                                ))
                            })
                            .map(str::to_owned)
                    })
            })
            .join()
            .map_err(|_e| {
                KmsError::ServerError("Azure KV secret resolution thread panicked".to_owned())
            })?
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cosmian KMS — `cosmian-kms://`
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "secret-cosmian-kms")]
mod cosmian_kms {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_2_1::{
            kmip_objects::Object,
            kmip_operations::{Get, GetResponse},
        },
        ttlv::{TTLV, from_ttlv, to_ttlv},
    };

    use super::{KResult, KmsError, SecretBackend};

    /// Cosmian KMS secret backend.
    ///
    /// URI format: `cosmian-kms://<host>[:<port>]/<object-id>`
    ///   - `host`      — hostname or IP of the target Cosmian KMS server
    ///   - `port`      — optional port; defaults to `9998`
    ///   - `object-id` — UID of the `SecretData` or `OpaqueObject` to fetch
    ///
    /// Optional env vars:
    ///   - `COSMIAN_KMS_TOKEN`          — Bearer token / API key for authentication
    ///   - `COSMIAN_KMS_INSECURE_CERTS` — set to `true` to skip TLS cert verification
    ///
    /// Example:
    ///   `cosmian-kms://kms.internal:9998/b4c2f00a-1234-5678-abcd-ef0123456789`
    pub(super) struct CosmianKmsBackend;

    impl CosmianKmsBackend {
        pub(super) const fn new() -> Self {
            Self
        }
    }

    impl SecretBackend for CosmianKmsBackend {
        fn scheme(&self) -> &'static str {
            "cosmian-kms"
        }

        fn resolve(&self, uri: &str) -> KResult<String> {
            // Parse  cosmian-kms://<host>[:<port>]/<object-id>
            let rest = uri.strip_prefix("cosmian-kms://").ok_or_else(|| {
                KmsError::InvalidRequest(format!("Invalid cosmian-kms URI: {uri}"))
            })?;

            let slash = rest.find('/').ok_or_else(|| {
                KmsError::InvalidRequest(format!(
                    "cosmian-kms URI must have the form \
                     cosmian-kms://<host>[:<port>]/<object-id>, got: {uri}"
                ))
            })?;
            let host_port = &rest[..slash];
            let object_id = rest[slash + 1..].to_owned();

            if object_id.is_empty() {
                return Err(KmsError::InvalidRequest(format!(
                    "cosmian-kms URI must contain a non-empty object ID: {uri}"
                )));
            }

            // Use HTTPS unless connecting to localhost (or explicit port 9998
            // via HTTP for dev environments where insecure certs are expected).
            let insecure_certs = std::env::var("COSMIAN_KMS_INSECURE_CERTS")
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                .unwrap_or(false);

            let is_local = host_port.starts_with("localhost")
                || host_port.starts_with("127.0.0.1")
                || host_port.starts_with("[::1]");

            let scheme = if is_local || insecure_certs {
                "http"
            } else {
                "https"
            };

            let server_url = if host_port.contains(':') {
                format!("{scheme}://{host_port}")
            } else {
                format!("{scheme}://{host_port}:9998")
            };

            let token = std::env::var("COSMIAN_KMS_TOKEN").ok();
            let uri_owned = uri.to_owned();

            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        KmsError::ServerError(format!(
                            "Failed to build tokio runtime for Cosmian KMS backend: {e}"
                        ))
                    })?
                    .block_on(async move {
                        fetch_kmip_object(
                            &server_url,
                            &object_id,
                            token.as_deref(),
                            insecure_certs,
                            &uri_owned,
                        )
                        .await
                    })
            })
            .join()
            .map_err(|_e| {
                KmsError::ServerError("Cosmian KMS secret resolution thread panicked".to_owned())
            })?
        }
    }

    /// Send a KMIP `Get` request to the target KMS server and return the secret
    /// as a UTF-8 string. Supports `SecretData` and `OpaqueObject` types.
    async fn fetch_kmip_object(
        server_url: &str,
        object_id: &str,
        token: Option<&str>,
        insecure_certs: bool,
        uri: &str,
    ) -> KResult<String> {
        let get_request = Get::from(object_id);
        let ttlv_request = to_ttlv(&get_request).map_err(|e| {
            KmsError::ServerError(format!(
                "Failed to serialise KMIP Get request for {uri}: {e}"
            ))
        })?;

        let mut builder = reqwest::Client::builder();
        if insecure_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder.build().map_err(|e| {
            KmsError::ServerError(format!(
                "Failed to build HTTP client for Cosmian KMS backend: {e}"
            ))
        })?;

        let endpoint = format!("{}/kmip/2_1", server_url.trim_end_matches('/'));
        let mut req = client.post(&endpoint).json(&ttlv_request);
        if let Some(tok) = token {
            req = req.bearer_auth(tok);
        }

        let resp = req.send().await.map_err(|e| {
            KmsError::ServerError(format!("Cosmian KMS request failed for {uri}: {e}"))
        })?;

        if !resp.status().is_success() {
            return Err(KmsError::ServerError(format!(
                "Cosmian KMS returned HTTP {} for {uri}",
                resp.status()
            )));
        }

        let ttlv_response: TTLV = resp.json().await.map_err(|e| {
            KmsError::ServerError(format!(
                "Failed to parse Cosmian KMS response for {uri}: {e}"
            ))
        })?;

        let get_response: GetResponse = from_ttlv(ttlv_response).map_err(|e| {
            KmsError::ServerError(format!(
                "Failed to deserialise Cosmian KMS GetResponse for {uri}: {e}"
            ))
        })?;

        extract_secret_string(get_response.object, uri)
    }

    /// Extract the secret value as a UTF-8 string from a KMIP `Object`.
    ///
    /// Supported types: `SecretData`, `OpaqueObject`.
    fn extract_secret_string(object: Object, uri: &str) -> KResult<String> {
        match object {
            Object::SecretData(sd) => {
                let bytes = sd.key_block.key_bytes().map_err(|e| {
                    KmsError::ServerError(format!(
                        "Failed to extract secret bytes from SecretData at {uri}: {e}"
                    ))
                })?;
                String::from_utf8(bytes.to_vec()).map_err(|e| {
                    KmsError::ServerError(format!(
                        "SecretData at {uri} contains non-UTF-8 bytes: {e}"
                    ))
                })
            }
            Object::OpaqueObject(obj) => String::from_utf8(obj.opaque_data_value).map_err(|e| {
                KmsError::ServerError(format!(
                    "OpaqueObject at {uri} contains non-UTF-8 bytes: {e}"
                ))
            }),
            other => Err(KmsError::ServerError(format!(
                "Cosmian KMS object at {uri} has type {:?}; \
                 expected SecretData or OpaqueObject",
                other.object_type()
            ))),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (always compiled — backends themselves are behind feature flags)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
        assert_eq!(
            v.get("password").and_then(|x| x.as_str()).unwrap(),
            "my-secret"
        );
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
            v.get("db")
                .and_then(|d| d.get("database_url"))
                .and_then(|x| x.as_str())
                .unwrap(),
            "pg://user:pass@localhost/kms"
        );
    }

    #[test]
    fn resolves_array() {
        let mut v: Value =
            toml::from_str(r#"hsm_password = ["echo://slot1", "echo://slot2"]"#).unwrap();
        resolve_secret_uris(&mut v, &echo_backends()).unwrap();
        let arr = v.get("hsm_password").and_then(|x| x.as_array()).unwrap();
        assert_eq!(arr.first().and_then(|x| x.as_str()).unwrap(), "slot1");
        assert_eq!(arr.get(1).and_then(|x| x.as_str()).unwrap(), "slot2");
    }

    #[test]
    fn leaves_non_matching_strings_unchanged() {
        let mut v: Value = toml::from_str(r#"port = "9998""#).unwrap();
        resolve_secret_uris(&mut v, &echo_backends()).unwrap();
        assert_eq!(v.get("port").and_then(|x| x.as_str()).unwrap(), "9998");
    }

    #[test]
    fn no_backends_is_noop() {
        let mut v: Value = toml::from_str(r#"password = "echo://secret""#).unwrap();
        resolve_secret_uris(&mut v, &[]).unwrap();
        // Unchanged because no backend handles the scheme
        assert_eq!(
            v.get("password").and_then(|x| x.as_str()).unwrap(),
            "echo://secret"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Integration tests — require live external services.
    // Run with:  cargo test --features secret-vault  -- --ignored test_secret_vault
    //            cargo test --features secret-aws    -- --ignored test_secret_aws_ssm
    //            cargo test --features secret-azure  -- --ignored test_secret_azure_kv
    //
    // Required env vars (set by CI scripts):
    //   Vault:  VAULT_ADDR, VAULT_TOKEN, KMS_TEST_VAULT_URI
    //   AWS:    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION (or profile),
    //           KMS_TEST_AWS_SSM_URI
    //   Azure:  AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
    //           KMS_TEST_AZURE_KV_URI
    // ─────────────────────────────────────────────────────────────────────────

    /// Vault integration test.
    ///
    /// Expects the secret at `KMS_TEST_VAULT_URI` (e.g.
    /// `vault://secret/kms-ci/db#password`) to exist and its resolved value to
    /// equal `KMS_TEST_VAULT_EXPECTED` (defaults to `"ci-secret-value"`).
    #[cfg(feature = "secret-vault")]
    #[test]
    #[ignore = "requires a running HashiCorp Vault instance (set KMS_TEST_VAULT_URI)"]
    fn test_secret_vault() {
        use super::vault::VaultBackend;
        let uri = std::env::var("KMS_TEST_VAULT_URI")
            .unwrap_or_else(|_e| "vault://secret/kms-ci/db#password".to_owned());
        let expected = std::env::var("KMS_TEST_VAULT_EXPECTED")
            .unwrap_or_else(|_e| "ci-secret-value".to_owned());

        let backend = VaultBackend::new();
        let resolved = backend.resolve(&uri).expect("Vault resolution failed");
        assert_eq!(
            resolved, expected,
            "Vault secret value mismatch: got '{resolved}', expected '{expected}'"
        );
    }

    /// AWS SSM integration test.
    ///
    /// Expects the parameter at `KMS_TEST_AWS_SSM_URI` (e.g.
    /// `aws-ssm://eu-west-1/kms/ci/db-password`) to exist and its resolved value
    /// to equal `KMS_TEST_AWS_SSM_EXPECTED` (defaults to `"ci-secret-value"`).
    #[cfg(feature = "secret-aws")]
    #[test]
    #[ignore = "requires AWS SSM access (set KMS_TEST_AWS_SSM_URI)"]
    fn test_secret_aws_ssm() {
        use super::aws::AwsSsmBackend;
        let uri = std::env::var("KMS_TEST_AWS_SSM_URI")
            .unwrap_or_else(|_e| "aws-ssm://eu-west-1/kms/ci/db-password".to_owned());
        let expected = std::env::var("KMS_TEST_AWS_SSM_EXPECTED")
            .unwrap_or_else(|_e| "ci-secret-value".to_owned());

        let backend = AwsSsmBackend::new();
        let resolved = backend.resolve(&uri).expect("AWS SSM resolution failed");
        assert_eq!(
            resolved, expected,
            "AWS SSM secret value mismatch: got '{resolved}', expected '{expected}'"
        );
    }

    /// Azure Key Vault integration test.
    ///
    /// Expects the secret at `KMS_TEST_AZURE_KV_URI` (e.g.
    /// `azure-kv://my-vault/secrets/kms-ci-db-password`) to exist and its
    /// resolved value to equal `KMS_TEST_AZURE_KV_EXPECTED` (defaults to
    /// `"ci-secret-value"`).
    #[cfg(feature = "secret-azure")]
    #[test]
    #[ignore = "requires Azure Key Vault access (set KMS_TEST_AZURE_KV_URI)"]
    fn test_secret_azure_kv() {
        use super::azure::AzureKvBackend;
        let uri = std::env::var("KMS_TEST_AZURE_KV_URI")
            .unwrap_or_else(|_e| "azure-kv://my-vault/secrets/kms-ci-db-password".to_owned());
        let expected = std::env::var("KMS_TEST_AZURE_KV_EXPECTED")
            .unwrap_or_else(|_e| "ci-secret-value".to_owned());

        let backend = AzureKvBackend::new();
        let resolved = backend.resolve(&uri).expect("Azure KV resolution failed");
        assert_eq!(
            resolved, expected,
            "Azure KV secret value mismatch: got '{resolved}', expected '{expected}'"
        );
    }

    /// Cosmian KMS integration test.
    ///
    /// Expects the object at `KMS_TEST_COSMIAN_KMS_URI` (e.g.
    /// `cosmian-kms://localhost:9998/<object-id>`) to be a `SecretData` or
    /// `OpaqueObject` whose resolved value equals `KMS_TEST_COSMIAN_KMS_EXPECTED`
    /// (defaults to `"ci-secret-value"`).
    ///
    /// Required env vars:
    ///   - `KMS_TEST_COSMIAN_KMS_URI` — full cosmian-kms:// URI
    ///   - `COSMIAN_KMS_TOKEN`        — Bearer token for the target server (optional)
    #[cfg(feature = "secret-cosmian-kms")]
    #[test]
    #[ignore = "requires a running Cosmian KMS instance (set KMS_TEST_COSMIAN_KMS_URI)"]
    fn test_secret_cosmian_kms() {
        use super::cosmian_kms::CosmianKmsBackend;
        let uri = std::env::var("KMS_TEST_COSMIAN_KMS_URI").unwrap_or_else(|_e| {
            "cosmian-kms://localhost:9998/00000000-0000-0000-0000-000000000000".to_owned()
        });
        let expected = std::env::var("KMS_TEST_COSMIAN_KMS_EXPECTED")
            .unwrap_or_else(|_e| "ci-secret-value".to_owned());

        let backend = CosmianKmsBackend::new();
        let resolved = backend
            .resolve(&uri)
            .expect("Cosmian KMS resolution failed");
        assert_eq!(
            resolved, expected,
            "Cosmian KMS secret value mismatch: got '{resolved}', expected '{expected}'"
        );
    }
}
