//! Secret URI resolution — called by `load_from_args` between TOML parsing
//! and deserialisation into `ClapConfig`.
//!
//! Credentials are passed in via `SecretBackendConfig` (populated by clap).
//! Zero `std::env::var` calls in production code.

use crate::{
    config::command_line::secret_backends::{SecretBackendConfig, SecretBackendKind},
    error::KmsError,
    result::KResult,
};

// ─── Shared async helper ────────────────────────────────────────────────────

fn run_blocking<F, T>(f: F) -> KResult<T>
where
    F: FnOnce() -> KResult<T> + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(f)
        .join()
        .map_err(|e| KmsError::ServerError(format!("Secret resolution thread panicked: {e:?}")))?
}

// ─── Trait ──────────────────────────────────────────────────────────────────

trait SecretBackend {
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

// ─── HashiCorp Vault KV-v2 ──────────────────────────────────────────────────

mod vault {
    use super::{KResult, KmsError, SecretBackend, run_blocking};
    use crate::config::command_line::secret_backends::VaultBackendConfig;

    pub(super) struct VaultBackend {
        addr: String,
        token: String,
    }

    impl VaultBackend {
        pub(super) fn new(cfg: &VaultBackendConfig) -> Self {
            Self {
                addr: cfg.vault_addr.clone(),
                token: cfg.vault_token.clone(),
            }
        }
    }

    impl SecretBackend for VaultBackend {
        fn resolve(&self, uri: &str) -> KResult<String> {
            if self.token.is_empty() {
                return Err(KmsError::ServerError(
                    "vault_token (VAULT_TOKEN) is empty; required for the vault secret backend"
                        .to_owned(),
                ));
            }
            let rest = uri
                .strip_prefix("secret://")
                .ok_or_else(|| KmsError::InvalidRequest(format!("Invalid secret URI: {uri}")))?;
            let (path_part, field) = rest
                .split_once('#')
                .map_or((rest, "value"), |(p, f)| (p, f));
            let slash = path_part.find('/').ok_or_else(|| {
                KmsError::InvalidRequest(format!(
                    "vault URI must be secret://<mount>/<path>[#<field>], got: {uri}"
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
            let field_owned = field.to_owned();
            let value: serde_json::Value = run_blocking(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| KmsError::ServerError(format!("tokio runtime: {e}")))?
                    .block_on(async {
                        let resp = reqwest::Client::new()
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
                                "Vault response parse error for {uri_owned}: {e}"
                            ))
                        })
                    })
            })?;
            value
                .get("data")
                .and_then(|d| d.get("data"))
                .and_then(|d| d.get(&field_owned))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    KmsError::ServerError(format!(
                        "Field '{field_owned}' not found in Vault secret at {uri}"
                    ))
                })
                .map(str::to_owned)
        }
    }
}

// ─── AWS SSM Parameter Store ─────────────────────────────────────────────────

mod aws {
    use chrono::Utc;
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    use super::{KResult, KmsError, SecretBackend, run_blocking};
    use crate::config::command_line::secret_backends::AwsSsmBackendConfig;

    type HmacSha256 = Hmac<Sha256>;

    pub(super) struct AwsSsmBackend {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    }

    impl AwsSsmBackend {
        pub(super) fn new(cfg: &AwsSsmBackendConfig) -> Self {
            Self {
                access_key_id: cfg.aws_access_key_id.clone(),
                secret_access_key: cfg.aws_secret_access_key.clone(),
                session_token: cfg.aws_session_token.clone(),
            }
        }
    }

    fn hex(b: &[u8]) -> String {
        hex::encode(b)
    }
    fn sha256(d: &[u8]) -> String {
        hex(&Sha256::digest(d))
    }
    fn hmac(key: &[u8], data: &[u8]) -> KResult<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| KmsError::ServerError(format!("HMAC key error: {e}")))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
    fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> KResult<Vec<u8>> {
        let k = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes())?;
        let k = hmac(&k, region.as_bytes())?;
        let k = hmac(&k, service.as_bytes())?;
        hmac(&k, b"aws4_request")
    }

    impl SecretBackend for AwsSsmBackend {
        fn resolve(&self, uri: &str) -> KResult<String> {
            if self.access_key_id.is_empty() {
                return Err(KmsError::ServerError(
                    "aws_access_key_id (AWS_ACCESS_KEY_ID) is not set; required for aws-ssm backend".to_owned(),
                ));
            }
            if self.secret_access_key.is_empty() {
                return Err(KmsError::ServerError(
                    "aws_secret_access_key (AWS_SECRET_ACCESS_KEY) is not set; required for aws-ssm backend".to_owned(),
                ));
            }
            let rest = uri
                .strip_prefix("secret://")
                .ok_or_else(|| KmsError::InvalidRequest(format!("Invalid secret URI: {uri}")))?;
            let slash = rest.find('/').ok_or_else(|| {
                KmsError::InvalidRequest(format!(
                    "aws-ssm URI must be secret://<region>/<param>, got: {uri}"
                ))
            })?;
            let region = rest[..slash].to_owned();
            let param_name = rest[slash..].to_owned();
            let access_key_id = self.access_key_id.clone();
            let secret_key = self.secret_access_key.clone();
            let session_token = self.session_token.clone();
            let uri_owned = uri.to_owned();
            run_blocking(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| KmsError::ServerError(format!("tokio runtime: {e}")))?
                    .block_on(call_ssm(
                        &region,
                        &param_name,
                        &access_key_id,
                        &secret_key,
                        session_token.as_deref(),
                        &uri_owned,
                    ))
            })
        }
    }

    async fn call_ssm(
        region: &str,
        param: &str,
        key_id: &str,
        secret: &str,
        token: Option<&str>,
        uri: &str,
    ) -> KResult<String> {
        let now = Utc::now();
        let dt = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let host = format!("ssm.{region}.amazonaws.com");
        let body = serde_json::json!({"Name": param, "WithDecryption": true}).to_string();
        let payload_hash = sha256(body.as_bytes());
        let (canon_hdrs, signed_hdrs) = token.map_or_else(
            || (format!("content-type:application/x-amz-json-1.1\nhost:{host}\nx-amz-date:{dt}\nx-amz-target:AmazonSSM.GetParameter\n"),
                "content-type;host;x-amz-date;x-amz-target".to_owned()),
            |t| (format!("content-type:application/x-amz-json-1.1\nhost:{host}\nx-amz-date:{dt}\nx-amz-security-token:{t}\nx-amz-target:AmazonSSM.GetParameter\n"),
                 "content-type;host;x-amz-date;x-amz-security-token;x-amz-target".to_owned()),
        );
        let canon_req = format!("POST\n/\n\n{canon_hdrs}\n{signed_hdrs}\n{payload_hash}");
        let scope = format!("{date}/{region}/ssm/aws4_request");
        let sts = format!(
            "AWS4-HMAC-SHA256\n{dt}\n{scope}\n{}",
            sha256(canon_req.as_bytes())
        );
        let key = signing_key(secret, &date, region, "ssm")?;
        let sig = hex(&hmac(&key, sts.as_bytes())?);
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders={signed_hdrs}, Signature={sig}"
        );
        let client = reqwest::Client::new();
        let req = client
            .post(format!("https://{host}/"))
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Date", &dt)
            .header("X-Amz-Target", "AmazonSSM.GetParameter")
            .header("Authorization", &auth);
        let req = if let Some(t) = token {
            req.header("X-Amz-Security-Token", t)
        } else {
            req
        };
        let resp =
            req.body(body).send().await.map_err(|e| {
                KmsError::ServerError(format!("AWS SSM request failed for {uri}: {e}"))
            })?;
        if !resp.status().is_success() {
            let s = resp.status();
            let b = resp.text().await.unwrap_or_default();
            return Err(KmsError::ServerError(format!(
                "AWS SSM HTTP {s} for {uri}: {b}"
            )));
        }
        let j: serde_json::Value = resp.json().await.map_err(|e| {
            KmsError::ServerError(format!("AWS SSM response parse error for {uri}: {e}"))
        })?;
        j.get("Parameter")
            .and_then(|p| p.get("Value"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                KmsError::ServerError(format!("AWS SSM missing Parameter.Value for {uri}"))
            })
            .map(str::to_owned)
    }
}

// ─── Azure Key Vault ─────────────────────────────────────────────────────────

mod azure {
    use super::{KResult, KmsError, SecretBackend, run_blocking};
    use crate::config::command_line::secret_backends::AzureKvBackendConfig;

    pub(super) struct AzureKvBackend {
        tenant_id: String,
        client_id: String,
        client_secret: String,
    }

    impl AzureKvBackend {
        pub(super) fn new(cfg: &AzureKvBackendConfig) -> Self {
            Self {
                tenant_id: cfg.azure_tenant_id.clone(),
                client_id: cfg.azure_client_id.clone(),
                client_secret: cfg.azure_client_secret.clone(),
            }
        }
    }

    impl SecretBackend for AzureKvBackend {
        fn resolve(&self, uri: &str) -> KResult<String> {
            for (name, val) in [
                ("azure_tenant_id (AZURE_TENANT_ID)", &self.tenant_id),
                ("azure_client_id (AZURE_CLIENT_ID)", &self.client_id),
                (
                    "azure_client_secret (AZURE_CLIENT_SECRET)",
                    &self.client_secret,
                ),
            ] {
                if val.is_empty() {
                    return Err(KmsError::ServerError(format!(
                        "{name} is not set; required for azure-kv secret backend"
                    )));
                }
            }
            let rest = uri
                .strip_prefix("secret://")
                .ok_or_else(|| KmsError::InvalidRequest(format!("Invalid secret URI: {uri}")))?;
            let slash = rest.find('/').ok_or_else(|| {
                KmsError::InvalidRequest(format!(
                    "azure-kv URI must be secret://<vault>/secrets/<name>, got: {uri}"
                ))
            })?;
            let vault_name = rest[..slash].to_owned();
            let secret_path = rest[slash + 1..].to_owned();
            let kv_url =
                format!("https://{vault_name}.vault.azure.net/{secret_path}?api-version=7.4");
            let tenant_id = self.tenant_id.clone();
            let client_id = self.client_id.clone();
            let client_secret = self.client_secret.clone();
            let uri_owned = uri.to_owned();
            run_blocking(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| KmsError::ServerError(format!("tokio runtime: {e}")))?
                    .block_on(async {
                        let token_url = format!(
                            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
                        );
                        let token_resp = reqwest::Client::new()
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
                                KmsError::ServerError(format!("Azure AD token request failed: {e}"))
                            })?;
                        if !token_resp.status().is_success() {
                            return Err(KmsError::ServerError(format!(
                                "Azure AD token endpoint returned HTTP {}",
                                token_resp.status()
                            )));
                        }
                        let token_body: serde_json::Value =
                            token_resp.json().await.map_err(|e| {
                                KmsError::ServerError(format!("Azure AD token parse error: {e}"))
                            })?;
                        let token = token_body
                            .get("access_token")
                            .and_then(serde_json::Value::as_str)
                            .ok_or_else(|| {
                                KmsError::ServerError(
                                    "No access_token in Azure AD response".to_owned(),
                                )
                            })?
                            .to_owned();
                        let resp = reqwest::Client::new()
                            .get(&kv_url)
                            .bearer_auth(&token)
                            .send()
                            .await
                            .map_err(|e| {
                                KmsError::ServerError(format!(
                                    "Azure KV request failed for {uri_owned}: {e}"
                                ))
                            })?;
                        if !resp.status().is_success() {
                            return Err(KmsError::ServerError(format!(
                                "Azure KV returned HTTP {} for {uri_owned}",
                                resp.status()
                            )));
                        }
                        let body: serde_json::Value = resp.json().await.map_err(|e| {
                            KmsError::ServerError(format!(
                                "Azure KV response parse error for {uri_owned}: {e}"
                            ))
                        })?;
                        body.get("value")
                            .and_then(serde_json::Value::as_str)
                            .ok_or_else(|| {
                                KmsError::ServerError(format!(
                                    "Field 'value' not found in Azure KV secret at {uri_owned}"
                                ))
                            })
                            .map(str::to_owned)
                    })
            })
        }
    }
}

// ─── Cosmian KMS (KMIP Get) ───────────────────────────────────────────────────

mod cosmian_kms {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_2_1::{
            kmip_objects::Object,
            kmip_operations::{Get, GetResponse},
        },
        ttlv::{TTLV, from_ttlv, to_ttlv},
    };

    use super::{KResult, KmsError, SecretBackend, run_blocking};
    use crate::config::command_line::secret_backends::CosmianKmsSecretConfig;

    pub(super) struct CosmianKmsBackend {
        token: Option<String>,
        insecure_certs: bool,
    }

    impl CosmianKmsBackend {
        pub(super) fn new(cfg: &CosmianKmsSecretConfig) -> Self {
            Self {
                token: cfg.cosmian_kms_secret_token.clone(),
                insecure_certs: cfg.cosmian_kms_insecure_certs,
            }
        }
    }

    impl SecretBackend for CosmianKmsBackend {
        fn resolve(&self, uri: &str) -> KResult<String> {
            let rest = uri
                .strip_prefix("secret://")
                .ok_or_else(|| KmsError::InvalidRequest(format!("Invalid secret URI: {uri}")))?;
            let slash = rest.find('/').ok_or_else(|| {
                KmsError::InvalidRequest(format!(
                    "cosmian-kms URI must be secret://<host>[:<port>]/<id>, got: {uri}"
                ))
            })?;
            let host_port = &rest[..slash];
            let object_id = rest[slash + 1..].to_owned();
            if object_id.is_empty() {
                return Err(KmsError::InvalidRequest(format!(
                    "cosmian-kms URI must have a non-empty object ID: {uri}"
                )));
            }
            let is_local = host_port.starts_with("localhost")
                || host_port.starts_with("127.0.0.1")
                || host_port.starts_with("[::1]");
            let scheme = if is_local || self.insecure_certs {
                "http"
            } else {
                "https"
            };
            let server_url = if host_port.contains(':') {
                format!("{scheme}://{host_port}")
            } else {
                format!("{scheme}://{host_port}:9998")
            };
            let token = self.token.clone();
            let insecure = self.insecure_certs;
            let uri_owned = uri.to_owned();
            run_blocking(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| KmsError::ServerError(format!("tokio runtime: {e}")))?
                    .block_on(fetch_object(
                        &server_url,
                        &object_id,
                        token.as_deref(),
                        insecure,
                        &uri_owned,
                    ))
            })
        }
    }

    async fn fetch_object(
        url: &str,
        id: &str,
        token: Option<&str>,
        insecure: bool,
        uri: &str,
    ) -> KResult<String> {
        let req_ttlv = to_ttlv(&Get::from(id)).map_err(|e| {
            KmsError::ServerError(format!("KMIP Get serialise error for {uri}: {e}"))
        })?;
        let mut b = reqwest::Client::builder();
        if insecure {
            b = b.danger_accept_invalid_certs(true);
        }
        let client = b
            .build()
            .map_err(|e| KmsError::ServerError(format!("HTTP client build error: {e}")))?;
        let endpoint = format!("{}/kmip/2_1", url.trim_end_matches('/'));
        let mut req = client.post(&endpoint).json(&req_ttlv);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.map_err(|e| {
            KmsError::ServerError(format!("Cosmian KMS request failed for {uri}: {e}"))
        })?;
        if !resp.status().is_success() {
            return Err(KmsError::ServerError(format!(
                "Cosmian KMS HTTP {} for {uri}",
                resp.status()
            )));
        }
        let ttlv: TTLV = resp.json().await.map_err(|e| {
            KmsError::ServerError(format!("Cosmian KMS response parse error for {uri}: {e}"))
        })?;
        let get_resp: GetResponse = from_ttlv(ttlv).map_err(|e| {
            KmsError::ServerError(format!("Cosmian KMS deserialise error for {uri}: {e}"))
        })?;
        extract_secret(get_resp.object, uri)
    }

    fn extract_secret(object: Object, uri: &str) -> KResult<String> {
        match object {
            Object::SecretData(sd) => {
                let bytes = sd.key_block.key_bytes().map_err(|e| {
                    KmsError::ServerError(format!("SecretData key_bytes error at {uri}: {e}"))
                })?;
                String::from_utf8(bytes.to_vec()).map_err(|e| {
                    KmsError::ServerError(format!("SecretData non-UTF-8 at {uri}: {e}"))
                })
            }
            Object::OpaqueObject(o) => String::from_utf8(o.opaque_data_value).map_err(|e| {
                KmsError::ServerError(format!("OpaqueObject non-UTF-8 at {uri}: {e}"))
            }),
            other => Err(KmsError::ServerError(format!(
                "Cosmian KMS object at {uri} has type {:?}; expected SecretData or OpaqueObject",
                other.object_type()
            ))),
        }
    }
}
