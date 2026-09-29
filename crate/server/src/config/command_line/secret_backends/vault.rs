//! `HashiCorp` Vault KV-v2 backend.

use super::{
    KResult, KmsError, SecretBackend, VaultBackendConfig,
    common::{http_json, parse_uri, require_non_empty, resolve_async},
};

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
        require_non_empty(&self.token, "VAULT_TOKEN", "vault")?;

        let (first, remainder) = parse_uri(uri, "vault", "secret://<mount>/<path>[#<field>]")?;
        let (path_part, field) = format!("{first}/{remainder}").split_once('#').map_or_else(
            || (format!("{first}/{remainder}"), "value".to_owned()),
            |(p, f)| (p.to_owned(), f.to_owned()),
        );
        let (mount, secret_path) = path_part.split_once('/').ok_or_else(|| {
            KmsError::InvalidRequest(format!("vault URI must have mount/path, got: {uri}"))
        })?;
        let url = format!(
            "{}/v1/{mount}/data/{secret_path}",
            self.addr.trim_end_matches('/')
        );
        let token = self.token.clone();
        let uri_owned = uri.to_owned();

        resolve_async(async move {
            let json = http_json(
                reqwest::Client::new()
                    .get(&url)
                    .header("X-Vault-Token", &token),
                &uri_owned,
                "Vault",
            )
            .await?;

            json.get("data")
                .and_then(|d| d.get("data"))
                .and_then(|d| d.get(&field))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    KmsError::ServerError(format!(
                        "Field '{field}' not found in Vault secret at {uri_owned}"
                    ))
                })
                .map(str::to_owned)
        })
    }
}
