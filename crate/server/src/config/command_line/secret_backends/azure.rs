//! Azure Key Vault backend.

use super::{
    AzureKvBackendConfig, KResult, KmsError, SecretBackend,
    common::{http_json, parse_uri, require_non_empty, resolve_async},
};

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

    /// Obtain an `OAuth2` access token from Azure AD using client credentials.
    async fn acquire_token(&self, uri: &str) -> KResult<String> {
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );
        let json = http_json(
            reqwest::Client::new().post(&token_url).form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("scope", "https://vault.azure.net/.default"),
            ]),
            uri,
            "Azure AD",
        )
        .await?;

        json.get("access_token")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| KmsError::ServerError("No access_token in Azure AD response".to_owned()))
            .map(str::to_owned)
    }
}

impl SecretBackend for AzureKvBackend {
    fn resolve(&self, uri: &str) -> KResult<String> {
        require_non_empty(&self.tenant_id, "AZURE_TENANT_ID", "azure-kv")?;
        require_non_empty(&self.client_id, "AZURE_CLIENT_ID", "azure-kv")?;
        require_non_empty(&self.client_secret, "AZURE_CLIENT_SECRET", "azure-kv")?;

        let (vault_name, secret_path) =
            parse_uri(uri, "azure-kv", "secret://<vault>/secrets/<name>")?;
        let kv_url = format!("https://{vault_name}.vault.azure.net/{secret_path}?api-version=7.4");
        let uri_owned = uri.to_owned();
        // Clone self for the 'static async block
        let backend = Self {
            tenant_id: self.tenant_id.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
        };

        resolve_async(async move {
            let token = backend.acquire_token(&uri_owned).await?;

            let json = http_json(
                reqwest::Client::new().get(&kv_url).bearer_auth(&token),
                &uri_owned,
                "Azure KV",
            )
            .await?;

            json.get("value")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    KmsError::ServerError(format!(
                        "Field 'value' not found in Azure KV secret at {uri_owned}"
                    ))
                })
                .map(str::to_owned)
        })
    }
}
