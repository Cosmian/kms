//! Cosmian KMS secret backend (KMIP Get).

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_2_1::{
        kmip_objects::Object,
        kmip_operations::{Get, GetResponse},
    },
    ttlv::{TTLV, from_ttlv, to_ttlv},
};

use super::{
    CosmianKmsSecretConfig, KResult, KmsError, SecretBackend,
    common::{parse_uri, resolve_async},
};

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

    /// Determine http/https scheme and default port from host string.
    fn server_url(&self, host_port: &str) -> String {
        // Exact host match: a prefix test would treat `localhost.evil.com` as loopback.
        let host = host_port.strip_prefix('[').map_or_else(
            || host_port.split(':').next().unwrap_or(host_port),
            |bracketed| bracketed.split(']').next().unwrap_or(bracketed),
        );
        let is_local =
            host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1";
        let scheme = if is_local || self.insecure_certs {
            "http"
        } else {
            "https"
        };
        if host_port.contains(':') {
            format!("{scheme}://{host_port}")
        } else {
            format!("{scheme}://{host_port}:9998")
        }
    }

    /// Send a KMIP Get request and extract the secret string from the response.
    async fn fetch_object(&self, url: &str, id: &str, uri: &str) -> KResult<String> {
        let req_ttlv = to_ttlv(&Get::from(id)).map_err(|e| {
            KmsError::ServerError(format!("KMIP Get serialise error for {uri}: {e}"))
        })?;

        let mut builder = reqwest::Client::builder();
        if self.insecure_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder
            .build()
            .map_err(|e| KmsError::ServerError(format!("HTTP client build error: {e}")))?;

        let endpoint = format!("{}/kmip/2_1", url.trim_end_matches('/'));
        let mut req = client.post(&endpoint).json(&req_ttlv);
        if let Some(t) = &self.token {
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
        let get_resp: GetResponse = from_ttlv(&ttlv).map_err(|e| {
            KmsError::ServerError(format!("Cosmian KMS deserialise error for {uri}: {e}"))
        })?;
        Self::extract_secret(get_resp.object, uri)
    }

    /// Extract a UTF-8 string from a `SecretData` or `OpaqueObject`.
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

impl SecretBackend for CosmianKmsBackend {
    fn resolve(&self, uri: &str) -> KResult<String> {
        let (host_port, object_id) =
            parse_uri(uri, "cosmian-kms", "secret://<host>[:<port>]/<id>")?;
        if object_id.is_empty() {
            return Err(KmsError::InvalidRequest(format!(
                "cosmian-kms URI must have a non-empty object ID: {uri}"
            )));
        }

        let server_url = self.server_url(host_port);
        let object_id = object_id.to_owned();
        let uri_owned = uri.to_owned();
        let backend = Self {
            token: self.token.clone(),
            insecure_certs: self.insecure_certs,
        };

        resolve_async(async move {
            backend
                .fetch_object(&server_url, &object_id, &uri_owned)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::CosmianKmsBackend;

    #[test]
    fn server_url_loopback_exact_match() {
        let backend = CosmianKmsBackend {
            token: None,
            insecure_certs: false,
        };
        assert_eq!(
            backend.server_url("localhost:9998"),
            "http://localhost:9998"
        );
        assert_eq!(backend.server_url("[::1]:9998"), "http://[::1]:9998");
        assert_eq!(
            backend.server_url("localhost.evil.com:9998"),
            "https://localhost.evil.com:9998"
        );
        assert_eq!(
            backend.server_url("127.0.0.1.attacker.com"),
            "https://127.0.0.1.attacker.com:9998"
        );
    }
}
