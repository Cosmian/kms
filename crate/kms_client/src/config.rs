use serde::{Deserialize, Serialize};

use crate::http_client::HttpClientConfig;

/// The configuration that is used by the google command
/// to perform actions over Gmail API.
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct GmailApiConf {
    #[serde(rename = "type")]
    pub account_type: String,
    pub project_id: String,
    pub private_key_id: String,
    pub private_key: String,
    pub client_email: String,
    pub client_id: String,
    pub auth_uri: String,
    pub token_uri: String,
    pub auth_provider_x509_cert_url: String,
    pub client_x509_cert_url: String,
    pub universe_domain: String,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct KmsClientConfig {
    pub http_config: HttpClientConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gmail_api_conf: Option<GmailApiConf>,
    /// will output the JSON KMIP request and response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub print_json: Option<bool>,
}

impl Default for KmsClientConfig {
    fn default() -> Self {
        Self {
            http_config: HttpClientConfig {
                server_url: "http://0.0.0.0:9998".to_owned(),
                ..HttpClientConfig::default()
            },
            gmail_api_conf: None,
            print_json: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{KmsClient, KmsClientConfig};

    /// A valid `"Name: Value"` string should be accepted without error.
    #[test]
    fn test_custom_headers_valid() {
        let mut config = KmsClientConfig::default();
        config.http_config.custom_headers = Some(vec!["X-My-Header: my-value".to_owned()]);
        assert!(
            KmsClient::new_with_config(config).is_ok(),
            "valid header should be accepted"
        );
    }

    /// Multiple valid headers should all be accepted.
    #[test]
    fn test_custom_headers_multiple_valid() {
        let mut config = KmsClientConfig::default();
        config.http_config.custom_headers = Some(vec![
            "X-First: first".to_owned(),
            "X-Second: second".to_owned(),
        ]);
        assert!(
            KmsClient::new_with_config(config).is_ok(),
            "multiple valid headers should be accepted"
        );
    }

    /// A string without a colon separator must be rejected at construction time.
    #[test]
    fn test_custom_headers_missing_colon_is_error() {
        let mut config = KmsClientConfig::default();
        config.http_config.custom_headers = Some(vec!["InvalidHeaderNoColo".to_owned()]);
        let result = KmsClient::new_with_config(config);
        assert!(
            result.is_err(),
            "expected an error for header without colon"
        );
        if let Err(e) = result {
            assert!(
                e.to_string().contains("InvalidHeaderNoColo"),
                "error message should reference the bad header: {e}"
            );
        }
    }

    /// A header with an invalid name (non-ASCII) must be rejected.
    #[test]
    fn test_custom_headers_invalid_name_is_error() {
        let mut config = KmsClientConfig::default();
        config.http_config.custom_headers = Some(vec!["X-Héader: value".to_owned()]);
        assert!(
            KmsClient::new_with_config(config).is_err(),
            "non-ASCII header name should be rejected"
        );
    }

    /// `None` (no custom headers configured) is accepted silently.
    #[test]
    fn test_custom_headers_none_is_ok() {
        let config = KmsClientConfig::default();
        assert!(
            KmsClient::new_with_config(config).is_ok(),
            "None custom_headers should be accepted"
        );
    }

    /// Serialisation round-trip: `custom_headers` must survive TOML
    /// serialise → deserialise.
    #[test]
    #[allow(clippy::panic_in_result_fn)]
    fn test_custom_headers_toml_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let mut original = KmsClientConfig::default();
        original.http_config.custom_headers = Some(vec![
            "X-Token: abc123".to_owned(),
            "X-Env: production".to_owned(),
        ]);
        let toml_str = toml::to_string(&original)?;
        let restored: KmsClientConfig = toml::from_str(&toml_str)?;
        assert_eq!(
            original.http_config.custom_headers,
            restored.http_config.custom_headers
        );
        Ok(())
    }
}
