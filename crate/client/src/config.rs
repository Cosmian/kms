use std::path::PathBuf;

use cosmian_config_utils::{location, ConfigUtils};
use cosmian_http_client::HttpClientConfig;
use cosmian_logger::reexport::tracing::warn;
use serde::{Deserialize, Serialize};

use crate::KmsClientError;

pub const KMS_CLI_CONF_ENV: &str = "KMS_CLI_CONF";
pub(crate) const KMS_CLI_CONF_DEFAULT_SYSTEM_PATH: &str = "/etc/cosmian/kms.json";
pub(crate) const KMS_CLI_CONF_PATH: &str = ".cosmian/kms.json";

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conf_path: Option<PathBuf>,
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
            conf_path: None,
            gmail_api_conf: None,
            print_json: None,
        }
    }
}

impl KmsClientConfig {
    pub fn location(config: Option<PathBuf>) -> Result<PathBuf, KmsClientError> {
        Ok(location(
            config,
            KMS_CLI_CONF_ENV,
            KMS_CLI_CONF_PATH,
            KMS_CLI_CONF_DEFAULT_SYSTEM_PATH,
        )?)
    }

    pub fn load(config: &PathBuf) -> Result<KmsClientConfig, KmsClientError> {
        match KmsClientConfig::from_json(config) {
            Ok(config) => Ok(config),
            Err(e) => {
                warn!(
                    "Error loading KMS client configuration from JSON format: {}",
                    e
                );
                Ok(KmsClientConfig::from_toml(config)?)
            }
        }
    }
}

impl ConfigUtils for KmsClientConfig {}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        path::{Path, PathBuf},
    };

    use cosmian_config_utils::{get_default_conf_path, ConfigUtils};
    use cosmian_logger::log_init;

    use super::{KmsClientConfig, KMS_CLI_CONF_ENV};
    use crate::config::KMS_CLI_CONF_PATH;

    #[test]
    pub(crate) fn test_save() {
        let conf_path = Path::new("/tmp/kms.json").to_path_buf();
        log_init(None);
        let conf = KmsClientConfig {
            conf_path: Some(conf_path.clone()),
            ..Default::default()
        };
        conf.to_toml(&conf_path).unwrap();

        let loaded_config = KmsClientConfig::load(&conf_path).unwrap();
        assert_eq!(loaded_config.conf_path, conf.conf_path);
    }

    #[test]
    pub(crate) fn test_load() {
        log_init(None);
        // valid conf
        unsafe {
            env::set_var(KMS_CLI_CONF_ENV, "../../test_data/configs/kms.json");
        }
        let conf_path = KmsClientConfig::location(None).unwrap();
        assert!(KmsClientConfig::load(&conf_path).is_ok());

        // another valid conf
        unsafe {
            env::set_var(KMS_CLI_CONF_ENV, "../../test_data/configs/kms_partial.json");
        }
        let conf_path = KmsClientConfig::location(None).unwrap();
        assert!(KmsClientConfig::load(&conf_path).is_ok());

        // Default conf file
        unsafe {
            env::remove_var(KMS_CLI_CONF_ENV);
        }
        let _ = fs::remove_file(get_default_conf_path(KMS_CLI_CONF_PATH).unwrap());
        let conf_path = KmsClientConfig::location(None).unwrap();
        assert!(KmsClientConfig::load(&conf_path).is_ok());
        assert!(get_default_conf_path(KMS_CLI_CONF_PATH).unwrap().exists());

        // invalid conf
        unsafe {
            env::set_var(KMS_CLI_CONF_ENV, "../../test_data/configs/kms.bad.toml");
        }
        let conf_path = KmsClientConfig::location(None).unwrap();
        let e = KmsClientConfig::load(&conf_path).err().unwrap().to_string();
        assert!(e.contains("missing field `server_url`"));

        // with a file
        unsafe {
            env::remove_var(KMS_CLI_CONF_ENV);
        }
        let conf_path =
            KmsClientConfig::location(Some(PathBuf::from("../../test_data/configs/kms.json")))
                .unwrap();
        assert!(KmsClientConfig::load(&conf_path).is_ok());
    }
}
