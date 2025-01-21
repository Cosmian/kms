use std::path::PathBuf;

use cosmian_config_utils::{location, ConfigUtils};
use cosmian_http_client::HttpClientConfig;
use serde::{Deserialize, Serialize};

use crate::KmsClientError;

pub const KMS_CLI_CONF_ENV: &str = "KMS_CLI_CONF";
pub(crate) const KMS_CLI_CONF_DEFAULT_SYSTEM_PATH: &str = "/etc/cosmian/kms.toml";
pub(crate) const KMS_CLI_CONF_PATH: &str = ".cosmian/kms.toml";

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

impl KmsClientConfig {
    pub fn location(conf_path: Option<PathBuf>) -> Result<PathBuf, KmsClientError> {
        Ok(location(
            conf_path,
            KMS_CLI_CONF_ENV,
            KMS_CLI_CONF_PATH,
            KMS_CLI_CONF_DEFAULT_SYSTEM_PATH,
        )?)
    }

    pub fn load(conf_path: Option<PathBuf>) -> Result<Self, KmsClientError> {
        let conf_path_buf = KmsClientConfig::location(conf_path)?;

        Ok(KmsClientConfig::from_toml(
            conf_path_buf.to_str().ok_or_else(|| {
                KmsClientError::Default(
                    "Unable to convert the configuration path to a string".to_owned(),
                )
            })?,
        )?)
    }

    pub fn save(&self, conf_path: Option<PathBuf>) -> Result<(), KmsClientError> {
        let conf_path_buf = KmsClientConfig::location(conf_path)?;

        self.to_toml(conf_path_buf.to_str().ok_or_else(|| {
            KmsClientError::Default(
                "Unable to convert the configuration path to a string".to_owned(),
            )
        })?)?;
        println!("Saving configuration to: {conf_path_buf:?}");

        Ok(())
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
        let conf_path = Path::new("/tmp/kms.toml").to_path_buf();
        log_init(None);
        let conf = KmsClientConfig::default();
        conf.to_toml(conf_path.to_str().unwrap()).unwrap();

        let _loaded_config = KmsClientConfig::from_toml(conf_path.to_str().unwrap()).unwrap();
    }

    #[test]
    pub(crate) fn test_load() {
        log_init(None);
        // valid conf
        unsafe {
            env::set_var(KMS_CLI_CONF_ENV, "../../test_data/configs/kms.toml");
        }
        let conf_path = KmsClientConfig::location(None).unwrap();
        assert!(KmsClientConfig::from_toml(conf_path.to_str().unwrap()).is_ok());

        // another valid conf
        unsafe {
            env::set_var(KMS_CLI_CONF_ENV, "../../test_data/configs/kms_partial.toml");
        }
        let conf_path = KmsClientConfig::location(None).unwrap();
        assert!(KmsClientConfig::from_toml(conf_path.to_str().unwrap()).is_ok());

        // Default conf file
        unsafe {
            env::remove_var(KMS_CLI_CONF_ENV);
        }
        let _ = fs::remove_file(get_default_conf_path(KMS_CLI_CONF_PATH).unwrap());
        let conf_path = KmsClientConfig::location(None).unwrap();
        assert!(KmsClientConfig::from_toml(conf_path.to_str().unwrap()).is_ok());
        assert!(get_default_conf_path(KMS_CLI_CONF_PATH).unwrap().exists());

        // invalid conf
        unsafe {
            env::set_var(KMS_CLI_CONF_ENV, "../../test_data/configs/kms.bad.toml");
        }
        let conf_path = KmsClientConfig::location(None).unwrap();
        let e = KmsClientConfig::from_toml(conf_path.to_str().unwrap())
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("missing field `server_url`"));

        // with a file
        unsafe {
            env::remove_var(KMS_CLI_CONF_ENV);
        }
        let conf_path =
            KmsClientConfig::location(Some(PathBuf::from("../../test_data/configs/kms.toml")))
                .unwrap();
        assert!(KmsClientConfig::from_toml(conf_path.to_str().unwrap()).is_ok());
    }
}
