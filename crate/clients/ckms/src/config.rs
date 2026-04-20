use std::path::PathBuf;

use cosmian_config_utils::{ConfigUtils, location};
use cosmian_kms_cli_actions::reexport::cosmian_kms_client::KmsClientConfig;
use cosmian_kms_logger::debug;
use serde::{Deserialize, Serialize};

use crate::error::CosmianError;

pub const CKMS_CONF_ENV: &str = "CKMS_CONF";
pub(crate) const CKMS_CONF_DEFAULT_SYSTEM_PATH: &str = "/etc/cosmian/ckms.toml";
pub(crate) const CKMS_CONF_PATH: &str = ".cosmian/ckms.toml";

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, Default)]
pub struct ClientConfig {
    #[serde(flatten)]
    pub kms_config: KmsClientConfig,
}

#[expect(clippy::print_stdout)]
impl ClientConfig {
    /// Load the default location of the configuration file.
    ///
    /// # Errors
    /// Return an error if the configuration file is not found or if the file is
    /// not a valid toml file.
    pub fn location(conf: Option<PathBuf>) -> Result<PathBuf, CosmianError> {
        Ok(location(
            conf,
            CKMS_CONF_ENV,
            CKMS_CONF_PATH,
            CKMS_CONF_DEFAULT_SYSTEM_PATH,
        )?)
    }

    /// Load the configuration from a toml file.
    /// # Errors
    /// Return an error if the configuration file is not found or if the file is
    /// not a valid toml file.
    pub fn load(conf_path: Option<PathBuf>) -> Result<Self, CosmianError> {
        let conf_path_buf = Self::location(conf_path)?;
        debug!("Loading configuration from: {conf_path_buf:?}");

        Ok(Self::from_toml(conf_path_buf.to_str().ok_or_else(
            || {
                CosmianError::Default(
                    "Unable to convert the configuration path to a string".to_owned(),
                )
            },
        )?)?)
    }

    /// Save the configuration to a toml file.
    ///
    /// # Errors
    /// Return an error if the configuration file is not found or if the file is
    /// not a valid toml file.
    pub fn save(&self, conf_path: Option<PathBuf>) -> Result<(), CosmianError> {
        let conf_path_buf = Self::location(conf_path)?;
        println!("Saving configuration to: {}", conf_path_buf.display());

        Ok(self.to_toml(conf_path_buf.to_str().ok_or_else(|| {
            CosmianError::Default("Unable to convert the configuration path to a string".to_owned())
        })?)?)
    }
}

impl ConfigUtils for ClientConfig {}

#[allow(clippy::assertions_on_result_states, clippy::unwrap_used)]
#[allow(clippy::expect_used, clippy::print_stdout)]
#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf};

    use cosmian_config_utils::{ConfigUtils, get_default_conf_path};
    use cosmian_kms_logger::log_init;

    use super::ClientConfig;
    use crate::config::{CKMS_CONF_ENV, CKMS_CONF_PATH};

    #[test]
    fn test_toml_roundtrip() {
        let config = ClientConfig::default();
        let tmp_path = std::env::temp_dir().join("ckms_roundtrip_test.toml");
        let tmp_str = tmp_path.to_str().expect("valid path");
        // Write the config to TOML
        config
            .to_toml(tmp_str)
            .expect("Failed to serialize ClientConfig to TOML");
        // Read back the TOML content
        let toml_str = std::fs::read_to_string(tmp_str).expect("Failed to read TOML file");
        println!("Serialized ClientConfig (default):\n{toml_str}");
        assert!(!toml_str.is_empty(), "Serialized TOML should not be empty");
        assert!(
            toml_str.contains("http_config"),
            "Serialized TOML should contain http_config section"
        );
        // Also check that we can deserialize it back
        let restored =
            ClientConfig::from_toml(tmp_str).expect("Failed to deserialize ClientConfig from TOML");
        assert_eq!(config, restored, "Round-trip should preserve the config");
        drop(std::fs::remove_file(tmp_str));
    }

    #[test]
    fn test_toml_roundtrip_with_cert_auth() {
        use cosmian_kms_cli_actions::reexport::cosmian_kms_client::{
            KmsClientConfig, reexport::cosmian_http_client::HttpClientConfig,
        };

        // Simulate a cert-auth config like the test server would create
        let http_config = HttpClientConfig {
            server_url: "https://localhost:9999".to_owned(),
            accept_invalid_certs: true,
            tls_client_pkcs12_path: Some("/path/to/owner.client.p12".to_owned()),
            tls_client_pkcs12_password: Some("password".to_owned()),
            ..HttpClientConfig::default()
        };
        let config = ClientConfig {
            kms_config: KmsClientConfig {
                http_config,
                print_json: Some(false),
                ..KmsClientConfig::default()
            },
        };
        let tmp_path = std::env::temp_dir().join("ckms_roundtrip_cert_auth_test.toml");
        let tmp_str = tmp_path.to_str().expect("valid path");
        // Write the config to TOML
        config
            .to_toml(tmp_str)
            .expect("Failed to serialize cert-auth ClientConfig to TOML");
        // Read back the TOML content
        let toml_str = std::fs::read_to_string(tmp_str).expect("Failed to read TOML file");
        println!("Serialized ClientConfig (cert auth):\n{toml_str}");
        assert!(!toml_str.is_empty(), "Serialized TOML should not be empty");
        assert!(
            toml_str.contains("http_config"),
            "Serialized TOML should contain http_config section"
        );
        assert!(
            toml_str.contains("https://localhost:9999"),
            "Serialized TOML should contain server URL"
        );
        // Also check that we can deserialize it back
        let restored = ClientConfig::from_toml(tmp_str)
            .expect("Failed to deserialize cert-auth ClientConfig from TOML");
        assert_eq!(
            config, restored,
            "Round-trip should preserve the cert-auth config"
        );
        drop(std::fs::remove_file(tmp_str));
    }

    #[allow(unsafe_code)]
    #[test]
    pub(crate) fn test_load() {
        log_init(None);
        // valid conf
        unsafe {
            env::set_var(CKMS_CONF_ENV, "../../../test_data/configs/ckms.toml");
        }
        assert!(ClientConfig::load(None).is_ok());

        // another valid conf
        unsafe {
            env::set_var(
                CKMS_CONF_ENV,
                "../../../test_data/configs/ckms_partial.toml",
            );
        }
        assert!(ClientConfig::load(None).is_ok());

        // Default conf file
        unsafe {
            env::remove_var(CKMS_CONF_ENV);
        }
        let default_conf = get_default_conf_path(CKMS_CONF_PATH).unwrap();
        drop(fs::remove_file(&default_conf));
        assert!(ClientConfig::load(None).is_ok());
        let resolved_conf = ClientConfig::location(None).unwrap();
        assert!(resolved_conf.exists());
        if resolved_conf == default_conf {
            assert!(default_conf.exists());
        }

        // invalid conf
        unsafe {
            env::set_var(CKMS_CONF_ENV, "../../../test_data/configs/ckms.bad.toml");
        }
        let e = ClientConfig::load(None).err().unwrap().to_string();
        assert!(e.contains("missing field `server_url`"));

        // with a file
        unsafe {
            env::remove_var(CKMS_CONF_ENV);
        }
        let conf_path =
            ClientConfig::location(Some(PathBuf::from("../../../test_data/configs/ckms.toml")))
                .unwrap();

        assert!(ClientConfig::from_toml(conf_path.to_str().unwrap()).is_ok());
    }
}
