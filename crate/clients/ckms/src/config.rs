use std::path::PathBuf;

use cosmian_config_utils::{ConfigUtils, location};
use cosmian_kms_cli::reexport::cosmian_kms_client::KmsClientConfig;
use cosmian_logger::debug;
use serde::{Deserialize, Serialize};

use crate::error::CosmianError;

pub const CKMS_CONF_ENV: &str = "CKMS_CONF";
pub(crate) const CKMS_CONF_DEFAULT_SYSTEM_PATH: &str = "/etc/cosmian/cosmian.toml";
pub(crate) const CKMS_CONF_PATH: &str = ".cosmian/cosmian.toml";

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, Default)]
pub struct ClientConfig {
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

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf};

    use cosmian_config_utils::{ConfigUtils, get_default_conf_path};
    use cosmian_logger::log_init;

    use super::ClientConfig;
    use crate::config::{CKMS_CONF_ENV, CKMS_CONF_PATH};

    #[allow(unsafe_code)]
    #[test]
    pub(crate) fn test_load() {
        log_init(None);
        // valid conf
        unsafe {
            env::set_var(CKMS_CONF_ENV, "../../../test_data/configs/cosmian.toml");
        }
        assert!(ClientConfig::load(None).is_ok());

        // another valid conf
        unsafe {
            env::set_var(
                CKMS_CONF_ENV,
                "../../../test_data/configs/cosmian_partial.toml",
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
            env::set_var(CKMS_CONF_ENV, "../../../test_data/configs/cosmian.bad.toml");
        }
        let e = ClientConfig::load(None).err().unwrap().to_string();
        assert!(e.contains("missing field `server_url`"));

        // with a file
        unsafe {
            env::remove_var(CKMS_CONF_ENV);
        }
        let conf_path = ClientConfig::location(Some(PathBuf::from(
            "../../../test_data/configs/cosmian.toml",
        )))
        .unwrap();

        assert!(ClientConfig::from_toml(conf_path.to_str().unwrap()).is_ok());
    }
}
