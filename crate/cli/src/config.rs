use std::path::PathBuf;

use cosmian_config_utils::{ConfigUtils, location};
use cosmian_findex_cli::reexports::cosmian_findex_client::FindexClientConfig;
use cosmian_kms_cli::reexport::cosmian_kms_client::KmsClientConfig;
use serde::{Deserialize, Serialize};

use crate::error::CosmianError;

pub const COSMIAN_CLI_CONF_ENV: &str = "COSMIAN_CLI_CONF";
pub(crate) const COSMIAN_CLI_CONF_DEFAULT_SYSTEM_PATH: &str = "/etc/cosmian/cosmian.toml";
pub(crate) const COSMIAN_CLI_CONF_PATH: &str = ".cosmian/cosmian.toml";

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct ClientConf {
    pub kms_config: KmsClientConfig,
    pub findex_config: Option<FindexClientConfig>,
}

impl Default for ClientConf {
    fn default() -> Self {
        Self {
            kms_config: KmsClientConfig::default(),
            findex_config: Some(FindexClientConfig::default()),
        }
    }
}

impl ClientConf {
    /// Load the default location of the configuration file.
    ///
    /// # Errors
    /// Return an error if the configuration file is not found or if the file is not a valid toml file.
    pub fn location(conf: Option<PathBuf>) -> Result<PathBuf, CosmianError> {
        Ok(location(
            conf,
            COSMIAN_CLI_CONF_ENV,
            COSMIAN_CLI_CONF_PATH,
            COSMIAN_CLI_CONF_DEFAULT_SYSTEM_PATH,
        )?)
    }
}

impl ConfigUtils for ClientConf {}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf};

    use cosmian_config_utils::{ConfigUtils, get_default_conf_path};
    use cosmian_logger::log_init;

    use super::{COSMIAN_CLI_CONF_ENV, ClientConf};
    use crate::config::COSMIAN_CLI_CONF_PATH;

    #[test]
    pub(crate) fn test_load() {
        log_init(None);
        // valid conf
        unsafe {
            env::set_var(COSMIAN_CLI_CONF_ENV, "../../test_data/configs/cosmian.toml");
        }
        let conf_path = ClientConf::location(None).unwrap();
        assert!(ClientConf::from_toml(&conf_path).is_ok());

        // another valid conf
        unsafe {
            env::set_var(
                COSMIAN_CLI_CONF_ENV,
                "../../test_data/configs/cosmian_partial.toml",
            );
        }
        let conf_path = ClientConf::location(None).unwrap();
        assert!(ClientConf::from_toml(&conf_path).is_ok());

        // Default conf file
        unsafe {
            env::remove_var(COSMIAN_CLI_CONF_ENV);
        }
        drop(fs::remove_file(
            get_default_conf_path(COSMIAN_CLI_CONF_PATH).unwrap(),
        ));
        let conf_path = ClientConf::location(None).unwrap();
        assert!(ClientConf::from_toml(&conf_path).is_ok());
        assert!(
            get_default_conf_path(COSMIAN_CLI_CONF_PATH)
                .unwrap()
                .exists()
        );

        // invalid conf
        unsafe {
            env::set_var(
                COSMIAN_CLI_CONF_ENV,
                "../../test_data/configs/cosmian.bad.toml",
            );
        }
        let conf_path = ClientConf::location(None).unwrap();
        let e = ClientConf::from_toml(&conf_path).err().unwrap().to_string();
        assert!(e.contains("missing field `server_url`"));

        // with a file
        unsafe {
            env::remove_var(COSMIAN_CLI_CONF_ENV);
        }
        let conf_path =
            ClientConf::location(Some(PathBuf::from("../../test_data/configs/cosmian.toml")))
                .unwrap();

        assert!(ClientConf::from_toml(&conf_path).is_ok());
    }
}
