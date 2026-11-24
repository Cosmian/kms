use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use cosmian_config_utils::{ConfigUtils, location};
use cosmian_kms_cli_actions::reexport::cosmian_kms_client::{KmsClientConfig, create_private_file};
use cosmian_logger::debug;
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
        writeln!(
            std::io::stdout().lock(),
            "Saving configuration to: {}",
            conf_path_buf.display()
        )?;
        self.save_to(&conf_path_buf)
    }

    /// Write the configuration to `path`, readable by its owner only (0600 on Unix).
    ///
    /// The TOML is written to an owner-only temporary file next to `path`, then renamed over it:
    /// the file is never truncated, left empty or briefly readable by others, and the previous
    /// content survives any failure.
    ///
    /// # Errors
    /// Return an error if the configuration cannot be serialized or written.
    pub(crate) fn save_to(&self, path: &Path) -> Result<(), CosmianError> {
        let mut tmp_name = path
            .file_name()
            .map(std::ffi::OsString::from)
            .ok_or_else(|| {
                CosmianError::Default(format!("Invalid configuration path: {}", path.display()))
            })?;
        tmp_name.push(format!(".{}.tmp", std::process::id()));
        let tmp = path.with_file_name(tmp_name);
        let tmp_str = tmp.to_str().ok_or_else(|| {
            CosmianError::Default("Unable to convert the configuration path to a string".to_owned())
        })?;
        // `to_toml` truncates in place, so the temporary file keeps this owner-only mode.
        drop(create_private_file(&tmp)?);
        let written = self
            .to_toml(tmp_str)
            .map_err(CosmianError::from)
            .and_then(|()| {
                fs::rename(&tmp, path).map_err(|e| {
                    CosmianError::Default(format!(
                        "Unable to replace the configuration file {}: {e}",
                        path.display()
                    ))
                })
            });
        if written.is_err() {
            drop(fs::remove_file(&tmp));
        }
        written
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

    #[expect(unsafe_code, reason = "std::env::set_var is unsafe in edition 2024")]
    #[test]
    pub(crate) fn test_load() {
        log_init(None);
        // valid conf
        unsafe {
            env::set_var(
                CKMS_CONF_ENV,
                "../../../test_data/configs/client/default.toml",
            );
        }
        ClientConfig::load(None).unwrap();

        // another valid conf
        unsafe {
            env::set_var(
                CKMS_CONF_ENV,
                "../../../test_data/configs/client/partial.toml",
            );
        }
        ClientConfig::load(None).unwrap();

        // Default conf file
        unsafe {
            env::remove_var(CKMS_CONF_ENV);
        }
        let default_conf = get_default_conf_path(CKMS_CONF_PATH).unwrap();
        drop(fs::remove_file(&default_conf));
        ClientConfig::load(None).unwrap();
        let resolved_conf = ClientConfig::location(None).unwrap();
        assert!(resolved_conf.exists());
        if resolved_conf == default_conf {
            assert!(default_conf.exists());
        }

        // invalid conf
        unsafe {
            env::set_var(CKMS_CONF_ENV, "../../../test_data/configs/client/bad.toml");
        }
        let e = ClientConfig::load(None).err().unwrap().to_string();
        assert!(e.contains("missing field `server_url`"));

        // with a file
        unsafe {
            env::remove_var(CKMS_CONF_ENV);
        }
        let conf_path = ClientConfig::location(Some(PathBuf::from(
            "../../../test_data/configs/client/default.toml",
        )))
        .unwrap();

        ClientConfig::from_toml(conf_path.to_str().unwrap()).unwrap();
    }

    /// An unknown key in the client TOML config must be rejected.
    #[test]
    fn unknown_key_in_client_toml_is_rejected() {
        use cosmian_config_utils::ConfigUtils;
        let bad_toml = "[http_config]\nserver_url = \"http://localhost:9998\"\n\nunknown_option \
                        = true\n";
        let tmp_path = std::env::temp_dir().join("ckms_bad_unknown_key.toml");
        let tmp_str = tmp_path.to_str().expect("valid path");
        std::fs::write(tmp_str, bad_toml).expect("write temp toml");
        let result = ClientConfig::from_toml(tmp_str);
        assert!(
            result.is_err(),
            "unknown key in client config must be rejected"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown_option") || err_msg.contains("unknown field"),
            "error message must identify the unknown key; got: {err_msg}"
        );
        drop(std::fs::remove_file(tmp_str));
    }

    /// An unknown key inside `[http_config]` must be rejected.
    ///
    /// Note: the `toml` v0.8 crate does not propagate the unknown-field name into
    /// the error message for nested struct deserialisation (it reports a generic
    /// "TOML parse error at line N, column M" instead of naming the offending key).
    /// The important guarantee is that the load is rejected — not the exact message.
    #[test]
    fn unknown_key_in_http_config_is_rejected() {
        use cosmian_config_utils::ConfigUtils;
        let bad_toml =
            "[http_config]\nserver_url = \"http://localhost:9998\"\ntypo_url = \"wrong\"\n";
        let tmp_path = std::env::temp_dir().join("ckms_bad_nested_key.toml");
        let tmp_str = tmp_path.to_str().expect("valid path");
        std::fs::write(tmp_str, bad_toml).expect("write temp toml");
        let result = ClientConfig::from_toml(tmp_str);
        assert!(
            result.is_err(),
            "unknown key in [http_config] must be rejected"
        );
        drop(std::fs::remove_file(tmp_str));
    }

    #[cfg(unix)]
    #[test]
    fn test_save_to_is_owner_only_and_leaves_no_temp_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ckms.toml");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let config = ClientConfig::default();
        config.save_to(&path).unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            ClientConfig::from_toml(path.to_str().unwrap()).unwrap(),
            config
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn test_save_to_failure_keeps_target_and_removes_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        // a directory cannot be replaced by a file: the rename fails
        let path = dir.path().join("ckms.toml");
        fs::create_dir(&path).unwrap();

        assert!(ClientConfig::default().save_to(&path).is_err());
        assert!(path.is_dir());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
