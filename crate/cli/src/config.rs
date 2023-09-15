use std::{
    env,
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};

use cosmian_kms_client::{BootstrapRestClient, KmsRestClient};
use serde::{Deserialize, Serialize};

use crate::error::{result::CliResultHelper, CliError};

/// Returns the path to the current user's home folder.
///
/// On Linux and macOS, the home folder is typically located at `/home/<username>`
/// or `/Users/<username>`, respectively. On Windows, the home folder is typically
/// located at `C:\Users\<username>`. However, the location of the home folder can
/// be changed by the user or by system administrators, so it's important to check
/// for the existence of the appropriate environment variables.
///
/// Returns `None` if the home folder cannot be determined.
fn get_home_folder() -> Option<PathBuf> {
    // Check for the existence of the HOME environment variable on Linux and macOS
    if let Some(home) = env::var_os("HOME") {
        return Some(PathBuf::from(home))
    }
    // Check for the existence of the USERPROFILE environment variable on Windows
    else if let Some(profile) = env::var_os("USERPROFILE") {
        return Some(PathBuf::from(profile))
    }
    // Check for the existence of the HOMEDRIVE and HOMEPATH environment variables on Windows
    else if let (Some(hdrive), Some(hpath)) = (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH"))
    {
        let mut path = PathBuf::new();
        path.push(hdrive);
        path.push(hpath);
        return Some(path)
    }
    // If none of the above environment variables exist, the home folder cannot be determined
    None
}

/// Returns the default configuration path
///  or an error if the home folder cannot be determined
fn get_default_conf_path() -> Result<PathBuf, CliError> {
    get_home_folder()
        .ok_or_else(|| CliError::NotSupported("unable to determine the home folder".to_owned()))
        .map(|home| home.join(".cosmian/kms.json"))
}

/// used for serialization
fn not(b: &bool) -> bool {
    !*b
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct CliConf {
    // accept_invalid_certs is useful if the cli needs to connect to an HTTPS KMS server
    // running an invalid or unsecure SSL certificate
    #[serde(default)]
    #[serde(skip_serializing_if = "not")]
    pub(crate) accept_invalid_certs: bool,
    pub(crate) kms_server_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) bootstrap_server_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kms_access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ssl_client_pkcs12_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ssl_client_pkcs12_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kms_database_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) jwe_public_key: Option<String>,
}

impl Default for CliConf {
    fn default() -> Self {
        Self {
            accept_invalid_certs: false,
            kms_server_url: "http://0.0.0.0:9998".to_string(),
            bootstrap_server_url: None,
            kms_access_token: None,
            kms_database_secret: None,
            ssl_client_pkcs12_path: None,
            ssl_client_pkcs12_password: None,
            jwe_public_key: None,
        }
    }
}

/// This method is used to configure the KMS CLI by reading a JSON configuration file.
///
/// The method looks for a JSON configuration file with the following structure:
///
/// ```json
/// {
///     "accept_invalid_certs": false,
///     "kms_server_url": "http://127.0.0.1:9998",
///     "bootstrap_server_url": "https://127.0.0.1:9998",
///     "kms_access_token": "AA...AAA",
///     "kms_database_secret": "BB...BBB",
///     "ssl_client_pkcs12_path": "/path/to/client.p12",
///     "ssl_client_pkcs12_password": "password"
/// }
/// ```
/// The path to the configuration file is specified through the `KMS_CLI_CONF` environment variable.
/// If the environment variable is not set, a default path is used.
/// If the configuration file does not exist at the path, a new file is created with default values.
///
/// This function returns a KMS client configured according to the settings specified in the configuration file.
pub const KMS_CLI_CONF_ENV: &str = "KMS_CLI_CONF";

impl CliConf {
    pub fn load() -> Result<(KmsRestClient, BootstrapRestClient), CliError> {
        // Obtain the configuration file path from the environment variable or default to a pre-determined path
        let conf_path = if let Ok(conf_path) = env::var(KMS_CLI_CONF_ENV).map(PathBuf::from) {
            // Error if the specified file does not exist
            if !conf_path.exists() {
                return Err(CliError::NotSupported(format!(
                    "Configuration file {conf_path:?} does not exist"
                )))
            }
            conf_path
        } else {
            get_default_conf_path()?
        };

        // Deserialize the configuration from the file, or create a default configuration if none exists
        let conf = if conf_path.exists() {
            // Configuration file exists, read and deserialize it
            let file = File::open(&conf_path)
                .with_context(|| format!("Unable to read configuration file {:?}", conf_path))?;
            serde_json::from_reader(BufReader::new(file)).with_context(|| {
                format!("Error while parsing configuration file {:?}", conf_path)
            })?
        } else {
            // Configuration file doesn't exist, create it with default values and serialize it
            let parent = conf_path
                .parent()
                .with_context(|| format!("Unable to get parent directory of {:?}", conf_path))?;
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Unable to create directory for configuration file {:?}",
                    parent
                )
            })?;
            let default_conf = Self::default();
            fs::write(
                &conf_path,
                serde_json::to_string(&default_conf).with_context(|| {
                    format!(
                        "Unable to serialize default configuration {:?}",
                        default_conf
                    )
                })?,
            )
            .with_context(|| {
                format!(
                    "Unable to write default configuration to file {:?}",
                    conf_path
                )
            })?;
            default_conf
        };

        // Instantiate a KMS server REST client with the given configuration
        let kms_rest_client = KmsRestClient::instantiate(
            &conf.kms_server_url,
            conf.kms_access_token.as_deref(),
            conf.ssl_client_pkcs12_path.as_deref(),
            conf.ssl_client_pkcs12_password.as_deref(),
            conf.kms_database_secret.as_deref(),
            conf.accept_invalid_certs,
            conf.jwe_public_key.as_deref(),
        )
        .with_context(|| {
            format!(
                "Unable to instantiate a KMS server REST client {}",
                &conf.kms_server_url
            )
        })?;

        // Instantiate a Bootstrap server REST client with the given configuration
        let bootstrap_rest_client = BootstrapRestClient::instantiate(
            conf.bootstrap_server_url
                .as_ref()
                .unwrap_or(&conf.kms_server_url.replace("http://", "https://")),
            conf.kms_access_token.as_deref(),
            conf.ssl_client_pkcs12_path.as_deref(),
            conf.ssl_client_pkcs12_password.as_deref(),
        )
        .with_context(|| {
            format!(
                "Unable to instantiate a Bootstrap server REST client {}",
                &conf.kms_server_url
            )
        })?;

        Ok((kms_rest_client, bootstrap_rest_client))
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use super::{get_default_conf_path, CliConf, KMS_CLI_CONF_ENV};

    #[test]
    pub fn test_load() {
        // valid conf
        env::set_var(KMS_CLI_CONF_ENV, "test_data/configs/kms.json");
        assert!(CliConf::load().is_ok());

        // another valid conf
        env::set_var(KMS_CLI_CONF_ENV, "test_data/configs/kms_partial.json");
        assert!(CliConf::load().is_ok());

        // Default conf file
        env::remove_var(KMS_CLI_CONF_ENV);
        let _ = fs::remove_file(get_default_conf_path().unwrap());
        assert!(CliConf::load().is_ok());
        assert!(get_default_conf_path().unwrap().exists());

        // invalid conf
        env::set_var(KMS_CLI_CONF_ENV, "test_data/configs/kms.bad");
        let e = CliConf::load().err().unwrap().to_string();
        assert!(e.contains("missing field `kms_server_url`"));
    }
}
