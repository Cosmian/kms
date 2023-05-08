use std::{
    env,
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};

use cosmian_kms_client::KmsRestClient;
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

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct CliConf {
    // Insecure is useful if the cli needs to connect to an HTTPS KMS using unsecured SSL certificate
    #[serde(default)]
    #[serde(skip_serializing_if = "not")]
    pub accept_invalid_certs: bool,
    pub kms_server_url: String,
    kms_access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_database_secret: Option<String>,
}

impl Default for CliConf {
    fn default() -> Self {
        Self {
            accept_invalid_certs: false,
            kms_server_url: "http://localhost:9998".to_string(),
            kms_access_token: "".to_string(),
            kms_database_secret: None,
        }
    }
}

/// Define the configuration of the CLI reading a json
///
/// {
///     "accept_invalid_certs": false
///     "`kms_server_url"`: "http://127.0.0.1:9998",
///     "`kms_access_token"`: "AA...AAA"
///     "`kms_database_secret"`: "BB...BBB"
/// }
///
pub const KMS_CLI_CONF_ENV: &str = "KMS_CLI_CONF";

impl CliConf {
    pub fn load() -> Result<KmsRestClient, CliError> {
        // Read the configuration file path from the environment variable or use a default value
        let cli_conf_filename = env::var(KMS_CLI_CONF_ENV)
            .map(PathBuf::from)
            .or_else(|_| get_default_conf_path())?;

        // Convert the configuration file path to a PathBuf
        let conf_path = PathBuf::from(&cli_conf_filename);

        // Check if the configuration file exists
        let conf = match conf_path.exists() {
            // If the configuration file exists, read it and deserialize it
            true => {
                let file = File::open(&cli_conf_filename)
                    .with_context(|| format!("Can't read {:?}", cli_conf_filename))?;
                serde_json::from_reader(BufReader::new(file))
                    .with_context(|| format!("Config JSON malformed in {:?}", cli_conf_filename))?
            }
            // If the configuration file doesn't exist, create it with default values and serialize it
            false => {
                let parent = conf_path
                    .parent()
                    .with_context(|| format!("cannot get parent of {:?}", conf_path))?;
                fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create all directories of {:?}", parent))?;
                let default_conf = CliConf::default();
                fs::write(
                    &conf_path,
                    serde_json::to_string(&default_conf).with_context(|| {
                        format!(
                            "cannot serialize the default configuration {:?}",
                            &default_conf
                        )
                    })?,
                )
                .with_context(|| {
                    format!("cannot write the default configuration to {:?}", conf_path)
                })?;
                default_conf
            }
        };

        // Create a client to query the KMS
        let kms_connector = KmsRestClient::instantiate(
            &conf.kms_server_url,
            &conf.kms_access_token,
            conf.kms_database_secret.as_deref(),
            conf.accept_invalid_certs,
        )
        .with_context(|| {
            format!(
                "Can't build the query to connect to the kms server {}",
                &conf.kms_server_url
            )
        })?;

        Ok(kms_connector)
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use super::{get_default_conf_path, CliConf, KMS_CLI_CONF_ENV};

    #[test]
    pub fn test_load() {
        // valid conf
        env::set_var(KMS_CLI_CONF_ENV, "test_data/kms.json");
        assert!(CliConf::load().is_ok());

        // another valid conf
        env::set_var(KMS_CLI_CONF_ENV, "test_data/kms_partial.json");
        assert!(CliConf::load().is_ok());

        // Default conf file
        env::remove_var(KMS_CLI_CONF_ENV);
        let _ = fs::remove_file(get_default_conf_path().unwrap());
        assert!(CliConf::load().is_ok());
        assert!(get_default_conf_path().unwrap().exists());

        // invalid conf
        env::set_var(KMS_CLI_CONF_ENV, "test_data/kms.bad");
        let e = CliConf::load().err().unwrap().to_string();
        assert!(e.contains("Config JSON malformed in \"test_data/kms.bad\""));
    }
}
