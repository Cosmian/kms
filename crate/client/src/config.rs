use std::{
    env,
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};

use der::{DecodePem, Encode};
#[cfg(target_os = "linux")]
use log::info;
use rustls::Certificate;
use serde::{Deserialize, Serialize};
use x509_cert::Certificate as X509Certificate;

#[cfg(target_os = "linux")]
use crate::client_bail;
use crate::{
    error::{result::RestClientResultHelper, ClientError},
    KmsClient,
};

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
        return Some(PathBuf::from(hdrive).join(hpath))
    }
    // If none of the above environment variables exist, the home folder cannot be determined
    None
}

/// Returns the default configuration path
///  or an error if the path cannot be determined
fn get_default_conf_path() -> Result<PathBuf, ClientError> {
    get_home_folder()
        .ok_or_else(|| ClientError::NotSupported("unable to determine the home folder".to_owned()))
        .map(|home| home.join(".cosmian/kms.json"))
}

/// used for serialization
const fn not(b: &bool) -> bool {
    !*b
}

/// The configuration that is used by the Login command
/// to perform the `OAuth2` authorize code flow and obtain an access token.
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct Oauth2Conf {
    /// The client ID of the `OAuth2` application.
    /// This is obtained from the `OAuth2` provider.
    pub client_id: String,
    /// The client secret of the `OAuth2` application.
    /// This is obtained from the `OAuth2` provider.
    pub client_secret: String,
    /// The URL of the `OAuth2` provider's authorization endpoint.
    /// For example, for Google, this is `https://accounts.google.com/o/oauth2/v2/auth`.
    pub authorize_url: String,
    /// The URL of the `OAuth2` provider's token endpoint.
    /// For example, for Google, this is `https://oauth2.googleapis.com/token`.
    pub token_url: String,
    /// The scopes to request.
    /// For example, for Google, this is `["openid", "profile"]`.
    pub scopes: Vec<String>,
}

/// The configuration that is used by the google command
/// to perform actions over Gmail API.
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct GmailApiConf {
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
pub struct ClientConf {
    // accept_invalid_certs is useful if the cli needs to connect to an HTTPS KMS server
    // running an invalid or unsecure SSL certificate
    #[serde(default)]
    #[serde(skip_serializing_if = "not")]
    pub accept_invalid_certs: bool,
    pub kms_server_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_client_pkcs12_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_client_pkcs12_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_database_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth2_conf: Option<Oauth2Conf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gmail_api_conf: Option<GmailApiConf>,
}

impl Default for ClientConf {
    fn default() -> Self {
        Self {
            accept_invalid_certs: false,
            kms_server_url: "http://0.0.0.0:9998".to_owned(),
            verified_cert: None,
            kms_access_token: None,
            kms_database_secret: None,
            ssl_client_pkcs12_path: None,
            ssl_client_pkcs12_password: None,
            oauth2_conf: None,
            gmail_api_conf: None,
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
#[cfg(target_os = "linux")]
pub(crate) const KMS_CLI_CONF_DEFAULT_SYSTEM_PATH: &str = "/etc/cosmian/kms.json";

impl ClientConf {
    pub fn location(conf: Option<PathBuf>) -> Result<PathBuf, ClientError> {
        // Obtain the configuration file path from:
        // - the `--conf` arg
        // - the environment variable corresponding to `KMS_CLI_CONF_ENV`
        // - default to a pre-determined path
        if let Some(conf_path) = conf {
            if !conf_path.exists() {
                return Err(ClientError::NotSupported(format!(
                    "Configuration file {conf_path:?} from CLI arg does not exist"
                )))
            }
            return Ok(conf_path)
        } else if let Ok(conf_path) = env::var(KMS_CLI_CONF_ENV).map(PathBuf::from) {
            // Error if the specified file does not exist
            if !conf_path.exists() {
                return Err(ClientError::NotSupported(format!(
                    "Configuration file {conf_path:?} specified in {KMS_CLI_CONF_ENV} environment \
                     variable does not exist"
                )))
            }
            return Ok(conf_path)
        }

        let user_conf_path = get_default_conf_path();

        #[cfg(not(target_os = "linux"))]
        return user_conf_path;

        #[cfg(target_os = "linux")]
        match user_conf_path {
            Err(_) => {
                // no user home, this may be the system attempting a load
                let default_system_path = PathBuf::from(KMS_CLI_CONF_DEFAULT_SYSTEM_PATH);
                if default_system_path.exists() {
                    info!(
                        "No active user, using configuration at {KMS_CLI_CONF_DEFAULT_SYSTEM_PATH}"
                    );
                    return Ok(default_system_path)
                }
                client_bail!(
                    "no configuration found at {KMS_CLI_CONF_DEFAULT_SYSTEM_PATH}, and no current \
                     user, bailing out"
                );
            }
            Ok(user_conf) => {
                // the user home exists, if there is no conf file, check /etc/cosmian/kms.json
                if !user_conf.exists() {
                    let default_system_path = PathBuf::from(KMS_CLI_CONF_DEFAULT_SYSTEM_PATH);
                    if default_system_path.exists() {
                        info!(
                            "Linux user conf path is at: {user_conf:?} but is empty, using \
                             {KMS_CLI_CONF_DEFAULT_SYSTEM_PATH} instead"
                        );
                        return Ok(default_system_path)
                    }
                    info!(
                        "Linux user conf path is at: {user_conf:?} and will be initialized with a \
                         default value"
                    );
                }
                Ok(user_conf)
            }
        }
    }

    pub fn save(&self, conf_path: &PathBuf) -> Result<(), ClientError> {
        fs::write(
            conf_path,
            serde_json::to_string_pretty(&self)
                .with_context(|| format!("Unable to serialize default configuration {self:?}"))?,
        )
        .with_context(|| {
            format!("Unable to write default configuration to file {conf_path:?}\n{self:?}")
        })?;

        Ok(())
    }

    pub fn load(conf_path: &PathBuf) -> Result<Self, ClientError> {
        // Deserialize the configuration from the file, or create a default configuration if none exists
        let conf = if conf_path.exists() {
            // Configuration file exists, read and deserialize it
            let file = File::open(conf_path)
                .with_context(|| format!("Unable to read configuration file {conf_path:?}"))?;
            serde_json::from_reader(BufReader::new(file))
                .with_context(|| format!("Error while parsing configuration file {conf_path:?}"))?
        } else {
            // Configuration file doesn't exist, create it with default values and serialize it
            let parent = conf_path
                .parent()
                .with_context(|| format!("Unable to get parent directory of {conf_path:?}"))?;
            fs::create_dir_all(parent).with_context(|| {
                format!("Unable to create directory for configuration file {parent:?}")
            })?;

            let default_conf = Self::default();
            default_conf.save(conf_path)?;
            default_conf
        };

        Ok(conf)
    }

    /// Initialize a KMS REST client.
    ///
    /// Parameters `kms_server_url` and `accept_invalid_certs` from the command line
    /// will override the ones from the configuration file.
    pub fn initialize_kms_client(
        &self,
        kms_server_url: Option<&str>,
        accept_invalid_certs: Option<bool>,
        print_json: bool,
    ) -> Result<KmsClient, ClientError> {
        let kms_server_url = kms_server_url.unwrap_or(&self.kms_server_url);
        let accept_invalid_certs = accept_invalid_certs.unwrap_or(self.accept_invalid_certs);

        // Instantiate a KMS server REST client with the given configuration
        let kms_rest_client = KmsClient::instantiate(
            kms_server_url,
            self.kms_access_token.as_deref(),
            self.ssl_client_pkcs12_path.as_deref(),
            self.ssl_client_pkcs12_password.as_deref(),
            self.kms_database_secret.as_deref(),
            accept_invalid_certs,
            if let Some(certificate) = &self.verified_cert {
                Some(Certificate(
                    X509Certificate::from_pem(certificate.as_bytes())?.to_der()?,
                ))
            } else {
                None
            },
            print_json,
        )
        .with_context(|| {
            format!("Unable to instantiate a KMS REST client to server at {kms_server_url}")
        })?;

        Ok(kms_rest_client)
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf};

    use super::{get_default_conf_path, ClientConf, KMS_CLI_CONF_ENV};

    #[test]
    pub(crate) fn test_load() {
        // valid conf
        unsafe {
            env::set_var(KMS_CLI_CONF_ENV, "test_data/configs/kms.json");
        }
        let conf_path = ClientConf::location(None).unwrap();
        assert!(ClientConf::load(&conf_path).is_ok());

        // another valid conf
        unsafe {
            env::set_var(KMS_CLI_CONF_ENV, "test_data/configs/kms_partial.json");
        }
        let conf_path = ClientConf::location(None).unwrap();
        assert!(ClientConf::load(&conf_path).is_ok());

        // Default conf file
        unsafe {
            env::remove_var(KMS_CLI_CONF_ENV);
        }
        let _ = fs::remove_file(get_default_conf_path().unwrap());
        let conf_path = ClientConf::location(None).unwrap();
        assert!(ClientConf::load(&conf_path).is_ok());
        assert!(get_default_conf_path().unwrap().exists());

        // invalid conf
        unsafe {
            env::set_var(KMS_CLI_CONF_ENV, "test_data/configs/kms.bad");
        }
        let conf_path = ClientConf::location(None).unwrap();
        let e = ClientConf::load(&conf_path).err().unwrap().to_string();
        assert!(e.contains("missing field `kms_server_url`"));

        // with a file
        unsafe {
            env::remove_var(KMS_CLI_CONF_ENV);
        }
        let conf_path =
            ClientConf::location(Some(PathBuf::from("test_data/configs/kms.json"))).unwrap();
        assert!(ClientConf::load(&conf_path).is_ok());
    }
}
