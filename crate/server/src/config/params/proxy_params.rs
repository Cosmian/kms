use std::fmt;

use tracing::debug;
use url::Url;

use crate::{config::ProxyConfig, kms_error, result::KResult};

#[derive(Clone)]
/// The Forward Proxy Parameters if any
pub struct ProxyParams {
    /// The proxy url
    pub url: Url,

    /// Set the Proxy-Authorization header username using Basic auth.
    pub basic_auth_username: Option<String>,

    /// Set the Proxy-Authorization header password using Basic auth.
    pub basic_auth_password: Option<String>,

    /// Set the Proxy-Authorization header to a specified value.
    pub custom_auth_header: Option<String>,

    /// The No Proxy exclusion list to this Proxy
    pub exclusion_list: Vec<String>,
}

/// Represents the HTTP parameters for the server configuration.
impl ProxyParams {
    /// Tries to create an instance of `ProxyParams` from the given `ProxyConfig`.
    ///
    /// # Arguments
    /// * `config` - The `ProxyConfig` object containing the configuration parameters.
    pub fn try_from(config: &ProxyConfig) -> KResult<Option<Self>> {
        debug!("try_from: proxy_config: {config:#?}");
        if let Some(url) = &config.proxy_url {
            let exclusion_list = config.proxy_exclusion_list.clone().unwrap_or_default();
            Ok(Some(Self {
                url: Url::parse(url)
                    .map_err(|e| kms_error!("Failed parsing the Proxy URL: {e}"))?,
                basic_auth_username: config.proxy_basic_auth_username.clone(),
                basic_auth_password: config.proxy_basic_auth_password.clone(),
                custom_auth_header: config.proxy_custom_auth_header.clone(),
                exclusion_list,
            }))
        } else {
            Ok(None)
        }
    }
}

impl fmt::Debug for ProxyParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyParams")
            .field("url", &self.url)
            .field("basi_auth_username", &self.basic_auth_username)
            .field("basic_auth_password", &self.basic_auth_password)
            .field("custom_auth_header", &self.custom_auth_header)
            .field("exclusion_list", &self.exclusion_list)
            .finish()
    }
}
