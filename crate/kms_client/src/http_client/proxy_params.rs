use std::fmt;

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
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

impl fmt::Debug for ProxyParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyParams")
            .field("url", &self.url)
            .field("basic_auth_username", &self.basic_auth_username)
            .field(
                "basic_auth_password",
                &self.basic_auth_password.as_ref().map(|_| "REDACTED"),
            )
            .field(
                "custom_auth_header",
                &self.custom_auth_header.as_ref().map(|_| "REDACTED"),
            )
            .field("exclusion_list", &self.exclusion_list)
            .finish()
    }
}
