use std::fmt::Display;

use clap::Args;
use serde::{Deserialize, Serialize};

#[derive(Args, Clone, Deserialize, Serialize)]
#[serde(default)]
#[derive(Default)]
pub struct ProxyConfig {
    /// The proxy URL:
    ///   - e.g., `https://secure.example` for an HTTP proxy
    ///   - e.g., `socks5://192.168.1.1:9000` for a SOCKS proxy
    #[clap(long, env = "CLI_PROXY_URL", verbatim_doc_comment)]
    pub proxy_url: Option<String>,

    /// Set the Proxy-Authorization header username using Basic auth.
    #[clap(long, env = "CLI_PROXY_BASIC_AUTH_USERNAME", verbatim_doc_comment)]
    pub proxy_basic_auth_username: Option<String>,

    /// Set the Proxy-Authorization header password using Basic auth.
    #[clap(long, env = "CLI_PROXY_BASIC_AUTH_PASSWORD", verbatim_doc_comment)]
    pub proxy_basic_auth_password: Option<String>,

    /// Set the Proxy-Authorization header to a specified value.
    #[clap(long, env = "CLI_PROXY_CUSTOM_AUTH_HEADER", verbatim_doc_comment)]
    pub proxy_custom_auth_header: Option<String>,

    /// The No Proxy exclusion list to this Proxy
    #[clap(long, env = "CLI_PROXY_NO_PROXY", verbatim_doc_comment)]
    pub proxy_exclusion_list: Option<Vec<String>>,
}

impl Display for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(url) = &self.proxy_url {
            write!(f, "Proxy URL: {url}, ")?;
        } else {
            write!(f, "No Proxy URL, ")?;
        }

        if let Some(username) = &self.proxy_basic_auth_username {
            write!(f, "Basic Auth Username: {username}, ")?;
        } else {
            write!(f, "No Basic Auth Username, ")?;
        }

        if let Some(_password) = &self.proxy_basic_auth_password {
            write!(f, "Basic Auth Password: ***, ")?;
        } else {
            write!(f, "No Basic Auth Password, ")?;
        }

        if let Some(header) = &self.proxy_custom_auth_header {
            write!(f, "Custom Auth Header: {header}, ")?;
        } else {
            write!(f, "No Custom Auth Header, ")?;
        }

        if let Some(exclusion_list) = &self.proxy_exclusion_list {
            write!(f, "No Proxy Exclusion List: {exclusion_list:?}")
        } else {
            write!(f, "No No-Proxy Exclusion List")
        }
    }
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", &self))
    }
}
