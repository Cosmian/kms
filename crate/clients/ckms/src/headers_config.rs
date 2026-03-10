use std::fmt::Display;

use clap::Args;
use serde::{Deserialize, Serialize};

#[derive(Args, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct HeadersConfig {
    /// Add a custom HTTP header to every request sent to the KMS server.
    ///
    /// The header must be specified in `"Name: Value"` format, matching the
    /// curl `-H` / `--header` convention. This option may be repeated to add
    /// multiple headers.
    ///
    /// The environment variable `CLI_HEADER` may also be used; separate
    /// multiple headers with a newline character.
    ///
    /// Example: `--header "cf-access-token: <token>"`
    #[clap(
        long = "header",
        short = 'H',
        value_name = "NAME: VALUE",
        env = "CLI_HEADER",
        verbatim_doc_comment
    )]
    pub custom_headers: Vec<String>,
}

impl Display for HeadersConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.custom_headers.is_empty() {
            write!(f, "No custom headers")
        } else {
            write!(f, "Custom headers: {:?}", self.custom_headers)
        }
    }
}

impl std::fmt::Debug for HeadersConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", &self))
    }
}
