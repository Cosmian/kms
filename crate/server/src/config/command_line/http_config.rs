use std::{fmt::Display, path::PathBuf};

use clap::Args;
use serde::{Deserialize, Serialize};

const DEFAULT_PORT: u16 = 9998;
const DEFAULT_HOSTNAME: &str = "0.0.0.0";

#[derive(Args, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpConfig {
    /// The KMS HTTP server port
    #[clap(long, env = "KMS_PORT", default_value_t = DEFAULT_PORT, verbatim_doc_comment)]
    pub port: u16,

    /// The KMS HTTP server hostname
    #[clap(long, env = "KMS_HOSTNAME", default_value = DEFAULT_HOSTNAME, verbatim_doc_comment)]
    pub hostname: String,

    /// An optional API token to use for authentication on the HTTP server.
    #[clap(long, env = "KMS_API_TOKEN", verbatim_doc_comment)]
    pub api_token_id: Option<String>,

    /// DEPRECATED: use the TLS section instead.
    /// The KMS server optional PKCS#12 Certificates and Key file. If provided, this will start the server in HTTPS mode.
    #[clap(long, env = "KMS_HTTPS_P12_FILE", verbatim_doc_comment)]
    pub https_p12_file: Option<PathBuf>,

    /// DEPRECATED: use the TLS section instead.
    /// The password to open the PKCS#12 Certificates and Key file.
    #[clap(long, env = "KMS_HTTPS_P12_PASSWORD", verbatim_doc_comment)]
    pub https_p12_password: Option<String>,

    /// DEPRECATED: use the TLS section instead.
    /// The server's optional X. 509 certificate in PEM format validates the client certificate presented for authentication.
    /// If provided, clients must present a certificate signed by this authority for authentication.
    /// The server must run in TLS mode for this to be used.
    #[clap(long, env = "KMS_AUTHORITY_CERT_FILE", verbatim_doc_comment)]
    pub authority_cert_file: Option<PathBuf>,
}

impl Display for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "https://{}:{}, ", self.hostname, self.port)?;
        if self.https_p12_file.is_some() {
            write!(f, "[THIS IS DEPRECATED - USE THE TLS SECTION INSTEAD], ")?;
            write!(f, "Pkcs12 file: {:?}, ", self.https_p12_file.as_ref())?;
            if let Some(https_p12_password) = &self.https_p12_password {
                write!(f, "password: {}, ", https_p12_password.replace('.', "*"))?;
            }
            write!(
                f,
                "authority cert file: {:?}",
                self.authority_cert_file.as_ref()
            )?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", &self))
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            hostname: DEFAULT_HOSTNAME.to_owned(),
            https_p12_file: None,
            https_p12_password: None,
            authority_cert_file: None,
            api_token_id: None,
        }
    }
}
