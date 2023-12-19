use std::{fmt::Display, path::PathBuf};

use clap::Args;
use clap_serde_derive::ClapSerde;
use serde::{Deserialize, Serialize};

#[derive(Args, ClapSerde, Clone, Deserialize, Serialize)]
pub struct HttpConfig {
    /// The KMS server port
    #[default(9998)]
    #[clap(long, env = "KMS_PORT")]
    pub port: u16,

    /// The KMS server hostname
    #[default("0.0.0.0".to_string())]
    #[clap(long, env = "KMS_HOSTNAME")]
    pub hostname: String,

    /// The KMS server optional PKCS#12 Certificates and Key file. If provided, this will start the server in HTTPS mode.
    #[clap(long, env = "KMS_HTTPS_P12_FILE")]
    pub https_p12_file: Option<PathBuf>,

    /// The password to open the PKCS#12 Certificates and Key file
    #[clap(long, env = "KMS_HTTPS_P12_PASSWORD")]
    pub https_p12_password: Option<String>,

    /// The server optional authority X509 certificate in PEM format used to validate the client certificate presented for authentication.
    /// If provided, this will require clients to present a certificate signed by this authority for authentication.
    /// The server must run in TLS mode for this to be used.
    #[clap(long, env = "KMS_AUTHORITY_CERT_FILE")]
    pub authority_cert_file: Option<PathBuf>,
}

impl Display for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.https_p12_file.is_some() {
            write!(f, "https://{}:{}, ", self.hostname, self.port)?;
            write!(f, "Pkcs12 file: {:?}, ", self.https_p12_file.as_ref())?;
            if let Some(https_p12_password) = &self.https_p12_password {
                write!(f, "password: {}, ", https_p12_password.replace('.', "*"))?;
            }
            write!(
                f,
                "authority cert file: {:?}",
                self.authority_cert_file.as_ref()
            )
        } else {
            write!(f, "http://{}:{}", self.hostname, self.port)
        }
    }
}

impl std::fmt::Debug for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", &self))
    }
}
