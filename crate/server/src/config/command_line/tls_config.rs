use std::{fmt::Display, path::PathBuf};

use clap::Args;
use serde::{Deserialize, Serialize};

#[derive(Args, Clone, Deserialize, Serialize)]
#[serde(default)]
#[derive(Default)]
pub struct TlsConfig {
    /// The KMS server optional PKCS#12 Certificates and Key file.
    /// Mandatory when starting the socket server.
    /// When provided, the Socket and HTTP server will start in TLS Mode.
    #[clap(long, env = "KMS_HTTPS_P12_FILE", verbatim_doc_comment)]
    pub tls_p12_file: Option<PathBuf>,

    /// The password to open the PKCS#12 Certificates and Key file
    #[clap(long, env = "KMS_HTTPS_P12_PASSWORD", verbatim_doc_comment)]
    pub tls_p12_password: Option<String>,

    /// The server's optional X. 509 certificate in PEM format validates the client certificate presented for authentication.
    /// If provided, clients must present a certificate signed by this authority for authentication.
    /// Mandatory to start the socket server.
    #[clap(long, env = "KMS_CLIENTS_CA_CERT_FILE", verbatim_doc_comment)]
    pub clients_ca_cert_file: Option<PathBuf>,
}

impl Display for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.tls_p12_file.is_some() {
            write!(f, "Pkcs12 file: {:?}, ", self.tls_p12_file.as_ref())?;
            if let Some(https_p12_password) = &self.tls_p12_password {
                write!(f, "password: {}, ", https_p12_password.replace('.', "*"))?;
            }
            write!(
                f,
                "clients' CA cert file: {:?}",
                self.clients_ca_cert_file.as_ref()
            )
        } else {
            write!(f, "No TLS config")
        }
    }
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", &self))
    }
}
