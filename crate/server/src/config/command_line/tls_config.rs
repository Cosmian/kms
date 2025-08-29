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
    #[clap(long, env = "KMS_TLS_P12_FILE", verbatim_doc_comment)]
    pub tls_p12_file: Option<PathBuf>,

    /// The password to open the PKCS#12 Certificates and Key file
    #[clap(long, env = "KMS_TLS_P12_PASSWORD", verbatim_doc_comment)]
    pub tls_p12_password: Option<String>,

    /// The server's optional X. 509 certificate in PEM format validates the client certificate presented for authentication.
    /// If provided, clients must present a certificate signed by this authority for authentication.
    /// Mandatory to start the socket server.
    #[clap(long, env = "KMS_CLIENTS_CA_CERT_FILE", verbatim_doc_comment)]
    pub clients_ca_cert_file: Option<PathBuf>,

    /// Colon-separated list of TLS cipher suites to enable:
    /// Example: --tls-cipher-suites `"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"`
    /// If not specified, OpenSSL default cipher suites will be used:
    /// ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:\
    /// ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
    /// DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:\
    /// ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:\
    /// ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:\
    /// DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:\
    /// EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:\
    /// AES256-SHA:DES-CBC3-SHA:!DSS"
    /// Otherwise, ANSSI-recommended cipher suites (RFC 8446 compliant) are:
    /// - For TLS 1.3 (preferred): `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_CCM_SHA256`, `TLS_AES_128_CCM_8_SHA256`
    /// - For TLS 1.2 (compatibility): `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`,
    ///   `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`,
    ///   `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
    #[clap(long, env = "KMS_TLS_CIPHER_SUITES", verbatim_doc_comment)]
    pub tls_cipher_suites: Option<String>,
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
                "clients' CA cert file: {:?}, cipher suites: {:?}",
                self.clients_ca_cert_file.as_ref(),
                self.tls_cipher_suites.as_ref()
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
