use std::{fs::File, io::Read, path::PathBuf};

use clap::Args;
use openssl::{
    pkcs12::{ParsedPkcs12_2, Pkcs12},
    x509::X509,
};

use crate::{kms_bail, result::KResult};

#[derive(Debug, Args, Clone)]
pub struct HTTPConfig {
    /// The server http port
    #[clap(long, env = "KMS_PORT", default_value = "9998")]
    pub port: u16,

    /// The server http hostname
    #[clap(long, env = "KMS_HOSTNAME", default_value = "0.0.0.0")]
    pub hostname: String,

    /// The server optional PKCS#12 Certificate file. If provided, this will start the server in HTTPS mode.
    #[clap(long, env = "KMS_HTTPS_P12_FILE")]
    pub https_p12_file: Option<PathBuf>,

    /// The password to open the PKCS#12 Certificate file
    #[clap(long, env = "KMS_HTTPS_P12_PASSWORD", default_value = "")]
    pub https_p12_password: String,

    /// The server optional authority X509 certificate in PEM format used to validate the client certificate presented for authentication.
    /// If provided, this will require clients to present a certificate signed by this authority for authentication.
    /// The server must run in TLS mode for this to be used.
    #[clap(long, env = "KMS_AUTHORITY_CERT_FILE")]
    pub authority_cert_file: Option<PathBuf>,
}

impl Default for HTTPConfig {
    fn default() -> Self {
        Self {
            port: 9998,
            hostname: "0.0.0.0".to_string(),
            https_p12_file: None,
            https_p12_password: String::new(),
            authority_cert_file: None,
        }
    }
}

impl HTTPConfig {
    pub fn init(&self) -> KResult<(String, Option<ParsedPkcs12_2>, Option<X509>)> {
        let host_port = format!("{}:{}", self.hostname, self.port);

        // If the server is running in TLS mode, we need to load the PKCS#12 certificate
        let p12 = if let Some(p12_file) = &self.https_p12_file {
            // Open and read the file into a byte vector
            let mut file = File::open(p12_file)?;
            let mut der_bytes = Vec::new();
            file.read_to_end(&mut der_bytes)?;

            // Parse the byte vector as a PKCS#12 object
            let sealed_p12 = Pkcs12::from_der(der_bytes.as_slice())?;
            let p12 = sealed_p12.parse2(&self.https_p12_password)?;
            Some(p12)
        } else {
            None
        };

        // If the server is authenticating users using a certificate, we need to load the authority certificate
        let x509 = if let Some(authority_cert_file) = &self.authority_cert_file {
            if p12.is_none() {
                kms_bail!(
                    "The authority certificate file can only be used when the server is running \
                     in TLS mode"
                )
            }
            // Open and read the file into a byte vector
            let mut file = File::open(authority_cert_file)?;
            let mut pem_bytes = Vec::new();
            file.read_to_end(&mut pem_bytes)?;

            // Parse the byte vector as a X509 object
            Some(X509::from_pem(pem_bytes.as_slice())?)
        } else {
            None
        };

        Ok((host_port, p12, x509))
    }
}
