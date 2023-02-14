use std::{fs::File, io::Read, path::PathBuf};

use clap::Args;
use openssl::pkcs12::{ParsedPkcs12, Pkcs12};

use crate::result::KResult;

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
}

impl Default for HTTPConfig {
    fn default() -> Self {
        HTTPConfig {
            port: 9998,
            hostname: "0.0.0.0".to_string(),
            https_p12_file: None,
            https_p12_password: "".to_string(),
        }
    }
}

impl HTTPConfig {
    pub fn init(&self) -> KResult<(String, Option<ParsedPkcs12>)> {
        let host_port = format!("{}:{}", self.hostname, self.port);

        let p12 = if let Some(p12_file) = &self.https_p12_file {
            // Open and read the file into a byte vector
            let mut file = File::open(p12_file)?;
            let mut der_bytes = Vec::new();
            file.read_to_end(&mut der_bytes)?;

            // Parse the byte vector as a PKCS#12 object
            let sealed_p12 = Pkcs12::from_der(der_bytes.as_slice())?;
            let p12 = sealed_p12.parse(&self.https_p12_password)?;
            Some(p12)
        } else {
            None
        };

        Ok((host_port, p12))
    }
}
