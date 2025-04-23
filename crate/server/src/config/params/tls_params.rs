use std::{fmt, path::PathBuf};

use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};

use crate::{
    config::{HttpConfig, TlsConfig},
    error::KmsError,
    result::{KResult, KResultHelper},
};

/// The TLS parameters of the API server
pub struct TlsParams {
    /// The TLS private key and certificate of the HTTP server and Socket server
    pub p12: ParsedPkcs12_2,
    /// The certificate used to verify the client TLS certificates
    /// used for authentication in PEM format
    pub client_ca_cert_pem: Option<Vec<u8>>,
}

/// Represents the HTTP parameters for the server configuration.
impl TlsParams {
    /// Tries to create an instance of `TlsParams` from the given `HttpConfig`.
    ///
    /// # Arguments
    ///
    /// * `config` - The `HttpConfig` object containing the configuration parameters.
    /// * `deprecated_config` - The `HttpConfig` object containing the deprecated configuration parameters.
    ///
    /// # Returns
    ///
    /// Returns a `KResult` containing the created `TlsParams` instance on success.
    ///
    /// # Errors
    ///
    /// This function can return an error if there is an issue reading the PKCS#12 file or parsing it.
    pub fn try_from(config: &TlsConfig, deprecated_config: &HttpConfig) -> KResult<Option<Self>> {
        let p12 = if let (Some(p12_file), Some(p12_password)) =
            (&config.tls_p12_file, &config.tls_p12_password)
        {
            open_p12(p12_file, p12_password)?
        } else if let (Some(p12_file), Some(p12_password)) = (
            &deprecated_config.https_p12_file,
            &deprecated_config.https_p12_password,
        ) {
            open_p12(p12_file, p12_password)?
        } else {
            return Ok(None);
        };
        let authority_cert_file = if let Some(authority_cert_file) = config
            .clients_ca_cert_file
            .as_ref()
            .or(deprecated_config.authority_cert_file.as_ref())
        {
            Some(std::fs::read(authority_cert_file).context(&format!(
                "TLS configuration. Failed opening authority cert file at {:?}",
                authority_cert_file.display()
            ))?)
        } else {
            None
        };
        Ok(Some(Self {
            p12,
            client_ca_cert_pem: authority_cert_file,
        }))
    }
}

/// Opens a PKCS#12 file and parses it into a `TlsParams` object.
fn open_p12(p12_file: &PathBuf, p12_password: &str) -> Result<ParsedPkcs12_2, KmsError> {
    // Open and read the file into a byte vector
    let der_bytes = std::fs::read(p12_file)?;
    // Parse the byte vector as a PKCS#12 object
    let sealed_p12 = Pkcs12::from_der(der_bytes.as_slice())?;
    sealed_p12
        .parse2(p12_password)
        .context("TLS configuration. Failed opening P12")
}

impl fmt::Debug for TlsParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsParams")
            .field(
                "p12",
                &self.p12.cert.as_ref().map_or("[N/A]".to_owned(), |cert| {
                    format!("{:?}", cert.subject_name())
                }),
            )
            .field("authority_cert_file ? ", &self.client_ca_cert_pem.is_some())
            .finish()
    }
}
