use std::{fmt, path::PathBuf};

use cosmian_logger::debug;
use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};
use x509_parser::pem::Pem;

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
    pub clients_ca_cert_pem: Option<Vec<u8>>,
    /// Configured cipher suites to use for TLS connections (OpenSSL cipher string format)
    pub cipher_suites: Option<String>,
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
        debug!("tls_config: {config:#?}, deprecated_config: {deprecated_config:#?}");
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
        debug!(
            "Client Authority cert file: {:?}",
            config.clients_ca_cert_file
        );
        debug!(
            "[DEPRECATED] Client Authority cert file: {:?}",
            deprecated_config.authority_cert_file
        );
        let clients_ca_cert_pem = if let Some(authority_cert_file) = config
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
        let cipher_suites = config.tls_cipher_suites.clone();

        Ok(Some(Self {
            p12,
            clients_ca_cert_pem,
            cipher_suites,
        }))
    }
}

/// Opens a PKCS#12 file and parses it into a `TlsParams` object.
fn open_p12(p12_file: &PathBuf, p12_password: &str) -> Result<ParsedPkcs12_2, KmsError> {
    // Open and read the file into a byte vector
    let der_bytes = std::fs::read(p12_file).context("TLS configuration. Failed opening P12")?;
    // Parse the byte vector as a PKCS#12 object
    let sealed_p12 = Pkcs12::from_der(der_bytes.as_slice())?;
    sealed_p12
        .parse2(p12_password)
        .context("TLS configuration. Failed parsing P12")
}

impl fmt::Debug for TlsParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ca_cert = if let Some(cert) = &self.clients_ca_cert_pem {
            let pem = Pem::iter_from_buffer(cert)
                .next()
                .transpose()
                .map_err(|_e| fmt::Error)?
                .ok_or(fmt::Error)?;
            let x509 = pem.parse_x509().map_err(|_e| fmt::Error)?;
            x509.subject().to_string()
        } else {
            "[N/A]".to_owned()
        };

        let cipher_suites = self.cipher_suites.as_ref().map_or_else(
            || "Default OpenSSL cipher suites".to_owned(),
            |cipher_string| format!("Custom cipher string: {cipher_string}"),
        );

        f.debug_struct("TlsParams")
            .field(
                "p12",
                &self.p12.cert.as_ref().map_or("[N/A]".to_owned(), |cert| {
                    format!("{:?}", cert.subject_name())
                }),
            )
            .field("authority_cert_file: ", &ca_cert)
            .field("cipher_suites: ", &cipher_suites)
            .finish()
    }
}
