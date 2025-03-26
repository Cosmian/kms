use std::{fmt, path::PathBuf};

use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};

use crate::{
    config::{HttpConfig, TlsConfig},
    error::KmsError,
    result::{KResult, KResultHelper},
};

/// The TLS parameters of the API server
pub enum TlsParams {
    Tls(ParsedPkcs12_2),
    Plain,
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
    pub fn try_from(config: &TlsConfig, deprecated_config: &HttpConfig) -> KResult<Self> {
        if let (Some(p12_file), Some(p12_password)) =
            (&config.tls_p12_file, &config.tls_p12_password)
        {
            open_p12(p12_file, p12_password)
        } else if let (Some(p12_file), Some(p12_password)) = (
            &deprecated_config.https_p12_file,
            &deprecated_config.https_p12_password,
        ) {
            open_p12(p12_file, p12_password)
        } else {
            Ok(Self::Plain)
        }
    }

    /// Checks if the server is running in TLS mode.
    ///
    /// # Returns
    ///
    /// Returns `true` if the server is running in HTTPS mode, `false` otherwise.
    #[must_use]
    pub const fn is_running_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }
}

/// Opens a PKCS#12 file and parses it into a `TlsParams` object.
fn open_p12(p12_file: &PathBuf, p12_password: &str) -> Result<TlsParams, KmsError> {
    // Open and read the file into a byte vector
    let der_bytes = std::fs::read(p12_file)?;
    // Parse the byte vector as a PKCS#12 object
    let sealed_p12 = Pkcs12::from_der(der_bytes.as_slice())?;
    let p12 = sealed_p12
        .parse2(p12_password)
        .context("HTTPS configuration")?;
    Ok(TlsParams::Tls(p12))
}

impl fmt::Debug for TlsParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls(ParsedPkcs12_2 {
                cert: Some(x509), ..
            }) => f
                .debug_tuple("server certificate CN")
                .field(&x509.subject_name())
                .finish(),
            Self::Tls(ParsedPkcs12_2 { cert: None, .. }) => {
                write!(f, "server certificate CN unknown. THIS IS AN ERROR")
            }
            Self::Plain => write!(f, "Http"),
        }
    }
}
