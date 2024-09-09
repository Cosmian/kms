use std::fmt;

use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};

use crate::{
    config::HttpConfig,
    result::{KResult, KResultHelper},
};

/// The HTTP parameters of the API server
pub enum HttpParams {
    Https(ParsedPkcs12_2),
    Http,
}

/// Represents the HTTP parameters for the server configuration.
impl HttpParams {
    /// Tries to create an instance of `HttpParams` from the given `HttpConfig`.
    ///
    /// # Arguments
    ///
    /// * `config` - The `HttpConfig` object containing the configuration parameters.
    ///
    /// # Returns
    ///
    /// Returns a `KResult` containing the created `HttpParams` instance on success.
    ///
    /// # Errors
    ///
    /// This function can return an error if there is an issue reading the PKCS#12 file or parsing it.
    pub fn try_from(config: &HttpConfig) -> KResult<Self> {
        // start in HTTPS mode if a PKCS#12 file is provided
        if let (Some(p12_file), Some(p12_password)) =
            (&config.https_p12_file, &config.https_p12_password)
        {
            // Open and read the file into a byte vector
            let der_bytes = std::fs::read(p12_file)?;
            // Parse the byte vector as a PKCS#12 object
            let sealed_p12 = Pkcs12::from_der(der_bytes.as_slice())?;
            let p12 = sealed_p12
                .parse2(p12_password)
                .context("HTTPS configuration")?;
            Ok(Self::Https(p12))
        // else start in HTTP mode which is the default
        } else {
            Ok(Self::Http)
        }
    }

    /// Checks if the server is running in HTTPS mode.
    ///
    /// # Returns
    ///
    /// Returns `true` if the server is running in HTTPS mode, `false` otherwise.
    #[must_use]
    pub const fn is_running_https(&self) -> bool {
        matches!(self, Self::Https(_))
    }
}

impl fmt::Debug for HttpParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Https(ParsedPkcs12_2 {
                cert: Some(x509), ..
            }) => f
                .debug_tuple("Https server certificate CN")
                .field(&x509.subject_name())
                .finish(),
            Self::Https(ParsedPkcs12_2 { cert: None, .. }) => {
                write!(f, "Https server certificate CN unknown. THIS IS AN ERROR")
            }
            Self::Http => write!(f, "Http"),
        }
    }
}
