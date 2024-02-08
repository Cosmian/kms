use std::{fmt, fs::File, io::Read};

use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};

use crate::{
    config::ClapConfig,
    result::{KResult, KResultHelper},
};

/// The HTTP parameters of the API server
pub enum HttpParams {
    Https(ParsedPkcs12_2),
    Http,
}

impl HttpParams {
    pub fn try_from(config: &ClapConfig) -> KResult<Self> {
        // start in HTTPS mode if a PKCS#12 file is provided
        if let (Some(p12_file), Some(p12_password)) =
            (&config.http.https_p12_file, &config.http.https_p12_password)
        {
            // Open and read the file into a byte vector
            let mut file = File::open(p12_file)?;
            let mut der_bytes = Vec::new();
            file.read_to_end(&mut der_bytes)?;
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

    #[must_use]
    pub fn is_running_https(&self) -> bool {
        matches!(self, Self::Https(_))
    }
}

impl fmt::Debug for HttpParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpParams::Https(ParsedPkcs12_2 {
                cert: Some(x509), ..
            }) => f
                .debug_tuple("Https server certificate CN")
                .field(&x509.subject_name())
                .finish(),
            HttpParams::Https(ParsedPkcs12_2 { cert: None, .. }) => {
                write!(f, "Https server certificate CN unknown. THIS IS AN ERROR")
            }
            HttpParams::Http => write!(f, "Http"),
        }
    }
}
