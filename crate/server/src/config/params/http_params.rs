use std::{
    fmt,
    fs::File,
    io::Read,
    sync::{Arc, Mutex},
};

use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};

use crate::{
    config::{command_line::HttpsCertbotConfig, ClapConfig, WorkspaceConfig},
    core::certbot::Certbot,
    result::KResult,
};

/// The HTTP parameters of the API server
pub enum HttpParams {
    Certbot(Arc<Mutex<Certbot>>),
    Https(ParsedPkcs12_2),
    Http,
}

impl HttpParams {
    pub fn try_from(config: &ClapConfig, workspace: &WorkspaceConfig) -> KResult<Self> {
        // certbot is the priority is that is provided
        if config.certbot_https.use_certbot {
            let certbot = Arc::new(Mutex::new(HttpsCertbotConfig::init(
                &config.certbot_https,
                workspace,
            )?));
            Ok(Self::Certbot(certbot))
        // else start in HTTPS mode if a PKCS#12 file is provided
        } else if let Some(p12_file) = &config.http.https_p12_file {
            // Open and read the file into a byte vector
            let mut file = File::open(p12_file)?;
            let mut der_bytes = Vec::new();
            file.read_to_end(&mut der_bytes)?;
            // Parse the byte vector as a PKCS#12 object
            let sealed_p12 = Pkcs12::from_der(der_bytes.as_slice())?;
            let p12 = sealed_p12.parse2(&config.http.https_p12_password)?;
            Ok(Self::Https(p12))
        // else start in HTTP mode which is the default
        } else {
            Ok(Self::Http)
        }
    }

    pub fn is_running_https(&self) -> bool {
        match self {
            Self::Certbot(_) | Self::Https(_) => true,
            Self::Http => false,
        }
    }
}

impl fmt::Debug for HttpParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpParams::Certbot(certbot) => f.debug_tuple("Certbot").field(certbot).finish(),
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
