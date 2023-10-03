use openssl::sha::Sha256;
use serde::{Deserialize, Serialize};

use crate::error::KmipUtilsError;

pub fn forge_report_data(
    nonce: &[u8; 32],
    pem_certificate: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
    // user_report_data = ( sha256(certificate_x509_pem) || 32bytes_nonce )
    let mut user_report_data = nonce.to_vec();

    let mut hasher = Sha256::new();
    hasher.update(pem_certificate);
    user_report_data.extend(hasher.finish()[..].to_vec());

    Ok(user_report_data)
}

// Response when querying the KMS certificates
#[derive(Deserialize, Serialize, Debug)]
pub struct CertificatesResponse {
    pub certificate: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuoteParams {
    pub nonce: String,
}
