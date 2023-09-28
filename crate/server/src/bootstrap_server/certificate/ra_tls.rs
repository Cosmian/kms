use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use ratls::generate::generate_ratls_cert;

use crate::{error, result::KResult};
pub(crate) fn generate_self_signed_ra_tls_cert(
    subject: &str,
    expiration_days: u64,
) -> KResult<(PKey<Private>, X509)> {
    let (private_key, cert) = generate_ratls_cert(subject, vec![], expiration_days, None, true)
        .map_err(|e| error::KmsError::RatlsError(e.to_string()))?;

    let cert = X509::from_pem(cert.as_bytes())?;
    let private_key = PKey::private_key_from_pem(private_key.as_bytes())?;

    Ok((private_key, cert))
}

#[cfg(test)]
mod tests {
    use crate::result::KResult;

    #[test]
    fn generate_self_signed_ra_tls_cert() -> KResult<()> {
        let (_pkey, cert) = super::generate_self_signed_ra_tls_cert("test", 10)?;
        assert_eq!(
            format!("{:?}", cert.subject_name()),
            format!("{:?}", cert.issuer_name())
        );
        Ok(())
    }
}
