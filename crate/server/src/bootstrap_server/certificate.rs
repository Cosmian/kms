use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkcs12::Pkcs12,
    pkey::{PKey, Public},
    x509::{X509Builder, X509},
};
use ratls::generate_ratls_cert;

use crate::{error, result::KResult};

pub(crate) fn generate_ratls_pkcs12(common_name: &str, pkcs12_password: &str) -> KResult<Pkcs12> {
    // TODO: design a way to make all certificate issuer args customizable
    let subject = format!("CN={common_name},O=Cosmian Tech,C=FR,L=Paris,ST=Ile-de-France");
    let (private_key, cert) = generate_ratls_cert(&subject, vec![], 365, None, false) // TODO: true
        .map_err(|e| error::KmsError::RatlsError(e.to_string()))?;

    std::fs::write("/tmp/cert.pem", &cert)?;

    let cert = X509::from_pem(cert.as_bytes())?;

    let private_key = PKey::private_key_from_pem(private_key.as_bytes())?;

    // Wrap it in a PKCS12 container
    let pkcs12 = Pkcs12::builder()
        .name(common_name)
        .pkey(&private_key)
        .cert(&cert)
        .build2(pkcs12_password)?;

    Ok(pkcs12)
}

#[allow(dead_code)]
pub(crate) fn generate_self_signed_cert(
    common_name: &str,
    pkcs12_password: &str,
) -> KResult<Pkcs12> {
    //TODO test if running inside an enclave
    //let is_running_inside_enclave = is_running_inside_enclave();

    let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
    let group = EcGroup::from_curve_name(nid)?;
    let ec_key = EcKey::generate(&group)?;
    let public_ec_key = ec_key.public_key_to_der()?;

    // We need to convert these keys to PKey objects to use in certificates
    let private_key = PKey::from_ec_key(ec_key)?;
    let public_key = PKey::<Public>::public_key_from_der(&public_ec_key)?;

    // Create a new X509 builder.
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;

    // Assign the public key
    builder.set_pubkey(&public_key)?;

    // Set the common name and the rest of the subject of the certificate.
    let mut x509_name = openssl::x509::X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "FR")?;
    x509_name.append_entry_by_text("ST", "IdF")?;
    x509_name.append_entry_by_text("O", "Cosmian KMS")?;
    x509_name.append_entry_by_text("CN", common_name)?;
    let x509_name = x509_name.build();
    builder.set_subject_name(&x509_name)?;

    // Set the issuer name (the same as the subject name since this is a self-signed certificate).
    builder.set_issuer_name(&x509_name)?;

    // Set the certificate serial number to some value.
    builder.set_serial_number(Asn1Integer::from_bn(BigNum::from_u32(12345)?.as_ref())?.as_ref())?;

    // Set the certificate validity period to 1 day.
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;

    builder.sign(&private_key, openssl::hash::MessageDigest::sha256())?;
    // now build the certificate
    let cert = builder.build();

    let pem = cert.to_pem()?;
    // write the pem to a cert.pem file in /tmp
    std::fs::write("/tmp/cert.pem", pem)?;

    // wrap it in a PKCS12 container
    let pkcs12 = Pkcs12::builder()
        .name(common_name)
        .pkey(&private_key)
        .cert(&cert)
        .build2(pkcs12_password)?;
    Ok(pkcs12)
}

#[cfg(test)]
mod tests {
    use crate::result::KResult;

    #[test]
    fn generate_self_signed_cert() -> KResult<()> {
        let pkcs12 = super::generate_self_signed_cert("test", "pwd")?;
        let p12 = pkcs12.parse2("pwd")?;
        assert!(p12.pkey.is_some());
        assert!(p12.cert.is_some());
        assert!(p12.ca.is_none());
        let cert = p12.cert.unwrap();
        assert_eq!(
            format!("{:?}", cert.subject_name()),
            format!("{:?}", cert.issuer_name())
        );
        Ok(())
    }
}
