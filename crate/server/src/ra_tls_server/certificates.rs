use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkcs12::Pkcs12,
    pkey::{PKey, Public},
    x509::X509Builder,
};

use crate::result::KResult;

pub(crate) fn generate_self_signed_cert(
    common_name: &str,
    pkcs12_password: &str,
) -> KResult<Pkcs12> {
    let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
    let group = EcGroup::from_curve_name(nid)?;
    let ec_key = EcKey::generate(&group)?;
    let public_ec_key = ec_key.public_key_to_der()?;

    // The certificate private key which will also be the signing key
    // let private_key = PKey::generate_ed25519()?;
    // let public_key = PKey::<Public>::public_key_from_der(&private_key.public_key_to_der()?)?;

    // We need to convert these keys to PKey objects to use in certificates
    let private_key = PKey::from_ec_key(ec_key)?;
    let public_key = PKey::<Public>::public_key_from_der(&public_ec_key)?;

    // Create a new X509 builder.
    let mut builder = X509Builder::new()?;

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

    // Set the key usage extension to allow the certificate to be used for TLS.
    builder.append_extension(
        openssl::x509::extension::KeyUsage::new()
            .key_agreement()
            .build()?,
    )?;

    builder.sign(&private_key, openssl::hash::MessageDigest::sha256())?;
    // now build the certificate
    let cert = builder.build();

    // wrap it in a PKCS12 container
    let pkcs12 = Pkcs12::builder()
        .name(common_name)
        .pkey(&private_key)
        .cert(&cert)
        .build2(pkcs12_password)?;
    Ok(pkcs12)
}
