use std::{fs::File, io::Read, path::Path};

use x509_parser::{
    oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER,
    prelude::{ParsedExtension, X509Certificate},
};

use crate::{error::KmsError, result::KResult};

const LETS_ENCRYPT_CA: &str = "src/tests/certificates/letsencrypt/lets-encrypt-x3-cross-signed.der";
const LETS_ENCRYPT_CERT: &str = "src/tests/certificates/letsencrypt/certificate.der";
const LETS_ENCRYPT_CRL: &str = "src/tests/certificates/letsencrypt/DSTROOTCAX3CRL.crl";
const LETS_ENCRYPT_CRL_ISSUER: &str =
    "src/tests/certificates/letsencrypt/fyicenter-certificate-11562.crt";

pub fn read_bytes_from_file(file: &(impl AsRef<Path> + ?Sized)) -> Result<Vec<u8>, KmsError> {
    let mut buffer = Vec::new();
    File::open(file).unwrap().read_to_end(&mut buffer).unwrap();

    Ok(buffer)
}

pub(crate) fn get_cert_authority_key_identifier(
    x509_cert: &X509Certificate<'_>,
) -> KResult<String> {
    let aki = x509_cert
        .get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)?
        .ok_or(KmsError::Certificate(
            "Extension Authority Key Identifier not found".to_string(),
        ))?;

    let aki = match &aki.parsed_extension() {
        ParsedExtension::AuthorityKeyIdentifier(aki) => aki
            .key_identifier
            .clone()
            .ok_or(KmsError::Certificate("Key identifier is None!".to_string())),
        _ => Err(KmsError::Certificate(format!(
            "Missing Authority Key Identifier on certificate {x509_cert:?}"
        ))),
    }?;
    Ok(hex::encode(aki.0))
}

// #[test]
// fn test_cert_parser() {
//     // log_init("cosmian=trace");
//     let bytes = read_bytes_from_file("src/tests/certificates/kms/subca.pem").unwrap();
//     let (_, pem) = parse_x509_pem(&bytes).unwrap();
//     let (_, x509) = parse_x509_certificate(&pem.contents).unwrap();
//
//     // Display the Authority Key Identifier of the cert
//     let aki_cert = get_cert_authority_key_identifier(&x509).unwrap();
//     debug!("Authority key identifier (certificate): {aki_cert}");
//     let ski_cert = get_certificate_subject_key_identifier(&x509)
//         .unwrap()
//         .unwrap();
//     debug!("Authority key identifier (certificate): {ski_cert}");
// }

// #[actix_rt::test]
// async fn test_certificate_crl_verification() {
//     // log_init("cosmian=trace");
//
//     let crl_bytes = read_bytes_from_file(LETS_ENCRYPT_CRL).unwrap();
//     let crl_issuer_bytes = read_bytes_from_file(LETS_ENCRYPT_CRL_ISSUER).unwrap();
//     let cert_bytes = read_bytes_from_file(LETS_ENCRYPT_CERT).unwrap();
//     let ca_bytes = read_bytes_from_file(LETS_ENCRYPT_CA).unwrap();
//
//     let (_, x509_crl) = parse_x509_crl(&crl_bytes).unwrap();
//     let (_, pem_crl_issuer) = parse_x509_pem(&crl_issuer_bytes).unwrap();
//     let (_, x509_crl_issuer) = parse_x509_certificate(&pem_crl_issuer.contents).unwrap();
//     let (_, x509_cert) = parse_x509_certificate(&cert_bytes).unwrap();
//     let (_, x509_ca) = parse_x509_certificate(&ca_bytes).unwrap();
//
//     // Debug info
//     if let Some(issuer_uid) = &x509_cert.issuer_uid {
//         debug!("X.509 Issuer uid: {:?}", issuer_uid);
//     }
//     debug!("Certificate serial number: {:?}", x509_cert.serial);
//     for revoked in x509_crl.iter_revoked_certificates() {
//         debug!("Revoked certificate serial: {}", revoked.serial());
//         debug!("  Reason: {}", revoked.reason_code().unwrap_or_default().1);
//         if x509_cert.serial == revoked.serial().clone() {
//             std::process::exit(123);
//         }
//     }
//
//     let aki_cert = get_cert_authority_key_identifier(&x509_cert).unwrap();
//     debug!("Authority key identifier (certificate): {aki_cert}");
//     let aki_crl = get_crl_authority_key_identifier(&x509_crl).unwrap();
//     debug!("Authority key identifier (crl): {aki_crl}");
//
//     // Display CRL extension AuthorityKeyIdentifier
//     for crl_extension in x509_crl.extensions() {
//         let ext = crl_extension.parsed_extension();
//         debug!("CRL extension: {ext:?}");
//         if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext {
//             debug!("      X509v3 Authority Key Identifier");
//             if let Some(key_id) = &aki.key_identifier {
//                 debug!("        Key Identifier: {:x}", key_id);
//             }
//             if let Some(issuer) = &aki.authority_cert_issuer {
//                 for name in issuer {
//                     debug!("        Cert Issuer: {}", name);
//                 }
//             }
//             if let Some(serial) = aki.authority_cert_serial {
//                 debug!("        Cert Serial: {}", format_serial(serial));
//             }
//         };
//     }
//
//     // Verify signatures
//     x509_crl
//         .verify_signature(&x509_crl_issuer.tbs_certificate.subject_pki)
//         .unwrap();
//     x509_cert
//         .verify_signature(Some(&x509_ca.tbs_certificate.subject_pki))
//         .unwrap();
// }
