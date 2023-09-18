use cosmian_kms_utils::access::ExtraDatabaseParams;
use tracing::{debug, trace};
use x509_parser::{
    nom::AsBytes,
    oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS,
    parse_x509_certificate, parse_x509_crl,
    prelude::{
        parse_x509_pem, DistributionPointName, GeneralName, ParsedExtension, X509Certificate,
    },
};

use crate::{
    core::{
        certificate::{
            locate_by_common_name_and_get_certificate_bytes,
            locate_by_spki_and_get_certificate_bytes,
            parsing::{get_common_name, get_crl_authority_key_identifier},
        },
        KMS,
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// The `verify_certificate` function  verifies the validity of a certificate
/// issued by a Certificate Authority (CA) by checking if it is expired, if the
/// signature is valid, and if the serial number is not revoked.
///
/// Arguments:
///
/// * `pem_certificate`: A byte array containing the PEM-encoded certificate that
/// needs to be verified.
/// * `kms`: The `kms` parameter is an instance of the `KMS` struct, which is used
/// to interact with a Key Management Service. It likely contains methods for
/// retrieving and managing cryptographic keys and certificates.
/// * `owner`: The `owner` parameter is a string that represents the owner or
/// identifier of the certificate. It is used to locate the CA (Certificate
/// Authority) certificate in the KMS (Key Management System) based on the common
/// name of the issuer.
/// * `params`: The `params` parameter is an optional `ExtraDatabaseParams` struct
/// that contains additional parameters for locating the certificate in the
/// database. It is used in the `locate_by_common_name_and_get_certificate_bytes`
/// function.
///
/// Returns:
///
/// Nothing
pub(crate) async fn verify_certificate(
    pem_certificate: &[u8],
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    // Parse PEM file and verify the validity of the certificate
    let (_, pem_cert) = parse_x509_pem(pem_certificate)?;
    let (_, x509_cert) = parse_x509_certificate(&pem_cert.contents)?;
    trace!("Verifying certificate: x509: {:?}", x509_cert);

    if !x509_cert.validity().is_valid() {
        return Err(KmsError::Certificate(format!(
            "Certificate is now expired. Certificate details: {x509_cert:?}"
        )))
    }
    debug!("Certificate is not expired: {:?}", x509_cert.validity());

    // Debug info
    let subject = x509_cert.subject();
    let issuer = x509_cert.issuer();
    debug!("X.509 Subject: {}", subject);
    debug!("X.509 Issuer: {}", issuer);

    let issuer_common_name = get_common_name(x509_cert.issuer())?;
    // From the issuer name, recover the KMIP certificate object
    let ca_certificate_bytes =
        locate_by_common_name_and_get_certificate_bytes(&issuer_common_name, kms, owner, params)
            .await?;
    debug!("Issuer CRT recovered from KMS");

    // Parse PEM file and verify the validity of the signature certificate
    let (_, pem_ca) = parse_x509_pem(&ca_certificate_bytes)?;
    let (_, x509_ca) = parse_x509_certificate(&pem_ca.contents)?;
    if !x509_ca.validity().is_valid() {
        return Err(KmsError::Certificate(format!(
            "Issuer Certificate is now expired. Certificate details: {x509_ca:?}"
        )))
    }
    debug!(
        "Issuer Certificate is not expired: {:?}",
        x509_ca.validity()
    );

    // Verify certificate signature against issuer public key
    x509_cert.verify_signature(Some(&x509_ca.tbs_certificate.subject_pki))?;
    debug!("Certificate signature is valid");

    // Verify if serial number is already revoked
    check_serial_number_in_crl(&x509_cert, &x509_ca, kms, owner, params).await?;

    Ok(())
}

/// The function `check_serial_number_in_crl` checks if a given X.509 certificate's
/// serial number is present in the Certificate Revocation List (CRL) of its issuer.
///
/// Arguments:
///
/// * `x509_cert`: The `x509_cert` parameter is an `X509Certificate` object
/// representing the certificate to be checked against the Certificate Revocation
/// List (CRL).
/// * `x509_ca`: The `x509_ca` parameter is an `X509Certificate` representing the CA
/// (Certificate Authority) certificate. It is used to obtain the CRL (Certificate
/// Revocation List) distribution points.
/// * `kms`: The `kms` parameter is of type `&KMS`, which is a reference to an
/// instance of the `KMS` struct. It is used to perform operations related to the
/// Key Management Service.
/// * `owner`: The `owner` parameter is a string that represents the owner of the
/// certificate. It is used in the `locate_by_spki_and_get_certificate_bytes`
/// function to locate the issuer certificate.
/// * `params`: The `params` parameter is an optional reference to a struct called
/// `ExtraDatabaseParams`. It is used to provide additional parameters for locating
/// the issuer certificate.
///
/// Returns:
///
/// The function `check_serial_number_in_crl` returns a `KResult<()>`, which is an
/// alias for `Result<(), KmsError>`.
pub(crate) async fn check_serial_number_in_crl(
    x509_cert: &X509Certificate<'_>,
    x509_ca: &X509Certificate<'_>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    trace!("check CRL: x509_cert: {:?}", x509_cert);
    trace!("check CRL: x509_ca: {:?}", x509_ca);
    // Parse the CRL (if provided by CA) and check the certificate serial number
    match &x509_ca
        .tbs_certificate
        .extensions_map()?
        .get(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
    {
        Some(crl_list) => {
            debug!("CRL list: {:?}", &crl_list);
            if let ParsedExtension::CRLDistributionPoints(crl) = crl_list.parsed_extension() {
                for crl_points in &crl.points {
                    debug!("CRL parsed extension: {:?}", crl_points);

                    if let Some(reasons) = crl_points.reasons.as_ref() {
                        debug!("Reasons: {}", reasons);
                    }

                    if let Some(DistributionPointName::FullName(names)) =
                        &crl_points.distribution_point
                    {
                        debug!("CRL names: {names:?}");
                        if let GeneralName::URI(uri) = names[0] {
                            debug!("CRL GeneralName: {uri:?}");
                            let crl_bytes = reqwest::get(uri)
                                .await
                                .map_err(|e| {
                                    KmsError::Certificate(format!(
                                        "Cannot fetch CRL ({uri:?} for CA {:?}: Error: {e:?})",
                                        x509_ca.issuer
                                    ))
                                })?
                                .bytes()
                                .await
                                .map_err(|e| {
                                    KmsError::Certificate(format!(
                                        "Cannot convert CRL content to bytes. Error: {e:?}"
                                    ))
                                })?;
                            let (_, x509_crl) = parse_x509_crl(crl_bytes.as_bytes())?;

                            // Get issuer common name
                            let issuer_common_name = get_common_name(x509_crl.issuer())?;
                            let issuer_spki = get_crl_authority_key_identifier(&x509_crl)?;
                            let issuer_cert_bytes = locate_by_spki_and_get_certificate_bytes(
                                &issuer_common_name,
                                &issuer_spki,
                                kms,
                                owner,
                                params,
                            )
                            .await?;

                            let (_, pem_issuer) = parse_x509_pem(&issuer_cert_bytes).unwrap();
                            let (_, x509_issuer) =
                                parse_x509_certificate(&pem_issuer.contents).unwrap();

                            x509_crl.verify_signature(&x509_issuer.tbs_certificate.subject_pki)?;
                            debug!("CRL signature verified successfully");

                            // Check serial number against CRL
                            debug!("Certificate serial number: {:?}", x509_cert.serial);
                            for revoked in x509_crl.iter_revoked_certificates() {
                                trace!("Revoked certificate serial: {}", revoked.serial());
                                trace!("  Reason: {}", revoked.reason_code().unwrap_or_default().1);
                                if x509_cert.serial == revoked.serial().clone() {
                                    kms_bail!(
                                        "Certificate has been revoked! Certificate serial number \
                                         was found in the issuer CRL"
                                    );
                                }
                            }
                            debug!("Certificate is not revoked");
                        }
                    }
                }
            }
        }
        None => {
            debug!(
                "Check serial number: no OID extension {OID_X509_EXT_CRL_DISTRIBUTION_POINTS} \
                 found"
            );
        }
    }

    Ok(())
}
