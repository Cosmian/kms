use async_recursion::async_recursion;
use cosmian_kms_utils::access::ExtraDatabaseParams;
use tracing::{debug, trace, warn};
use x509_parser::{
    num_bigint::BigUint,
    oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS,
    parse_x509_certificate, parse_x509_crl,
    prelude::{
        parse_x509_pem, CRLDistributionPoint, DistributionPointName, GeneralName, ParsedExtension,
        X509Certificate,
    },
    x509::X509Name,
};

use crate::{
    core::{
        certificate::{
            locate::{
                locate_certificate_by_common_name_and_get_bytes,
                locate_certificate_by_spki_and_get_bytes,
            },
            parsing::{
                get_certificate_authority_subject_key_identifier,
                get_certificate_subject_key_identifier, get_common_name,
                get_crl_authority_key_identifier,
            },
        },
        KMS,
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// The `verify_certificate` function verifies the validity and integrity of
/// a given X.509 certificate, including checking its expiration, signature, and
/// serial number against a Certificate Revocation List (CRL). It also verifies that the certificate chain is valid.
///
/// Arguments:
///
/// * `pem_certificate`: A byte slice containing the PEM-encoded certificate.
/// * `leaf_serial_number`: This parameter represents the serial number of the leaf
/// certificate that is being verified. If provided, it is used to check if the
/// serial number is already revoked in the Certificate Revocation List (CRL) of all the CRL found in the chain.
/// * `kms`: The `kms` parameter is of type `&KMS`, which is a reference to an
/// instance of the `KMS` struct. It is used to interact with a Key Management
/// Service (KMS) for operations related to certificates.
/// * `owner`: The `owner` parameter is a string that represents the owner of the
/// certificate. It is used to locate the certificate in the KMS (Key Management
/// System) and perform various operations on it, such as verifying its validity and
/// checking if it has been revoked.
/// * `params`: The `params` parameter is an optional reference to an
/// `ExtraDatabaseParams` struct.
///
/// Returns:
///
/// Nothing if success
#[async_recursion(?Send)]
pub(crate) async fn verify_certificate(
    pem_certificate: &[u8],
    leaf_serial_number: Option<&'async_recursion BigUint>,
    kms: &KMS,
    owner: &str,
    params: Option<&'async_recursion ExtraDatabaseParams>,
) -> KResult<()> {
    // Parse PEM file and verify the validity of the certificate
    let (_, pem_cert) = parse_x509_pem(pem_certificate)?;
    let (_, x509_cert) = parse_x509_certificate(&pem_cert.contents)?;
    let common_name = get_common_name(x509_cert.subject())?;
    let issuer_common_name = get_common_name(x509_cert.issuer())?;
    let spki = get_certificate_subject_key_identifier(&x509_cert)?;
    debug!(
        "verify_certificate:\n\tissuer common name: {issuer_common_name}\n\tsubject common name: \
         {common_name}\n\tsubject public key identifier: {spki:?}"
    );

    if !x509_cert.validity().is_valid() {
        return Err(KmsError::Certificate(format!(
            "verify_certificate: Certificate is now expired. Certificate details: {x509_cert:?}"
        )))
    }
    debug!(
        "verify_certificate: Certificate is not expired: {:?}",
        x509_cert.validity()
    );

    // Subject common name being issuer common name indicates this is the root certificate
    // It also indicates it is a self-signed certificate
    if x509_cert.subject() == x509_cert.issuer() {
        x509_cert.verify_signature(None)?;
        debug!("verify_certificate:Certificate signature is valid: {spki:?}");
        if let Some(serial_number) = leaf_serial_number {
            check_serial_number_in_crl(serial_number, &x509_cert, kms, owner, params).await?;
        }
        check_serial_number_in_crl(&x509_cert.serial, &x509_cert, kms, owner, params).await?;
    } else {
        // From the issuer name, recover the KMIP certificate object
        let ca_certificate_bytes =
            match get_certificate_authority_subject_key_identifier(&x509_cert)? {
                Some(ca_spki) => {
                    locate_certificate_by_spki_and_get_bytes(
                        &issuer_common_name,
                        &ca_spki,
                        kms,
                        owner,
                        params,
                    )
                    .await?
                }
                None => {
                    locate_certificate_by_common_name_and_get_bytes(
                        &issuer_common_name,
                        kms,
                        owner,
                        params,
                    )
                    .await?
                }
            };

        // Parse PEM file and verify the validity of the signature certificate
        let (_, pem_ca) = parse_x509_pem(&ca_certificate_bytes)?;
        let (_, x509_ca) = parse_x509_certificate(&pem_ca.contents)?;
        let ca_spki = get_certificate_subject_key_identifier(&x509_ca)?;
        debug!(
            "verify_certificate: issuer certificate recovered from KMS with Subject Public Key \
             Identifier: {ca_spki:?}"
        );

        // Verify certificate signature against issuer public key
        x509_cert.verify_signature(Some(&x509_ca.tbs_certificate.subject_pki))?;
        debug!("verify_certificate: certificate signature is valid: {spki:?}");

        // Verify if serial number is already revoked
        check_serial_number_in_crl(&x509_cert.serial, &x509_cert, kms, owner, params).await?;
        check_serial_number_in_crl(&x509_cert.serial, &x509_ca, kms, owner, params).await?;

        verify_certificate(
            &ca_certificate_bytes,
            leaf_serial_number,
            kms,
            owner,
            params,
        )
        .await?;
    }

    Ok(())
}

/// The function `check_serial_number_in_crl` checks if a given serial number is
/// present in the Certificate Revocation List (CRL) of a certificate.
///
/// Arguments:
///
/// * `serial_number`: The serial number of the certificate that needs to be checked
/// in the Certificate Revocation List (CRL).
/// * `cert`: The x509 certificate carrying the CRL (issuer certificate or leaf certificate)
/// * `kms`: The `kms` instance
/// * `owner`: The `owner` parameter
/// * `params`: The `params` parameter is an optional reference to an
/// `ExtraDatabaseParams` struct. It is used to provide additional parameters for
/// the database query.
///
/// Returns:
///
/// Nothing if success
pub(crate) async fn check_serial_number_in_crl(
    serial_number: &BigUint,
    cert: &X509Certificate<'_>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    debug!("check_serial_number_in_crl: serial_number: {serial_number:?}",);
    debug!(
        "check_serial_number_in_crl: cert: {:?}",
        get_certificate_subject_key_identifier(cert)
    );

    // Parse the CRL (if provided by CA) and check the certificate serial number
    match &cert
        .tbs_certificate
        .extensions_map()?
        .get(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
    {
        Some(crl_list) => {
            debug!(
                "check_serial_number_in_crl: Found a CRL Distribution points x509 extension: {:?}",
                &crl_list
            );
            if let ParsedExtension::CRLDistributionPoints(crl) = crl_list.parsed_extension() {
                for crl_point in &crl.points {
                    check_distribution_point(serial_number, cert, crl_point, kms, owner, params)
                        .await?;
                }
            }
        }
        None => {
            debug!(
                "check_serial_number_in_crl: no OID extension \
                 {OID_X509_EXT_CRL_DISTRIBUTION_POINTS} found"
            );
        }
    }

    Ok(())
}

async fn check_distribution_point(
    serial_number: &BigUint,
    cert: &X509Certificate<'_>,
    crl_point: &CRLDistributionPoint<'_>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    debug!("check_distribution_point: CRL parsed extension: {crl_point:?}");

    if let Some(reasons) = crl_point.reasons.as_ref() {
        debug!("check_distribution_point: Reasons: {reasons}");
    }

    if let Some(DistributionPointName::FullName(names)) = &crl_point.distribution_point {
        for crl_name in names {
            if let GeneralName::URI(uri) = crl_name {
                debug!("check_crl_names: CRL GeneralName: {uri:?}");
                check_crl(uri, serial_number, &cert.issuer, kms, owner, params).await?;
            }
        }
    }
    Ok(())
}

async fn check_crl(
    uri: &str,
    serial_number: &BigUint,
    issuer: &X509Name<'_>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    debug!("check_crl_names: URI: {uri:?}");

    let distribution_point_bytes = match reqwest::get(uri).await {
        Ok(response) => response.bytes().await.map_err(|e| {
            KmsError::Certificate(format!("Cannot convert CRL content to bytes. Error: {e:?}"))
        })?,
        Err(e) => {
            warn!("Cannot fetch CRL ({uri:?} for certificate {issuer:?}: Error: {e:?})",);
            return Ok(())
        }
    };

    let (_, distribution_point) = parse_x509_pem(&distribution_point_bytes)?;
    let (_, x509_crl) = parse_x509_crl(&distribution_point.contents)?;

    // Get issuer common name
    let issuer_common_name = get_common_name(x509_crl.issuer())?;
    debug!("check_crl_names: issuer common name: {issuer_common_name:?}");
    let issuer_cert_bytes = match get_crl_authority_key_identifier(&x509_crl) {
        Some(ca_spki) => {
            locate_certificate_by_spki_and_get_bytes(
                &issuer_common_name,
                &ca_spki,
                kms,
                owner,
                params,
            )
            .await?
        }
        None => {
            locate_certificate_by_common_name_and_get_bytes(&issuer_common_name, kms, owner, params)
                .await?
        }
    };
    debug!("check_crl_names: found the CRL issuer certificate");

    let (_, pem_issuer) = parse_x509_pem(&issuer_cert_bytes)?;
    let (_, x509_issuer) = parse_x509_certificate(&pem_issuer.contents)?;
    debug!("check_crl_names: issuer certificate recovered from KMS",);

    x509_crl.verify_signature(&x509_issuer.tbs_certificate.subject_pki)?;
    debug!("check_crl_names: CRL signature verified successfully");

    // Check serial number against CRL
    debug!(
        "check_crl_names: Certificate serial number: {:?}",
        serial_number
    );
    for revoked in x509_crl.iter_revoked_certificates() {
        trace!(
            "check_crl_names: Revoked certificate serial: {}",
            revoked.serial()
        );
        trace!(
            "check_crl_names: Reason: {}",
            revoked.reason_code().unwrap_or_default().1
        );
        if serial_number == revoked.serial() {
            kms_bail!(
                "Certificate has been revoked! Certificate serial number was found in the issuer \
                 CRL"
            );
        }
    }
    debug!("check_crl_names: Certificate is not revoked");

    Ok(())
}
