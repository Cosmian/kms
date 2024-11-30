use std::{
    collections::{HashMap, HashSet},
    fs, path,
};

use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Validate, ValidateResponse},
    kmip_types::{UniqueIdentifier, ValidityIndicator},
    KmipOperation,
};
use cosmian_kms_server_database::ExtraStoreParams;
use openssl::{
    asn1::Asn1Time,
    stack::Stack,
    x509::{
        store::X509StoreBuilder, CrlStatus, DistPointNameRef, DistPointRef, GeneralNameRef,
        X509Crl, X509StoreContext, X509,
    },
};
use tracing::{debug, trace, warn};

use crate::{
    core::{retrieve_object_utils::retrieve_object_for_operation, KMS},
    error::KmsError,
    result::KResult,
};

lazy_static::lazy_static! {
    static ref CRL_CACHE_MAP: tokio::sync::RwLock<HashMap<String, Vec<u8>>> = tokio::sync::RwLock::new(HashMap::new());
}

/// This operation requests the server to validate a certificate chain and return
/// information on its validity.
///
/// Only a single certificate chain SHALL be included in each request.
/// The request MAY contain a list of certificate objects, and/or a list of
/// Unique Identifiers that identify Managed Certificate objects.
///
/// Together, the two lists compose a certificate chain to be validated.
///
/// The request MAY also contain a date for which all certificates in the
/// certificate chain are REQUIRED to be valid.
///
/// The method or policy by which validation is conducted is a decision of the
/// server and is outside of the scope of this protocol. Likewise, the order in
/// which the supplied certificate chain is validated and the specification of
/// trust anchors used to terminate validation are also controlled by the server.
///
/// # Arguments
///
/// * `kms` - A reference to the KMS (Key Management Service) instance.
/// * `request` - The `Validate` request containing the unique identifier and/or certificates to be validated.
/// * `user` - A string slice representing the user requesting the validation.
/// * `params` - An optional reference to additional database parameters.
///
/// # Returns
///
/// A `KResult` containing a `ValidateResponse` which indicates the validity of the certificates.
///
/// # Errors
///
/// This function will return a `KmsError` if:
/// - The number of certificates found in the database does not match the number of certificates in the request.
/// - There is an error converting the certificates from bytes to X509 format.
/// - There is an error sorting the certificates.
/// - There is an error verifying the chain signature.
/// - There is an error validating the chain date.
/// - There is an error verifying the CRLs (Certificate Revocation Lists).
/// ```
pub(crate) async fn validate_operation(
    kms: &KMS,
    request: Validate,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<ValidateResponse> {
    trace!("Validate: {}", request);

    debug!("Get input certificates as bytes");
    let (certificates, certificates_number) = match (request.unique_identifier, request.certificate)
    {
        (None, None) => {
            return Err(KmsError::Certificate(
                "Empty chain cannot be validated".to_owned(),
            ));
        }
        (None, Some(certificates)) => Ok::<_, KmsError>((certificates.clone(), certificates.len())),
        (Some(mut unique_identifiers), None) => {
            let set: HashSet<_> = unique_identifiers.drain(..).collect(); // dedup
            unique_identifiers.extend(set.into_iter());
            Ok((
                certificates_by_uid(unique_identifiers.clone(), kms, user, params).await?,
                unique_identifiers.len(),
            ))
        }
        (Some(mut unique_identifiers), Some(certificates)) => {
            let set: HashSet<_> = unique_identifiers.drain(..).collect(); // dedup
            unique_identifiers.extend(set.into_iter());
            Ok((
                [
                    certificates.clone(),
                    certificates_by_uid(unique_identifiers.clone(), kms, user, params).await?,
                ]
                .concat(),
                certificates.len() + unique_identifiers.len(),
            ))
        }
    }?;

    debug!("Number of certificates in chain: {certificates_number}");
    if certificates.len() != certificates_number {
        return Err(KmsError::Certificate(
            "Number of certificates found in database and number of certificates in request do \
             not match"
                .to_owned(),
        ));
    };

    // Convert the certificates from bytes to X509
    let certificates = certificates
        .into_iter()
        .map(|cert| X509::from_der(cert.as_slice()))
        .collect::<Result<Vec<X509>, _>>()?;

    // Sort the chain in right order: ROOT/SUBCA/../LEAF.
    // Sorting the chain greatly simplify the flow in the signature and revocation verification
    let certificates = if certificates.len() > 1 {
        sort_certificates(&certificates)?
    } else {
        certificates
    };

    verify_chain_signature(&certificates)?;
    validate_chain_date(&certificates, &request.validity_time)?;
    verify_crls(certificates).await?;

    Ok(ValidateResponse {
        validity_indicator: ValidityIndicator::Valid,
    })
}

/// Extracts the subject key identifier and authority key identifier from an X509 certificate.
///
/// # Arguments
///
/// * `certificate` - A reference to an `X509` certificate from which the identifiers will be extracted.
///
/// # Returns
///
/// A tuple containing two byte slices:
///
/// * The first element is the subject key identifier as a byte slice.
/// * The second element is the authority key identifier as a byte slice.
///
/// If either identifier is not present in the certificate, an empty byte slice is returned for that identifier.
fn get_certificate_identifiers(certificate: &X509) -> (&[u8], &[u8]) {
    (
        certificate
            .subject_key_id()
            .map(openssl::asn1::Asn1OctetStringRef::as_slice)
            .unwrap_or_default(),
        certificate
            .authority_key_id()
            .map(openssl::asn1::Asn1OctetStringRef::as_slice)
            .unwrap_or_default(),
    )
}

/// Debug the details of a given X.509 certificate along with a debug message.
///
/// This function retrieves the Subject Key Identifier (SKI) and Authority Key Identifier (AKI)
/// from the provided certificate and logs them along with the certificate's subject name and
/// a custom debug message.
///
/// # Arguments
///
/// * `debug_msg` - A string slice that holds the debug message to be logged.
/// * `certificate` - A reference to an `X509` certificate whose details are to be traced.
///
/// # Panics
///
/// This function does not panic.
///
/// # Errors
///
/// This function does not return errors.
fn trace_certificate(debug_msg: &str, certificate: &X509) {
    let (ski, aki) = get_certificate_identifiers(certificate);
    trace!(
        "{debug_msg}. Certificate: subject: {:?}, AKI: {:?}, SKI: {:?}",
        certificate.subject_name(),
        hex::encode(ski),
        hex::encode(aki),
    );
}

/// Sort a X509 certificate list according to their Authority Key Identifier (AKI) and Subject Key Identifier (SKI).
/// AKI and SKI MUST appear as CA certificate X509 extensions.
///
/// Order of output chain will be ROOT/SUBCA/../LEAF.
///
/// As a reminder: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2>:
///
/// To facilitate certification path construction, this extension MUST
/// appear in all conforming CA certificates, that is, all certificates
/// including the basic constraints extension (Section 4.2.1.9) where the
/// value of cA is TRUE.  In conforming CA certificates, the value of the
/// subject key identifier MUST be the value placed in the key identifier
/// field of the authority key identifier extension (Section 4.2.1.1) of
/// certificates issued by the subject of this certificate.  Applications
/// are not required to verify that key identifiers match when performing
/// certification path validation.
///
/// Only leaf certificates can omit AKI and SKI.
///
/// # Arguments
///
/// * `certificates` - The list of X509 certificates to sort.
///
/// # Returns
///
/// Returns a `Result` containing the sorted list of X509 certificates if successful,
/// or a `KmsError` if an error occurs during the sorting process.
fn sort_certificates(certificates: &[X509]) -> KResult<Vec<X509>> {
    let mut sorted_chains = Vec::<X509>::with_capacity(certificates.len());
    let mut certificates_copy: Vec<X509> = certificates.to_vec();
    let mut indexes_to_remove = vec![];

    // First step, identify root and leaf
    // Each of this certificate can be identified with their SKI and AKI
    // Root has the same SKI and AKI
    // And only a leaf can omit AKI and SKI
    for (index, certificate) in certificates_copy.iter().enumerate() {
        let (ski, aki) = get_certificate_identifiers(certificate);
        trace_certificate("Finding root (or leaf)", certificate);

        if ski == aki && !ski.is_empty() {
            trace_certificate("Root found", certificate);
            sorted_chains.insert(0, certificate.to_owned());
            indexes_to_remove.push(index);
        }

        if aki.is_empty() && ski.is_empty() {
            trace_certificate("No AKI nor SKI -> leaf found", certificate);
            sorted_chains.push(certificate.to_owned());
            indexes_to_remove.push(index);
        }
    }

    if sorted_chains.is_empty() {
        return Err(KmsError::Certificate(
            "No root authority found, cannot proceed full chain validation".to_owned(),
        ));
    }

    for &index in indexes_to_remove.iter().rev() {
        certificates_copy.remove(index);
    }

    trace!(
        "Root and possibly leaf removed from initial certificate list. Left: {}",
        certificates_copy.len()
    );
    // since certificates are not in the right order, we need to loop on the number of certificates - worst case
    for _ in 0..certificates.len() {
        if sorted_chains.len() == certificates.len() {
            trace!("All certificates have been sorted");
            break;
        }
        for certificate in &certificates_copy {
            if sorted_chains.len() == certificates.len() {
                trace!("All certificates have been sorted");
                break;
            }
            let (ski, aki) = get_certificate_identifiers(certificate);
            trace_certificate(
                "Trying to find the certificate position on the sorted list",
                certificate,
            );

            for (idx, sorted_certificate) in sorted_chains.clone().iter().enumerate() {
                let (ski_2, aki_2) = get_certificate_identifiers(sorted_certificate);
                trace_certificate("Iterate on sorted certificates", sorted_certificate);

                // Found a certificate child
                if aki == ski_2 && !aki.is_empty() && !sorted_chains.contains(certificate) {
                    trace_certificate(
                        &format!("Insert certificate at index: {}", idx + 1),
                        certificate,
                    );
                    sorted_chains.insert(idx + 1, certificate.to_owned());
                    break;
                }

                // Found the authority of the certificate
                if ski == aki_2 && !ski.is_empty() && !sorted_chains.contains(certificate) {
                    trace_certificate(&format!("Insert certificate at index: {idx}"), certificate);
                    sorted_chains.insert(idx, certificate.to_owned());
                    break;
                }

                warn!(
                    "Could not insert: certificate: AKI: {}, SKI: {}",
                    hex::encode(aki),
                    hex::encode(ski)
                );
            }
        }
    }

    if sorted_chains.len() != certificates.len() {
        return Err(KmsError::Certificate(
            "Failed to sort the certificates. Certificate chain incomplete?".to_owned(),
        ));
    }

    Ok(sorted_chains)
}

/// Verifies the signature of a chain of X509 certificates.
///
/// # Arguments
///
/// * `certificates` - A slice of X509 certificates representing the certificate chain.
///
/// # Returns
///
/// * `KResult<ValidityIndicator>` - Returns `Ok(ValidityIndicator::Valid)` if the certificate chain is valid,
///   otherwise returns an error of type `KmsError::Certificate`.
///
/// # Errors
///
/// This function will return an error in the following cases:
///
/// * If the certificate chain is empty.
/// * If there is an issue creating the X509 store builder.
/// * If there is an issue adding certificates to the store.
/// * If there is an issue building the store.
/// * If there is an issue creating the store context for verification.
/// * If the verification of the certificate chain fails.
/// * If the verification of individual certificates in the chain fails.
/// ```
fn verify_chain_signature(certificates: &[X509]) -> KResult<ValidityIndicator> {
    if certificates.is_empty() {
        return Err(KmsError::Certificate(
            "Certificate chain is empty".to_owned(),
        ));
    }

    // Create a new X509 store builder
    let mut builder = X509StoreBuilder::new()?;

    // Get leaf
    let leaf = certificates.last().ok_or_else(|| {
        KmsError::Certificate("Failed to get last element of the chain".to_owned())
    })?;

    // Add authorities to the store
    if certificates.len() == 1 {
        builder.add_cert(leaf.to_owned())?;
    } else {
        for certificate in certificates.iter().take(certificates.len() - 1) {
            builder.add_cert(certificate.to_owned())?;
        }
    }

    // Build the store
    let store = builder.build();

    // Create a store context for verification
    let mut context = X509StoreContext::new()?;
    let result = context.init(
        &store,
        leaf,
        Stack::new()?.as_ref(),
        openssl::x509::X509StoreContextRef::verify_cert,
    )?;

    if !result {
        return Err(KmsError::Certificate(
            "Result of the function verify_cert: {result:?}".to_owned(),
        ));
    }

    // verify signatures in cascade
    let mut issuer_public_key = certificates
        .first()
        .ok_or_else(|| {
            KmsError::Certificate("Failed to get the first element of the chain".to_owned())
        })?
        .public_key()?;
    for cert in certificates {
        if !cert.verify(&issuer_public_key)? {
            return Err(KmsError::Certificate(format!(
                "Failed to verify the certificate: {:?}",
                cert.subject_name()
            )));
        }
        issuer_public_key = cert.public_key()?;
    }

    Ok(ValidityIndicator::Valid)
}

enum UriType {
    Url(String),
    Path(String),
}

/// Retrieves Certificate Revocation List (CRL) bytes from a list of URIs.
///
/// This function takes a list of URIs, which can be either URLs or file paths, and retrieves the
/// corresponding CRL bytes. The retrieved CRLs are cached to avoid redundant network or file system
/// access. If a CRL is already cached, it is directly retrieved from the cache.
///
/// # Arguments
///
/// * `uri_list` - A vector of strings representing the URIs from which to retrieve the CRLs.
///
/// # Returns
///
/// A `KResult` containing a `HashMap` where the keys are the URIs and the values are the corresponding
/// CRL bytes. If an error occurs during the retrieval process, a `KmsError::Certificate` is returned.
///
/// # Errors
///
/// This function will return an error if:
/// - The provided URI is invalid.
/// - There is an error in retrieving the CRL from a URL.
/// - There is an error in reading the CRL from a file path.
/// ```
async fn get_crl_bytes(uri_list: Vec<String>) -> KResult<HashMap<String, Vec<u8>>> {
    trace!("get_crl_bytes: entering: uri_list: {uri_list:?}");

    let mut result = HashMap::new();

    for uri in uri_list {
        // checking whether the resource is an URL or a Pathname
        let uri_type = if let Ok(url) = url::Url::parse(&uri) {
            Some(UriType::Url(url.into()))
        } else {
            let path_buf = path::Path::new(&uri).canonicalize()?;
            match path_buf.to_str() {
                Some(s) => Some(UriType::Path(s.to_owned())),
                None => {
                    return Err(KmsError::Certificate(
                        "The uri provided is invalid".to_owned(),
                    ))
                }
            }
        };

        // Retrieving the object from its location
        match uri_type {
            Some(UriType::Url(url)) => {
                let mut crls = CRL_CACHE_MAP.write().await;
                if crls.contains_key(&url) {
                    debug!("CRL list already contains key: {url}");
                    crls.get(&url).and_then(|v| result.insert(url, v.clone()));
                    continue;
                }

                let response = reqwest::Client::new().get(&url).send().await?;
                debug!("after getting CRL: url: {url}");
                if response.status().is_success() {
                    let crl_bytes =
                        response
                            .bytes()
                            .await
                            .map(|text| text.to_vec())
                            .map_err(|e| {
                                KmsError::Certificate(format!(
                                    "Error in getting the body of the response for the following \
                                     URL: {url}. Error: {e:?} "
                                ))
                            })?;
                    debug!("reading full bytes of CRL: url: {url}");
                    crls.insert(url.clone(), crl_bytes.clone());
                    result.insert(url, crl_bytes);
                    break;
                }
                return Err(KmsError::Certificate(format!(
                    "The CRL at the following URL {url} is not available. Status: {}",
                    response.status()
                )));
            }
            Some(UriType::Path(path)) => {
                // Get PEM file (path should be already canonic)
                let mut crls = CRL_CACHE_MAP.write().await;
                if crls.contains_key(&path) {
                    debug!("CRL list already contains key: {path}");
                    crls.get(&path).and_then(|v| result.insert(path, v.clone()));
                    continue;
                }

                let crl_bytes = fs::read(path::Path::new(&path))?;
                crls.insert(path.clone(), crl_bytes.clone());
                result.insert(path, crl_bytes);
            }
            _ => {
                return Err(KmsError::Certificate(
                    "Error that should not manifest".to_owned(),
                ))
            }
        };
    }

    debug!(
        "get_crl_bytes: exiting in success with {} CRLs",
        result.len()
    );
    Ok(result)
}

/// Verifies the Certificate Revocation Lists (CRLs) for a given list of certificates.
///
/// This function iterates over the provided certificates and performs the following checks:
/// 1. For each certificate, if it is not the first one, it checks if the certificate is present in the parent CRLs.
/// 2. If the certificate has CRL distribution points, it fetches the CRLs from the specified URIs and verifies them.
///
/// # Arguments
///
/// * `certificates` - A vector of `X509` certificates to be verified.
///
/// # Returns
///
/// * `KResult<ValidityIndicator>` - Returns `ValidityIndicator::Valid` if all certificates are valid,
///   otherwise returns an error indicating the reason for invalidity.
///
/// # Errors
///
/// This function will return an error in the following cases:
/// * If a certificate is found to be revoked or removed from the CRL.
/// * If there is an issue deserializing a CRL.
/// * If the CRL signature is invalid.
/// * If there is an issue fetching the CRL bytes from the URIs.
/// ```
async fn verify_crls(certificates: Vec<X509>) -> KResult<ValidityIndicator> {
    let mut current_crls: HashMap<String, Vec<u8>> = HashMap::new();

    for (idx, certificate) in certificates.iter().enumerate() {
        debug!(
            "[{idx}] Verifying certificate: subject: {:?}",
            certificate.subject_name()
        );

        //
        // Test if certificate is in parent CRLs
        //
        if idx > 0 {
            for (crl_path, crl_value) in &current_crls {
                let crl = X509Crl::from_pem(crl_value.as_slice())?;
                trace!("CRL deserialized OK: {crl_path}");
                let res = crl_status_to_validity_indicator(&crl.get_by_cert(certificate));
                debug!("Parent CRL verification: revocation status: {res:?}");
                if res == ValidityIndicator::Invalid {
                    return Err(KmsError::Certificate(
                        "Certificate is revoked or removed from CRL".to_owned(),
                    ));
                }
            }
        }
        if let Some(crl_dp) = certificate.crl_distribution_points() {
            let crl_size = crl_dp.len();
            let mut uri_list = Vec::with_capacity(crl_size);
            for i in 0..crl_size {
                let crl_uri = crl_dp
                    .get(i)
                    .and_then(DistPointRef::distpoint)
                    .and_then(DistPointNameRef::fullname)
                    .and_then(|x| x.get(0))
                    .and_then(GeneralNameRef::uri);
                if let Some(crl_uri) = crl_uri {
                    if !uri_list.contains(&crl_uri.to_owned()) {
                        uri_list.push(crl_uri.to_owned());
                        trace!("Found CRL URI: {crl_uri}");
                    }
                }
            }

            current_crls = get_crl_bytes(uri_list).await?;

            //
            // Test if certificate is in current CRLs
            //
            for (crl_path, crl_value) in &current_crls {
                // Verifying that the CRL is properly signed by its issuer
                let crl = X509Crl::from_pem(crl_value.as_slice())?;
                trace!("CRL deserialized OK: {crl_path}");

                // Except when this is a leaf certificate (CRL are always signed by CA)
                let cert_key = certificate.public_key()?;
                debug!("Get certificate public key OK: {cert_key:?}");
                if crl.verify(&cert_key)? {
                    return Err(KmsError::Certificate(format!(
                        "Invalid CRL signature: {:?}",
                        crl.issuer_name()
                    )))
                };

                let res = crl_status_to_validity_indicator(&crl.get_by_cert(certificate));
                debug!("Revocation status: result: {res:?}");
                if res == ValidityIndicator::Invalid {
                    return Err(KmsError::Certificate(
                        "Certificate is revoked or removed from CRL".to_owned(),
                    ));
                }
            }
        }
    }
    trace!("verify_crls: exiting in success");
    Ok(ValidityIndicator::Valid)
}

// If fetching a certificate fails, the method reports the first error happening.
// Otherwise it returns a vector of certificates.
async fn certificates_by_uid(
    unique_identifiers: Vec<UniqueIdentifier>,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<Vec<Vec<u8>>> {
    debug!("certificates_by_uid: entering: {unique_identifiers:?}");
    let mut results = Vec::new();
    for unique_identifier in unique_identifiers {
        let unique_identifier = unique_identifier.as_str().ok_or_else(|| {
            KmsError::Certificate("as_str returned None in certificates_by_uid".to_owned())
        })?;
        let result = certificate_by_uid(unique_identifier, kms, user, params).await?;
        results.push(result);
    }
    Ok(results)
}

// Fetches a certificate. If it fails, returns the according error
async fn certificate_by_uid(
    unique_identifier: &str,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<Vec<u8>> {
    let uid_owm = retrieve_object_for_operation(
        unique_identifier,
        KmipOperation::Validate,
        kms,
        user,
        params,
    )
    .await?;

    if let Object::Certificate {
        certificate_type: _,
        certificate_value,
    } = uid_owm.object()
    {
        Ok(certificate_value.clone())
    } else {
        Err(KmsError::Certificate(format!(
            "Requested a Certificate Object, got a {}",
            uid_owm.object().object_type()
        )))
    }
}

fn validate_chain_date(certificates: &[X509], date: &Option<String>) -> KResult<ValidityIndicator> {
    let current_date = date.clone().map_or_else(
        || Asn1Time::days_from_now(0),
        |date| Asn1Time::from_str(date.as_str()),
    )?;
    certificates
        .iter()
        .try_fold(ValidityIndicator::Valid, |acc, certificate| {
            let validation = validate_date(certificate, &current_date);
            if validation == ValidityIndicator::Invalid {
                Err(KmsError::Certificate(format!(
                    "According to this date ({date:?}), the following certificate will be invalid \
                     {:?}",
                    certificate.subject_name()
                )))
            } else {
                Ok(acc.and(validation))
            }
        })
}

fn validate_date(certificate: &X509, date: &Asn1Time) -> ValidityIndicator {
    let now = date.as_ref();
    let (start, stop) = (certificate.not_before(), certificate.not_after());
    if start <= now && now <= stop {
        ValidityIndicator::Valid
    } else {
        ValidityIndicator::Invalid
    }
}

const fn crl_status_to_validity_indicator(status: &CrlStatus) -> ValidityIndicator {
    match status {
        CrlStatus::NotRevoked => ValidityIndicator::Valid,
        CrlStatus::RemoveFromCrl(_) | CrlStatus::Revoked(_) => ValidityIndicator::Invalid,
    }
}
