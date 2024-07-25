use std::{collections::HashSet, fs, path, time::Duration};

use cosmian_kmip::{
    kmip::{
        kmip_objects::Object,
        kmip_operations::{ErrorReason, Validate, ValidateResponse},
        kmip_types::{UniqueIdentifier, ValidityIndicator},
    },
    KmipError,
};
use cosmian_kms_client::access::ObjectOperationType;
use http::{HeaderMap, HeaderValue};
use openssl::{
    asn1::Asn1Time,
    stack::Stack,
    x509::{
        store::X509StoreBuilder, CrlStatus, DistPointNameRef, DistPointRef, GeneralNameRef,
        X509Crl, X509StoreContext, X509,
    },
};
use tracing::{debug, error, trace, warn};

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    database::retrieve_object_for_operation,
    error::KmsError,
    result::KResult,
};

const MAX_RETRY_COUNT: u32 = 2;

/// This operation requests the server to validate a certificate chain and return
/// information on its validity.
/// Only a single certificate chain SHALL be included in each request.
/// The request MAY contain a list of certificate objects, and/or a list of
/// Unique Identifiers that identify Managed Certificate objects.
/// Together, the two lists compose a certificate chain to be validated.
/// The request MAY also contain a date for which all certificates in the
/// certificate chain are REQUIRED to be valid.
/// The method or policy by which validation is conducted is a decision of the
/// server and is outside of the scope of this protocol. Likewise, the order in
/// which the supplied certificate chain is validated and the specification of
/// trust anchors used to terminate validation are also controlled by the server.
pub(crate) async fn validate_operation(
    kms: &KMS,
    request: Validate,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ValidateResponse> {
    trace!("Validate: {:?}", request);

    let mut headers = HeaderMap::new();
    headers.insert("Connection", HeaderValue::from_static("keep-alive"));
    let client = reqwest::ClientBuilder::new()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(10))
        .tcp_keepalive(Duration::from_secs(15))
        .pool_idle_timeout(Duration::from_secs(0))
        .pool_max_idle_per_host(0)
        .default_headers(headers)
        .build()
        .map_err(|e| {
            KmsError::Certificate(format!("Unable to build Reqwest client: Error: {e:?}"))
        })?;

    debug!("Get input certificates as bytes");
    let (certificates, certificates_number) = match (request.unique_identifier, request.certificate)
    {
        (None, None) => {
            return Ok(ValidateResponse {
                validity_indicator: ValidityIndicator::Unknown,
            })
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
        error!(
            "Number of certificates found in database and number of certificates in request do \
             not match"
        );
        return Ok(ValidateResponse {
            validity_indicator: ValidityIndicator::Invalid,
        })
    };

    let certificates = certificates
        .into_iter()
        .map(|cert| X509::from_der(cert.as_slice()))
        .collect::<Result<Vec<X509>, _>>()?;

    let sorted_certificates = if certificates.len() > 1 {
        index_certificates(&certificates)?
    } else {
        certificates.clone()
    };

    let signature_validity = verify_chain_signature(&sorted_certificates)?;
    debug!("Verifying chain signature: {signature_validity:?}");
    if signature_validity == ValidityIndicator::Invalid {
        return Ok(ValidateResponse {
            validity_indicator: ValidityIndicator::Invalid,
        });
    }

    let date_validity = validate_chain_date(&certificates, request.validity_time)?;
    debug!("Verifying if the certificate chain has not expired: result: {date_validity:?}");
    if date_validity == ValidityIndicator::Invalid {
        return Ok(ValidateResponse {
            validity_indicator: ValidityIndicator::Invalid,
        });
    }

    let crl_status_validity = verify_crls(&client, sorted_certificates).await?;
    debug!(
        "Verifying if the certificate chain has revoked elements: result: {crl_status_validity:?}"
    );
    if crl_status_validity == ValidityIndicator::Invalid {
        return Ok(ValidateResponse {
            validity_indicator: ValidityIndicator::Invalid,
        });
    }

    Ok(ValidateResponse {
        validity_indicator: ValidityIndicator::Valid,
    })
}

/// Sort a X509 certificate list. Format of output chain will be ROOT/SUBCA/../LEAF
///
/// # Arguments
///
/// * `certificates` - The list of X509 certificates to be indexed.
///
/// # Returns
///
/// Returns a `Result` containing the sorted list of X509 certificates if successful,
/// or a `KmsError` if an error occurs during the indexing process.
fn index_certificates(certificates: &[X509]) -> KResult<Vec<X509>> {
    let mut sorted_chains = Vec::<X509>::with_capacity(certificates.len());
    let mut certificates_copy: Vec<X509> = certificates.to_vec();
    let mut indexes_to_remove = vec![];

    for (index, certificate) in certificates_copy.iter().enumerate() {
        let ski = certificate
            .subject_key_id()
            .map(openssl::asn1::Asn1OctetStringRef::as_slice)
            .unwrap_or_default();
        let aki = certificate
            .authority_key_id()
            .map(openssl::asn1::Asn1OctetStringRef::as_slice)
            .unwrap_or_default();
        trace!(
            "Finding root: iterate on certificate: AKI: {}, SKI: {}",
            hex::encode(aki),
            hex::encode(ski)
        );

        if ski == aki && !ski.is_empty() {
            trace!(
                "Root found: AKI: {}, SKI: {}",
                hex::encode(aki),
                hex::encode(ski)
            );
            sorted_chains.insert(0, certificate.to_owned());
            indexes_to_remove.push(index);
        }

        if aki.is_empty() && ski.is_empty() {
            trace!(
                "Leaf found: AKI: {}, SKI: {}",
                hex::encode(aki),
                hex::encode(ski)
            );
            sorted_chains.push(certificate.to_owned());
            indexes_to_remove.push(index);
        }
    }

    if sorted_chains.is_empty() {
        return Err(KmsError::Certificate(
            "No root authority found, cannot proceed full chain validation".to_string(),
        ));
    }

    for &index in indexes_to_remove.iter().rev() {
        certificates_copy.remove(index);
    }

    for _ in 0..certificates.len() {
        for certificate in &certificates_copy {
            let ski_1 = certificate
                .subject_key_id()
                .map(openssl::asn1::Asn1OctetStringRef::as_slice)
                .unwrap_or_default();
            let aki_1 = certificate
                .authority_key_id()
                .map(openssl::asn1::Asn1OctetStringRef::as_slice)
                .unwrap_or_default();
            trace!("Iterate on certificate: {:?}", certificate.subject_name());

            for (idx, sorted_certificate) in sorted_chains.clone().iter().enumerate() {
                let ski_2 = sorted_certificate
                    .subject_key_id()
                    .map(openssl::asn1::Asn1OctetStringRef::as_slice)
                    .unwrap_or_default();
                let aki_2 = sorted_certificate
                    .authority_key_id()
                    .map(openssl::asn1::Asn1OctetStringRef::as_slice)
                    .unwrap_or_default();
                trace!(
                    "Iterate on SORTED certificate: {:?}: AKI: {}, SKI: {}",
                    sorted_certificate.subject_name(),
                    hex::encode(aki_2),
                    hex::encode(ski_2)
                );
                // Found a certificate child
                if aki_1 == ski_2 && !aki_1.is_empty() && !sorted_chains.contains(certificate) {
                    trace!(
                        "Insert certificate at index: {}: AKI: {}, SKI: {}",
                        idx + 1,
                        hex::encode(aki_1),
                        hex::encode(ski_1)
                    );
                    sorted_chains.insert(idx + 1, certificate.to_owned());
                    break;
                }

                // Found the authority of the certificate
                if ski_1 == aki_2 && !ski_1.is_empty() && !sorted_chains.contains(certificate) {
                    trace!(
                        "Insert certificate at index: {}: AKI: {}, SKI: {}",
                        idx,
                        hex::encode(aki_1),
                        hex::encode(ski_1)
                    );
                    sorted_chains.insert(idx, certificate.to_owned());
                    break;
                }

                warn!(
                    "Could not insert: certificate: AKI: {}, SKI: {}",
                    hex::encode(aki_1),
                    hex::encode(ski_1)
                );
            }
        }
    }

    if sorted_chains.len() != certificates.len() {
        return Err(KmsError::from(KmipError::InvalidKmipObject(
            ErrorReason::Internal_Server_Error,
            "Failed to sort the certificates".to_string(),
        )));
    }

    Ok(sorted_chains)
}

fn verify_chain_signature(certificates: &[X509]) -> KResult<ValidityIndicator> {
    if certificates.is_empty() {
        return Ok(ValidityIndicator::Invalid);
    }

    // Create a new X509 store builder
    let mut builder = X509StoreBuilder::new()?;

    // Get leaf
    let leaf = certificates.last().ok_or_else(|| {
        KmsError::Certificate("Failed to get last element of the chain".to_string())
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

    debug!("Result of the function verify_cert: {result:?}");
    if !result {
        return Ok(ValidityIndicator::Invalid);
    }

    // verify signatures in cascade
    let mut issuer_public_key = certificates
        .first()
        .ok_or_else(|| {
            KmsError::Certificate("Failed to get the first element of the chain".to_string())
        })?
        .public_key()?;
    for cert in certificates {
        if !cert.verify(&issuer_public_key)? {
            warn!(
                "Failed to verify the certificate: {:?}",
                cert.subject_name()
            );
            return Ok(ValidityIndicator::Invalid);
        }
        issuer_public_key = cert.public_key()?;
    }

    Ok(ValidityIndicator::Valid)
}

enum UriType {
    Url(String),
    Path(String),
}

async fn get_crl_bytes(client: &reqwest::Client, uri_list: Vec<String>) -> KResult<Vec<Vec<u8>>> {
    trace!("get_crl_bytes: entering");
    let mut crl_bytes_list = Vec::<Vec<u8>>::new();

    tokio::time::sleep(Duration::from_secs(1)).await;
    for uri in uri_list {
        // checking whether the resource is an URL or a Pathname
        let uri_type = if let Ok(url) = url::Url::parse(&uri) {
            Some(UriType::Url(url.into()))
        } else {
            let path_buf = path::Path::new(&uri).canonicalize()?;
            match path_buf.to_str() {
                Some(s) => Some(UriType::Path(s.to_string())),
                None => {
                    return Err(KmsError::Certificate(
                        "The uri provided is invalid".to_string(),
                    ))
                }
            }
        };

        // Retrieving the object from its location
        match uri_type {
            Some(UriType::Url(url)) => {
                let mut retry_count = 0;
                for _ in 0..MAX_RETRY_COUNT {
                    let response_result = client.get(&url).send().await;
                    match response_result {
                        Ok(response) => {
                            let response_status = response.status();
                            if response_status.is_success() {
                                let crl_bytes = response
                                    .text()
                                    .await
                                    .map(|text| text.as_bytes().to_vec())
                                    .map_err(|e| {
                                        KmsError::Certificate(format!(
                                            "Error in getting the body of the response for the \
                                             following URL: {url}. Error: {e:?} "
                                        ))
                                    })?;
                                crl_bytes_list.push(crl_bytes);
                                break;
                            } else {
                                retry_count += 1;
                                warn!(
                                    "The CRL at the following URL {url} is not available. Retry \
                                     count {retry_count}. Status: {response_status}",
                                );
                                if retry_count >= MAX_RETRY_COUNT {
                                    return Err(KmsError::Certificate(format!(
                                        "The CRL at the following URL {url} is not available"
                                    )));
                                }
                            }
                        }
                        Err(error) => {
                            retry_count += 1;
                            warn!(
                                "Error getting the CRL at the following URL {url}. Retry count \
                                 {retry_count}. Error: {error:?}",
                            );
                            if retry_count >= MAX_RETRY_COUNT {
                                return Err(KmsError::Certificate(format!(
                                    "The CRL at the following URL {url} is not available"
                                )));
                            }
                        }
                    }
                }
            }
            Some(UriType::Path(path)) => {
                // Get PEM file (path should be already canonic)
                let crl_bytes = fs::read(path::Path::new(&path))?;
                crl_bytes_list.push(crl_bytes);
            }
            _ => {
                return Err(KmsError::Certificate(
                    "Error that should not manifest".to_string(),
                ))
            }
        };
    }

    trace!(
        "get_crl_bytes: exiting in success with {} CRLs",
        crl_bytes_list.len()
    );
    Ok(crl_bytes_list)
}

async fn verify_crls(
    client: &reqwest::Client,
    certificates: Vec<X509>,
) -> KResult<ValidityIndicator> {
    let mut crls = Vec::<Vec<u8>>::new();

    for (idx, certificate) in certificates.iter().enumerate() {
        debug!(
            "[{idx}] Verifying certificate: subject: {:?}",
            certificate.subject_name()
        );
        if idx > 0 {
            for crl in crls {
                let crl = X509Crl::from_pem(crl.as_slice())?;
                let res = crl_status_to_validity_indicator(crl.get_by_cert(certificate));
                debug!("Verifying that the certificate is not revoked: result: {res:?}");
                if res == ValidityIndicator::Invalid {
                    debug!("Certificate is revoked or removed from CRL");
                    return Ok(ValidityIndicator::Invalid)
                }
            }
        }
        let uri_list = match certificate.crl_distribution_points() {
            None => vec![],
            Some(crl_dp) => {
                let crl_size = crl_dp.len();
                let mut uri_list = Vec::<String>::new();
                for i in 0..crl_size {
                    let crl_uri = crl_dp
                        .get(i)
                        .and_then(DistPointRef::distpoint)
                        .and_then(DistPointNameRef::fullname)
                        .and_then(|x| x.get(0))
                        .and_then(GeneralNameRef::uri);
                    if let Some(crl_uri) = crl_uri {
                        uri_list.push(crl_uri.to_string());
                        debug!("Found CRL URI: {crl_uri}");
                    }
                }
                uri_list
            }
        };

        crls = get_crl_bytes(client, uri_list).await?;
        debug!("Number of CRL found {}", crls.len());
        for crl in crls.clone() {
            // Verifying that the CRL is properly signed by its issuer
            let crl = X509Crl::from_pem(crl.as_slice())?;
            let cert_key = &certificate.public_key()?;
            if crl.verify(cert_key)? {
                return Err(KmsError::Certificate("Invalid CRL signature".to_string()))
            };
            debug!("Direct verification: Verifying that the certificate is not revoked");
            let res = crl_status_to_validity_indicator(crl.get_by_cert(certificate));
            debug!(
                "Direct verification: Verifying that the certificate is not revoked: result: \
                 {res:?}"
            );
            if res == ValidityIndicator::Invalid {
                debug!("Direct verification: Certificate is revoked or removed from CRL");
                return Ok(ValidityIndicator::Invalid)
            }
        }
    }
    debug!("verify_crls: exiting in success");
    Ok(ValidityIndicator::Valid)
}

// If fetching a certificate fails, the method reports the first error happening.
// Otherwise it returns a vector of certificates.
async fn certificates_by_uid(
    unique_identifiers: Vec<UniqueIdentifier>,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Vec<Vec<u8>>> {
    debug!("certificates_by_uid: entering: {unique_identifiers:?}");
    let res = futures::future::join_all(unique_identifiers.iter().map(|unique_identifier| async {
        let unique_identifier = unique_identifier.as_str().ok_or_else(|| {
            KmsError::Certificate("as_str returned None in certificates_by_uid".to_string())
        })?;
        certificate_by_uid(unique_identifier, kms, user, params).await
    }))
    .await;

    // checking if there are any errors
    res.into_iter().collect()
}

// Fetches a certificate. If it fails, returns the according error
async fn certificate_by_uid(
    unique_identifier: &str,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Vec<u8>> {
    let uid_owm = retrieve_object_for_operation(
        unique_identifier,
        ObjectOperationType::Validate,
        kms,
        user,
        params,
    )
    .await?;

    if let Object::Certificate {
        certificate_type: _,
        certificate_value,
    } = uid_owm.object
    {
        Ok(certificate_value)
    } else {
        Err(KmsError::from(KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Object_Type,
            format!(
                "Requested a Certificate Object, got a {}",
                uid_owm.object.object_type()
            ),
        )))
    }
}

fn validate_chain_date(certificates: &[X509], date: Option<String>) -> KResult<ValidityIndicator> {
    let current_date = if let Some(date) = date {
        Asn1Time::from_str(date.as_str())
    } else {
        Asn1Time::days_from_now(0)
    }?;
    certificates
        .iter()
        .try_fold(ValidityIndicator::Valid, |acc, certificate| {
            //let certificate = X509::from_der(certificate)?;
            let validation = validate_date(certificate, &current_date)?;
            Ok(acc.and(validation))
        })
}

fn validate_date(certificate: &X509, date: &Asn1Time) -> KResult<ValidityIndicator> {
    let now = date.as_ref();
    let (start, stop) = (certificate.not_before(), certificate.not_after());
    if start <= now && now <= stop {
        Ok(ValidityIndicator::Valid)
    } else {
        Ok(ValidityIndicator::Invalid)
    }
}

const fn crl_status_to_validity_indicator(status: CrlStatus) -> ValidityIndicator {
    match status {
        CrlStatus::NotRevoked => ValidityIndicator::Valid,
        CrlStatus::RemoveFromCrl(_) => ValidityIndicator::Invalid,
        CrlStatus::Revoked(_) => ValidityIndicator::Invalid,
    }
}
