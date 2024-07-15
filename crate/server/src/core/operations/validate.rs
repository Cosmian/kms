use std::{collections::HashMap, fs, path, time::Duration};

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
    asn1::{Asn1OctetStringRef, Asn1Time},
    x509::{CrlStatus, DistPointNameRef, DistPointRef, GeneralNameRef, X509Crl, X509},
};
use tracing::{debug, info, trace};

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    database::retrieve_object_for_operation,
    error::KmsError,
    result::KResult,
};

const HEAD: &[u8] = b"head";
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
        .tcp_keepalive(Duration::from_secs(5))
        .pool_idle_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(2)
        .default_headers(headers)
        .build()
        .map_err(|e| {
            KmsError::from(KmipError::ObjectNotFound(format!(
                "Unable to build Reqwest client: Error: {e:?}"
            )))
        })?;

    let certificates = match (request.unique_identifier, request.certificate) {
        (None, None) => {
            return Ok(ValidateResponse {
                validity_indicator: ValidityIndicator::Unknown,
            })
        }
        (None, Some(certificates)) => Ok(certificates),
        (Some(unique_identifiers), None) => {
            certificates_by_uid(unique_identifiers, kms, user, params).await
        }
        (Some(unique_identifiers), Some(certificates)) => Ok([
            certificates,
            certificates_by_uid(unique_identifiers, kms, user, params).await?,
        ]
        .concat()),
    }?;

    let mut certs = Vec::<X509>::new();
    let certificates = certificates.into_iter().try_fold(&mut certs, |acc, x| {
        let x = X509::from_der(x.as_slice())?;
        acc.push(x);
        KResult::Ok(acc)
    })?;

    // Indexing Certificate Chain
    let hm_certificates = index_certificates(certificates)?;

    // Getting root certificate from indexing
    let root_idx = if let Some(root_idx) = hm_certificates.get(HEAD) {
        root_idx
    } else {
        return Ok(ValidateResponse {
            validity_indicator: ValidityIndicator::Invalid,
        })
    };
    let root_x509 = certificates.get(*root_idx as usize).ok_or_else(|| {
        KmsError::from(KmipError::InvalidKmipObject(
            ErrorReason::Item_Not_Found,
            "Root not found".to_string(),
        ))
    })?;

    // Verifying that the root certificate is auto-signed
    let root_pkey = root_x509.public_key()?;
    if !root_x509.verify(&root_pkey)? {
        return Ok(ValidateResponse {
            validity_indicator: ValidityIndicator::Invalid,
        })
    };

    // Checking structural validity. The chain is valid, and is well signed.
    // The result is a ValidityIndicator, representing the validity of the chain,
    // and a u8, representing the length of the chain
    let (structural_validity, count) =
        validate_chain_structure(root_x509, certificates, &hm_certificates, 0)?;
    if certificates.len() != count as usize {
        return Ok(ValidateResponse {
            validity_indicator: ValidityIndicator::Invalid,
        })
    };

    // Checking if the certificate chain has not expired
    let date_validation = validate_chain_date(certificates, request.validity_time)?;

    // Checking if the certificate chain has revoked elements
    let uri_list = get_crl_uris_from_certificate_chain(certificates)?;
    let validity_indicator = if uri_list.is_empty() {
        structural_validity.and(date_validation)
    } else {
        info!("URI list: {uri_list:?}");
        let mut crl_bytes_list =
            get_crl_bytes(&client, uri_list, &hm_certificates, certificates).await?;
        info!("CRL list size: {}", crl_bytes_list.len());

        let revocation_status = chain_revocation_status(certificates, &mut crl_bytes_list)?;
        revocation_status.and(structural_validity.and(date_validation))
    };

    debug!("validate_operation: exiting with success");
    Ok(ValidateResponse { validity_indicator })
}

/// This function builds a map from an array of X509 certificates. This map can be
/// seen as an indexing of the certificate array
/// The key is the "authority key identifier" attribute of the certificate;
/// the value is the index representing the location of the certificate in the array.
/// Example: The certificate root key is "root". To find the son of the root, just get the
/// authority key identifier from this certificate. That's the key of the son.
fn index_certificates(
    certificates: &[X509], // return a map created in the fun
) -> KResult<HashMap<Vec<u8>, u8>> {
    let mut hm_certificates = HashMap::<Vec<u8>, u8>::new();
    for (i, cert) in certificates.iter().enumerate() {
        let aki = cert.authority_key_id();
        let ski = cert.subject_key_id();
        let is_root = match (aki, ski) {
            (Some(aki), Some(ski)) => aki.as_slice() == ski.as_slice(),
            (None, Some(_)) => true,
            (Some(_), None) => {
                return Err(KmsError::from(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Object_Type,
                    "Certificate has no Subject Key Identifier".to_string(),
                )))
            }
            (None, None) => {
                return Err(KmsError::from(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Object_Type,
                    "Certificate has neither Subject Key Identifier nor Authority Key Identifier"
                        .to_string(),
                )))
            }
        };
        if is_root {
            hm_certificates.insert(HEAD.to_vec(), i as u8);
        } else {
            let asn1_aki = aki.ok_or_else(|| {
                KmsError::from(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Object_Type,
                    "No AKI found".to_string(),
                ))
            })?;
            hm_certificates.insert(Asn1OctetStringRef::as_slice(asn1_aki).to_vec(), i as u8);
        }
    }
    Ok(hm_certificates)
}

// validate_chain_structure searches for the issuer certificate
// of the certificate to be checked and carries out a complete certificate check
// of this certificate.
// Start of the check is the root certificate. Iteratively, the offspring
// certificates are checked. The check comprehends checking the signature validity.
fn validate_chain_structure(
    root: &X509,
    certificates: &[X509],
    hm_certificates: &HashMap<Vec<u8>, u8>,
    _count: u8,
) -> KResult<(ValidityIndicator, u8)> {
    let son_issuer_id = root
        .subject_key_id()
        .ok_or_else(|| {
            KmsError::from(KmipError::InvalidKmipObject(
                ErrorReason::Item_Not_Found,
                "Issuer son not found".to_string(),
            ))
        })?
        .as_slice()
        .to_vec();
    // If there is no certificate son in the vector, the iteration on the indexed
    // structure ends returning valid.
    let son_cert = {
        if let Some(son_idx) = hm_certificates.get(&son_issuer_id) {
            certificates.get(*son_idx as usize)
        } else {
            return Ok((ValidityIndicator::Valid, _count + 1))
        }
    };
    let son_cert = if let Some(son_cert) = son_cert {
        son_cert
    } else {
        return Ok((ValidityIndicator::Invalid, _count + 1))
    };
    let root_pkey = root.public_key()?;
    let validity = son_cert.verify(&root_pkey)?;
    let (res, count) =
        validate_chain_structure(son_cert, certificates, hm_certificates, _count + 1)?;
    if ValidityIndicator::from_bool(validity).and(res) == ValidityIndicator::Valid {
        Ok((ValidityIndicator::Valid, count))
    } else {
        Ok((ValidityIndicator::Invalid, count))
    }
}

// If fetching a certificate fails, the method reports the first error happening.
// Otherwise it returns a vector of certificates.
async fn certificates_by_uid(
    unique_identifiers: Vec<UniqueIdentifier>,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Vec<Vec<u8>>> {
    let mut res = Vec::new();
    for unique_identifier in unique_identifiers {
        let unique_identifier = unique_identifier.as_str().ok_or_else(|| {
            KmsError::from(KmipError::InvalidKmipObject(
                ErrorReason::Item_Not_Found,
                "as_str returned None in certificates_by_uid".to_string(),
            ))
        })?;
        let certificate = certificate_by_uid(unique_identifier, kms, user, params).await;
        res.push(certificate);
    }

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
    let uid_own = retrieve_object_for_operation(
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
    } = uid_own.object
    {
        Ok(certificate_value)
    } else {
        Err(KmsError::from(KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Object_Type,
            format!(
                "Requested a Certificate Object, got a {}",
                uid_own.object.object_type()
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

// getting crl uri for all the chain.
// returns a vector
fn get_crl_uris_from_certificate_chain(certificates: &[X509]) -> KResult<Vec<(String, Vec<u8>)>> {
    certificates
        .iter()
        .try_fold(Vec::new(), |mut acc, certificate| {
            get_crl_uri_from_certificate(certificate).map(|mut uris| {
                acc.append(&mut uris);
                acc
            })
        })
}

fn get_crl_uri_from_certificate(certificate: &X509) -> KResult<Vec<(String, Vec<u8>)>> {
    let certificate_hash = certificate.authority_key_id();
    let certificate_hash = if let Some(auth_id) = certificate_hash {
        auth_id.as_slice().to_vec()
    } else {
        HEAD.to_vec()
    };
    let crl_dp = certificate.crl_distribution_points();
    match crl_dp {
        None => Ok(vec![]),
        Some(crl_dp) => {
            let crl_size = crl_dp.len();
            let uri_list = &mut Vec::<String>::new();
            for i in 0..crl_size {
                let crl_uri = crl_dp
                    .get(i)
                    .and_then(DistPointRef::distpoint)
                    .and_then(DistPointNameRef::fullname)
                    .and_then(|x| x.get(0))
                    .and_then(GeneralNameRef::uri);
                if let Some(crl_uri) = crl_uri {
                    uri_list.push(crl_uri.to_string());
                }
            }
            let res = uri_list
                .iter()
                .map(|x| (x.clone(), certificate_hash.clone()))
                .collect();
            Ok(res)
        }
    }
}

fn crl_status_to_validity_indicator(status: CrlStatus) -> ValidityIndicator {
    match status {
        CrlStatus::NotRevoked => ValidityIndicator::Valid,
        CrlStatus::RemoveFromCrl(_) => ValidityIndicator::Invalid,
        CrlStatus::Revoked(_) => ValidityIndicator::Invalid,
    }
}

fn chain_revocation_status(
    certificates: &[X509],
    crls: &mut [Vec<u8>],
) -> KResult<ValidityIndicator> {
    certificates
        .iter()
        .map(|cert| certificate_revocation_status(cert, crls))
        .try_fold(ValidityIndicator::Valid, |s1, s2| Ok(s1.and(s2?)))
}

fn certificate_revocation_status(
    certificate: &X509,
    crls: &mut [Vec<u8>],
) -> KResult<ValidityIndicator> {
    let res = crls.iter().try_fold(ValidityIndicator::Valid, |acc, crl| {
        let crl = X509Crl::from_pem(crl.as_slice())?;
        let res = crl_status_to_validity_indicator(crl.get_by_cert(certificate));
        KResult::Ok(acc.and(res))
    })?;
    Ok(res)
}

enum UriType {
    Url(String),
    Path(String),
}

// Retrieving a verifying that a CRL is well-signed. If the test passes, it returns
// the crl object as a vector of u8.
// It retrieves files in locale and in remote (via http request).
async fn test_and_get_resource_from_uri(
    client: &reqwest::Client,
    uri: &String,
    hm_certificates: &HashMap<Vec<u8>, u8>,
    certificates: &[X509],
    certificate_id: &[u8],
) -> KResult<Vec<u8>> {
    debug!("test_and_get_resource_from_uri: entering");
    // Getting the CRL issuer Certificate
    let certificate_idx = hm_certificates.get(certificate_id).ok_or_else(|| {
        KmsError::from(KmipError::InvalidKmipObject(
            ErrorReason::Item_Not_Found,
            "The certificate must be in the hashmap".to_string(),
        ))
    })?;
    let certificate = certificates.get(*certificate_idx as usize).ok_or_else(|| {
        KmsError::from(KmipError::InvalidKmipObject(
            ErrorReason::Item_Not_Found,
            "The certificate index must be valid".to_string(),
        ))
    })?;

    // checking whether the resource is an URL or a Pathname
    let uri_type = if let Ok(url) = url::Url::parse(uri) {
        Some(UriType::Url(url.into()))
    } else {
        let path_buf = path::Path::new(uri).canonicalize()?;
        match path_buf.to_str() {
            Some(s) => Some(UriType::Path(s.to_string())),
            None => {
                return Err(KmsError::from(KmipError::InvalidKmipValue(
                    ErrorReason::Illegal_Object_Type,
                    "The uri provided is invalid".to_string(),
                )))
            }
        }
    };
    // Retrieving the object from its location
    let crl_bytes = match uri_type {
        Some(UriType::Url(url)) => {
            let mut retry_count = 0;
            loop {
                let response = client.get(&url).send().await?;
                if response.status().is_success() {
                    return response
                        .text()
                        .await
                        .map(|text| text.as_bytes().to_vec())
                        .map_err(|e| {
                            KmsError::from(KmipError::ObjectNotFound(format!(
                                "Error in getting the body of the response for the following URL: \
                                 {url}. Error: {e:?} "
                            )))
                        });
                } else {
                    retry_count += 1;
                    if retry_count >= MAX_RETRY_COUNT {
                        return Err(KmsError::from(KmipError::ObjectNotFound(format!(
                            "The CRL at the following URL {url} is not available"
                        ))));
                    }
                }
            }
        }
        Some(UriType::Path(path)) => {
            // Get PEM file (path should be already canonic)
            fs::read(path::Path::new(&path))?
        }
        _ => {
            return Err(KmsError::KmipError(
                ErrorReason::General_Failure,
                "Error that should not manifest".to_string(),
            ))
        }
    };

    // Verifying that the CRL is well signed by its issuer
    let crl = X509Crl::from_pem(crl_bytes.as_slice())?;
    let cert_key = &certificate.public_key()?;
    if crl.verify(cert_key)? {
        return Err(KmsError::from(KmipError::OpenSSL(
            "The CRL is not well-signed".to_string(),
        )))
    };
    debug!("test_and_get_resource_from_uri: exiting in success");
    Ok(crl_bytes)
}

// request and receive crl objects. Input: uri.
async fn get_crl_bytes(
    client: &reqwest::Client,
    uri_crls: Vec<(String, Vec<u8>)>,
    hm_certificates: &HashMap<Vec<u8>, u8>,
    certificates: &[X509],
) -> KResult<Vec<Vec<u8>>> {
    let crl_bytes = futures::future::join_all(uri_crls.into_iter().map(
        move |(uri, certificate_id)| async move {
            test_and_get_resource_from_uri(
                client,
                &uri,
                hm_certificates,
                certificates,
                &certificate_id,
            )
            .await
        },
    ))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

    Ok(crl_bytes)
}
