use std::{collections::HashMap, fs, path};

use cosmian_kmip::{
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Validate, ValidateResponse},
        kmip_types::{UniqueIdentifier, ValidityIndicator},
    },
    KmipError,
};
use cosmian_kms_client::access::ObjectOperationType;
use futures::future::join_all;
use openssl::{
    asn1::{Asn1OctetStringRef, Asn1Time},
    x509::{CrlStatus, DistPointNameRef, DistPointRef, GeneralNameRef, X509Crl, X509},
};
use tracing::trace;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    database::retrieve_object_for_operation,
    error::KmsError,
    result::KResult,
};

const HEAD: &[u8] = b"head";

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

    // Indexing Certificate Chain
    let mut hm_certificates =
        index_certificates(&certificates, &mut HashMap::<Vec<u8>, u8>::new())?;

    // Getting root certificate from indexing
    let root_idx = *hm_certificates.get(&HEAD.to_vec()).ok_or_else(|| {
        KmsError::from(KmipError::ObjectNotFound(
            "The certificate chain has no root".to_string(),
        ))
    })?;
    let root_cert = certificates.get(root_idx as usize).ok_or_else(|| {
        KmsError::from(KmipError::InvalidKmipObject(
            cosmian_kmip::kmip::kmip_operations::ErrorReason::Item_Not_Found,
            "Root not found".to_string(),
        ))
    })?;
    let root_x509 = X509::from_der(root_cert)?;

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
        validate_chain_structure(root_cert, &certificates, &mut hm_certificates, 0)?;
    if certificates.len() != count as usize {
        return Ok(ValidateResponse {
            validity_indicator: ValidityIndicator::Invalid,
        })
    };

    // Checking if the certificate chain has not expired
    let date_validation = validate_chain_date(&certificates, request.validity_time)?;

    // Checking if the certificate chain has revocked elements
    let uri_list = get_crl_uris_from_certificate_chain(&certificates)?;
    if uri_list.is_empty() {
        Ok(ValidateResponse {
            validity_indicator: structural_validity.and(date_validation),
        })
    } else {
        let mut crl_bytes_list =
            get_crl_bytes(uri_list, &mut hm_certificates, certificates.clone()).await?;

        let revocation_status =
            chain_revocation_status(certificates.as_slice(), &mut crl_bytes_list)?;
        Ok(ValidateResponse {
            validity_indicator: revocation_status.and(structural_validity.and(date_validation)),
        })
    }
}

/// This function builds a map from an array of X509 certificates. This map can be
/// seen as an indexing of the certificate array
/// The key is the "authority key identifier" attribute of the certificate;
/// the value is the index representing the location of the certificate in the array.
/// Example: The certificate root key is "root". To find the son of the root, just get the
/// authority key identifier from this certificate. That's the key of the son.
fn index_certificates(
    certificates: &[Vec<u8>],
    hm_certificates: &mut HashMap<Vec<u8>, u8>,
) -> KResult<HashMap<Vec<u8>, u8>> {
    for (i, cert) in certificates.iter().enumerate() {
        let cert = X509::from_der(cert)?;
        let aki = cert.authority_key_id();
        let ski = cert.subject_key_id();
        let is_root = match (aki, ski) {
            (Some(aki), Some(ski)) => aki.as_slice() == ski.as_slice(),
            (None, Some(_)) => true,
            _ => {
                return Err(KmsError::from(KmipError::InvalidKmipObject(
                    cosmian_kmip::kmip::kmip_operations::ErrorReason::Invalid_Object_Type,
                    "Certificate has no Subject Key Identifier".to_string(),
                )))
            }
        };
        if is_root {
            hm_certificates.insert(HEAD.to_vec(), i as u8);
        } else {
            hm_certificates.insert(Asn1OctetStringRef::as_slice(aki.unwrap()).to_vec(), i as u8);
        }
    }
    Ok(hm_certificates.clone())
}

// validate_chain_structure searches for the issuer certificate
// of the certificate to be checked and carries out a complete certificate check
// of this certificate.
// Start of the check is the root certificate. Iteratively, the offspring
// certificates are checked. The check comprehends checking the signature validity.
fn validate_chain_structure(
    root: &[u8],
    certificates: &Vec<Vec<u8>>,
    hm_certificates: &mut HashMap<Vec<u8>, u8>,
    _count: u8,
) -> KResult<(ValidityIndicator, u8)> {
    let root_x509 = X509::from_der(root)?;
    let son_issuer_id = root_x509
        .subject_key_id()
        .ok_or_else(|| {
            KmsError::from(KmipError::InvalidKmipObject(
                cosmian_kmip::kmip::kmip_operations::ErrorReason::Item_Not_Found,
                "Issuer son not found".to_string(),
            ))
        })?
        .as_slice()
        .to_vec();
    // If there is no certificate son in the vector, the iteration on the indexed
    // structure ends returning valid.
    let son_cert = {
        if let Some(son_idx) = hm_certificates.get(&son_issuer_id) {
            // safe unwrap. It is guarder by the if
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
    let son_x509 = X509::from_der(son_cert)?;
    let root_pkey = root_x509.public_key()?;
    let validity = son_x509.verify(&root_pkey)?;
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
    let res = join_all(unique_identifiers.iter().map(|unique_identifier| async {
        let unique_identifier = unique_identifier.as_str().ok_or_else(|| {
            KmsError::from(KmipError::InvalidKmipObject(
                cosmian_kmip::kmip::kmip_operations::ErrorReason::Item_Not_Found,
                "as_str returned None in certificates_by_uid".to_string(),
            ))
        })?;
        certificate_by_uid(unique_identifier, kms, user, params).await
    }))
    .await;

    // is any of them an Error?
    let is_ok = res.iter().all(|x| x.is_ok());

    // checking if there are any errors
    if is_ok {
        Ok(res
            .iter()
            .map(|x| x.clone().expect("safe unwrap of uids"))
            .collect())
    } else {
        Err(KmsError::from(KmipError::ObjectNotFound(
            "There is a Kms Certificate UID that cannot be retrieved".to_string(),
        )))
    }
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
    .await;
    match uid_own {
        Err(e) => Err(e),
        Ok(kms_object) => {
            if let Object::Certificate {
                certificate_type: _,
                certificate_value,
            } = kms_object.object
            {
                Ok(certificate_value)
            } else {
                Err(KmsError::from(KmipError::InvalidKmipObject(
                    cosmian_kmip::kmip::kmip_operations::ErrorReason::Invalid_Object_Type,
                    String::from("Requested a Certificate Object, got a ")
                        + &kms_object.object.object_type().to_string(),
                )))
            }
        }
    }
}

fn validate_chain_date(
    certificates: &[Vec<u8>],
    date: Option<String>,
) -> KResult<ValidityIndicator> {
    let current_date = if let Some(date) = date {
        Asn1Time::from_str(date.as_str())
    } else {
        Asn1Time::days_from_now(0)
    }?;
    certificates
        .iter()
        .try_fold(ValidityIndicator::Valid, |acc, certificate| {
            let certificate = X509::from_der(certificate)?;
            let validation = validate_date(&certificate, &current_date)?;
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
fn get_crl_uris_from_certificate_chain(
    certificates: &[Vec<u8>],
) -> KResult<Vec<(String, Vec<u8>)>> {
    certificates
        .iter()
        .try_fold(Vec::new(), |mut acc, certificate| {
            get_crl_uri_from_certificate(certificate).map(|mut uris| {
                acc.append(&mut uris);
                acc
            })
        })
}

fn get_crl_uri_from_certificate(certificate: &[u8]) -> KResult<Vec<(String, Vec<u8>)>> {
    /* and vec<u8> */
    let certificate = X509::from_der(certificate)?;
    let certificate_hash = certificate.authority_key_id();
    let certificate_hash = if let Some(auth_id) = certificate_hash {
        auth_id.as_slice().to_vec()
    } else {
        HEAD.to_vec()
    };
    let crl_dp = certificate.crl_distribution_points();
    match crl_dp {
        None => Ok([].to_vec()),
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
                    uri_list.push(crl_uri.to_string())
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
    certificates: &[Vec<u8>],
    crls: &mut [Vec<u8>],
) -> KResult<ValidityIndicator> {
    certificates
        .iter()
        .map(|cert| certificate_revocation_status(cert, crls))
        .try_fold(ValidityIndicator::Valid, |s1, s2| Ok(s1.and(s2?)))
}

fn certificate_revocation_status(
    certificate: &[u8],
    crls: &mut [Vec<u8>],
) -> KResult<ValidityIndicator> {
    let res = crls.iter().try_fold(ValidityIndicator::Valid, |acc, crl| {
        let certificate = X509::from_der(certificate)?;
        let crl = X509Crl::from_pem(crl.as_slice())?;
        let res = crl_status_to_validity_indicator(crl.get_by_cert(&certificate));
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
    uri: &String,
    hm_certificates: &mut HashMap<Vec<u8>, u8>,
    certificates: Vec<Vec<u8>>,
    certificate_id: Vec<u8>,
) -> KResult<Vec<u8>> {
    // checking wether the resource is an URL or a Pathname
    let uri_type = match url::Url::parse(uri) {
        Err(_) => {
            let path = path::Path::new(uri);
            let path_buf = path.canonicalize()?;
            let path = path_buf.as_path();
            if let Some(s) = path.to_str() {
                Some(UriType::Path(s.to_string()))
            } else {
                return Err(KmsError::from(KmipError::InvalidKmipValue(
                    cosmian_kmip::kmip::kmip_operations::ErrorReason::Illegal_Object_Type,
                    "The uri provided is ill defined".to_string(),
                )))
            }
        }
        Ok(_) => Some(UriType::Url(uri.to_string())),
    };
    // Retrieving the object from its location
    let crl_bytes = match uri_type {
        Some(UriType::Url(url)) => {
            let response = reqwest::get(&url).await;
            // missing error conversion
            let response = if let Ok(response) = response {
                response
            } else {
                return Err(KmsError::from(KmipError::ObjectNotFound(
                    "No certificate found at the following uri ".to_string() + uri,
                )))
            };
            let body = if let Ok(text) = response.text().await {
                text
            } else {
                return Err(KmsError::from(KmipError::ObjectNotFound(
                    "Error in getting the body of the response for the following uri ".to_string()
                        + url.as_str(),
                )))
            };
            KResult::Ok(body.as_bytes().to_vec())
        }
        Some(UriType::Path(path)) => {
            // path should be already canonic
            let pem = fs::read(path::Path::new(&path))?;
            Ok(pem)
        }
        _ => {
            return Err(KmsError::KmipError(
                cosmian_kmip::kmip::kmip_operations::ErrorReason::General_Failure,
                "Error that should not manifest".to_string(),
            ))
        }
    }?;
    // Getting the CRL issuer Certificate
    let certificate_idx = hm_certificates.get(&certificate_id).ok_or_else(|| {
        KmsError::from(KmipError::InvalidKmipObject(
            cosmian_kmip::kmip::kmip_operations::ErrorReason::Item_Not_Found,
            "The certificate must be in the hashmap".to_string(),
        ))
    })?;
    let certificate = certificates.get(*certificate_idx as usize).ok_or_else(|| {
        KmsError::from(KmipError::InvalidKmipObject(
            cosmian_kmip::kmip::kmip_operations::ErrorReason::Item_Not_Found,
            "The certificate index must be valid".to_string(),
        ))
    })?;
    let certificate = X509::from_der(certificate.as_slice())?;

    // Verifying that the CRL is well signed by its issuer
    let crl = X509Crl::from_pem(crl_bytes.as_slice())?;
    let cert_key = &certificate.public_key()?;
    if crl.verify(cert_key)? {
        return Err(KmsError::from(KmipError::OpenSSL(
            "The CRL is not well-signed".to_string(),
        )))
    };
    Ok(crl_bytes)
}

// request and receive crl objects. Input: uri.
async fn get_crl_bytes(
    uri_crls: Vec<(String, Vec<u8>)>,
    hm_certificates: &mut HashMap<Vec<u8>, u8>,
    certificates: Vec<Vec<u8>>,
) -> KResult<Vec<Vec<u8>>> {
    let mut responses = join_all(uri_crls.iter().map(|(uri, certificate_id)| async {
        test_and_get_resource_from_uri(
            uri,
            &mut hm_certificates.clone(),
            certificates.clone(),
            certificate_id.clone(),
        )
        .await
    }))
    .await;

    // filtering errors
    let is_ok = responses.iter().all(|x| x.is_ok());

    // checking if there are any errors
    if is_ok {
        Ok(responses
            .iter_mut()
            .map(|x| {
                x.clone()
                    .expect("Safe unwrap of Result elements. The vector must not contain Err.")
            })
            .collect())
    } else {
        Err(KmsError::from(KmipError::ObjectNotFound(
            "One of the Crl cannot be found".to_string(),
        )))
    }
}
