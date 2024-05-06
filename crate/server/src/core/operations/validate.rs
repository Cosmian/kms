use std::{
    collections::{HashMap, HashSet},
    fmt::Error,
};

use chrono::{DateTime, Local};
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
struct _IndexedCertificateChain {
    pub head: u8,
    pub map: HashMap<Vec<u8>, u8>,
    pub vec: Vec<Vec<u8>>,
    pub current: u8,
}

impl _IndexedCertificateChain {
    pub fn _reset(&mut self) {
        self.current = self.head;
    }

    pub fn _next(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let current_cert = self
            .vec
            .get(self.current as usize)
            .expect("existing element")
            .as_slice()
            .to_vec();
        let current_x509 = X509::from_der(&current_cert)?;
        let son_issuer_id = current_x509
            .subject_key_id()
            .expect("existing subject key id")
            .as_slice()
            .to_vec();
        let son_cert_id = self.map.get(&son_issuer_id);
        if let Some(son_cert_id) = son_cert_id {
            let res = self
                .vec
                .get(*son_cert_id as usize)
                .expect("the son certificate must exist");
            self.current = *son_cert_id;
            Result::Ok(Some(res.clone()))
        } else {
            Result::Ok(None)
        }
    }
}
// validation has to change :
// vectors to certificates.
// uids to certificates.
// build an ordered certificate chain :
// - issuer has a subject
// - a subject is the next issuer
// - iterate and build a chain
// check, for each element :
// - date
// - check serial number not revoked, following the chain order in CRL.

pub(crate) async fn validate(
    kms: &KMS,
    request: Validate,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ValidateResponse> {
    trace!("Validate: {:?}", request);
    let certificates = match (request.unique_identifier, request.certificate) {
        (None, None) =>
        // None uid, None cert case
        {
            return KResult::Ok(ValidateResponse {
                validity_indicator: ValidityIndicator::Unknown,
            })
        }
        (None, Some(certificates)) => {
            // None uid, Some cert case
            KResult::Ok(certificates)
        }
        (Some(unique_identifiers), None) =>
        // None uid, Some cert case
        {
            certificates_by_uid(unique_identifiers, kms, user, params).await
        }
        (Some(unique_identifiers), Some(certificates)) =>
        // None uid, Some cert case
        {
            let mut certificates_uid =
                certificates_by_uid(unique_identifiers, kms, user, params).await?;
            let mut certificates = certificates.clone();
            certificates.append(&mut certificates_uid);
            KResult::Ok(certificates.clone())
        }
    }?;
    let hm_certificates = &mut HashMap::<Vec<u8>, u8>::new();
    let root_idx = index_certificates(&mut certificates.clone(), hm_certificates)?;

    let root_cert = certificates.get(root_idx as usize).expect("root not found");
    let root_x509 = X509::from_der(root_cert)?;
    let root_pkey = root_x509.public_key()?;
    // Checking if the root certificate is is well signed.
    // A root certificate signes itself.
    if !root_x509.verify(&root_pkey).unwrap() {
        return KResult::Ok(ValidateResponse {
            validity_indicator: ValidityIndicator::Invalid,
        })
    };

    // Checking structural validity. The chain is valid, and is well signed.
    // The result is a ValidityIndicator, representing the validity of the chain,
    // and a u8, representing the length of the chain
    let (structural_validity, count) =
        validate_chain_structure(root_cert, &certificates, hm_certificates, 0)?;
    if certificates.len() != count as usize {
        return KResult::Ok(ValidateResponse {
            validity_indicator: ValidityIndicator::Invalid,
        })
    };

    // Checking if the certificate chain has not expired
    let date_validation = validate_chain_date(&mut certificates.clone(), request.validity_time)?;

    // Checking if the certificate chain has revocked elements
    let uri_list = get_crl_uris_from_certificate_chain(&mut certificates.clone())?;
    let mut crl_list = get_crl_objects(uri_list).await?;
    let revocation_status = chain_revocation_status(certificates.as_slice(), &mut crl_list)?;

    KResult::Ok(ValidateResponse {
        validity_indicator: revocation_status.and(structural_validity.and(date_validation)),
    })
}

// key : authority key identifier
// value : index array
// certificate root, and mutation on hash map storing indexes
fn index_certificates(
    certificates: &mut [Vec<u8>],
    hm_certificates: &mut HashMap<Vec<u8>, u8>,
) -> KResult<u8> {
    let (head, _) = certificates.iter().try_fold((0, 0), |(head, i), cert| {
        let cert = X509::from_der(cert)?;
        match cert.authority_key_id() {
            None => KResult::Ok((i, i + 1)),
            Some(key) => {
                hm_certificates.insert(Asn1OctetStringRef::as_slice(key).to_vec(), i);
                KResult::Ok((head, i + 1))
            }
        }
    })?;
    KResult::Ok(head)
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
        .expect("mandatory information")
        .as_slice()
        .to_vec();
    let son_idx = hm_certificates.get(&son_issuer_id);
    // If there is no certificate son in the vector, the iteration on the indexed
    // structure ends returning valid.
    if son_idx.is_none() {
        return KResult::Ok((ValidityIndicator::Valid, _count))
    };

    // safe unwrap by construction
    let son_cert = certificates
        .get(*son_idx.expect("By construction, the certificate must exist in the vector") as usize);

    let son_x509 = X509::from_der(son_cert.unwrap())?;
    let root_pkey = root_x509.public_key()?;
    let validity = son_x509.verify(&root_pkey)?;
    let (res, count) =
        validate_chain_structure(son_cert.unwrap(), certificates, hm_certificates, _count + 1)?;
    if ValidityIndicator::from_bool(validity).and(res) == ValidityIndicator::Valid {
        KResult::Ok((ValidityIndicator::Valid, count))
    } else {
        KResult::Ok((ValidityIndicator::Invalid, count))
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
    KResult::Ok(
        join_all(unique_identifiers.iter().map(|unique_identifier| async {
            let unique_identifier = unique_identifier
                .as_str()
                .expect("as_str returned None in certificates_by_uid");
            certificate_by_uid(unique_identifier, kms, user, params)
                .await
                .unwrap()
        }))
        .await,
    )
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
        Err(e) => KResult::Err(e),
        Ok(kms_object) => {
            // maybe I can find revocation information on the kms_object
            if let Object::Certificate {
                certificate_type: _,
                certificate_value,
            } = kms_object.object
            {
                KResult::Ok(certificate_value)
            } else {
                KResult::Err(KmsError::from(KmipError::InvalidKmipObject(
                    cosmian_kmip::kmip::kmip_operations::ErrorReason::Invalid_Object_Type,
                    String::from("Requested a Certificate Object, got a ")
                        + &kms_object.object.object_type().to_string(),
                )))
            }
        }
    }
}

fn validate_chain_date(
    certificates: &mut [Vec<u8>],
    date: Option<DateTime<Local>>,
) -> KResult<ValidityIndicator> {
    let current_date = {
        if let Some(date) = date {
            Asn1Time::from_str(&date.to_string())
        } else {
            Asn1Time::from_str(&Local::now().to_string())
        }
    }?;
    certificates
        .iter()
        .try_fold(ValidityIndicator::Valid, |acc, certificate| {
            let validation = validate_date(certificate, &current_date)?;
            KResult::Ok(acc.and(validation))
        })
}

fn validate_date(certificate: &[u8], date: &Asn1Time) -> KResult<ValidityIndicator> {
    let certificate = X509::from_der(certificate)?;
    let (certificate_validity_start, certificate_validity_end) =
        (certificate.not_before(), certificate.not_after());
    if date.as_ref() <= certificate_validity_end && certificate_validity_start <= date.as_ref() {
        KResult::Ok(ValidityIndicator::Valid)
    } else {
        KResult::Ok(ValidityIndicator::Invalid)
    }
}

// getting crl uri for all the chain.
fn get_crl_uris_from_certificate_chain(certificates: &mut [Vec<u8>]) -> KResult<Vec<String>> {
    let init = &mut Vec::<String>::new();
    let res = certificates.iter().try_fold(init, |acc, certificate| {
        let res = &mut _get_crl_uri_from_certificate(certificate)?;
        acc.append(res);
        KResult::Ok(acc)
    })?;
    KResult::Ok(
        res.clone()
            .into_iter()
            .collect::<HashSet<String>>()
            .into_iter()
            .collect::<Vec<String>>(),
    )
}

fn _crl_status_to_validity_indicator(status: CrlStatus) -> ValidityIndicator {
    match status {
        CrlStatus::NotRevoked => ValidityIndicator::Valid,
        CrlStatus::RemoveFromCrl(_) => ValidityIndicator::Invalid,
        CrlStatus::Revoked(_) => ValidityIndicator::Invalid,
    }
}

fn chain_revocation_status(
    certificates: &[Vec<u8>],
    crls: &mut [X509Crl],
) -> KResult<ValidityIndicator> {
    certificates
        .iter()
        .try_fold(ValidityIndicator::Valid, |acc, certificate| {
            let res = certificate_revocation_status(certificate, crls)?;
            KResult::Ok(acc.and(res))
        })
}

fn certificate_revocation_status(
    certificate: &[u8],
    crls: &mut [X509Crl],
) -> KResult<ValidityIndicator> {
    let res = crls.iter().try_fold(ValidityIndicator::Valid, |acc, crl| {
        let certificate = X509::from_der(certificate)?;
        let res = _crl_status_to_validity_indicator(crl.get_by_serial(certificate.serial_number()));
        KResult::Ok(acc.and(res))
    })?;
    KResult::Ok(res)
}

fn _get_crl_uri_from_certificate(certificate: &[u8]) -> KResult<Vec<String>> {
    let certificate = X509::from_der(certificate)?;
    let crl_dp = certificate.crl_distribution_points();
    match crl_dp {
        None => KResult::Ok([].to_vec()),
        Some(crl_dp) => {
            let crl_size = crl_dp.len();
            let uri_list = &mut Vec::<String>::new();
            for i in 0..crl_size {
                let crl_uri = crl_dp
                    .get(i)
                    .and_then(DistPointRef::distpoint)
                    .and_then(DistPointNameRef::fullname)
                    .and_then(|x| x.get(0))
                    .and_then(GeneralNameRef::uri)
                    .unwrap();
                uri_list.push(crl_uri.to_string())
            }
            KResult::Ok(
                // returning uris
                uri_list.clone(),
            )
        }
    }
}

// request and receive crl objects. Input: uri.
async fn get_crl_objects(uri_crls: Vec<String>) -> KResult<Vec<X509Crl>> {
    let responses = join_all(uri_crls.iter().map(|uri: &String| async {
        let response = reqwest::get(uri.clone())
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let response = response.as_bytes();
        X509Crl::from_der(response).unwrap()
    }))
    .await;

    KResult::Ok(responses)
}
