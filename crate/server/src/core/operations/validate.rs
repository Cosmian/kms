use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use chrono::{DateTime, Local};
use cosmian_kmip::{
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Validate, ValidateResponse},
        kmip_types::ValidityIndicator,
    },
    //openssl::kmip_certificate_to_openssl,
    //openssl::{kmip_certificate_to_openssl, openssl_certificate_to_kmip},
    KmipError,
};
use cosmian_kms_client::access::ObjectOperationType;
use futures::future::join_all;
use openssl::{
    asn1::{Asn1OctetStringRef, Asn1Time},
    x509::{CrlStatus, DistPointNameRef, DistPointRef, GeneralNameRef, X509CrlRef, X509},
};
use tracing::trace;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    database::retrieve_object_for_operation,
    error::KmsError,
    result::KResult,
};

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

pub async fn validate(
    _kms: &KMS,
    request: Validate,
    _user: &str,
    _params: Option<&ExtraDatabaseParams>,
) -> KResult<ValidateResponse> {
    trace!("Validate: {:?}", request);
    match (request.unique_identifier, request.certificate) {
        (None, None) =>
        // None uid, None cert case
        {
            KResult::Ok(ValidateResponse {
                validity_indicator: ValidityIndicator::Unknown,
            })
        }
        (None, Some(certificates)) => {
            // None uid, Some cert case
            let hm_certificates = &mut HashMap::<Vec<u8>, u8>::new();
            let _root_certificate = index_certificates(&mut certificates.clone(), hm_certificates)?;
            if hm_certificates.len() != certificates.len() {
                return KResult::Ok(ValidateResponse {
                    validity_indicator: ValidityIndicator::Invalid,
                })
            };
            let _date_validation =
                _validate_date_chain(&mut certificates.clone(), request.validity_time)?;

            KResult::Ok(ValidateResponse {
                validity_indicator: ValidityIndicator::Unknown,
            })
        }
        (Some(_uids), None) =>
        // None uid, Some cert case
        {
            KResult::Ok(ValidateResponse {
                validity_indicator: ValidityIndicator::Unknown,
            })
        }
        (Some(_uids), Some(_certificates)) =>
        // None uid, Some cert case
        {
            KResult::Ok(ValidateResponse {
                validity_indicator: ValidityIndicator::Unknown,
            })
        }
    }
}
// match (request.unique_identifier, request.certificate) {
//     (None, None) => {
//         // None uid, None cert case
//         KResult::Ok(ValidateResponse {
//             validity_indicator: ValidityIndicator::Unknown,
//         })
//     }
//     (None, Some(certificates)) => {
//         let validity_indicator = validate_certificates(
//             &certificates,
//             kms,
//             user,
//             params,
//             request.validity_time.unwrap(),
//         )
//         .await?;
//         KResult::Ok(ValidateResponse { validity_indicator })
//     }
//     (Some(uids), None) => {
//         let validity_indicator = join_all(uids.iter().map(|unique_identifier| async {
//             let uid = unique_identifier
//                 .as_str()
//                 .context("Validate: certificate unique_identifier must be a string")
//                 .unwrap();
//             validate_unique_identifier(uid, kms, user, params, request.validity_time)
//                 .await
//                 .unwrap()
//         }))
//         .await;
//         let validity_indicator = validity_indicator
//             .iter()
//             .fold(ValidityIndicator::Valid, |v1, v2| {
//                 validity_indicator_and(v1, *v2)
//             });
//         KResult::Ok(ValidateResponse { validity_indicator })
//     }
//     (Some(_), Some(_)) => {
//         // Some uid, Some cert case
//         // else if some certificate list, map verification on each of them. Body of
//         // verification must be put in a function, used by both branches of the if.
//         // Final result Unknown, positive results returned in the ifs.
//         // what if both certificate and unique identifier are some? then we should
//         // return the logical and btw validations?
//         KResult::Err(KmsError::NotSupported(String::from("still implementing")))
//     }
// }

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

// If fetching a certificate fails, the method reports the first error happening.
// Otherwise it returns a vector of certificates.
async fn _certificates_by_uid(
    unique_identifiers: Vec<&str>,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Vec<Vec<u8>>> {
    KResult::Ok(
        join_all(unique_identifiers.iter().map(|unique_identifier| async {
            _certificate_by_uid(unique_identifier, kms, user, params)
                .await
                .unwrap()
        }))
        .await,
    )
}

// Fetches a certificate. If it fails, returns the according error
async fn _certificate_by_uid(
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

fn _validate_date_chain(
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
            let validation = _validate_date(certificate, &current_date)?;
            KResult::Ok(_validity_indicator_and(acc, validation))
        })
}

// getting crl uri for all the chain.
fn _get_crl_uris_from_certificate_chain(certificates: &mut [Vec<u8>]) -> KResult<Vec<String>> {
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

fn _chain_revocation_status(
    certificates: &mut [Vec<u8>],
    crls: &mut [X509CrlRef],
) -> KResult<ValidityIndicator> {
    certificates
        .iter()
        .try_fold(ValidityIndicator::Valid, |acc, certificate| {
            let res = _certificate_revocation_status(certificate, crls)?;
            KResult::Ok(_validity_indicator_and(acc, res))
        })
}

fn _certificate_revocation_status(
    certificate: &[u8],
    crls: &mut [X509CrlRef],
) -> KResult<ValidityIndicator> {
    let res = crls.iter().try_fold(ValidityIndicator::Valid, |acc, crl| {
        let certificate = X509::from_der(certificate)?;
        let res = _crl_status_to_validity_indicator(crl.get_by_serial(certificate.serial_number()));
        KResult::Ok(_validity_indicator_and(acc, res))
    })?;
    KResult::Ok(res)
}

// request and receive crl objects. Input: uri.
async fn _get_crl_objects(_: Vec<String>) -> KResult<Vec<X509CrlRef>> {
    KResult::Err(KmsError::NotSupported(
        String::from_str("Still implementing!").unwrap(),
    ))
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

fn _validate_date(certificate: &[u8], date: &Asn1Time) -> KResult<ValidityIndicator> {
    let certificate = X509::from_der(certificate)?;
    let (certificate_validity_start, certificate_validity_end) =
        (certificate.not_before(), certificate.not_after());
    if date.as_ref() <= certificate_validity_end && certificate_validity_start <= date.as_ref() {
        KResult::Ok(ValidityIndicator::Valid)
    } else {
        KResult::Ok(ValidityIndicator::Invalid)
    }
}

fn _validity_indicator_and(v1: ValidityIndicator, v2: ValidityIndicator) -> ValidityIndicator {
    match (v1, v2) {
        (ValidityIndicator::Valid, ValidityIndicator::Valid) => ValidityIndicator::Valid,
        (ValidityIndicator::Invalid, _) | (_, ValidityIndicator::Invalid) => {
            ValidityIndicator::Invalid
        }
        _ => ValidityIndicator::Unknown,
    }
}

// async fn _validate_unique_identifier(
//     unique_identifier: &str,
//     kms: &KMS,
//     user: &str,
//     params: Option<&ExtraDatabaseParams>,
//     date: Option<DateTime<Local>>,
// ) -> KResult<ValidityIndicator> {
//     let uid_own = retrieve_object_for_operation(
//         unique_identifier,
//         ObjectOperationType::Validate,
//         kms,
//         user,
//         params,
//     )
//     .await?;
//     if let Object::Certificate {
//         certificate_type: _certificate_type,
//         certificate_value,
//     } = uid_own.object
//     {
//         let validity_indicator = _validate_date(&certificate_value, date)?;
//         // No serial number validation. It's presence in the DB
//         // implies that certificate and associated keys were not
//         // revoked.
//         KResult::Ok(validity_indicator)
//     } else {
//         KResult::Err(KmsError::from(KmipError::InvalidKmipObject(
//             cosmian_kmip::kmip::kmip_operations::ErrorReason::Invalid_Object_Type,
//             String::from("Requested a Certificate Object, got a ")
//                 + &uid_own.object.object_type().to_string(),
//         )))
//     }
// }

// async fn _validate_certificates(
//     certificates: &[Vec<u8>],
//     kms: &KMS,
//     user: &str,
//     params: Option<&ExtraDatabaseParams>,
//     date: DateTime<Local>,
// ) -> KResult<ValidityIndicator> {
//     // None uid, Some cert case
//     // Given a certificate vector, the result is a vector of pairs of ValidityIndicators.
//     // The first element is the result of the date validation of the certificate.
//     // The second element is the result of the serial number validation of the
//     // certificate.
//     let check_serial_numbers_and_date =
//         join_all(certificates.iter().map(|certificate: &Vec<u8>| async {
//             (
//                 _validate_date(certificate, Some(date)).unwrap(),
//                 _validate_serial_number(certificate, kms, user, params)
//                     .await
//                     .unwrap(),
//             )
//         }))
//         .await;
//     let validity_indicator = check_serial_numbers_and_date.iter().fold(
//         ValidityIndicator::Valid,
//         |acc, (v_date, v_serial): &(ValidityIndicator, ValidityIndicator)| {
//             _validity_indicator_and(acc, _validity_indicator_and(*v_date, *v_serial))
//         },
//     );
//     KResult::Ok(validity_indicator)
// }
// async fn _validate_serial_number(
//     certificate: &[u8],
//     kms: &KMS,
//     user: &str,
//     params: Option<&ExtraDatabaseParams>,
// ) -> KResult<ValidityIndicator> {
//     let certificate = &X509::from_der(certificate)?;
//     let (uid_cert, _) = openssl_certificate_to_kmip(certificate)?;
//     let uid_own = retrieve_object_for_operation(
//         &uid_cert as &str,
//         ObjectOperationType::Validate,
//         kms,
//         user,
//         params,
//     )
//     .await?;
//     let certificate_kms = kmip_certificate_to_openssl(&uid_own.object)?;
//     let (auth_key_id1, auth_key_id2) = ({ certificate_kms.authority_key_id().unwrap() }, {
//         certificate.authority_key_id().unwrap()
//     });
//     if Asn1OctetStringRef::as_slice(auth_key_id1) == (Asn1OctetStringRef::as_slice(auth_key_id2)) {
//         KResult::Ok(ValidityIndicator::Valid)
//     } else {
//         KResult::Ok(ValidityIndicator::Invalid)
//     }
//}
