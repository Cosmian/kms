use chrono::{DateTime, Local};
use cosmian_kmip::{
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Validate, ValidateResponse},
        kmip_types::ValidityIndicator,
    },
    //openssl::kmip_certificate_to_openssl,
    KmipError,
    KmipResultHelper,
};
use cosmian_kms_client::access::ObjectOperationType;
use openssl::{asn1::Asn1Time, x509::X509};
use tracing::trace;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    database::retrieve_object_for_operation,
    error::KmsError,
    result::KResult,
};

const _X509_VERSION3: i32 = 2;

pub async fn validate(
    kms: &KMS,
    request: Validate,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ValidateResponse> {
    trace!("Validate: {:?}", request);
    let req = request.clone();
    match request.unique_identifier {
        None => match request.certificate {
            None => KResult::Ok(ValidateResponse {
                validity_indicator: ValidityIndicator::Unknown,
            }),
            Some(certificates) =>
            // else if some certificate list, map verification on each of them. Body of
            // verification must be put in a function, used by both branches of the if.
            // Final result Unknown, positive results returned in the ifs.
            // what if both certificate and unique identifier are some? then we should
            // return the logical and btw validations?
            {
                let check_serial_numbers_and_date = certificates
                    .iter()
                    .map(|certificate: &Vec<u8>| {
                        (
                            validate_date(certificate, req.validity_time).unwrap(),
                            validate_serial_number(certificate, kms, &req, user, params).unwrap(),
                        )
                    })
                    .collect::<Vec<(ValidityIndicator, ValidityIndicator)>>();
                let validity_indicator = check_serial_numbers_and_date.iter().fold(
                    ValidityIndicator::Valid,
                    |acc, (v_date, v_serial): &(ValidityIndicator, ValidityIndicator)| {
                        let inner_and = validity_indicator_and(*v_date, *v_serial);
                        validity_indicator_and(acc, inner_and)
                    },
                );
                KResult::Ok(ValidateResponse { validity_indicator })
            }
        },
        Some(uid) => {
            let uid = uid
                .as_str()
                .context("Validate: public key unique_identifier must be a string")?;
            let uid_own = retrieve_object_for_operation(
                uid,
                ObjectOperationType::Validate,
                kms,
                user,
                params,
            )
            .await?;
            // I've to deal with borrowing uid_own
            match request.certificate {
                None => {
                    if let Object::Certificate {
                        certificate_type: _certificate_type,
                        certificate_value,
                    } = uid_own.object
                    {
                        let check_date = validate_date(&certificate_value, request.validity_time)?;
                        // No serial number validation. It's presence in the DB
                        // implies that certificate and associated keys were not
                        // revoked.
                        KResult::Ok(ValidateResponse {
                            validity_indicator: check_date,
                        })
                    } else {
                        KResult::Err(KmsError::from(KmipError::InvalidKmipObject(
                            cosmian_kmip::kmip::kmip_operations::ErrorReason::Invalid_Object_Type,
                            String::from("Requested a Certificate Object, got a ")
                                + &uid_own.object.object_type().to_string(),
                        )))
                    }
                }
                Some(_) => {
                    // else if some certificate list, map verification on each of them. Body of
                    // verification must be put in a function, used by both branches of the if.
                    // Final result Unknown, positive results returned in the ifs.
                    // what if both certificate and unique identifier are some? then we should
                    // return the logical and btw validations?
                    KResult::Err(KmsError::NotSupported(String::from("still implementing")))
                }
            }
        }
    }
}

fn validate_date(certificate: &[u8], date: Option<DateTime<Local>>) -> KResult<ValidityIndicator> {
    let certificate = X509::from_der(certificate)?;
    let current_date = {
        if let Some(date) = date {
            Asn1Time::from_str(&date.to_string())
        } else {
            Asn1Time::from_str(&Local::now().to_string())
        }
    }?;
    let (certificate_validity_start, certificate_validity_end) =
        (certificate.not_before(), certificate.not_after());
    if current_date.as_ref() <= certificate_validity_end
        && certificate_validity_start <= current_date.as_ref()
    {
        KResult::Ok(ValidityIndicator::Valid)
    } else {
        KResult::Ok(ValidityIndicator::Invalid)
    }
}

fn validate_serial_number(
    _certificate: &[u8],
    _kms: &KMS,
    _request: &Validate,
    _user: &str,
    _params: Option<&ExtraDatabaseParams>,
) -> KResult<ValidityIndicator> {
    // retrieve an uid
    // get it from kms
    // check same issuer
    Ok(ValidityIndicator::Unknown)
}

fn validity_indicator_and(v1: ValidityIndicator, v2: ValidityIndicator) -> ValidityIndicator {
    match (v1, v2) {
        (ValidityIndicator::Valid, ValidityIndicator::Valid) => ValidityIndicator::Valid,
        (ValidityIndicator::Invalid, _) | (_, ValidityIndicator::Invalid) => {
            ValidityIndicator::Invalid
        }
        _ => ValidityIndicator::Unknown,
    }
}
