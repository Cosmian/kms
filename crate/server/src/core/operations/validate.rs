use cloudproof::reexport::crypto_core::reexport::x509_cert::Certificate;
use cosmian_kmip::{
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Validate, ValidateResponse},
        kmip_types::ValidityIndicator,
    },
    openssl::kmip_certificate_to_openssl,
    KmipError, KmipResultHelper,
};
use cosmian_kms_client::access::ObjectOperationType;
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

    let mut _uid = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::InvalidRequest(
            "Attributes specifying the issuer private key id are missing".to_string(),
        ))?;

    if let Some(uid) = &request.unique_identifier {
        let uid = uid
            .as_str()
            .context("Certify: public key unique_identifier must be a string")?;
        let uid_own =
            retrieve_object_for_operation(uid, ObjectOperationType::Validate, kms, user, params)
                .await?;
        let certificate = kmip_certificate_to_openssl(&uid_own.object)?;
        if let Object::Certificate {
            certificate_type: _certificate_type,
            certificate_value: _certificate_value,
        } = uid_own.object
        {
            // just for not having yellow lines
            let certificate_str = String::from_utf8(certificate.to_text().unwrap())?;

            // check if date is some. in case use that date, otherwise actual time.

            return KResult::Err(KmsError::DatabaseError(certificate_str));
        } else {
            return KResult::Err(KmsError::from(KmipError::InvalidKmipObject(
                cosmian_kmip::kmip::kmip_operations::ErrorReason::Invalid_Object_Type,
                String::from("Requested a Certificate Object, got a ")
                    + &uid_own.object.object_type().to_string(),
            )));
        }
    } else if let Some(_certificates) = &request.certificate {
        // else if some certificate list, map verification on each of them. Body of
        // verification must be put in a function, used by both branches of the if.
        // Final result Unknown, positive results returned in the ifs.
        // what if both certificate and unique identifier are some? then we should
        // return the logical and btw validations?
        return KResult::Err(KmsError::NotSupported(String::from("still implementing")));
    }

    Ok(ValidateResponse {
        validity_indicator: ValidityIndicator::Unknown,
    })
}
