#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::AlternativeName;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::{
    AlternativeNameType, CryptographicUsageMask,
};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attributes;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Create;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason, kmip_2_1::kmip_operations::Operation, ttlv::to_ttlv,
};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_2_1::kmip_objects::ObjectType, time_normalize,
};

#[cfg(feature = "non-fips")]
pub(super) use super::super::test_utils::https_clap_config_opts;
#[cfg(feature = "non-fips")]
use super::super::test_utils::post_2_1;
use crate::{
    config::{ClapConfig, ServerParams},
    core::operations::algorithm_policy::enforce_kmip_algorithm_policy_for_operation,
    error::KmsError,
};

pub(super) fn params_with_default_policy() -> ServerParams {
    let mut params =
        ServerParams::try_from(ClapConfig::default()).expect("default clap config should build");
    params.kmip_policy.enforce = true;
    params
}

pub(super) fn params_with_allowlists(conf: ClapConfig) -> ServerParams {
    ServerParams::try_from(conf).expect("config should build")
}

fn deny_reason(res: Result<(), KmsError>) -> ErrorReason {
    match res {
        Ok(()) => panic!("expected KMIP policy failure"),
        Err(KmsError::Kmip21Error(reason, _)) => reason,
        Err(other) => {
            panic!("unexpected error type (wanted Kmip21Error): {other:?}")
        }
    }
}

pub(super) fn assert_policy_denied(res: Result<(), KmsError>) {
    let reason = deny_reason(res);
    assert_eq!(
        reason,
        ErrorReason::Constraint_Violation,
        "policy enforcement should return Constraint_Violation for denied parameters"
    );
}

pub(super) fn enforce(
    params: &ServerParams,
    operation_tag: &str,
    op: &Operation,
) -> Result<(), KmsError> {
    let ttlv = to_ttlv(op)?;
    enforce_kmip_algorithm_policy_for_operation(params, operation_tag, &ttlv)
}

#[cfg(feature = "non-fips")]
pub(super) async fn create_aes_key_with_size<B, S>(
    app: &S,
    tag: &str,
    bits: i32,
) -> Result<String, KmsError>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let req = Operation::Create(Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(bits),
            cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
            activation_date: Some(time_normalize().expect("time_normalize should work")),
            alternative_name: Some(AlternativeName {
                alternative_name_type: AlternativeNameType::UninterpretedTextString,
                alternative_name_value: tag.to_owned(),
            }),
            ..Default::default()
        },
        protection_storage_masks: None,
    });
    let resp: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::CreateResponse =
        post_2_1(app, &req).await?;
    Ok(resp
        .unique_identifier
        .as_str()
        .expect("uid should be a string")
        .to_owned())
}

pub(super) fn assert_constraint_violation(err: KmsError) {
    match err {
        KmsError::Kmip21Error(ErrorReason::Constraint_Violation, _) => {}
        KmsError::ServerError(msg) if msg.contains("Constraint_Violation") => {}
        other => panic!("expected Constraint_Violation, got: {other:?}"),
    }
}

// Keep the helper module lean: no re-exports. Each test module imports what it needs.
