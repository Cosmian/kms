use cosmian_kmip::kmip::kmip_operations::{Validate, ValidateResponse};

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    error::KmsError,
    result::KResult,
};

pub async fn validate(
    _kms: &KMS,
    _request: Validate,
    _user: &str,
    _params: Option<&ExtraDatabaseParams>,
) -> KResult<ValidateResponse> {
    KResult::Err(KmsError::DatabaseError(String::from("still implementing")))
}
