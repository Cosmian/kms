use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        KmipOperation,
        kmip_operations::{Activate, ActivateResponse},
        kmip_types::UniqueIdentifier,
    },
    cosmian_kms_interfaces::{ObjectWithMetadata, SessionParams},
};
use tracing::trace;

use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation},
    result::{KResult, KResultHelper},
};

pub(crate) async fn activate(
    kms: &KMS,
    request: Activate,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<ActivateResponse> {
    trace!("Activate: {}", serde_json::to_string(&request)?);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_str()
        .context("Activate: the unique identifier must be a string")?;

    let owm: ObjectWithMetadata = retrieve_object_for_operation(
        uid_or_tags,
        KmipOperation::GetAttributes,
        kms,
        user,
        params.clone(),
    )
    .await?;
    trace!("Activate: Retrieved object for: {}", owm.object());

    // All Objects are activated by default on the KMS, so simply answer OK
    Ok(ActivateResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
    })
}
