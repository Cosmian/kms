use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation,
            kmip_operations::{Activate, ActivateResponse},
            kmip_types::UniqueIdentifier,
        },
    },
    cosmian_kms_interfaces::{ObjectWithMetadata, SessionParams},
};
use time::OffsetDateTime;
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

    let mut owm: ObjectWithMetadata = retrieve_object_for_operation(
        uid_or_tags,
        KmipOperation::GetAttributes,
        kms,
        user,
        params.clone(),
    )
    .await?;
    trace!("Activate: Retrieved object for: {}", owm.object());

    // Update the state of the object to Active and activation date
    let activation_date = OffsetDateTime::now_utc();
    if let Ok(object_attributes) = owm.object_mut().attributes_mut() {
        object_attributes.state = Some(State::Active);
        // update the activation date
        object_attributes.activation_date = Some(activation_date);
    }
    // Update the state in the "external" attributes
    owm.attributes_mut().state = Some(State::Active);
    // Update the activation date in the "external" attributes
    owm.attributes_mut().activation_date = Some(activation_date);

    // Update the object in the database
    kms.database
        .update_object(
            owm.id(),
            owm.object(),
            owm.attributes(),
            None,
            params.clone(),
        )
        .await?;

    // All Objects are activated by default on the KMS, so simply answer OK
    Ok(ActivateResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
    })
}
