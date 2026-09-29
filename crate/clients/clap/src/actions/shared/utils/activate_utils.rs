use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{kmip_operations::Activate, kmip_types::UniqueIdentifier},
};

use crate::{
    actions::console,
    cli_bail,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Activate a cryptographic object on the KMS.
///
/// Transitions the object from `Pre-Active` to `Active` state.
pub(crate) async fn activate(
    kms_rest_client: KmsClient,
    uid: &str,
) -> KmsCliResult<UniqueIdentifier> {
    let uid = UniqueIdentifier::TextString(uid.to_owned());
    let activate_request = Activate {
        unique_identifier: uid.clone(),
    };

    let activate_response = kms_rest_client
        .activate(activate_request)
        .await
        .with_context(|| format!("activation of object {uid} failed"))?;

    if uid == activate_response.unique_identifier {
        let mut stdout = console::Stdout::new("Successfully activated the object.");
        stdout.set_unique_identifier(&uid);
        stdout.write()?;
        Ok(uid)
    } else {
        cli_bail!("Something went wrong when activating the object.")
    }
}
