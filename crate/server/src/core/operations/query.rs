use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_data_structures::ServerInformation,
    kmip_objects::ObjectType,
    kmip_operations::{Query, QueryResponse},
    kmip_types::{OperationEnumeration, QueryFunction},
};
use tracing::trace;

use crate::result::KResult;

/// This operation is used by the client to interrogate the server
/// to determine its capabilities and/or protocol mechanisms.
/// The Query operation SHOULD be invocable by unauthenticated clients
/// to interrogate server features and functions.
/// The Query Function field in the request SHALL contain one or more of the following items:
pub(crate) async fn query(request: Query) -> KResult<QueryResponse> {
    trace!("Query: {request:#?}");

    let mut response = QueryResponse {
        operation: None,
        object_type: None,
        vendor_identification: None,
        application_namespaces: None,
        server_information: None,
        extension_information: None,
        attestation_types: None,
        rng_parameters: None,
        profiles_information: None,
        validation_information: None,
        capability_information: None,
        defaults_information: None,
        protection_storage_masks: None,
    };

    if let Some(functions) = request.query_function {
        for func in functions {
            match func {
                QueryFunction::QueryOperations => {
                    response.operation = Some(vec![
                        OperationEnumeration::Activate,
                        OperationEnumeration::Certify,
                        OperationEnumeration::Create,
                        OperationEnumeration::CreateKeyPair,
                        OperationEnumeration::Decrypt,
                        OperationEnumeration::Destroy,
                        OperationEnumeration::Encrypt,
                        OperationEnumeration::Get,
                        OperationEnumeration::GetAttributes,
                        OperationEnumeration::Locate,
                        OperationEnumeration::Query,
                        OperationEnumeration::Recover,
                        OperationEnumeration::Register,
                        OperationEnumeration::ReKey,
                        OperationEnumeration::ReKeyKeyPair,
                        OperationEnumeration::Revoke,
                        OperationEnumeration::SetAttribute,
                        OperationEnumeration::Validate,
                    ]);
                }
                QueryFunction::QueryObjects => {
                    response.object_type = Some(vec![
                        ObjectType::Certificate,
                        ObjectType::SymmetricKey,
                        ObjectType::PrivateKey,
                        ObjectType::PublicKey,
                    ]);
                }
                QueryFunction::QueryServerInformation => {
                    response.vendor_identification = Some("Cosmian".to_owned());
                    response.server_information = Some(ServerInformation {
                        server_name: Some("Cosmian KMS".to_owned()),
                        server_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                        ..Default::default()
                    });
                }
                QueryFunction::QueryApplicationNamespaces
                | QueryFunction::QueryExtensionList
                | QueryFunction::QueryExtensionMap
                | QueryFunction::QueryAttestationTypes
                | QueryFunction::QueryRNGs
                | QueryFunction::QueryValidations
                | QueryFunction::QueryProfiles
                | QueryFunction::QueryCapabilities
                | QueryFunction::QueryClientRegistrationMethods
                | QueryFunction::QueryDefaultsInformation
                | QueryFunction::QueryStorageProtectionMasks => {}
            }
        }
    }
    Ok(response)
}
