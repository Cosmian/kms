use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{DRBGAlgorithm, RNGAlgorithm},
    kmip_2_1::{
        kmip_data_structures::{RNGParameters, ServerInformation},
        kmip_objects::ObjectType,
        kmip_operations::{Query, QueryResponse},
        kmip_types::{CryptographicAlgorithm, OperationEnumeration, QueryFunction},
    },
};
use cosmian_logger::trace;

use crate::result::KResult;

/// This operation is used by the client to interrogate the server
/// to determine its capabilities and/or protocol mechanisms.
/// The Query operation SHOULD be invocable by unauthenticated clients
/// to interrogate server features and functions.
/// The Query Function field in the request SHALL contain one or more of the following items:
pub(crate) async fn query(request: Query, vendor_identification: &str) -> KResult<QueryResponse> {
    trace!("{request}");

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
                        // Core object lifecycle and attribute ops
                        OperationEnumeration::Activate,
                        OperationEnumeration::AddAttribute,
                        OperationEnumeration::ModifyAttribute,
                        OperationEnumeration::SetAttribute,
                        OperationEnumeration::DeleteAttribute,
                        OperationEnumeration::GetAttributeList,
                        OperationEnumeration::GetAttributes,
                        // Key management ops
                        OperationEnumeration::Create,
                        OperationEnumeration::CreateKeyPair,
                        OperationEnumeration::Register,
                        OperationEnumeration::Import,
                        OperationEnumeration::Export,
                        OperationEnumeration::Get,
                        OperationEnumeration::Locate,
                        OperationEnumeration::ReKey,
                        OperationEnumeration::ReKeyKeyPair,
                        OperationEnumeration::Destroy,
                        OperationEnumeration::Revoke,
                        // Crypto ops
                        OperationEnumeration::Encrypt,
                        OperationEnumeration::Decrypt,
                        OperationEnumeration::Sign,
                        OperationEnumeration::SignatureVerify,
                        OperationEnumeration::MAC,
                        OperationEnumeration::MACVerify,
                        OperationEnumeration::Hash,
                        OperationEnumeration::DeriveKey,
                        // Server/platform ops
                        OperationEnumeration::Query,
                        OperationEnumeration::DiscoverVersions,
                        // RNG
                        OperationEnumeration::RNGRetrieve,
                        OperationEnumeration::RNGSeed,
                        // Certificate/validation
                        OperationEnumeration::Certify,
                        OperationEnumeration::Validate,
                        // Additional supported/interop surface
                        OperationEnumeration::PKCS11,
                        #[cfg(feature = "interop")]
                        OperationEnumeration::Interop,
                        OperationEnumeration::Log,
                        OperationEnumeration::Check,
                        // Split key ops (KMIP 1.4 §4.38–§4.39)
                        OperationEnumeration::CreateSplitKey,
                        OperationEnumeration::JoinSplitKey,
                    ]);
                }
                QueryFunction::QueryObjects => {
                    response.object_type = Some(vec![
                        ObjectType::Certificate,
                        ObjectType::SymmetricKey,
                        ObjectType::PrivateKey,
                        ObjectType::PublicKey,
                        ObjectType::SecretData,
                        ObjectType::SplitKey,
                        ObjectType::OpaqueObject,
                    ]);
                }
                QueryFunction::QueryServerInformation => {
                    response.vendor_identification = Some(vendor_identification.to_owned());
                    response.server_information = Some(ServerInformation {
                        server_name: Some("Cosmian KMS".to_owned()),
                        server_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                        ..Default::default()
                    });
                }
                QueryFunction::QueryRNGs => {
                    // `KmsRng`: OpenSSL AES-256 CTR-DRBG (SP 800-90A r1). OpenSSL does not
                    // request prediction resistance on ordinary generate calls.
                    response.rng_parameters = Some(vec![RNGParameters {
                        rng_algorithm: RNGAlgorithm::DRBG,
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        cryptographic_length: Some(256),
                        hashing_algorithm: None,
                        drbg_algorithm: Some(DRBGAlgorithm::CTR),
                        recommended_curve: None,
                        fips186_variation: None,
                        prediction_resistance: Some(false),
                    }]);
                }
                QueryFunction::QueryApplicationNamespaces
                | QueryFunction::QueryExtensionList
                | QueryFunction::QueryExtensionMap
                | QueryFunction::QueryAttestationTypes
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

#[cfg(test)]
#[allow(clippy::expect_used)] // tests: a panic is the failure signal
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::{DRBGAlgorithm, RNGAlgorithm},
        kmip_2_1::{kmip_operations::Query, kmip_types::QueryFunction},
    };

    use super::query;

    #[tokio::test]
    async fn query_rngs_describes_the_ctr_drbg() {
        let response = query(
            Query {
                query_function: Some(vec![QueryFunction::QueryRNGs]),
            },
            "Cosmian",
        )
        .await
        .expect("query");
        let rngs = response.rng_parameters.expect("rng_parameters");
        assert_eq!(rngs.len(), 1, "expected exactly one RNG");
        let rng = rngs.first().expect("one RNG");
        assert_eq!(rng.rng_algorithm, RNGAlgorithm::DRBG);
        assert_eq!(rng.drbg_algorithm, Some(DRBGAlgorithm::CTR));
        assert_eq!(rng.cryptographic_length, Some(256));
    }

    #[tokio::test]
    async fn rng_parameters_are_only_returned_when_requested() {
        let response = query(
            Query {
                query_function: Some(vec![QueryFunction::QueryObjects]),
            },
            "Cosmian",
        )
        .await
        .expect("query");
        assert!(response.rng_parameters.is_none());
    }
}
