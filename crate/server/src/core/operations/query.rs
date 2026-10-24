use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{DRBGAlgorithm, ErrorReason, RNGAlgorithm},
    kmip_2_1::{
        kmip_data_structures::{ExtensionInformation, RNGParameters, ServerInformation},
        kmip_objects::ObjectType,
        kmip_operations::{Query, QueryResponse},
        kmip_types::{CryptographicAlgorithm, ItemType, OperationEnumeration, QueryFunction},
    },
};
use cosmian_logger::trace;

use crate::{error::KmsError, result::KResult};

/// Item Tag of the Cosmian `CertificateAttributes` vendor extension (`Tag::CertificateAttributes`).
const CERTIFICATE_ATTRIBUTES_TAG: i32 = 0x54_0001;
pub(super) const SUPPORTED_QUERY_OBJECT_TYPES: &[ObjectType] = &[
    ObjectType::Certificate,
    ObjectType::SymmetricKey,
    ObjectType::PrivateKey,
    ObjectType::PublicKey,
    ObjectType::SecretData,
    ObjectType::SplitKey,
    ObjectType::OpaqueObject,
    #[cfg(feature = "non-fips")]
    ObjectType::PGPKey,
];

/// This operation is used by the client to interrogate the server
/// to determine its capabilities and/or protocol mechanisms.
/// The Query operation SHOULD be invocable by unauthenticated clients
/// to interrogate server features and functions.
/// The Query Function field in the request SHALL contain one or more of the following items.
/// `pkcs11_available` is true when the PKCS#11 operation can be served (an HSM and a
/// Crypto Officer are configured); it is only then advertised in the Operations list.
pub(crate) async fn query(
    request: Query,
    vendor_identification: &str,
    pkcs11_available: bool,
) -> KResult<QueryResponse> {
    trace!("Query request");

    // Query Function is REQUIRED (KMIP 2.1 Table 282).
    if request.query_function.as_ref().is_none_or(Vec::is_empty) {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            "Query: at least one Query Function is required".to_owned(),
        ));
    }
    // The server defines no Object Groups specific information (KMIP 2.1 Table 284).
    if request
        .object_groups
        .as_ref()
        .is_some_and(|g| !g.is_empty())
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Feature_Not_Supported,
            "Query: Object Group specific queries are not supported".to_owned(),
        ));
    }
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
                    let mut operations = vec![
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
                        OperationEnumeration::ReCertify,
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
                        // Ticket authentication and server constraints (KMIP 2.1 §6.1.30,
                        // §6.1.31, §6.1.52, §6.1.22)
                        OperationEnumeration::Login,
                        OperationEnumeration::Logout,
                        OperationEnumeration::SetConstraints,
                        OperationEnumeration::GetConstraints,
                        OperationEnumeration::Ping,
                        // RNG
                        OperationEnumeration::RNGRetrieve,
                        OperationEnumeration::RNGSeed,
                        // Certificate/validation
                        OperationEnumeration::Certify,
                        OperationEnumeration::Validate,
                        // Additional supported/interop surface
                        OperationEnumeration::Log,
                        #[cfg(feature = "interop")]
                        OperationEnumeration::Interop,
                        OperationEnumeration::Check,
                        // Split key ops (KMIP 1.4 §4.38–§4.39)
                        OperationEnumeration::CreateSplitKey,
                        OperationEnumeration::JoinSplitKey,
                    ];
                    // PKCS#11 needs an HSM and a Crypto Officer (see `check_role_permission`).
                    if pkcs11_available {
                        operations.push(OperationEnumeration::PKCS11);
                    }
                    response.operation = Some(operations);
                }
                QueryFunction::QueryObjects => {
                    response.object_type = Some(SUPPORTED_QUERY_OBJECT_TYPES.to_vec());
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
                // KMIP 2.1 §6.1.40: nothing to return, so nothing is returned; no Protection
                // Storage Mask is supported (requests carrying masks are rejected with
                // Feature_Not_Supported).
                QueryFunction::QueryStorageProtectionMasks => {
                    response.protection_storage_masks = None;
                }
                QueryFunction::QueryExtensionList | QueryFunction::QueryExtensionMap => {
                    response.extension_information = Some(vec![ExtensionInformation {
                        extension_name: "CertificateAttributes".to_owned(),
                        extension_tag: Some(CERTIFICATE_ATTRIBUTES_TAG),
                        extension_type: Some(ItemType::Structure),
                        extension_attribute: Some(true),
                        extension_parent_structure_tag: None,
                        extension_enumeration: None,
                        extension_description: Some(
                            "Subject and issuer fields of a certificate, as an object attribute"
                                .to_owned(),
                        ),
                    }]);
                }
                QueryFunction::QueryApplicationNamespaces
                | QueryFunction::QueryAttestationTypes
                | QueryFunction::QueryValidations
                | QueryFunction::QueryProfiles
                | QueryFunction::QueryCapabilities
                | QueryFunction::QueryClientRegistrationMethods
                | QueryFunction::QueryDefaultsInformation => {}
            }
        }
    }
    Ok(response)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    #[cfg(feature = "non-fips")]
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType;
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::{DRBGAlgorithm, ErrorReason, RNGAlgorithm},
        kmip_2_1::{
            kmip_operations::Query,
            kmip_types::{OperationEnumeration, QueryFunction},
        },
    };

    use super::query;
    use crate::error::KmsError;

    fn request(function: QueryFunction) -> Query {
        Query {
            query_function: Some(vec![function]),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn query_rngs_describes_the_ctr_drbg() {
        let response = query(request(QueryFunction::QueryRNGs), "Cosmian", false)
            .await
            .expect("query");
        let rngs = response.rng_parameters.expect("rng_parameters");
        let [rng] = rngs.as_slice() else {
            panic!("expected exactly one RNG, got {}", rngs.len());
        };
        assert_eq!(rng.rng_algorithm, RNGAlgorithm::DRBG);
        assert_eq!(rng.drbg_algorithm, Some(DRBGAlgorithm::CTR));
        assert_eq!(rng.cryptographic_length, Some(256));
    }

    #[tokio::test]
    async fn rng_parameters_are_only_returned_when_requested() {
        let response = query(request(QueryFunction::QueryObjects), "Cosmian", false)
            .await
            .expect("query");
        assert!(response.rng_parameters.is_none());
    }

    #[tokio::test]
    async fn query_operations_advertises_recertify() {
        let response = query(request(QueryFunction::QueryOperations), "Cosmian", false)
            .await
            .expect("query");

        assert!(
            response
                .operation
                .is_some_and(|operations| operations.contains(&OperationEnumeration::ReCertify))
        );
    }

    #[tokio::test]
    async fn query_operations_advertises_pkcs11_only_when_available() {
        for available in [false, true] {
            let response = query(
                request(QueryFunction::QueryOperations),
                "Cosmian",
                available,
            )
            .await
            .expect("query");
            let operations = response.operation.expect("operations");
            assert_eq!(
                operations.contains(&OperationEnumeration::PKCS11),
                available
            );
        }
    }

    #[tokio::test]
    async fn query_extension_list_describes_certificate_attributes() {
        for function in [
            QueryFunction::QueryExtensionList,
            QueryFunction::QueryExtensionMap,
        ] {
            let response = query(request(function), "Cosmian", false)
                .await
                .expect("query");
            let extensions = response.extension_information.expect("extensions");
            assert!(extensions.iter().any(|extension| {
                extension.extension_name == "CertificateAttributes"
                    && extension.extension_tag == Some(0x54_0001)
            }));
        }
    }

    #[tokio::test]
    async fn query_requires_a_function_and_rejects_object_groups() {
        let missing = query(Query::default(), "Cosmian", false).await;
        assert!(matches!(
            missing,
            Err(KmsError::Kmip21Error(ErrorReason::Invalid_Field, _))
        ));

        let groups = query(
            Query {
                query_function: Some(vec![QueryFunction::QueryOperations]),
                object_groups: Some(vec!["group".to_owned()]),
            },
            "Cosmian",
            false,
        )
        .await;
        assert!(matches!(
            groups,
            Err(KmsError::Kmip21Error(ErrorReason::Feature_Not_Supported, _))
        ));
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn query_objects_advertises_pgp_keys() {
        let response = query(request(QueryFunction::QueryObjects), "Cosmian", false)
            .await
            .expect("query");

        assert!(
            response
                .object_type
                .is_some_and(|object_types| object_types.contains(&ObjectType::PGPKey))
        );
    }
}
