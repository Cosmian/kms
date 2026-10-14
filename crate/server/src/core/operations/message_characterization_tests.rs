//! Characterization tests pinning BASE behavior of `get_operation_name`.

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        kmip_objects::ObjectType,
        kmip_operations::{Activate, Create, GetAttributes, Operation, Revoke, Validate},
        kmip_types::UniqueIdentifier,
    },
};

use super::get_operation_name;

#[test]
fn characterization_get_operation_name_default_constructible_operations() {
    let cases: Vec<(Operation, &str)> = vec![
        (Operation::Certify(Box::default()), "Certify"),
        (Operation::CreateKeyPair(Box::default()), "CreateKeyPair"),
        (Operation::Decrypt(Box::default()), "Decrypt"),
        (
            Operation::DeleteAttribute(Default::default()),
            "DeleteAttribute",
        ),
        (Operation::Destroy(Default::default()), "Destroy"),
        (Operation::Encrypt(Box::default()), "Encrypt"),
        (Operation::Export(Default::default()), "Export"),
        (Operation::Get(Default::default()), "Get"),
        (Operation::Hash(Default::default()), "Hash"),
        (Operation::Locate(Box::default()), "Locate"),
        (Operation::MAC(Default::default()), "MAC"),
        (Operation::Query(Default::default()), "Query"),
        (Operation::ReCertify(Default::default()), "ReCertify"),
        (Operation::ReKey(Default::default()), "ReKey"),
        (Operation::ReKeyKeyPair(Default::default()), "ReKeyKeyPair"),
        (Operation::Sign(Default::default()), "Sign"),
        (
            Operation::SignatureVerify(Default::default()),
            "SignatureVerify",
        ),
    ];
    for (operation, name) in cases {
        assert_eq!(get_operation_name(&operation), name);
    }
}

#[test]
fn characterization_get_operation_name_literal_operations() {
    let uid = UniqueIdentifier::TextString("uid".to_owned());
    assert_eq!(
        get_operation_name(&Operation::Activate(Activate {
            unique_identifier: uid.clone()
        })),
        "Activate"
    );
    assert_eq!(
        get_operation_name(&Operation::Create(Create {
            object_type: ObjectType::SymmetricKey,
            attributes: Default::default(),
            protection_storage_masks: None,
        })),
        "Create"
    );
    assert_eq!(
        get_operation_name(&Operation::GetAttributes(GetAttributes {
            unique_identifier: Some(uid.clone()),
            attribute_reference: None,
        })),
        "GetAttributes"
    );
    assert_eq!(
        get_operation_name(&Operation::Revoke(Revoke {
            unique_identifier: Some(uid),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::Unspecified,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: false,
        })),
        "Revoke"
    );
    assert_eq!(
        get_operation_name(&Operation::Validate(Validate {
            certificate: None,
            unique_identifier: None,
            validity_time: None,
        })),
        "Validate"
    );
}

#[test]
fn characterization_get_operation_name_unlisted_operation_is_unknown() {
    // BASE: operations without a dedicated arm (e.g. response variants) map to "Unknown".
    let response = Operation::ActivateResponse(
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::ActivateResponse {
            unique_identifier: UniqueIdentifier::TextString("uid".to_owned()),
        },
    );
    assert_eq!(get_operation_name(&response), "Unknown");
}
