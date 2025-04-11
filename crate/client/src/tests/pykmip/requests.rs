use std::vec;

use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask, kmip_1_4::kmip_attributes::Attribute,
};
use cosmian_logger::log_init;
use tracing::info;

use crate::{
    kmip_1_4::{
        kmip_data_structures::TemplateAttribute,
        kmip_operations::{Create, Operation, Query},
        kmip_types::{CryptographicAlgorithm, ObjectType, QueryFunction},
    },
    send_to_pykmip_server,
};

#[test]
fn test_query() {
    log_init(option_env!("RUST_LOG"));

    let query = Query {
        query_function: Some(vec![
            QueryFunction::QueryOperations,
            QueryFunction::QueryObjects,
        ]),
    };

    let query_response = send_to_pykmip_server!(query, Query, QueryResponse);

    let Some(supported_operations) = &query_response.operation else {
        panic!("No supported operations")
    };
    assert!(!supported_operations.is_empty());
}

#[test]
fn test_create_aes_symmetric_key() {
    // log_init(option_env!("RUST_LOG"));
    log_init(Some("debug"));
    let attributes = vec![
        Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
        Attribute::CryptographicLength(128),
        Attribute::CryptographicUsageMask(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::KeyAgreement,
        ),
        Attribute::Sensitive(false),
        // Note: PyKMIP server does not support ObjectType, UniqueIdentifier and CustomAttribute
        // Attribute::ObjectType(ObjectType::SymmetricKey),
        // Attribute::UniqueIdentifier(UniqueIdentifier::TextString("test_key".to_owned())),
        // Attribute::CustomAttribute(
        //     CustomAttribute::TextString("custom value".to_owned()),
        // ),
    ];

    let create_kk = Create {
        object_type: ObjectType::SymmetricKey,
        template_attribute: TemplateAttribute {
            attribute: Some(attributes),
        },
    };

    let response = send_to_pykmip_server!(create_kk, Create, CreateResponse);

    info!("Response: {:#?}", response);
}
