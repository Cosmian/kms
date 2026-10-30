//! A KMIP 1.4 `Certify` carrying a PKCS#10 request, as sent by the SPIRE `kmip`
//! `UpstreamAuthority` plugin: the issuer key is given by a `PrivateKeyLink` and the X.509
//! extension config by the server-defined custom attribute `y-cosmian-x509-extension`.
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4::{
        self,
        kmip_attributes::{Attribute, CustomAttributeValue},
        kmip_data_structures::TemplateAttribute,
        kmip_operations::{Certify, CreateKeyPair},
        kmip_types::{
            CertificateRequestType, CryptographicAlgorithm, CustomAttribute, Link, LinkType,
            OperationEnumeration,
        },
    },
    kmip_2_1::{
        self,
        extra::{VENDOR_ATTR_X509_EXTENSION, tagging::VENDOR_ID_COSMIAN},
        kmip_attributes::Attributes,
        kmip_objects::Object,
        kmip_operations::{Get, Operation as Operation21},
        kmip_types::{
            CertificateAttributes, UniqueIdentifier, VendorAttribute, VendorAttributeValue,
        },
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;
use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    x509::{X509, X509NameBuilder, X509Req},
};

use super::socket_client::SocketClient;
use crate::tests::ttlv_tests::get_client;

const ROOT_EXT: &[u8] =
    b"[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,digitalSignature\n";
const INTERMEDIATE_EXT: &[u8] = b"[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,digitalSignature\n";

fn header(major: i32, minor: i32) -> RequestMessageHeader {
    RequestMessageHeader {
        protocol_version: ProtocolVersion {
            protocol_version_major: major,
            protocol_version_minor: minor,
        },
        batch_count: 1,
        ..Default::default()
    }
}

fn send_1_4(
    client: &SocketClient,
    operation: OperationEnumeration,
    payload: kmip_1_4::kmip_operations::Operation,
) -> kmip_1_4::kmip_operations::Operation {
    let request = RequestMessage {
        request_header: header(1, 4),
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            kmip_1_4::kmip_messages::RequestMessageBatchItem {
                operation,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: payload,
                message_extension: None,
            },
        )],
    };
    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request)
        .expect("Failed to send KMIP 1.4 request");
    let Some(ResponseMessageBatchItemVersioned::V14(item)) = response.batch_item.into_iter().next()
    else {
        panic!("Expected a V14 response batch item");
    };
    assert_eq!(
        item.result_status,
        ResultStatusEnumeration::Success,
        "{:?}",
        item.result_message
    );
    item.response_payload.expect("Expected a response payload")
}

fn send_2_1(
    client: &SocketClient,
    operation: kmip_2_1::kmip_types::OperationEnumeration,
    payload: Operation21,
) -> Operation21 {
    let request = RequestMessage {
        request_header: header(2, 1),
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            kmip_2_1::kmip_messages::RequestMessageBatchItem {
                operation,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: payload,
                message_extension: None,
            },
        )],
    };
    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip2, &request)
        .expect("Failed to send KMIP 2.1 request");
    let Some(ResponseMessageBatchItemVersioned::V21(item)) = response.batch_item.into_iter().next()
    else {
        panic!("Expected a V21 response batch item");
    };
    assert_eq!(
        item.result_status,
        ResultStatusEnumeration::Success,
        "{:?}",
        item.result_message
    );
    item.response_payload.expect("Expected a response payload")
}

fn get_certificate(client: &SocketClient, uid: &str) -> X509 {
    let Operation21::GetResponse(response) = send_2_1(
        client,
        kmip_2_1::kmip_types::OperationEnumeration::Get,
        Operation21::Get(Get {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            ..Get::default()
        }),
    ) else {
        panic!("Expected GetResponse");
    };
    let Object::Certificate(certificate) = response.object else {
        panic!("Expected a Certificate object");
    };
    X509::from_der(&certificate.certificate_value).expect("Invalid certificate DER")
}

fn ec_p256_csr_der() -> Vec<u8> {
    let key = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "spire-intermediate")
        .unwrap();
    let mut builder = X509Req::builder().unwrap();
    builder.set_subject_name(&name.build()).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}

#[test]
fn test_certify_csr_1_4() {
    log_init(option_env!("RUST_LOG"));
    let client = get_client();

    // Root key pair (KMIP 1.4)
    let kmip_1_4::kmip_operations::Operation::CreateKeyPairResponse(key_pair) = send_1_4(
        &client,
        OperationEnumeration::CreateKeyPair,
        kmip_1_4::kmip_operations::Operation::CreateKeyPair(CreateKeyPair {
            common_template_attribute: Some(TemplateAttribute {
                attribute: Some(vec![
                    Attribute::CryptographicAlgorithm(CryptographicAlgorithm::RSA),
                    Attribute::CryptographicLength(2048),
                    // an Active issuer key is required to sign
                    Attribute::ActivationDate(
                        cosmian_kms_server_database::reexport::cosmian_kmip::time_normalize()
                            .expect("Failed to set activation date"),
                    ),
                ]),
            }),
            private_key_template_attribute: None,
            public_key_template_attribute: None,
        }),
    ) else {
        panic!("Expected CreateKeyPairResponse");
    };

    // Self-signed root CA (KMIP 2.1), extension config as a `cosmian` vendor attribute
    let Operation21::CertifyResponse(root) = send_2_1(
        &client,
        kmip_2_1::kmip_types::OperationEnumeration::Certify,
        Operation21::Certify(Box::new(kmip_2_1::kmip_operations::Certify {
            unique_identifier: Some(UniqueIdentifier::TextString(
                key_pair.public_key_unique_identifier.clone(),
            )),
            attributes: Some(Attributes {
                certificate_attributes: Some(
                    CertificateAttributes::parse_subject_line("CN=spire-root").unwrap(),
                ),
                vendor_attributes: Some(vec![VendorAttribute {
                    vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
                    attribute_name: VENDOR_ATTR_X509_EXTENSION.to_owned(),
                    attribute_value: VendorAttributeValue::ByteString(ROOT_EXT.to_vec()),
                }]),
                ..Attributes::default()
            }),
            ..kmip_2_1::kmip_operations::Certify::default()
        })),
    ) else {
        panic!("Expected CertifyResponse");
    };
    let root_cert = get_certificate(&client, &root.unique_identifier.to_string());

    // Intermediate CA: KMIP 1.4 Certify with a PKCS#10 CSR, no Unique Identifier
    let kmip_1_4::kmip_operations::Operation::CertifyResponse(intermediate) = send_1_4(
        &client,
        OperationEnumeration::Certify,
        kmip_1_4::kmip_operations::Operation::Certify(Certify {
            unique_identifier: None,
            certificate_request_type: Some(CertificateRequestType::PKCS10),
            certificate_request: Some(ec_p256_csr_der()),
            template_attribute: Some(TemplateAttribute {
                attribute: Some(vec![
                    Attribute::Link(Link {
                        link_type: LinkType::PrivateKeyLink,
                        linked_object_identifier: key_pair.private_key_unique_identifier,
                    }),
                    Attribute::CustomAttribute(CustomAttribute {
                        name: format!("y-{VENDOR_ID_COSMIAN}::{VENDOR_ATTR_X509_EXTENSION}"),
                        value: CustomAttributeValue::TextString(
                            String::from_utf8(INTERMEDIATE_EXT.to_vec()).unwrap(),
                        ),
                    }),
                ]),
            }),
        }),
    ) else {
        panic!("Expected CertifyResponse");
    };

    let cert = get_certificate(&client, &intermediate.unique_identifier);
    assert!(cert.verify(&root_cert.public_key().unwrap()).unwrap());
    let text = String::from_utf8(cert.to_text().unwrap()).unwrap();
    assert!(text.contains("CA:TRUE"), "{text}");
    assert!(text.contains("pathlen:0"), "{text}");
    assert!(
        text.contains("CN = spire-intermediate") || text.contains("CN=spire-intermediate"),
        "{text}"
    );
}
