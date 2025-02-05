use cosmian_cover_crypt::{EncryptionHint, MasterSecretKey, QualifiedAttribute};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kmip::kmip_2_1::{
    extra::tagging::EMPTY_TAGS,
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_messages::{Message, MessageBatchItem, MessageHeader, MessageResponse},
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Import, Operation},
    kmip_types::{
        Attributes, CryptographicAlgorithm, KeyFormatType, OperationEnumeration, ProtocolVersion,
        ResultStatusEnumeration, UniqueIdentifier,
    },
};
use cosmian_kms_crypto::crypto::cover_crypt::kmip_requests::build_create_covercrypt_master_keypair_request;

use crate::{kms_error, result::KResult, tests::test_utils};

const RSA_PRIVATE_KEY: &str = r"
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCNzNM2hQNhfdUO
7hTM9F/a4ZNfCBnIpTP6VRvHNLcA7T8Zt+2+ozC7zKneXGXAfs70zLfa00wAlcm0
FJ/4OJoPfEgDodN05rh0e8hmUjGs15HJAu5QS7b6p1zn/HUUmYSS4bffG6cV54BR
TcI1I7lf4hnedLet04gvrDABJUkoE+Az0Af3nGqbFdA04WmZuuK/9zlUCp3siHzc
fwoHOjCxhE1iJaogm8VU/bbinZQ02qmvRZf5A+SChBgfmEoZFHxuPcFViHOUQT7j
8FAunYQJ9JgJ7WRFiqV9KkFEeusqFn5VwSxiD/3NsAo+Ytzh9ExHropobkA2l7s6
x5UUsfI1AgMBAAECggEAFB4BvhufV+q7+icFTPGDkuBLYeFalRh4+BQwgXHFX8yI
1ft973yj+pTF6b3Wkrl634iWseUlxHR7vgBqFJNlKfrCFb/U6eIcu6vfCcMx+HlJ
3ch8amhfgI6Tc/chXieMgzEiPrUj3ovuLLq5KYRUtZl0fZa2A2N+D/NgCR2S1CxN
oy0Yvj7eMlRlGpOcoc/6dIJjJoS3PcxRMxAquIJsY8rBjkZ8F8AtaDS+F1nbTH6a
D3HazA4eIWmb3mxiRkRV3P1X6JVCplyr7yGmWnUN5T+mwygH89K2mP1K9Zxr9MWw
jUt84PtsR1WX+V8gGZWxHDqNCp8WiHH0qnqrzDqiYQKBgQDAy+PmePj36DmagxJO
p16usED7oYRvzab/XvYI/hQKQqiyey4G8JnEkKdtY2RV2sBLJmKiSdE+YsPRqhl3
mWBDtEg25UipEZAiH0BDu0Jg92iUP4FSPWc7h/Rt+W3O7Gt+UetpKRAnWWSyxgJ9
GG/mt+N58r8B79yOp4rynzxWIQKBgQC8SSdye2g31VmukxGZk1iDbVnVg1XYQcOj
E7MteFNUHLUeDO2XYgdhp1/hmLiaTCVvrhDp1WqwNthaOidV+ysSzABu316yq4Pm
qdcVsSoak69Rw50AXbxNju0Yz6YuYxUAjWQ5Jk8+gNplwRN3ha4lXpKUJBld92vM
el1ikCexlQKBgFlu+1QRL+TIC9iaDqb/ytMcHbjcbvPyIRJ7OYRoYGF2FI1eyLYd
bCcbtx7uKUAOTn9N2hlQRsk6xX1/+3pYYqhle85DRBZxeDvr5ULGHf+fJRsH7nR4
2WdrJL7TItYHI8IgPCS3ELBALo8jfUoMSPRsvw/1xBcg7l4aaEEuDq4hAoGBAIyF
EDKplVMuIDtguV7jj8iugMAPv66hDjAUEMJbrdz1e9qMjXlQiO/BqZZFk2hccggS
Yb8SLwiKNhfIlPjfdfsWUzBr9lHkHZG1qbcfvKuPEuYz1mWij1lW1O6ScpTmD5OU
8nqQc83S/qu4WB34n8p19XEoK+JsOICnxjA8I9OtAoGAVziHvUjC84B6BXVuC5B3
KLNVGWKs8oqvZIgRXhp3Yu4Kw41PKyQYPyQ91TAUbSvahkrNOwALmabx9OovNGtD
3IvcjbcH8hlJ1MmqxObwe4Hun4A3/ekv0G08kIRpkBgVeVhY3MJ2uKo+3LIk5AMf
jRuCab6FPsJq5BTA5QYDjR8=
-----END PRIVATE KEY-----
";

#[tokio::test]
async fn integration_tests_bulk() -> KResult<()> {
    // cosmian_logger::log_init("trace,hyper=info,reqwest=info");
    let app = test_utils::test_app(None).await;
    let pem: pem::Pem = pem::parse(RSA_PRIVATE_KEY.as_bytes())
        .map_err(|e| kms_error!(format!("cannot parse RSA private key: {}", e)))?;

    let import_key = Import {
        unique_identifier: UniqueIdentifier::TextString(String::new()),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: Attributes::default(),
        object: Object::PublicKey {
            key_block: KeyBlock {
                key_format_type: KeyFormatType::PKCS8,
                key_compression_type: None,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(pem.contents().to_vec().into()),
                    attributes: None,
                },
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: None,
                key_wrapping_data: None,
            },
        },
    };

    let y = import_key.object_type;
    let binding = y.to_string();
    let u = binding.as_bytes();
    let mut msk = MasterSecretKey::deserialize(u)?;

    msk.access_structure.add_anarchy("Department".to_owned())?;
    [
        ("HR", EncryptionHint::Classic),
        ("MKG", EncryptionHint::Classic),
        ("FIN", EncryptionHint::Classic),
    ]
    .into_iter()
    .try_for_each(|(attribute, hint)| {
        msk.access_structure.add_attribute(
            QualifiedAttribute {
                dimension: "Department".to_owned(),
                name: attribute.to_owned(),
            },
            hint,
            None,
        )
    })?;

    msk.access_structure.add_hierarchy("Level".to_owned())?;

    msk.access_structure.add_attribute(
        QualifiedAttribute {
            dimension: "Level".to_owned(),
            name: "Confidential".to_owned(),
        },
        EncryptionHint::Classic,
        None,
    )?;
    msk.access_structure.add_attribute(
        QualifiedAttribute {
            dimension: "Level".to_owned(),
            name: "Top Secret".to_owned(),
        },
        EncryptionHint::Hybridized,
        None,
    )?;

    let access_structure = msk.access_structure.serialize()?;

    let request_message = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            batch_count: 2,
            ..Default::default()
        },
        items: vec![
            MessageBatchItem::new(Operation::CreateKeyPair(
                build_create_covercrypt_master_keypair_request(
                    &access_structure,
                    EMPTY_TAGS,
                    false,
                )?,
            )),
            MessageBatchItem::new(Operation::CreateKeyPair(
                build_create_covercrypt_master_keypair_request(
                    &access_structure,
                    EMPTY_TAGS,
                    false,
                )?,
            )),
        ],
    };

    let response: MessageResponse = test_utils::post(&app, &request_message).await?;
    assert_eq!(response.items.len(), 2);

    // 1. Create keypair
    assert_eq!(
        response.items[0].operation,
        Some(OperationEnumeration::CreateKeyPair)
    );
    assert_eq!(
        response.items[0].result_status,
        ResultStatusEnumeration::Success
    );
    let Some(Operation::CreateKeyPairResponse(_)) = &response.items[0].response_payload else {
        panic!("not a create key pair response payload");
    };

    // 2. Create keypair
    assert_eq!(
        response.items[1].operation,
        Some(OperationEnumeration::CreateKeyPair)
    );
    assert_eq!(
        response.items[1].result_status,
        ResultStatusEnumeration::Success
    );
    let Some(Operation::CreateKeyPairResponse(_)) = &response.items[1].response_payload else {
        panic!("not a create key pair response payload");
    };

    Ok(())
}
