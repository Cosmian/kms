use cosmian_logger::log_init;
use num_bigint_dig::BigInt;
use tracing::info;
use zeroize::Zeroizing;

use crate::{
    SafeBigInt,
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_1_4::{
        kmip_attributes::Attribute,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, TemplateAttribute},
        kmip_objects::{Object, PrivateKey, SymmetricKey},
        kmip_types::{
            CryptographicAlgorithm, CryptographicDomainParameters, KeyFormatType, Name, NameType,
            RecommendedCurve,
        },
    },
    ttlv::{from_ttlv, to_ttlv},
};

#[test]
fn test_template_attributes() {
    log_init(option_env!("RUST_LOG"));

    let template_attribute = TemplateAttribute {
        attribute: Some(vec![
            Attribute::Name(Name {
                name_value: "TestName".to_owned(),
                name_type: NameType::UninterpretedTextString,
            }),
            Attribute::Name(Name {
                name_value: "http://localhost".to_owned(),
                name_type: NameType::URI,
            }),
            Attribute::CryptographicAlgorithm(CryptographicAlgorithm::ECDH),
            Attribute::CryptographicLength(128),
            Attribute::CryptographicDomainParameters(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::P256),
            }),
            Attribute::CryptographicUsageMask(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
        ]),
    };

    let ttlv = to_ttlv(&template_attribute).expect("Failed to convert TemplateAttribute to TTLV");
    info!("TTLV: {:#?}", ttlv);

    // Deserialize the TTLV back to TemplateAttribute
    let deserialized_template_attribute: TemplateAttribute =
        from_ttlv(ttlv).expect("Failed to deserialize TTLV");

    info!(
        "Deserialized TemplateAttribute: {:#?}",
        deserialized_template_attribute
    );
    assert_eq!(
        template_attribute, deserialized_template_attribute,
        "Deserialized TemplateAttribute does not match the original"
    );
}

#[test]
fn test_object_raw() {
    log_init(option_env!("RUST_LOG"));

    let object = Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::Raw,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::new(vec![0x01, 0x02, 0x03])),
                attribute: None,
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let ttlv = to_ttlv(&object).expect("Failed to convert Object to TTLV");
    info!("TTLV: {:#?}", ttlv);

    // Deserialize the TTLV back to Object
    let deserialized_object: Object = from_ttlv(ttlv).expect("Failed to deserialize TTLV");

    info!("Deserialized Object: {:#?}", deserialized_object);
    assert_eq!(
        object, deserialized_object,
        "Deserialized Object does not match the original"
    );

    // JSON Serde
    let json = serde_json::to_string_pretty(&object).expect("Failed to serialize to JSON");
    info!("JSON: {}", json);
    let deserialized_object_json: Object =
        serde_json::from_str(&json).expect("Failed to deserialize from JSON");
    assert_eq!(
        object, deserialized_object_json,
        "Deserialized Object from JSON does not match the original"
    );
}

#[test]
fn test_object_structured_sym() {
    log_init(option_env!("RUST_LOG"));
    let object = Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentSymmetricKey {
                    key: Zeroizing::new(vec![0x01, 0x02, 0x03]),
                },
                attribute: None,
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let ttlv = to_ttlv(&object).expect("Failed to convert Object to TTLV");
    info!("TTLV: {:#?}", ttlv);

    // Deserialize the TTLV back to Object
    let deserialized_object: Object = from_ttlv(ttlv).expect("Failed to deserialize TTLV");

    info!("Deserialized Object: {:#?}", deserialized_object);
    assert_eq!(
        object, deserialized_object,
        "Deserialized Object does not match the original"
    );

    // JSON Serde
    let json = serde_json::to_string_pretty(&object).expect("Failed to serialize to JSON");
    info!("JSON: {}", json);
    let deserialized_object_json: Object =
        serde_json::from_str(&json).expect("Failed to deserialize from JSON");
    assert_eq!(
        object, deserialized_object_json,
        "Deserialized Object from JSON does not match the original"
    );
}

#[test]
fn test_object_structured_rsa() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("trace"));
    let object = Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentRSAPrivateKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentRSAPrivateKey {
                    modulus: Box::new(BigInt::from(1)),
                    private_exponent: Some(Box::new(SafeBigInt::from(BigInt::from(1)))),
                    public_exponent: Some(Box::new(BigInt::from(u128::MAX))),
                    p: Some(Box::new(SafeBigInt::from(BigInt::from(2)))),
                    q: Some(Box::new(SafeBigInt::from(BigInt::from(3)))),
                    prime_exponent_p: Some(Box::new(SafeBigInt::from(BigInt::from(4)))),
                    prime_exponent_q: Some(Box::new(SafeBigInt::from(BigInt::from(5)))),
                    crt_coefficient: Some(Box::new(SafeBigInt::from(BigInt::from(6)))),
                },
                attribute: None,
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let ttlv = to_ttlv(&object).expect("Failed to convert Object to TTLV");
    info!("TTLV: {:#?}", ttlv);

    // Deserialize the TTLV back to Object
    let deserialized_object: Object = from_ttlv(ttlv).expect("Failed to deserialize TTLV");

    info!("Deserialized Object: {:#?}", deserialized_object);
    assert_eq!(
        object, deserialized_object,
        "Deserialized Object does not match the original"
    );

    // JSON Serde
    let json = serde_json::to_string_pretty(&object).expect("Failed to serialize to JSON");
    info!("JSON: {}", json);
    let deserialized_object_json: Object =
        serde_json::from_str(&json).expect("Failed to deserialize from JSON");
    assert_eq!(
        object, deserialized_object_json,
        "Deserialized Object from JSON does not match the original"
    );
}
