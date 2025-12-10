use cosmian_logger::log_init;

use crate::{
    error::result::KmipResult,
    kmip_0::kmip_messages::RequestMessage,
    ttlv::{kmip_ttlv_deserializer::from_ttlv, ttlv_struct::TTLV},
};

#[test]
fn test_mysql_kmip_11_create_request() -> KmipResult<()> {
    log_init(option_env!("RUST_LOG"));
    // Same JSON as above; AttributeIndex appears before AttributeValue inside Attribute structures
    let json = r#"
    {
        "tag": "RequestMessage",
        "type": "Structure",
        "value": [
            {
                "tag": "RequestHeader",
                "type": "Structure",
                "value": [
                    {
                        "tag": "ProtocolVersion",
                        "type": "Structure",
                        "value": [
                            { "tag": "ProtocolVersionMajor", "type": "Integer", "value": 1 },
                            { "tag": "ProtocolVersionMinor", "type": "Integer", "value": 1 }
                        ]
                    },
                    { "tag": "MaximumResponseSize", "type": "Integer", "value": 280000 },
                    { "tag": "BatchCount", "type": "Integer", "value": 1 }
                ]
            },
            {
                "tag": "BatchItem",
                "type": "Structure",
                "value": [
                    { "tag": "Operation", "type": "Enumeration", "value": "0x00000001" },
                    {
                        "tag": "RequestPayload",
                        "type": "Structure",
                        "value": [
                            { "tag": "ObjectType", "type": "Enumeration", "value": "0x00000002" },
                            {
                                "tag": "TemplateAttribute",
                                "type": "Structure",
                                "value": [
                                    {
                                        "tag": "Attribute",
                                        "type": "Structure",
                                        "value": [
                                            { "tag": "AttributeName", "type": "TextString", "value": "Cryptographic Algorithm" },
                                            { "tag": "AttributeIndex", "type": "Integer", "value": 0 },
                                            { "tag": "AttributeValue", "type": "Enumeration", "value": "0x00000003" }
                                        ]
                                    },
                                    {
                                        "tag": "Attribute",
                                        "type": "Structure",
                                        "value": [
                                            { "tag": "AttributeName", "type": "TextString", "value": "Cryptographic Length" },
                                            { "tag": "AttributeIndex", "type": "Integer", "value": 0 },
                                            { "tag": "AttributeValue", "type": "Integer", "value": 256 }
                                        ]
                                    },
                                    {
                                        "tag": "Attribute",
                                        "type": "Structure",
                                        "value": [
                                            { "tag": "AttributeName", "type": "TextString", "value": "Cryptographic Usage Mask" },
                                            { "tag": "AttributeIndex", "type": "Integer", "value": 0 },
                                            { "tag": "AttributeValue", "type": "Integer", "value": 12 }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }
    "#;

    let ttlv: TTLV = serde_json::from_str(json)?;
    from_ttlv::<RequestMessage>(ttlv)?;
    Ok(())
}
