use crate::{
    kmip_0::kmip_messages::{RequestMessage, RequestMessageBatchItemVersioned},
    kmip_1_4::kmip_operations::{Get, Operation},
    ttlv::{from_ttlv, xml::TTLVXMLDeserializer},
};

#[test]
fn kmip_1_4_get_with_empty_payload() {
    // Minimal KMIP 1.4 Get request with empty RequestPayload; UniqueIdentifier is optional in 1.4
    let xml = r#"<RequestMessage type="Structure">
    <RequestHeader type="Structure">
        <ProtocolVersion type="Structure">
            <ProtocolVersionMajor type="Integer" value="1"/>
            <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
    </RequestHeader>
    <BatchItem type="Structure">
        <Operation type="Enumeration" value="10" name="Get"/>
        <RequestPayload type="Structure">
        </RequestPayload>
    </BatchItem>
</RequestMessage>"#;

    let ttlv = TTLVXMLDeserializer::from_xml(xml).expect("xml -> ttlv");
    let req: RequestMessage = from_ttlv(ttlv).expect("ttlv -> RequestMessage");
    let RequestMessageBatchItemVersioned::V14(item) = &req.batch_item[0] else {
        panic!("expected V14")
    };
    match &item.request_payload {
        Operation::Get(Get {
            unique_identifier,
            key_format_type,
            key_compression_type,
            key_wrapping_specification,
        }) => {
            assert!(unique_identifier.is_none());
            assert!(key_format_type.is_none());
            assert!(key_compression_type.is_none());
            assert!(key_wrapping_specification.is_none());
        }
        other => panic!("unexpected operation: {other}"),
    }
}
