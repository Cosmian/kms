//! Tests for XML serializer/deserializer and (eventually) parser.
#[cfg(test)]
mod inner {
    use cosmian_logger::trace;

    use crate::{
        kmip_0::{
            self,
            kmip_messages::{
                RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            },
            kmip_types::ProtocolVersion,
        },
        kmip_1_4::{
            kmip_messages::RequestMessageBatchItem,
            kmip_operations::{Operation, Query},
            kmip_types::{OperationEnumeration, QueryFunction},
        },
        ttlv::{
            from_ttlv, to_ttlv,
            xml::{TTLVXMLDeserializer, TTLVXMLSerializer},
        },
    };

    #[test]
    fn ttlv_xml_round_trip() {
        let request_message = RequestMessage {
            request_header: RequestMessageHeader {
                protocol_version: ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 4,
                },
                maximum_response_size: Some(256),
                batch_count: 1,
                ..Default::default()
            },
            batch_item: vec![RequestMessageBatchItemVersioned::V14(
                RequestMessageBatchItem {
                    operation: OperationEnumeration::Query,
                    ephemeral: None,
                    unique_batch_item_id: None,
                    request_payload: Operation::Query(Query {
                        query_function: Some(vec![
                            QueryFunction::QueryOperations,
                            QueryFunction::QueryObjects,
                        ]),
                    }),
                    message_extension: None,
                },
            )],
        };
        let ttlv = to_ttlv(&request_message).expect("to_ttlv");
        let xml = TTLVXMLSerializer::to_xml(&ttlv).expect("ttlv->xml");
        let ttlv2 = TTLVXMLDeserializer::from_xml(&xml).expect("xml->ttlv");
        assert_eq!(
            ttlv2, ttlv,
            "Round trip TTLV mismatch. XML produced:\n{xml}"
        );
        let request_message_rt: RequestMessage = from_ttlv(ttlv2).expect("from_ttlv");
        assert!(
            request_message_rt == request_message,
            "Round trip RequestMessage mismatch"
        );
    }

    #[test]
    fn response_message() {
        let xml_str = r#"<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="2"/>
      <ProtocolVersionMinor type="Integer" value="1"/>
    </ProtocolVersion>
    <TimeStamp type="DateTime" value="1970-01-01T00:00:00Z"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="GetAttributes"/>
    <ResultStatus type="Enumeration" value="Success"/>
    <ResponsePayload>
      <UniqueIdentifier type="TextString" value="5171c5de-0782-4351-9850-f2c428e58a9b"/>
      <Attributes>
        <UniqueIdentifier type="TextString" value="5171c5de-0782-4351-9850-f2c428e58a9b"/>
        <ShortUniqueIdentifier type="ByteString" value="uid-0"/>
        <ObjectType type="Enumeration" value="PrivateKey"/>
        <CryptographicAlgorithm type="Enumeration" value="RSA"/>
        <CryptographicLength type="Integer" value="2048"/>
        <AlwaysSensitive type="Boolean" value="false"/>
        <CryptographicUsageMask type="Integer" value="Sign"/>
        <DestroyDate type="DateTime" value="1970-01-01T00:00:00Z"/>
        <Digest>
          <HashingAlgorithm type="Enumeration" value="SHA_256"/>
          <DigestValue type="ByteString" value="4e9dd3c937db82d2ec12cdc50e14066c2fb93855cc772a9e1fc13dbf40f4eaf7"/>
          <KeyFormatType type="Enumeration" value="PKCS_1"/>
        </Digest>
    <KeyFormatType type="Enumeration" value="PKCS_1"/>
        <Extractable type="Boolean" value="true"/>
        <Fresh type="Boolean" value="true"/>
        <InitialDate type="DateTime" value="1970-01-01T00:00:00Z"/>
        <LastChangeDate type="DateTime" value="1970-01-01T00:00:00Z"/>
        <LeaseTime type="Interval" value="3600"/>
        <Link>
          <LinkType type="Enumeration" value="PublicKeyLink"/>
          <LinkedObjectIdentifier type="TextString" value="0171c5de-0782-4351-9850-f2c428e58a9b"/>
        </Link>
        <Name>
          <NameValue type="TextString" value="AKLC-O-1-21-private"/>
          <NameType type="Enumeration" value="UninterpretedTextString"/>
        </Name>
        <NeverExtractable type="Boolean" value="false"/>
        <OriginalCreationDate type="DateTime" value="1970-01-01T00:00:00Z"/>
    <ProtectionStorageMask type="Integer" value="Software"/>
        <RandomNumberGenerator>
          <RNGAlgorithm type="Enumeration" value="ANSIX9_31"/>
          <CryptographicAlgorithm type="Enumeration" value="AES"/>
          <CryptographicLength type="Integer" value="256"/>
        </RandomNumberGenerator>
        <Sensitive type="Boolean" value="false"/>
        <State type="Enumeration" value="Destroyed"/>
      </Attributes>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>
"#;
        let ttlv = TTLVXMLDeserializer::from_xml(xml_str).expect("xml->ttlv");
        let response_message: kmip_0::kmip_messages::ResponseMessage =
            from_ttlv(ttlv).expect("from_ttlv");
        trace!("Deserialized ResponseMessage: {}", response_message);
    }
}
