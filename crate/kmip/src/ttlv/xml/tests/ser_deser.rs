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

    /// KMIP XML `BigInteger` values are padded big-endian two's complement hex, even when every digit
    /// is decimal (`0000000000010001`) or the top bit of the magnitude is set.
    #[test]
    fn xml_big_integer_is_padded_hex() {
        use crate::ttlv::{TTLValue, kmip_big_int::KmipBigInt};

        for (literal, expected) in [
            ("0000000000010001", vec![0x01, 0x00, 0x01]),
            ("0000000000000000930451c9", vec![0x93, 0x04, 0x51, 0xc9]),
            ("0x10001", vec![0x01, 0x00, 0x01]),
        ] {
            let xml = format!(r#"<Modulus type="BigInteger" value="{literal}"/>"#);
            let ttlv = TTLVXMLDeserializer::from_xml(&xml).expect("xml->ttlv");
            let TTLValue::BigInteger(value) = ttlv.value else {
                panic!("{literal}: not a BigInteger");
            };
            let mut padded = vec![0_u8];
            padded.extend_from_slice(&expected);
            assert_eq!(
                value,
                KmipBigInt::from_signed_bytes_be(&padded),
                "{literal}"
            );
        }
    }

    /// KMIP 1.4 Table 325 `ContentCommitment` usage mask bit (0x400) and the Key Wrap Type
    /// enumeration names (`NotWrapped`, `AsRegistered`) parse from their XML spellings.
    #[test]
    fn xml_content_commitment_and_key_wrap_type() {
        use crate::ttlv::TTLValue;

        let mask = r#"<CryptographicUsageMask type="Integer" value="Sign ContentCommitment"/>"#;
        let ttlv = TTLVXMLDeserializer::from_xml(mask).expect("xml->ttlv");
        assert_eq!(ttlv.value, TTLValue::Integer(0x401));
        for (name, code) in [("NotWrapped", 1), ("AsRegistered", 2)] {
            let xml = format!(r#"<KeyWrapType type="Enumeration" value="{name}"/>"#);
            let ttlv = TTLVXMLDeserializer::from_xml(&xml).expect("xml->ttlv");
            let TTLValue::Enumeration(e) = ttlv.value else {
                panic!("{name}: not an Enumeration");
            };
            assert_eq!(e.value, code, "{name}");
        }
    }

    /// `BigInteger` literals: the KMIP XML profile writes hex padded to a multiple of 8 bytes, so
    /// an unprefixed all-digit value of 16k characters is hex (a 16-digit decimal is read as
    /// hex too: write such a decimal unpadded or with another length); other all-digit values
    /// are decimal; hex letters or `0x` force hex.
    #[test]
    fn xml_big_integer_literal_forms() {
        use crate::ttlv::TTLValue;

        let bytes = |literal: &str| {
            let xml = format!(r#"<PublicExponent type="BigInteger" value="{literal}"/>"#);
            let ttlv = TTLVXMLDeserializer::from_xml(&xml).expect("xml->ttlv");
            let TTLValue::BigInteger(v) = ttlv.value else {
                panic!("{literal}: not a BigInteger");
            };
            v.to_signed_bytes_be()
        };
        // padded hex (profile form), also when only digits
        assert_eq!(bytes("0000000000010001"), vec![0, 0, 0, 0, 0, 1, 0, 1]);
        assert_eq!(
            bytes("1234567890123456"),
            vec![0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56]
        );
        // a value with the top bit set stays positive thanks to the zero padding
        assert_eq!(bytes("0000000000000080"), vec![0, 0, 0, 0, 0, 0, 0, 0x80]);
        // other digit-only values are decimal (65537 = 0x010001)
        assert_eq!(bytes("65537"), vec![0, 0, 0, 0, 0, 1, 0, 1]);
        // letters or 0x force hex
        assert_eq!(bytes("0x010001"), vec![0, 0, 0, 0, 0, 1, 0, 1]);
        // unpadded hex is two's complement as given: 0x80FF is negative
        assert_eq!(
            bytes("80FF"),
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0xFF]
        );
    }
}
