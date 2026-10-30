use super::BulkData;

#[test]
fn characterization_bulk_data_is_bulk_data_boundaries() {
    assert!(!BulkData::is_bulk_data(&[]));
    assert!(!BulkData::is_bulk_data(&[0x87]));
    assert!(!BulkData::is_bulk_data(&[0x87, 0x87]));
    assert!(BulkData::is_bulk_data(&[0x87, 0x87, 0x00]));
    assert!(BulkData::is_bulk_data(&[0x87, 0x87, 0x00, 0xFF]));
    assert!(!BulkData::is_bulk_data(&[0x87, 0x86, 0x00]));
    assert!(!BulkData::is_bulk_data(&[0x86, 0x87, 0x00]));
}

#[test]
fn characterization_bulk_data_serialize_roundtrip_golden() {
    let bd = BulkData::from(vec![vec![1_u8, 2], vec![3_u8]]);
    let ser = bd.serialize().unwrap();
    assert_eq!(hex::encode(ser.as_slice()), "8787020201020103");
    let back = BulkData::deserialize(&hex::decode("8787020201020103").unwrap()).unwrap();
    assert_eq!(back.len(), 2);
    assert_eq!(back.first().unwrap().as_slice(), [1_u8, 2]);
    assert_eq!(back.get(1).unwrap().as_slice(), [3_u8]);
}

#[test]
fn characterization_bulk_data_deserialize_errors() {
    for (input, msg) in [
        (
            "",
            "Invalid KMIP 2.1 Object: Illegal_Object_Type: Not a BulkData",
        ),
        (
            "8787",
            "Invalid KMIP 2.1 Object: Illegal_Object_Type: Not a BulkData",
        ),
        (
            "000102",
            "Invalid KMIP 2.1 Object: Illegal_Object_Type: Not a BulkData",
        ),
        (
            "878705",
            "Invalid KMIP 2.1 Object: Illegal_Object_Type: BulkData count 5 exceeds remaining data length 0; not valid BulkData",
        ),
        (
            "8787010501",
            "Serialization error: when reading 5 bytes, readable buffer too small: 1 bytes",
        ),
    ] {
        let err = BulkData::deserialize(&hex::decode(input).unwrap()).unwrap_err();
        assert_eq!(err.to_string(), msg);
    }
}
