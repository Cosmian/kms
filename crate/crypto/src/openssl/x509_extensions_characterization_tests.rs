use super::{der_encode_base128, der_encode_length, der_encode_oid, der_encode_sequence};

#[test]
fn characterization_der_encode_length_all_ranges() {
    assert_eq!(der_encode_length(0), vec![0x00]);
    assert_eq!(der_encode_length(127), vec![0x7F]);
    assert_eq!(der_encode_length(128), vec![0x81, 0x80]);
    assert_eq!(der_encode_length(255), vec![0x81, 0xFF]);
    assert_eq!(der_encode_length(256), vec![0x82, 0x01, 0x00]);
    assert_eq!(der_encode_length(0x1234), vec![0x82, 0x12, 0x34]);
    assert_eq!(der_encode_length(0xFFFF), vec![0x82, 0xFF, 0xFF]);
}

#[test]
fn characterization_der_encode_sequence_and_oid() {
    let content = [0x01, 0x02, 0x03];
    let seq = der_encode_sequence(&content);
    assert_eq!(seq, vec![0x30, 0x03, 0x01, 0x02, 0x03]);

    let oid = der_encode_oid("1.2.840.113549.1.1.1").unwrap();
    let expected = hex::decode("06092a864886f70d010101").unwrap();
    assert_eq!(oid, expected);

    let base128_0 = der_encode_base128(0);
    assert_eq!(base128_0, vec![0x00]);

    let base128_val = der_encode_base128(840);
    assert_eq!(base128_val, vec![0x86, 0x48]);
}
