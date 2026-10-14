//! Characterization tests pinning BASE behavior of `encode_der_length`.

use super::encode_der_length;

fn encoded(len: usize) -> Vec<u8> {
    let mut buf = vec![0xAA_u8];
    encode_der_length(&mut buf, len).unwrap();
    buf
}

#[test]
fn characterization_encode_der_length_short_form() {
    assert_eq!(encoded(0), vec![0xAA, 0x00]);
    assert_eq!(encoded(1), vec![0xAA, 0x01]);
    assert_eq!(encoded(127), vec![0xAA, 0x7F]);
}

#[test]
fn characterization_encode_der_length_one_byte_long_form() {
    assert_eq!(encoded(128), vec![0xAA, 0x81, 0x80]);
    assert_eq!(encoded(200), vec![0xAA, 0x81, 0xC8]);
    assert_eq!(encoded(255), vec![0xAA, 0x81, 0xFF]);
}

#[test]
fn characterization_encode_der_length_two_byte_long_form() {
    assert_eq!(encoded(256), vec![0xAA, 0x82, 0x01, 0x00]);
    assert_eq!(encoded(0x1234), vec![0xAA, 0x82, 0x12, 0x34]);
    assert_eq!(encoded(65535), vec![0xAA, 0x82, 0xFF, 0xFF]);
}

#[test]
fn characterization_encode_der_length_too_large() {
    let mut buf = vec![0xAA_u8];
    let err = encode_der_length(&mut buf, 65536).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Invalid Request: CRL Distribution Point URI produces a DER length of 65536 bytes, which exceeds the maximum supported value of 65535. Shorten kms_public_url or the issuer identifier."
    );
    assert_eq!(buf, vec![0xAA]);
}
