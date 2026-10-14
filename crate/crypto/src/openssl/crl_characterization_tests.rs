use super::aki_write_length;

#[test]
fn characterization_aki_write_length_short_and_long_forms() {
    // len < 128 (short form)
    let mut buf = Vec::new();
    aki_write_length(&mut buf, 0x42).unwrap();
    assert_eq!(buf, vec![0x42]);

    // len in 128..=255 (2 bytes)
    buf.clear();
    aki_write_length(&mut buf, 0x80).unwrap();
    assert_eq!(buf, vec![0x81, 0x80]);

    buf.clear();
    aki_write_length(&mut buf, 0xFF).unwrap();
    assert_eq!(buf, vec![0x81, 0xFF]);

    // len in 256..=65535 (3 bytes)
    buf.clear();
    aki_write_length(&mut buf, 0x0100).unwrap();
    assert_eq!(buf, vec![0x82, 0x01, 0x00]);

    buf.clear();
    aki_write_length(&mut buf, 0x1234).unwrap();
    assert_eq!(buf, vec![0x82, 0x12, 0x34]);

    buf.clear();
    aki_write_length(&mut buf, 0xFFFF).unwrap();
    assert_eq!(buf, vec![0x82, 0xFF, 0xFF]);

    // len > 65535 fails
    buf.clear();
    let err = aki_write_length(&mut buf, 0x10000).unwrap_err();
    assert_eq!(
        err.to_string(),
        "AKI key identifier length 65536 exceeds 65535"
    );
}
