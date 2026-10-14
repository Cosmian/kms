//! Characterization tests for `cosmian_pkcs11` backend serial number formatting
//! and provider helper behavior.

use cosmian_pkcs11_module::traits::Backend;

use super::CliBackend;

fn format_token_serial_number(version_bytes: &[u8]) -> [u8; 16] {
    let len = version_bytes.len().min(16);
    let mut sn = [0x20; 16];
    let dst_slice = sn.get_mut(..len).unwrap();
    let src_slice = version_bytes.get(..len).unwrap();
    dst_slice.copy_from_slice(src_slice);
    sn
}

#[test]
fn characterization_token_serial_number_empty_version() {
    let sn = format_token_serial_number(b"");
    const EXPECTED: [u8; 16] = [0x20; 16];
    assert_eq!(sn, EXPECTED);
}

#[test]
fn characterization_token_serial_number_len_5() {
    let sn = format_token_serial_number(b"5.28.");
    const EXPECTED: [u8; 16] = [
        0x35, 0x2e, 0x32, 0x38, 0x2e, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20,
    ];
    assert_eq!(sn, EXPECTED);
}

#[test]
fn characterization_token_serial_number_len_16() {
    let sn = format_token_serial_number(b"1234567890abcdef");
    const EXPECTED: [u8; 16] = [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x61, 0x62, 0x63, 0x64, 0x65,
        0x66,
    ];
    assert_eq!(sn, EXPECTED);
}

#[test]
fn characterization_token_serial_number_len_20() {
    let sn = format_token_serial_number(b"1234567890abcdefghij");
    const EXPECTED: [u8; 16] = [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x61, 0x62, 0x63, 0x64, 0x65,
        0x66,
    ];
    assert_eq!(sn, EXPECTED);
}

#[test]
fn characterization_token_serial_number_backend_direct_call() {
    // Construct dummy client without network calls to instantiate CliBackend
    let kms_rest_client =
        ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kms_client::KmsClient::new()
            .unwrap();
    let backend = CliBackend {
        kms_rest_client,
        vendor_id: "cosmian".to_owned(),
    };
    let sn = backend.token_serial_number();

    // 1. Derived from env!("CARGO_PKG_VERSION")
    let version_bytes = env!("CARGO_PKG_VERSION").as_bytes();
    let len = version_bytes.len().min(16);
    let mut expected_derived = [0x20; 16];
    let dst = expected_derived.get_mut(..len).unwrap();
    let src = version_bytes.get(..len).unwrap();
    dst.copy_from_slice(src);
    assert_eq!(sn, expected_derived);

    // 2. Literal pinned expectation for package version "5.28.0" (ASCII bytes + space padding to 16 bytes)
    const EXPECTED_LITERAL_5_28_0: [u8; 16] = [
        0x35, 0x2e, 0x32, 0x38, 0x2e, 0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20,
    ];
    assert_eq!(sn, EXPECTED_LITERAL_5_28_0);
}
