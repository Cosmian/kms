//! Characterization tests for `cosmian_pkcs11` backend serial number formatting
//! and provider helper behavior.

use cosmian_pkcs11_module::traits::Backend;

use super::CliBackend;

fn format_token_serial_number(version_bytes: &[u8]) -> [u8; 16] {
    let len = version_bytes.len().min(16);
    let mut sn = [0x20; 16];
    sn[..len].copy_from_slice(&version_bytes[..len]);
    sn
}

#[test]
fn characterization_token_serial_number_empty_version() {
    assert_eq!(format_token_serial_number(b""), [0x20; 16]);
}

#[test]
fn characterization_token_serial_number_len_5() {
    assert_eq!(
        format_token_serial_number(b"5.28."),
        [
            0x35, 0x2e, 0x32, 0x38, 0x2e, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20,
        ]
    );
}

#[test]
fn characterization_token_serial_number_len_16() {
    assert_eq!(
        format_token_serial_number(b"1234567890abcdef"),
        [
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x61, 0x62, 0x63, 0x64,
            0x65, 0x66,
        ]
    );
}

#[test]
fn characterization_token_serial_number_len_20() {
    assert_eq!(
        format_token_serial_number(b"1234567890abcdefghij"),
        [
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x61, 0x62, 0x63, 0x64,
            0x65, 0x66,
        ]
    );
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
    expected_derived[..len].copy_from_slice(&version_bytes[..len]);
    assert_eq!(sn, expected_derived);

    // 2. Literal pinned expectation for package version "5.28.0" (ASCII bytes + space padding to 16 bytes)
    assert_eq!(
        sn,
        [
            0x35, 0x2e, 0x32, 0x38, 0x2e, 0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20,
        ]
    );
}
