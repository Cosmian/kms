//! Characterization tests for the `cosmian_pkcs11` backend serial number.

use cosmian_pkcs11_module::traits::Backend;

use super::CliBackend;

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

    // The serial number is the package version, truncated to 16 bytes and padded with spaces.
    let version = env!("CARGO_PKG_VERSION").as_bytes();
    let len = version.len().min(16);
    assert_eq!(&sn[..len], &version[..len]);
    assert!(sn[len..].iter().all(|&byte| byte == b' '), "{sn:?}");
}
