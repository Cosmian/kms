#[cfg(not(windows))]
use std::path::PathBuf;

#[cfg(not(windows))]
use super::{register, status, unregister, verify};

#[cfg(not(windows))]
#[test]
fn characterization_cng_register_not_windows() {
    let err = register(&PathBuf::from("x.dll")).unwrap_err();
    assert_eq!(
        err.to_string(),
        "CNG KSP registration is only supported on Windows"
    );
}

#[cfg(not(windows))]
#[test]
fn characterization_cng_unregister_not_windows() {
    let err = unregister().unwrap_err();
    assert_eq!(
        err.to_string(),
        "CNG KSP unregistration is only supported on Windows"
    );
}

#[cfg(not(windows))]
#[test]
fn characterization_cng_status_not_windows() {
    status();
}

#[cfg(not(windows))]
#[test]
fn characterization_cng_verify_not_windows() {
    let err = verify(&PathBuf::from("x.dll")).unwrap_err();
    assert_eq!(
        err.to_string(),
        "CNG KSP verification is only supported on Windows"
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn characterization_cng_process_status_not_windows() {
    use test_kms_server::start_default_test_kms_server;

    use super::CngCommands;
    let ctx = start_default_test_kms_server().await;
    CngCommands::Status
        .process(ctx.get_owner_client())
        .await
        .unwrap();
    let err = CngCommands::Unregister
        .process(ctx.get_owner_client())
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "CNG KSP unregistration is only supported on Windows"
    );
}
