use std::{env, path::PathBuf};

use cosmian_logger::log_init;

use crate::tests::ttlv_tests::start_test_server;

#[test]
fn test_pykmip() {
    log_init(Some("info,cosmian_kms=debug"));
    let _server_handles = start_test_server();

    let crate_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("Failed to get CARGO_MANIFEST_DIR"));
    let project_root = crate_dir.parent().unwrap().parent().unwrap();
    let script_dir = project_root.join("scripts/test_pykmip.sh");

    let output = std::process::Command::new("sh")
        .arg(script_dir)
        .arg("all")
        .current_dir(project_root)
        .output()
        .expect("Failed to execute PyKMIP test script");

    println!("{}", String::from_utf8_lossy(&output.stdout));

    assert!(
        output.status.success(),
        "PyKMIP tests failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
