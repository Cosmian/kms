use std::{env, path::PathBuf};

use cosmian_logger::log_init;
use tracing::warn;

use crate::tests::ttlv_tests::start_test_server;

#[test]
fn test_pykmip() {
    log_init(Some("warn"));
    // log_init(option_env!("RUST_LOG"));
    let _server_handles = start_test_server(5696);

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

    warn!("{}", String::from_utf8_lossy(&output.stdout));

    assert!(
        output.status.success(),
        "PyKMIP tests failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
