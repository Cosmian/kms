use std::{env, path::PathBuf};

use cosmian_logger::log_init;
use tracing::warn;

use crate::tests::ttlv_tests::start_test_server;

#[cfg(not(target_os = "windows"))]
#[test]
fn test_pykmip() {
    log_init(Some("warn"));
    // log_init(option_env!("RUST_LOG"));
    let _server_handles = start_test_server(5696);

    let crate_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("Failed to get CARGO_MANIFEST_DIR"));
    let project_root = crate_dir.parent().unwrap().parent().unwrap();
    let script_file = project_root.join("scripts/test_pykmip.sh");

    let mut command = {
        #[cfg(target_os = "macos")]
        let output = std::process::Command::new("zsh");
        #[cfg(target_os = "linux")]
        let output = std::process::Command::new("bash");
        output
    };
    let output = command
        .arg("-c")
        .arg(format!("{} all", script_file.display()))
        .arg("all")
        .current_dir(project_root)
        .output()
        .expect("Failed to execute PyKMIP test script");

    warn!("{}", String::from_utf8_lossy(&output.stdout));

    assert!(
        output.status.success(),
        "PyKMIP tests failed: {}\n\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
