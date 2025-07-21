use std::{env, path::PathBuf};

use cosmian_logger::log_init;
use tracing::{info, warn};

use crate::tests::ttlv_tests::start_test_server;

#[ignore]
#[test]
fn test_pykmip() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("info,kmip=debug"));

    // start the server
    let _server_handles = start_test_server(15696);

    let crate_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("Failed to get CARGO_MANIFEST_DIR"));
    let project_root = crate_dir.parent().unwrap().parent().unwrap();

    // setup pykmip
    info!("Setting up PyKMIP...");
    let setup_script_file = project_root.join("scripts/setup_pykmip.sh");
    let mut command = {
        #[cfg(target_os = "macos")]
        let output = std::process::Command::new("zsh");
        #[cfg(target_os = "linux")]
        let output = std::process::Command::new("bash");
        output
    };
    let output = command
        .arg("-c")
        .arg(setup_script_file)
        .current_dir(project_root)
        .output()
        .expect("Failed to execute PyKMIP setup script");
    assert!(
        output.status.success(),
        "PyKMIP setup  failed: {}\n\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Activate venv
    info!("Activating PyKMIP virtual environment...");
    let activate_script_file = project_root.join("scripts/activate_venv.sh ");
    let mut command = {
        #[cfg(target_os = "macos")]
        let output = std::process::Command::new("zsh");
        #[cfg(target_os = "linux")]
        let output = std::process::Command::new("bash");
        output
    };
    let output = command
        .arg("-c")
        .arg(activate_script_file)
        .current_dir(project_root)
        .output()
        .expect("Failed to execute PyKMIP activate script");
    assert!(
        output.status.success(),
        "PyKMIP activate venv failed: {}\n\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Run the tests
    info!("Running PyKMIP tests...");
    let test_script_file = project_root.join("scripts/test_pykmip.sh");

    let mut command = {
        #[cfg(target_os = "macos")]
        let output = std::process::Command::new("zsh");
        #[cfg(target_os = "linux")]
        let output = std::process::Command::new("bash");
        output
    };
    let output = command
        .arg("-c")
        .arg(format!("{} all", test_script_file.display()))
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
