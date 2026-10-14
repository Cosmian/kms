//! Characterization tests for the `HSM_SLOT_ID*` environment parsing of the test server.
//!
//! The production code reads the real process environment, and mutating it in-process would
//! need `unsafe` (denied workspace-wide). Each scenario therefore re-executes this test binary
//! as a child process with the desired environment; the child probe runs the code under test
//! and prints either `RESULT:<value>` or `ERROR:<message>` on stdout.

use std::process::{Command, Output};

use super::{env_slot_id, get_hsm_slot_id, start_default_test_kms_server_with_three_softhsm2};

const MODE_VAR: &str = "KMS_CHARACTERIZATION_CHILD_MODE";
const HSM_VARS: [&str; 4] = [
    "HSM_SLOT_ID",
    "HSM_SLOT_ID_1",
    "HSM_SLOT_ID_2",
    "HSM_SLOT_ID_3",
];
const PROBE: &str = "test_server::characterization_tests::characterization_env_child_probe";

fn render(result: Result<usize, impl std::fmt::Display>) -> String {
    match result {
        Ok(value) => format!("RESULT:{value}"),
        Err(e) => format!("ERROR:{e}"),
    }
}

/// Runs inside the child process only; a no-op in a normal test run.
#[test]
fn characterization_env_child_probe() {
    let Ok(mode) = std::env::var(MODE_VAR) else {
        return;
    };
    let line = if mode == "slot_id" {
        render(get_hsm_slot_id())
    } else if let Some(name) = mode.strip_prefix("env_slot_id:") {
        render(env_slot_id(name))
    } else if mode == "three_softhsm2" {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(start_default_test_kms_server_with_three_softhsm2());
        "RESULT:UNEXPECTEDLY_STARTED".to_owned()
    } else {
        format!("RESULT:UNKNOWN_MODE:{mode}")
    };
    println!("{line}");
}

/// Re-execute this test binary running only the probe, with exactly `envs` set among the
/// `HSM_SLOT_ID*` variables.
fn run_child_output(mode: &str, envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([PROBE, "--exact", "--nocapture", "--test-threads=1"])
        .env(MODE_VAR, mode);
    for var in HSM_VARS {
        command.env_remove(var);
    }
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().unwrap()
}

/// The single `RESULT:`/`ERROR:` line the child printed.
fn run_child(mode: &str, envs: &[(&str, &str)]) -> String {
    let output = run_child_output(mode, envs);
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    stdout
        .lines()
        .find_map(|line| {
            line.find("RESULT:")
                .or_else(|| line.find("ERROR:"))
                .and_then(|idx| line.get(idx..))
        })
        .map(str::to_owned)
        .unwrap_or_else(|| {
            let stderr = String::from_utf8_lossy(&output.stderr);
            format!(
                "NO_OUTPUT status={:?} stdout={stdout} stderr={stderr}",
                output.status
            )
        })
}

#[test]
fn characterization_get_hsm_slot_id_valid_value() {
    assert_eq!(run_child("slot_id", &[("HSM_SLOT_ID", "7")]), "RESULT:7");
    assert_eq!(run_child("slot_id", &[("HSM_SLOT_ID", "0")]), "RESULT:0");
    assert_eq!(
        run_child("slot_id", &[("HSM_SLOT_ID", "18446744073709551615")]),
        "RESULT:18446744073709551615"
    );
}

#[test]
fn characterization_get_hsm_slot_id_missing_is_an_error() {
    assert_eq!(
        run_child("slot_id", &[]),
        "ERROR:Unexpected Error: HSM_SLOT_ID must be set to run HSM tests: environment variable not found"
    );
}

#[test]
fn characterization_get_hsm_slot_id_not_numeric_is_an_error() {
    for (raw, reason) in [
        ("abc", "invalid digit found in string"),
        ("", "cannot parse integer from empty string"),
        ("-1", "invalid digit found in string"),
        ("18446744073709551616", "number too large to fit in target type"),
        (" 7", "invalid digit found in string"),
    ] {
        assert_eq!(
            run_child("slot_id", &[("HSM_SLOT_ID", raw)]),
            format!("ERROR:Unexpected Error: HSM_SLOT_ID '{raw}' is not a valid usize: {reason}")
        );
    }
}

#[test]
fn characterization_env_slot_id_messages_for_the_three_softhsm2_variables() {
    for var in ["HSM_SLOT_ID_1", "HSM_SLOT_ID_2", "HSM_SLOT_ID_3"] {
        let mode = format!("env_slot_id:{var}");
        assert_eq!(run_child(&mode, &[(var, "5")]), "RESULT:5");
        assert_eq!(
            run_child(&mode, &[]),
            format!(
                "ERROR:Unexpected Error: {var} must be set to run HSM tests: environment variable not found"
            )
        );
        assert_eq!(
            run_child(&mode, &[(var, "x")]),
            format!(
                "ERROR:Unexpected Error: {var} 'x' is not a valid usize: invalid digit found in string"
            )
        );
        assert_eq!(
            run_child(&mode, &[(var, "")]),
            format!(
                "ERROR:Unexpected Error: {var} '' is not a valid usize: cannot parse integer from empty string"
            )
        );
    }
}

/// The three-SoftHSM2 starter reports a missing or invalid slot id by logging and aborting the
/// whole test process; it must never start a server in that case.
#[test]
fn characterization_three_softhsm2_missing_or_invalid_slot_ids_abort_the_process() {
    let invalid_third: &[(&str, &str)] = &[
        ("HSM_SLOT_ID_1", "1"),
        ("HSM_SLOT_ID_2", "2"),
        ("HSM_SLOT_ID_3", "-3"),
    ];
    let cases: [&[(&str, &str)]; 5] = [
        &[],
        &[("HSM_SLOT_ID_1", "1")],
        &[("HSM_SLOT_ID_1", "1"), ("HSM_SLOT_ID_2", "2")],
        &[("HSM_SLOT_ID_1", "x")],
        invalid_third,
    ];
    for envs in cases {
        let output = run_child_output("three_softhsm2", envs);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !output.status.success()
                && !stdout.contains("RESULT:")
                && !stdout.contains("ERROR:"),
            "expected an abort for {envs:?}, got status {:?} stdout {stdout}",
            output.status
        );
    }
}
