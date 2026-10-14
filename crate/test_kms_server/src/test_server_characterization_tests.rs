//! Characterization tests for the `HSM_SLOT_ID*` environment parsing of the test server.
//!
//! The production code reads the real process environment, and mutating it in-process would
//! need `unsafe` (denied workspace-wide). Each scenario therefore re-executes this test binary
//! as a child process with the desired environment; the child probe runs the code under test
//! and prints either `RESULT:<value>` or `PANIC:<payload>` on stdout.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    process::Command,
};

use super::{get_hsm_slot_id, start_default_test_kms_server_with_three_softhsm2};

const MODE_VAR: &str = "KMS_CHARACTERIZATION_CHILD_MODE";
const HSM_VARS: [&str; 4] = [
    "HSM_SLOT_ID",
    "HSM_SLOT_ID_1",
    "HSM_SLOT_ID_2",
    "HSM_SLOT_ID_3",
];
const PROBE: &str = "test_server::characterization_tests::characterization_env_child_probe";

fn payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_else(|| "<non-string panic payload>".to_owned())
}

/// Runs inside the child process only; a no-op in a normal test run.
#[test]
fn characterization_env_child_probe() {
    let Ok(mode) = std::env::var(MODE_VAR) else {
        return;
    };
    let outcome = match mode.as_str() {
        "slot_id" => catch_unwind(|| get_hsm_slot_id().to_string()),
        "three_softhsm2" => catch_unwind(AssertUnwindSafe(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            runtime.block_on(start_default_test_kms_server_with_three_softhsm2());
            "UNEXPECTEDLY_STARTED".to_owned()
        })),
        other => Ok(format!("UNKNOWN_MODE:{other}")),
    };
    match outcome {
        Ok(value) => println!("RESULT:{value}"),
        Err(payload) => println!("PANIC:{}", payload_message(payload.as_ref())),
    }
}

/// Re-execute this test binary running only the probe, with exactly `envs` set among the
/// `HSM_SLOT_ID*` variables, and return the single `RESULT:`/`PANIC:` line it printed.
fn run_child(mode: &str, envs: &[(&str, &str)]) -> String {
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
    let output = command.output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    stdout
        .lines()
        .find_map(|line| {
            line.find("RESULT:")
                .or_else(|| line.find("PANIC:"))
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
fn characterization_get_hsm_slot_id_missing_panics() {
    assert_eq!(
        run_child("slot_id", &[]),
        "PANIC:HSM_SLOT_ID environment variable must be set to run HSM+KEK tests: NotPresent"
    );
}

#[test]
fn characterization_get_hsm_slot_id_not_numeric_panics() {
    assert_eq!(
        run_child("slot_id", &[("HSM_SLOT_ID", "abc")]),
        "PANIC:HSM_SLOT_ID 'abc' is not a valid usize"
    );
    assert_eq!(
        run_child("slot_id", &[("HSM_SLOT_ID", "")]),
        "PANIC:HSM_SLOT_ID '' is not a valid usize"
    );
    assert_eq!(
        run_child("slot_id", &[("HSM_SLOT_ID", "-1")]),
        "PANIC:HSM_SLOT_ID '-1' is not a valid usize"
    );
    assert_eq!(
        run_child("slot_id", &[("HSM_SLOT_ID", "18446744073709551616")]),
        "PANIC:HSM_SLOT_ID '18446744073709551616' is not a valid usize"
    );
    assert_eq!(
        run_child("slot_id", &[("HSM_SLOT_ID", " 7")]),
        "PANIC:HSM_SLOT_ID ' 7' is not a valid usize"
    );
}

#[test]
fn characterization_three_softhsm2_missing_slot_ids_panic() {
    assert_eq!(
        run_child("three_softhsm2", &[]),
        "PANIC:HSM_SLOT_ID_1 must be set: NotPresent"
    );
    assert_eq!(
        run_child("three_softhsm2", &[("HSM_SLOT_ID_1", "1")]),
        "PANIC:HSM_SLOT_ID_2 must be set: NotPresent"
    );
    assert_eq!(
        run_child(
            "three_softhsm2",
            &[("HSM_SLOT_ID_1", "1"), ("HSM_SLOT_ID_2", "2")]
        ),
        "PANIC:HSM_SLOT_ID_3 must be set: NotPresent"
    );
}

#[test]
fn characterization_three_softhsm2_invalid_slot_ids_panic() {
    assert_eq!(
        run_child("three_softhsm2", &[("HSM_SLOT_ID_1", "x")]),
        "PANIC:HSM_SLOT_ID_1 must be a valid usize: ParseIntError { kind: InvalidDigit }"
    );
    assert_eq!(
        run_child(
            "three_softhsm2",
            &[("HSM_SLOT_ID_1", "1"), ("HSM_SLOT_ID_2", "")]
        ),
        "PANIC:HSM_SLOT_ID_2 must be a valid usize: ParseIntError { kind: Empty }"
    );
    assert_eq!(
        run_child(
            "three_softhsm2",
            &[
                ("HSM_SLOT_ID_1", "1"),
                ("HSM_SLOT_ID_2", "2"),
                ("HSM_SLOT_ID_3", "-3")
            ]
        ),
        "PANIC:HSM_SLOT_ID_3 must be a valid usize: ParseIntError { kind: InvalidDigit }"
    );
}
