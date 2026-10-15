//! Characterization tests of the `ckms` binary entry point and command dispatch.
use std::process::{Command, Output};

#[cfg(test)]
fn write_conf(dir: &std::path::Path) -> std::path::PathBuf {
    let conf = dir.join("ckms.toml");
    std::fs::write(
        &conf,
        "[http_config]\nserver_url = \"http://localhost:9\"\n",
    )
    .unwrap();
    conf
}

#[cfg(test)]
fn run_ckms(args: &[&str], conf: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ckms"))
        .args(args)
        .env("CKMS_CONF_PATH", conf)
        .env_remove("KMS_DEFAULT_URL")
        .env_remove("KMS_AUDIT_FILE_PATH")
        .env_remove("KMS_AUDIT_POSTGRES_URL")
        .output()
        .unwrap()
}

#[test]
fn characterization_main_unreachable_server_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let conf = write_conf(dir.path());
    let out = run_ckms(
        &["--url", "http://127.0.0.1:1", "sym", "keys", "create"],
        &conf,
    );
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "");
    assert_eq!(
        String::from_utf8(out.stderr).unwrap(),
        "ERROR: failed creating the key: HTTP Client: HTTP request failed: client error (Connect)\n"
    );
}

#[test]
fn characterization_main_audit_short_circuit_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("absent.toml");
    let missing = dir.path().join("missing.jsonl");
    let missing = missing.to_str().unwrap();
    let out = run_ckms(&["audit", "verify", "--path", missing], &conf);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(
        stderr.replace(missing, "<PATH>"),
        "ERROR: No such file or directory (os error 2)\n"
    );
    // the audit command never needs (nor creates) the configuration file
    assert!(!conf.exists());
}

#[test]
fn characterization_main_help_head() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_ckms(&["--help"], &dir.path().join("ckms.toml"));
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let head: Vec<&str> = stdout.lines().take(HELP_LINES).collect();
    assert_eq!(head.join("\n"), HELP_HEAD);
}

const HELP_HEAD: &str = "Command Line Interface used to manage the Cosmian KMS server.

If any assistance is needed, please either visit the Cosmian technical documentation at https://docs.cosmian.com
or contact the Cosmian support team on Discord https://discord.com/invite/7kPMNtHpnz


Usage: ckms [OPTIONS] <COMMAND>";

const HELP_LINES: usize = 7;

#[test]
fn characterization_main_unknown_subcommand_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_ckms(&["no-such-command"], &dir.path().join("ckms.toml"));
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "");
}

#[test]
fn characterization_markdown_writes_documentation() {
    let dir = tempfile::tempdir().unwrap();
    let md = dir.path().join("ckms.md");
    let out = run_ckms(&["markdown", md.to_str().unwrap()], &write_conf(dir.path()));
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("Markdown generated to {}\n", md.display())
    );
    let text = std::fs::read_to_string(&md).unwrap();
    let head: Vec<&str> = text.lines().take(6).collect();
    assert_eq!(
        head.join("\n"),
        "\n##  ckms\n\nCommand Line Interface used to manage the Cosmian KMS server.\n\nIf any assistance is needed, please either visit the Cosmian technical documentation at https://docs.cosmian.com"
    );
}

#[test]
fn characterization_main_missing_config_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("ckms.toml");
    let out = run_ckms(&["sym", "keys", "create"], &conf);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "");
    assert_eq!(
        String::from_utf8(out.stderr)
            .unwrap()
            .replace(conf.to_str().unwrap(), "<CONF>"),
        "ERROR: Not found: Configuration file \"<CONF>\" does not exist\n"
    );
}

#[test]
fn characterization_main_audit_verify_empty_file_exit_0() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.jsonl");
    std::fs::write(&log, "").unwrap();
    let out = run_ckms(
        &["audit", "verify", "--path", log.to_str().unwrap()],
        &dir.path().join("absent.toml"),
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("{}: chain OK: 0 events verified\n", log.display())
    );
}
