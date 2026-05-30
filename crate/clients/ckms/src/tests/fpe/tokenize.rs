use std::process::Command;

use assert_cmd::prelude::*;
use test_kms_server::start_default_test_kms_server;

use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{PROG_NAME, save_kms_cli_config, utils::recover_cmd_logs},
};

const TOKENIZE_CMD: &str = "tokenize";

fn run_tokenize(
    cli_conf_path: &str,
    subcommand: &str,
    extra_args: &[&str],
) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.arg(TOKENIZE_CMD).arg(subcommand);
    cmd.args(extra_args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(std::str::from_utf8(&output.stdout)?.to_owned());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_tokenize_hash_sha2() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (conf, _) = save_kms_cli_config(ctx);
    let out = run_tokenize(
        &conf,
        "hash",
        &["--data", "hello world", "--method", "sha2"],
    )?;
    assert!(!out.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_tokenize_hash_sha3() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (conf, _) = save_kms_cli_config(ctx);
    let out = run_tokenize(
        &conf,
        "hash",
        &["--data", "hello world", "--method", "sha3"],
    )?;
    assert!(!out.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_tokenize_noise_gaussian_float() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (conf, _) = save_kms_cli_config(ctx);
    run_tokenize(
        &conf,
        "noise",
        &[
            "--data",
            "42.5",
            "--data-type",
            "float",
            "--method",
            "Gaussian",
            "--mean",
            "0",
            "--std-dev",
            "1",
        ],
    )?;
    Ok(())
}

#[tokio::test]
async fn test_tokenize_noise_uniform_integer() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (conf, _) = save_kms_cli_config(ctx);
    run_tokenize(
        &conf,
        "noise",
        &[
            "--data",
            "100",
            "--data-type",
            "integer",
            "--method",
            "Uniform",
            "--min-bound=-10", // use = to prevent clap from treating negative numbers as flags
            "--max-bound=10",
        ],
    )?;
    Ok(())
}

#[tokio::test]
async fn test_tokenize_word_mask() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (conf, _) = save_kms_cli_config(ctx);
    let out = run_tokenize(
        &conf,
        "word-mask",
        &[
            "--data",
            "My name is Alice and I know Bob",
            "--word",
            "Alice",
            "--word",
            "Bob",
        ],
    )?;
    assert!(!out.contains("Alice"), "Alice should be masked");
    assert!(!out.contains("Bob"), "Bob should be masked");
    Ok(())
}

#[tokio::test]
async fn test_tokenize_word_tokenize() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (conf, _) = save_kms_cli_config(ctx);
    let out = run_tokenize(
        &conf,
        "word-tokenize",
        &[
            "--data",
            "Contact Alice at alice@example.com",
            "--word",
            "Alice",
            "--word",
            "alice@example.com",
        ],
    )?;
    assert!(!out.contains("Alice"), "Alice should be tokenized");
    Ok(())
}

#[tokio::test]
async fn test_tokenize_word_pattern_mask() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (conf, _) = save_kms_cli_config(ctx);
    let out = run_tokenize(
        &conf,
        "word-pattern-mask",
        &[
            "--data",
            "Call me at 555-1234",
            "--pattern",
            r"\d{3}-\d{4}",
            "--replace",
            "XXX-XXXX",
        ],
    )?;
    assert!(out.contains("XXX-XXXX"), "phone number should be masked");
    Ok(())
}

#[tokio::test]
async fn test_tokenize_aggregate_number_integer() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (conf, _) = save_kms_cli_config(ctx);
    run_tokenize(
        &conf,
        "aggregate-number",
        &[
            "--data",
            "1234",
            "--data-type",
            "integer",
            "--power-of-ten",
            "2",
        ],
    )?;
    Ok(())
}

#[tokio::test]
async fn test_tokenize_aggregate_date() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (conf, _) = save_kms_cli_config(ctx);
    run_tokenize(
        &conf,
        "aggregate-date",
        &["--data", "2024-07-15T13:45:30Z", "--time-unit", "Day"],
    )?;
    Ok(())
}

#[tokio::test]
async fn test_tokenize_scale_number_float() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (conf, _) = save_kms_cli_config(ctx);
    run_tokenize(
        &conf,
        "scale-number",
        &[
            "--data",
            "75.0",
            "--data-type",
            "float",
            "--mean",
            "50",
            "--std-deviation",
            "10",
            "--scale",
            "1",
            "--translate",
            "0",
        ],
    )?;
    Ok(())
}
