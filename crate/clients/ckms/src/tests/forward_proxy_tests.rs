//! Forward proxy integration test for the `ckms` CLI.
//!
//! This test is skipped by default (`#[ignore]`) and only runs in CI environments
//! where a Squid proxy is pre-configured on `localhost:8888` with basic auth.
//!
//! Proxy credentials match `.github/scripts/squid/squid.conf`:
//!   user: `myuser`, password: `mypwd`
//!
//! To run locally, set up squid as described in `.github/scripts/squid/squid.conf`
//! and run:
//!
//! ```bash
//! KMS_URL=http://<your-local-ip>:9998 \
//!   cargo test --lib --features non-fips -- --nocapture --ignored test_server_version_using_forward_proxy
//! ```

#![allow(deprecated)]

use std::process::Command;

use assert_cmd::prelude::*;
use test_kms_server::{AuthenticationOptions, MainDBConfig, start_test_server_with_options};

const PROXY_URL: &str = "http://localhost:8888";
const PROXY_USER: &str = "myuser";
const PROXY_PASSWORD: &str = "mypwd";

/// Verify that `ckms server version` succeeds when the connection to the KMS
/// server is routed through an authenticated forward HTTP proxy.
///
/// Steps:
/// 1. Start a plain-HTTP KMS server on port 9998 (no auth, `SQLite` backend).
/// 2. Read `KMS_URL` from the environment to determine the target URL.
///    In CI this is set to `http://<local-ip>:9998` so the proxy actually
///    forwards the request — Squid does not proxy connections to `127.0.0.1`.
/// 3. Run `ckms server version` with the proxy env vars configured.
/// 4. Assert the command exits successfully.
#[ignore = "requires a Squid proxy on localhost:8888 (myuser/mypwd) and KMS_URL set to a non-loopback address"]
#[tokio::test]
pub(crate) async fn test_server_version_using_forward_proxy() {
    let ctx = start_test_server_with_options(
        MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            clear_database: true,
            ..MainDBConfig::default()
        },
        9998,
        AuthenticationOptions::new(),
        None,
        None,
    )
    .await
    .expect("Failed to start test KMS server");

    // In CI, KMS_URL is set to the machine's non-loopback IP so that Squid
    // forwards the connection (Squid skips proxying 127.0.0.1).
    let kms_url = std::env::var("KMS_URL")
        .unwrap_or_else(|_| format!("http://127.0.0.1:{}", ctx.server_port));

    Command::cargo_bin("ckms")
        .expect("ckms binary not found")
        .env("KMS_DEFAULT_URL", &kms_url)
        .env("CLI_PROXY_URL", PROXY_URL)
        .env("CLI_PROXY_BASIC_AUTH_USERNAME", PROXY_USER)
        .env("CLI_PROXY_BASIC_AUTH_PASSWORD", PROXY_PASSWORD)
        .arg("server")
        .arg("version")
        .assert()
        .success();
}
