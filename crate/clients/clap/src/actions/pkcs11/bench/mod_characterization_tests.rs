use std::{env, path::PathBuf};

use ::clap::Parser as _;
use cosmian_config_utils::ConfigUtils;
use cosmian_kms_client::KmsClientConfig;
use serde::{Deserialize, Serialize};
use serial_test::serial;
use test_kms_server::start_default_test_kms_server;

use super::Pkcs11BenchAction;
use crate::actions::bench::output::criterion_home;

/// Same on-disk layout as the `ckms.toml` read by the PKCS#11 provider.
#[derive(Serialize, Deserialize, Debug, Default)]
struct ProviderConf {
    #[serde(flatten)]
    kms_config: KmsClientConfig,
}

impl ConfigUtils for ProviderConf {}

fn provider_dylib() -> PathBuf {
    let exe = env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join(format!(
        "{}cosmian_pkcs11{}",
        env::consts::DLL_PREFIX,
        env::consts::DLL_SUFFIX
    ))
}

#[test]
fn characterization_pkcs11_bench_action_defaults() {
    let a = Pkcs11BenchAction::try_parse_from(["bench", "--dll", "/x/lib.so"]).unwrap();
    assert_eq!(
        format!(
            "{:?} {:?} {:?} {:?} {:?} {} {} {} {} {} {} {} {} {:?}",
            a.dll,
            a.conf,
            a.token,
            a.mode,
            a.filter,
            a.delegated,
            a.hsm_slot,
            a.concurrency,
            a.time,
            a.warmup,
            a.cooldown,
            a.sanity,
            a.shared_session,
            a.speed
        ),
        "\"/x/lib.so\" None None All BenchFilter { algorithms: [], key_sizes: [] } false 0 1,2,4,8,16 20 5 2 false false Quick"
    );
}

/// Full sanity sweep (2 s per level) of the real `libcosmian_pkcs11` provider against the
/// in-process test server. Skipped (with a message) when the library has not been built:
/// `cargo build -p cosmian_pkcs11 --features non-fips` first.
#[tokio::test]
#[serial(bench_files)]
async fn characterization_pkcs11_bench_process_sanity_aes_gcm() {
    let dylib = provider_dylib();
    if !dylib.exists() {
        // Only the non-fips CI/`mise` flow builds `cosmian_pkcs11` before running the tests.
        eprintln!(
            "skipping: {} not built (cargo build -p cosmian_pkcs11 --features non-fips)",
            dylib.display()
        );
        return;
    }
    let ctx = start_default_test_kms_server().await;
    let conf = env::temp_dir().join(format!(
        "pkcs11_bench_characterization_{}.toml",
        ctx.server_port
    ));
    ProviderConf {
        kms_config: ctx.owner_client_config.clone(),
    }
    .to_toml(conf.to_str().unwrap())
    .unwrap();
    let action = Pkcs11BenchAction::try_parse_from([
        "bench",
        "--dll",
        dylib.to_str().unwrap(),
        "--conf",
        conf.to_str().unwrap(),
        "--sanity",
        "--mode",
        "encrypt",
        "-a",
        "aes-gcm",
    ])
    .unwrap();
    action.process(ctx.get_owner_client()).await.unwrap();
    std::fs::remove_file(conf).unwrap();
    std::fs::remove_file(criterion_home().join("load_pkcs11.json")).unwrap();
}
