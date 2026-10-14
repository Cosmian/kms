use std::fs;

use ::clap::Parser as _;
use serial_test::serial;
use test_kms_server::start_default_test_kms_server;

use super::criterion_home;
use crate::actions::bench::types::BenchAction;

#[test]
fn characterization_bench_action_defaults() {
    let a = BenchAction::try_parse_from(["bench"]).unwrap();
    assert_eq!(
        format!(
            "{:?} {:?} {:?} {:?} {:?} {} {:?} {:?} {:?} {:?} {} {} {} {} {} {} {}",
            a.mode,
            a.filter,
            a.protocol,
            a.format,
            a.speed,
            a.time,
            a.max_group_time,
            a.save_baseline,
            a.load_baseline,
            a.version_label,
            a.load,
            a.load_concurrency,
            a.load_plaintext_size,
            a.warmup_time,
            a.cooldown_time,
            a.hsm,
            a.hsm_slot
        ),
        "All BenchFilter { algorithms: [], key_sizes: [] } All Text Normal 10 Some(30) None None None false 1,2,4,8,16 4096 20 20 false 0"
    );
}

#[test]
fn characterization_bench_action_explicit_flags() {
    let a = BenchAction::try_parse_from([
        "bench",
        "-m",
        "sign",
        "-a",
        "aes-gcm, rsa",
        "-k",
        "256,p256",
        "-p",
        "jose",
        "-f",
        "markdown",
        "-s",
        "quick",
        "-t",
        "3",
        "--max-group-time",
        "7",
        "--load",
        "--load-concurrency",
        "1,2",
        "--load-plaintext-size",
        "64",
        "--warmup-time",
        "0",
        "--cooldown-time",
        "1",
        "--hsm",
        "--hsm-slot",
        "5",
        "--save-baseline",
        "b1",
        "--version-label",
        "v1",
    ])
    .unwrap();
    assert_eq!(
        format!(
            "{:?} {:?} {:?} {:?} {:?} {} {:?} {:?} {:?} {:?} {} {} {} {} {} {} {}",
            a.mode,
            a.filter,
            a.protocol,
            a.format,
            a.speed,
            a.time,
            a.max_group_time,
            a.save_baseline,
            a.load_baseline,
            a.version_label,
            a.load,
            a.load_concurrency,
            a.load_plaintext_size,
            a.warmup_time,
            a.cooldown_time,
            a.hsm,
            a.hsm_slot
        ),
        "SignVerify BenchFilter { algorithms: [\"aes-gcm\", \" rsa\"], key_sizes: [\"256\", \"p256\"] } Jose Markdown Quick 3 Some(7) Some(\"b1\") None Some(\"v1\") true 1,2 64 0 1 true 5"
    );
}

/// Real load sweep (1 s per level) against the in-process test server: exercises the
/// `bench_load` call from `BenchAction::process`, the JSON report and the HTML report.
#[tokio::test]
#[serial(bench_files)]
async fn characterization_bench_process_load_html() {
    let ctx = start_default_test_kms_server().await;
    let action = BenchAction::try_parse_from([
        "bench",
        "--load",
        "--mode",
        "encrypt",
        "--protocol",
        "ttlv-json",
        "-a",
        "aes-gcm",
        "--format",
        "html",
        "--load-concurrency",
        "1,2",
        "--load-plaintext-size",
        "64",
        "--time",
        "1",
        "--warmup-time",
        "0",
        "--cooldown-time",
        "0",
    ])
    .unwrap();
    action.process(ctx.get_owner_client()).await.unwrap();
    let json = fs::read_to_string(criterion_home().join("load_ttlv-json.json")).unwrap();
    let lines: Vec<String> = json
        .lines()
        .map(|l| {
            l.split(",\"throughput_rps\"")
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    assert_eq!(
        lines,
        vec![
            "{\"protocol\":\"ttlv-json\",\"operation\":\"encrypt/aes-gcm\",\"concurrency\":1",
            "{\"protocol\":\"ttlv-json\",\"operation\":\"encrypt/aes-gcm\",\"concurrency\":2"
        ]
    );
    let html = fs::read_to_string(criterion_home().join("load-report").join("index.html")).unwrap();
    assert!(html.contains("<h2>ttlv-json/encrypt/aes-gcm</h2>"));
}

/// Runs the criterion groups of one `--mode`/`--protocol` pair once at `sanity` speed.
async fn run_sanity(mode: &str, protocol: &str, extra: &[&str]) {
    let ctx = start_default_test_kms_server().await;
    let mut args = vec![
        "bench",
        "--speed",
        "sanity",
        "--mode",
        mode,
        "--protocol",
        protocol,
        "--warmup-time",
        "0",
        "--max-group-time",
        "1",
    ];
    args.extend_from_slice(extra);
    let action = BenchAction::try_parse_from(args).unwrap();
    action.process(ctx.get_owner_client()).await.unwrap();
}

#[tokio::test]
#[serial(bench_files)]
async fn characterization_bench_process_sanity_encrypt_ttlv_json() {
    run_sanity("encrypt", "ttlv-json", &[]).await;
}

#[tokio::test]
#[serial(bench_files)]
async fn characterization_bench_process_sanity_encrypt_ttlv_bytes() {
    run_sanity("encrypt", "ttlv-bytes", &[]).await;
}

#[tokio::test]
#[serial(bench_files)]
async fn characterization_bench_process_sanity_encrypt_jose() {
    run_sanity("encrypt", "jose", &[]).await;
}

#[tokio::test]
#[serial(bench_files)]
async fn characterization_bench_process_sanity_batch_ttlv_json() {
    run_sanity("batch", "ttlv-json", &[]).await;
}

#[tokio::test]
#[serial(bench_files)]
async fn characterization_bench_process_sanity_batch_jose() {
    run_sanity("batch", "jose", &[]).await;
}

#[tokio::test]
#[serial(bench_files)]
async fn characterization_bench_process_sanity_key_creation_rsa() {
    run_sanity("key-creation", "ttlv-json", &["-a", "rsa", "-k", "4096"]).await;
}
