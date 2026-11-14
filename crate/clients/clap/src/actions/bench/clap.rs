use std::{io::Write as _, time::Duration};

use cosmian_kms_client::KmsClient;
use criterion::Criterion;
use tokio::runtime::Runtime;

use super::{
    helpers::run_warmup,
    jose::{
        bench_jose_batch, bench_jose_encrypt, bench_jose_key_creation, bench_jose_mac,
        bench_jose_sign_verify,
    },
    kmip::{
        bench_batch, bench_encrypt, bench_hsm_encrypt, bench_hsm_key_creation,
        bench_hsm_sign_verify, bench_key_creation, bench_sign_verify,
    },
    load::{
        LoadBenchParams, LoadResult, bench_load, generate_html_output, generate_load_json_output,
        generate_markdown_load_output_combined, parse_concurrency_levels, print_load_results,
    },
    output::{
        collect_json_output, count_baseline_files, criterion_home, generate_compact_output,
        generate_markdown_output,
    },
    transport::{Transport, set_bench_filter, set_max_group_time},
    types::{BenchAction, BenchFormat, BenchMode, BenchProtocol, BenchSpeed, bench_ko_reset},
};
use crate::error::{KmsCliError, result::KmsCliResult};

impl BenchAction {
    /// Run the benchmark suite using criterion.
    ///
    /// Spawns a blocking task with a fresh tokio runtime (required because
    /// criterion's measurement loop is synchronous) and runs all selected
    /// benchmark groups.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let config = kms_rest_client.config.clone();
        let mode = self.mode;
        let filter = self.filter.clone();
        let protocol = self.protocol.clone();
        let format = self.format.clone();
        let speed = self.speed.clone();
        let time = self.time;
        let max_group_time = self.max_group_time;
        let save_baseline = self.save_baseline.clone();
        let load_baseline = self.load_baseline.clone();
        let version_label = self.version_label.clone();
        let load = self.load;
        let load_concurrency = self.load_concurrency.clone();
        let warmup_time = self.warmup_time;
        let cooldown_time = self.cooldown_time;
        let load_plaintext_size = self.load_plaintext_size;
        let hsm_prefix = self.hsm.then(|| format!("hsm::{}", self.hsm_slot));
        // Drop the existing client (bound to the current runtime)
        drop(kms_rest_client);

        tokio::task::spawn_blocking(move || -> KmsCliResult<()> {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| KmsCliError::Default(format!("Runtime creation failed: {e}")))?;
            let client = KmsClient::new_with_config(config)
                .map_err(|e| KmsCliError::Default(e.to_string()))?;

            // Verify server is reachable
            let version = rt
                .block_on(client.version())
                .map_err(|e| KmsCliError::Default(format!("Server unreachable: {e}")))?;
            eprintln!("[bench] Connected to KMS server version {version}");

            // Warmup phase for criterion benchmarks (load tests handle warmup
            // per-level using the actual operation at target concurrency).
            if !load {
                run_warmup(&rt, &client, warmup_time)?;
            }

            // Reset KO accumulator for this run
            bench_ko_reset();

            // Sanity speed implies compact unless the user explicitly chose another format
            let effective_format = if speed == BenchSpeed::Sanity && format == BenchFormat::Text {
                BenchFormat::Compact
            } else {
                format.clone()
            };

            // ── Load test mode (orthogonal concurrency sweep; skips criterion) ─────
            if load {
                let concurrency_levels = parse_concurrency_levels(&load_concurrency)?;
                let warmup = Duration::from_secs(warmup_time);
                let duration = Duration::from_secs(time.max(1));
                let cooldown = Duration::from_secs(cooldown_time);

                // Run per-protocol load tests, collect all results.
                let mut all_proto_results: Vec<(&str, Vec<LoadResult>)> = Vec::new();
                for proto in protocol.protocols() {
                    let results = bench_load(
                        &rt,
                        &client,
                        &LoadBenchParams {
                            mode,
                            protocol: proto,
                            concurrency_levels: &concurrency_levels,
                            warmup,
                            duration,
                            cooldown,
                            plaintext_size: load_plaintext_size,
                            hsm_prefix: hsm_prefix.as_deref(),
                            filter: Some(&filter),
                        },
                    )?;
                    if results.is_empty() {
                        continue;
                    }
                    print_load_results(&results)?;
                    // Always write per-protocol JSON (used by plot_version_compare.py).
                    generate_load_json_output(&results, proto.slug())?;
                    if effective_format == BenchFormat::Html {
                        generate_html_output(&results)?;
                    }
                    all_proto_results.push((proto.slug(), results));
                }
                // When all protocols ran, also write a combined markdown table.
                if matches!(protocol, BenchProtocol::All)
                    && effective_format == BenchFormat::Markdown
                {
                    generate_markdown_load_output_combined(&all_proto_results)?;
                }
                return Ok(());
            }

            // Snapshot time just before starting criterion so we can filter
            // stale criterion data from previous runs in generate_compact_output.
            let run_start = std::time::SystemTime::now();

            let mut c = match speed {
                BenchSpeed::Sanity => Criterion::default()
                    .sample_size(10)
                    .measurement_time(Duration::from_millis(1))
                    .warm_up_time(Duration::from_millis(1)),
                BenchSpeed::Quick => Criterion::default()
                    .sample_size(10)
                    .measurement_time(Duration::from_secs(1))
                    .warm_up_time(Duration::from_millis(500)),
                BenchSpeed::Normal => Criterion::default()
                    .sample_size(100)
                    .measurement_time(Duration::from_secs(time))
                    .warm_up_time(Duration::from_secs(3)),
            };

            if let Some(ref name) = save_baseline {
                eprintln!("[bench] Saving baseline '{name}'");
                c = c.save_baseline(name.clone());
            } else if let Some(ref name) = load_baseline {
                eprintln!("[bench] Comparing against baseline '{name}'");
                c = c.retain_baseline(name.clone(), false);
            }

            // Suppress criterion's verbose output during the run.
            std::io::stdout().flush().ok();
            std::io::stderr().flush().ok();

            let (saved_stdout_fd, saved_stderr_fd): (Option<i32>, Option<i32>) =
                match effective_format {
                    BenchFormat::Json => {
                        #[expect(
                            unsafe_code,
                            reason = "libc fd redirection to silence criterion output"
                        )]
                        let s = unsafe { libc::dup(1) };
                        #[expect(
                            unsafe_code,
                            reason = "libc fd redirection to silence criterion output"
                        )]
                        unsafe {
                            libc::dup2(2, 1)
                        };
                        (if s < 0 { None } else { Some(s) }, None)
                    }
                    BenchFormat::Compact => {
                        #[expect(
                            unsafe_code,
                            reason = "libc fd redirection to silence criterion output"
                        )]
                        let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY) };
                        if devnull >= 0 {
                            #[expect(
                                unsafe_code,
                                reason = "libc fd redirection to silence criterion output"
                            )]
                            let se = unsafe { libc::dup(2) };
                            #[expect(
                                unsafe_code,
                                reason = "libc fd redirection to silence criterion output"
                            )]
                            unsafe {
                                libc::dup2(devnull, 2)
                            };
                            #[expect(
                                unsafe_code,
                                reason = "libc fd redirection to silence criterion output"
                            )]
                            let so = unsafe { libc::dup(1) };
                            #[expect(
                                unsafe_code,
                                reason = "libc fd redirection to silence criterion output"
                            )]
                            unsafe {
                                libc::dup2(2, 1);
                                libc::close(devnull);
                            }
                            (
                                if so < 0 { None } else { Some(so) },
                                if se < 0 { None } else { Some(se) },
                            )
                        } else {
                            (None, None)
                        }
                    }
                    _ => (None, None),
                };

            let is_sanity = speed == BenchSpeed::Sanity;
            let run_json = matches!(protocol, BenchProtocol::All | BenchProtocol::TtlvJson);
            let run_wire = matches!(protocol, BenchProtocol::All | BenchProtocol::TtlvBytes);
            let run_jose = matches!(protocol, BenchProtocol::All | BenchProtocol::Jose);

            // Apply the optional per-group wall-clock budget (KMIP groups only).
            set_max_group_time(max_group_time.map(Duration::from_secs));
            set_bench_filter(Some(filter.clone()));

            let bench_result = (|| -> KmsCliResult<()> {
                if run_json {
                    if let Some(ref hsm_prefix) = hsm_prefix {
                        run_hsm_kmip_benches(&mut c, &client, &rt, mode, Transport::Json, hsm_prefix)?;
                    } else {
                        run_kmip_benches(&mut c, &client, &rt, mode, Transport::Json, is_sanity)?;
                    }
                }

                if run_wire {
                    if hsm_prefix.is_some() {
                        eprintln!(
                            "[bench] --hsm only benchmarks the ttlv-json transport for delegated \
                             crypto operations: a ttlv-bytes run measured strictly after the \
                             ttlv-json group on the same HSM token would be contaminated by \
                             cumulative SoftHSM2 load from that group, invalidating the comparison, \
                             skipping ttlv-bytes"
                        );
                    } else {
                        run_kmip_benches(&mut c, &client, &rt, mode, Transport::Bytes, is_sanity)?;
                    }
                }

                if run_jose && hsm_prefix.is_some() {
                    eprintln!(
                        "[bench] --hsm does not support the jose protocol (no way to request a \
                         caller-chosen kid via POST /v1/crypto/keys), skipping"
                    );
                } else if run_jose {
                    match mode {
                        BenchMode::All => {
                            bench_jose_encrypt(&mut c, &client, &rt);
                            bench_jose_sign_verify(&mut c, &client, &rt);
                            bench_jose_mac(&mut c, &client, &rt);
                            bench_jose_key_creation(&mut c, &client, &rt);
                            bench_jose_batch(&mut c, &client, &rt, is_sanity);
                        }
                        BenchMode::Encrypt => bench_jose_encrypt(&mut c, &client, &rt),
                        BenchMode::KeyCreation => bench_jose_key_creation(&mut c, &client, &rt),
                        BenchMode::SignVerify => {
                            bench_jose_sign_verify(&mut c, &client, &rt);
                            bench_jose_mac(&mut c, &client, &rt);
                        }
                        BenchMode::Batch => bench_jose_batch(&mut c, &client, &rt, is_sanity),
                    }
                }
                Ok(())
            })();

            // Drop criterion to finalize reports
            drop(c);

            // Restore stderr (compact mode silenced criterion's warnings).
            if let Some(saved) = saved_stderr_fd {
                #[expect(
                    unsafe_code,
                    reason = "libc fd redirection to silence criterion output"
                )]
                unsafe {
                    libc::dup2(saved, 2);
                    libc::close(saved);
                }
            }

            // Restore stdout before we emit the report.
            if let Some(saved) = saved_stdout_fd {
                #[expect(
                    unsafe_code,
                    reason = "libc fd redirection to silence criterion output"
                )]
                unsafe {
                    libc::dup2(saved, 1);
                    libc::close(saved);
                }
            }

            bench_result?;

            if let Some(ref name) = save_baseline {
                let home = criterion_home();
                let count = count_baseline_files(&home, name);
                eprintln!(
                    "[bench] Baseline '{name}' saved: {count} estimates written under {}",
                    home.display()
                );
            }

            match effective_format {
                BenchFormat::Json => {
                    for proto in protocol.protocols() {
                        collect_json_output(version_label.as_deref(), proto.slug())?;
                    }
                }
                BenchFormat::Markdown => {
                    for proto in protocol.protocols() {
                        generate_markdown_output(proto.slug())?;
                    }
                }
                BenchFormat::Compact => generate_compact_output(run_start)?,
                BenchFormat::Text | BenchFormat::Html => {}
            }

            Ok(())
        })
        .await
        .map_err(|e| KmsCliError::Default(format!("Benchmark task panicked: {e}")))?
    }
}

/// Run all KMIP criterion benchmark groups for a single transport (JSON or binary TTLV).
fn run_kmip_benches(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    mode: BenchMode,
    transport: Transport,
    is_sanity: bool,
) -> KmsCliResult<()> {
    match mode {
        BenchMode::All => {
            bench_encrypt(c, client, rt, transport)?;
            bench_key_creation(c, client, rt, transport)?;
            bench_sign_verify(c, client, rt, transport)?;
            bench_batch(c, client, rt, transport, is_sanity)?;
        }
        BenchMode::Encrypt => bench_encrypt(c, client, rt, transport)?,
        BenchMode::KeyCreation => bench_key_creation(c, client, rt, transport)?,
        BenchMode::SignVerify => bench_sign_verify(c, client, rt, transport)?,
        BenchMode::Batch => bench_batch(c, client, rt, transport, is_sanity)?,
    }
    Ok(())
}

/// HSM counterpart of [`run_kmip_benches`]: keys are created with an
/// `hsm::`-prefixed unique identifier so both key generation and Encrypt/Sign
/// execute directly on the HSM (PKCS#11). `Batch` has no HSM equivalent (out
/// of scope — the oracle has no bulk-operation support) and is skipped with a
/// notice.
fn run_hsm_kmip_benches(
    c: &mut Criterion,
    client: &KmsClient,
    rt: &Runtime,
    mode: BenchMode,
    transport: Transport,
    hsm_prefix: &str,
) -> KmsCliResult<()> {
    match mode {
        BenchMode::All => {
            bench_hsm_encrypt(c, client, rt, transport, hsm_prefix)?;
            bench_hsm_key_creation(c, client, rt, transport, hsm_prefix)?;
            bench_hsm_sign_verify(c, client, rt, transport, hsm_prefix)?;
        }
        BenchMode::Encrypt => bench_hsm_encrypt(c, client, rt, transport, hsm_prefix)?,
        BenchMode::KeyCreation => bench_hsm_key_creation(c, client, rt, transport, hsm_prefix)?,
        BenchMode::SignVerify => bench_hsm_sign_verify(c, client, rt, transport, hsm_prefix)?,
        BenchMode::Batch => {
            eprintln!("[bench] --hsm does not support --mode batch (no HSM bulk-op support)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod characterization_tests {
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
        let html =
            fs::read_to_string(criterion_home().join("load-report").join("index.html")).unwrap();
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
}
