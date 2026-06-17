use std::{io::Write as _, time::Duration};

use cosmian_kms_client::KmsClient;
use criterion::Criterion;

use super::{
    helpers::run_warmup,
    jose::{
        bench_jose_batch, bench_jose_encrypt, bench_jose_key_creation, bench_jose_mac,
        bench_jose_sign_verify,
    },
    kmip_ttlv_bytes::{
        bench_wire_batch, bench_wire_encrypt, bench_wire_key_creation, bench_wire_sign_verify,
    },
    kmip_ttlv_json::{bench_batch, bench_encrypt, bench_key_creation, bench_sign_verify},
    load::{
        LoadResult, bench_load, generate_html_output, generate_load_json_output,
        generate_markdown_load_output_combined, parse_concurrency_levels, print_load_results,
    },
    output::{
        collect_json_output, count_baseline_files, criterion_home, generate_compact_output,
        generate_markdown_output,
    },
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
        let mode = self.mode.clone();
        let protocol = self.protocol.clone();
        let format = self.format.clone();
        let speed = self.speed.clone();
        let time = self.time;
        let save_baseline = self.save_baseline.clone();
        let load_baseline = self.load_baseline.clone();
        let version_label = self.version_label.clone();
        let load = self.load;
        let load_concurrency = self.load_concurrency.clone();
        let warmup_time = self.warmup_time;
        let cooldown_time = self.cooldown_time;

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
                run_warmup(&rt, &client, warmup_time);
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
                        &mode,
                        proto,
                        &concurrency_levels,
                        warmup,
                        duration,
                        cooldown,
                    );
                    if results.is_empty() {
                        continue;
                    }
                    print_load_results(&results);
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
                        #[allow(unsafe_code)]
                        let s = unsafe { libc::dup(1) };
                        #[allow(unsafe_code)]
                        unsafe {
                            libc::dup2(2, 1)
                        };
                        (if s < 0 { None } else { Some(s) }, None)
                    }
                    BenchFormat::Compact => {
                        #[allow(unsafe_code)]
                        let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY) };
                        if devnull >= 0 {
                            #[allow(unsafe_code)]
                            let se = unsafe { libc::dup(2) };
                            #[allow(unsafe_code)]
                            unsafe {
                                libc::dup2(devnull, 2)
                            };
                            #[allow(unsafe_code)]
                            let so = unsafe { libc::dup(1) };
                            #[allow(unsafe_code)]
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

            if run_json {
                match mode {
                    BenchMode::All => {
                        bench_encrypt(&mut c, &client, &rt);
                        bench_key_creation(&mut c, &client, &rt);
                        bench_sign_verify(&mut c, &client, &rt);
                        bench_batch(&mut c, &client, &rt, is_sanity);
                    }
                    BenchMode::Encrypt => bench_encrypt(&mut c, &client, &rt),
                    BenchMode::KeyCreation => bench_key_creation(&mut c, &client, &rt),
                    BenchMode::SignVerify => bench_sign_verify(&mut c, &client, &rt),
                    BenchMode::Batch => bench_batch(&mut c, &client, &rt, is_sanity),
                }
            }

            if run_wire {
                match mode {
                    BenchMode::All => {
                        bench_wire_encrypt(&mut c, &client, &rt);
                        bench_wire_key_creation(&mut c, &client, &rt);
                        bench_wire_sign_verify(&mut c, &client, &rt);
                        bench_wire_batch(&mut c, &client, &rt, is_sanity);
                    }
                    BenchMode::Encrypt => bench_wire_encrypt(&mut c, &client, &rt),
                    BenchMode::KeyCreation => bench_wire_key_creation(&mut c, &client, &rt),
                    BenchMode::SignVerify => bench_wire_sign_verify(&mut c, &client, &rt),
                    BenchMode::Batch => bench_wire_batch(&mut c, &client, &rt, is_sanity),
                }
            }

            if run_jose {
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

            // Drop criterion to finalize reports
            drop(c);

            // Restore stderr (compact mode silenced criterion's warnings).
            if let Some(saved) = saved_stderr_fd {
                #[allow(unsafe_code)]
                unsafe {
                    libc::dup2(saved, 2);
                    libc::close(saved);
                }
            }

            // Restore stdout before we emit the report.
            if let Some(saved) = saved_stdout_fd {
                #[allow(unsafe_code)]
                unsafe {
                    libc::dup2(saved, 1);
                    libc::close(saved);
                }
            }

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
