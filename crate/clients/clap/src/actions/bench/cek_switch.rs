//! JOSE CEK-switch scenario (`ckms bench --cek-switch`): a fixed-rate, open-loop stream of JWEs
//! (decrypt with an RSA-OAEP CEK unwrap, then re-encrypt with `dir` + A256GCM) spread round-robin
//! over one or more KMS servers. Halfway through, the senders switch to a second CEK (hence a
//! second `encrypted_key`), like Estreem rotating its AES CEK once an hour.

use std::{fmt::Write as _, fs, sync::Arc, time::Duration};

use cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm;
use cosmian_kms_client::{
    KmsClient,
    http_client::Bytes,
    jose::{JoseEncReq, b64url},
    kmip_2_1::{kmip_operations::Get, kmip_types::UniqueIdentifier},
};
use num_traits::ToPrimitive as _;
use serde::Serialize;
use tokio::{
    runtime::Runtime,
    task::JoinSet,
    time::{Instant, sleep_until},
};

use super::{
    jose::{jose_jwe_decrypt_body, jose_protected_header, jose_wrap_new_cek},
    load::load_percentile,
    output::criterion_home,
};
use crate::error::{KmsCliError, result::KmsCliResult};

/// Number of distinct JWE bodies (distinct IVs, one shared `encrypted_key`) per CEK.
const POOL_SIZE: usize = 1024;
/// Timeline bucket width.
const BUCKET_MS: u64 = 100;
/// After the measurement window, senders that are still behind give up after this long.
const DRAIN: Duration = Duration::from_secs(5);
/// Latency window before the switch used as the baseline (capped by `--cek-switch-at`).
const PRE_SWITCH_MS: u64 = 10_000;
/// Window after the switch whose latency is reported separately.
const POST_SWITCH_MS: u64 = 1_000;
/// Recovery = this many consecutive buckets (1 s) at or below the threshold.
const RECOVERY_BUCKETS: u64 = 10;

/// JOSE key-management algorithm used to wrap the CEKs.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default)]
pub(super) enum CekSwitchAlg {
    /// JWA `RSA-OAEP` (SHA-1).
    #[default]
    #[value(name = "RSA-OAEP")]
    RsaOaep,
    /// JWA `RSA-OAEP-256` (SHA-256).
    #[value(name = "RSA-OAEP-256")]
    RsaOaep256,
}

impl CekSwitchAlg {
    const fn jwa(self) -> &'static str {
        match self {
            Self::RsaOaep => "RSA-OAEP",
            Self::RsaOaep256 => "RSA-OAEP-256",
        }
    }

    const fn hash(self) -> HashingAlgorithm {
        match self {
            Self::RsaOaep => HashingAlgorithm::SHA1,
            Self::RsaOaep256 => HashingAlgorithm::SHA256,
        }
    }
}

/// JOSE CEK-switch scenario options (`ckms bench --cek-switch`).
#[derive(clap::Args, Clone, Debug, Default)]
pub(crate) struct CekSwitchArgs {
    /// Run the JOSE CEK-switch scenario instead of the criterion or load benchmarks:
    /// JWEs are sent at a fixed rate, each decrypted (RSA-OAEP CEK unwrap, kid
    /// --cek-switch-rsa-kid) then re-encrypted (`dir` + A256GCM, kid --cek-switch-aes-kid).
    /// All JWEs reuse one CEK and one `encrypted_key` until --cek-switch-at seconds into
    /// the measurement, then a second CEK. Uses --time (measurement seconds),
    /// --warmup-time and --load-plaintext-size.
    #[clap(long = "cek-switch", default_value = "false")]
    pub(super) enabled: bool,

    /// Additional KMS URL; messages are spread round-robin over --url and these (repeatable).
    #[clap(long = "cek-switch-url", value_name = "URL")]
    pub(super) urls: Vec<String>,

    /// Public key id of the RSA key pair wrapping the CEKs (required with --cek-switch).
    #[clap(long = "cek-switch-rsa-kid")]
    pub(super) rsa_kid: Option<String>,

    /// AES-256 key id used to re-encrypt each plaintext (required with --cek-switch).
    #[clap(long = "cek-switch-aes-kid")]
    pub(super) aes_kid: Option<String>,

    /// JWE key-management algorithm.
    #[clap(long = "cek-switch-alg", default_value = "RSA-OAEP")]
    pub(super) alg: CekSwitchAlg,

    /// Target messages per second (one message = one decrypt + one encrypt).
    #[clap(long = "cek-switch-rate", default_value = "2500")]
    pub(super) rate: u32,

    /// Concurrent senders; must cover rate × per-message latency.
    #[clap(long = "cek-switch-workers", default_value = "256")]
    pub(super) workers: usize,

    /// Seconds after the start of the measurement window at which the CEK changes.
    #[clap(long = "cek-switch-at", default_value = "20")]
    pub(super) switch_at: u64,
}

/// One message (decrypt, then re-encrypt on success) scheduled inside the measurement window.
#[derive(Clone, Copy, Debug)]
struct Sample {
    /// Scheduled send time, µs since the start of the measurement.
    t_us: u64,
    /// Completion time, µs since the start of the measurement.
    done_us: u64,
    server: usize,
    generation: usize,
    ok: bool,
    /// Decrypt round trip, from the actual send.
    decrypt_us: u64,
    /// From the scheduled time to the end of the encrypt: includes the queueing behind a slow
    /// request (coordinated-omission correction).
    message_us: u64,
}

/// Latency statistics (ms) of the successful messages of a window; `n` counts them.
#[derive(Clone, Debug, Default, Serialize)]
struct WindowStats {
    n: usize,
    decrypt_p50_ms: f64,
    decrypt_p99_ms: f64,
    decrypt_max_ms: f64,
    message_p50_ms: f64,
    message_p99_ms: f64,
    message_max_ms: f64,
}

/// One JSONL line of `cek_switch_timeline.json`.
#[derive(Clone, Debug, Serialize)]
struct TimelineBucket {
    t_ms: u64,
    server: String,
    errors: usize,
    #[serde(flatten)]
    stats: WindowStats,
}

/// Per-group (`all`, `kms1`..) figures of `cek_switch_summary.json`.
#[derive(Clone, Debug, Serialize)]
struct ServerSummary {
    server: String,
    samples: usize,
    errors: usize,
    pre_switch: WindowStats,
    post_switch_1s: WindowStats,
    peak_message_ms: f64,
    slow_messages: usize,
    recovery_ms: Option<u64>,
}

#[derive(Serialize)]
struct Summary {
    urls: Vec<String>,
    alg: &'static str,
    rate_target: u32,
    workers: usize,
    plaintext_size: usize,
    warmup_s: u64,
    duration_s: u64,
    switch_at_s: u64,
    bucket_ms: u64,
    rate_achieved: f64,
    unsent: u64,
    per_server: Vec<ServerSummary>,
}

fn us(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

fn ms(us: u64) -> f64 {
    us.to_f64().unwrap_or(f64::NAN) / 1000.0
}

fn sorted(mut v: Vec<f64>) -> Vec<f64> {
    v.sort_by(f64::total_cmp);
    v
}

fn window_stats<'a>(samples: impl Iterator<Item = &'a Sample>) -> WindowStats {
    let (mut dec, mut msg) = (Vec::new(), Vec::new());
    for s in samples.filter(|s| s.ok) {
        dec.push(ms(s.decrypt_us));
        msg.push(ms(s.message_us));
    }
    let (dec, msg) = (sorted(dec), sorted(msg));
    WindowStats {
        n: msg.len(),
        decrypt_p50_ms: load_percentile(&dec, 0.50),
        decrypt_p99_ms: load_percentile(&dec, 0.99),
        decrypt_max_ms: dec.last().copied().unwrap_or(0.0),
        message_p50_ms: load_percentile(&msg, 0.50),
        message_p99_ms: load_percentile(&msg, 0.99),
        message_max_ms: msg.last().copied().unwrap_or(0.0),
    }
}

const fn at(s: &Sample) -> u64 {
    s.t_us / 1000
}

fn group_label(group: usize) -> String {
    if group == 0 {
        "all".to_owned()
    } else {
        format!("kms{group}")
    }
}

/// Aggregate the samples of the measurement window into 100 ms timeline buckets and per-group
/// summaries, for `all` followed by `kms1..kmsN`. Messages are bucketed by scheduled time, so a
/// latency spike appears at the moment the load was offered.
fn summarize(
    samples: &[Sample],
    n_servers: usize,
    switch_ms: u64,
    duration_ms: u64,
) -> (Vec<TimelineBucket>, Vec<ServerSummary>) {
    let n_buckets = usize::try_from(duration_ms.div_ceil(BUCKET_MS)).unwrap_or(0);
    let mut timeline = Vec::new();
    let mut summaries = Vec::new();
    for group in 0..=n_servers {
        let label = group_label(group);
        let in_group: Vec<&Sample> = samples
            .iter()
            .filter(|s| group == 0 || s.server == group - 1)
            .collect();
        let mut buckets: Vec<Vec<&Sample>> = vec![Vec::new(); n_buckets];
        for s in &in_group {
            let b = usize::try_from(s.t_us / 1000 / BUCKET_MS).unwrap_or(usize::MAX);
            if let Some(bucket) = buckets.get_mut(b) {
                bucket.push(s);
            }
        }
        let mut bucket_p99 = Vec::with_capacity(n_buckets);
        for (b, bucket) in buckets.iter().enumerate() {
            let stats = window_stats(bucket.iter().copied());
            let errors = bucket.iter().filter(|s| !s.ok).count();
            bucket_p99.push((!bucket.is_empty()).then_some(stats.message_p99_ms));
            if !bucket.is_empty() {
                timeline.push(TimelineBucket {
                    t_ms: b.to_u64().unwrap_or(0) * BUCKET_MS,
                    server: label.clone(),
                    errors,
                    stats,
                });
            }
        }

        let pre_from = switch_ms.saturating_sub(PRE_SWITCH_MS);
        let pre_switch = window_stats(
            in_group
                .iter()
                .copied()
                .filter(|s| (pre_from..switch_ms).contains(&at(s))),
        );
        let post_switch_1s = window_stats(
            in_group
                .iter()
                .copied()
                .filter(|s| (switch_ms..switch_ms + POST_SWITCH_MS).contains(&at(s))),
        );
        let threshold = 2.0 * pre_switch.message_p99_ms;
        let after_switch = || {
            in_group
                .iter()
                .copied()
                .filter(|s| s.ok && at(s) >= switch_ms)
        };
        let peak_message_ms = after_switch().map(|s| ms(s.message_us)).fold(0.0, f64::max);
        let slow_messages = after_switch()
            .filter(|s| ms(s.message_us) > threshold)
            .count();

        // First 1 s run of buckets, entirely inside the window, whose p99 is back to the
        // baseline (empty buckets pass, but a window with no successful message at all, or no
        // pre-switch baseline, is not a recovery).
        let first = usize::try_from(switch_ms / BUCKET_MS).unwrap_or(usize::MAX);
        let run = usize::try_from(RECOVERY_BUCKETS).unwrap_or(10);
        let recovery_ms = if pre_switch.n == 0 {
            None
        } else {
            (first..=n_buckets.saturating_sub(run))
                .find(|&b0| {
                    bucket_p99.get(b0..b0 + run).is_some_and(|w| {
                        w.iter().any(Option::is_some)
                            && w.iter().all(|p| p.is_none_or(|p99| p99 <= threshold))
                    })
                })
                .map(|b0| b0.to_u64().unwrap_or(0) * BUCKET_MS - switch_ms)
        };

        summaries.push(ServerSummary {
            server: label,
            samples: in_group.len(),
            errors: in_group.iter().filter(|s| !s.ok).count(),
            pre_switch,
            post_switch_1s,
            peak_message_ms,
            slow_messages,
            recovery_ms,
        });
    }
    (timeline, summaries)
}

struct Server {
    client: KmsClient,
    decrypt_url: String,
    encrypt_url: String,
}

/// Everything the senders share; read-only after construction.
struct Shared {
    servers: Vec<Server>,
    /// `pools[generation][i % POOL_SIZE]`: decrypt bodies of CEK `generation`.
    pools: Vec<Vec<Bytes>>,
    encrypt_body: Bytes,
    rate: u64,
    workers: u64,
    start: Instant,
    measure_start: Instant,
    switch: Instant,
    end: Instant,
}

/// A request still pending at `deadline` (the end of the drain period) counts as failed, so a
/// server that stops answering yields errors and a report instead of a hung run.
async fn post_ok(client: &KmsClient, url: &str, body: Bytes, deadline: Instant) -> bool {
    tokio::time::timeout_at(
        deadline,
        client.client.post_bytes(url, body, "application/json"),
    )
    .await
    .is_ok_and(|resp| resp.is_ok_and(|resp| resp.status.is_success()))
}

/// Sender `w`: messages `w, w + workers, ...`, message `i` scheduled at `start + i / rate`.
/// A late sender does not sleep, so its backlog drains as a burst; it stops at the end of the
/// window, or `DRAIN` after it when it cannot keep up (its unsent messages are not recorded).
async fn run_worker(w: u64, shared: Arc<Shared>) -> Vec<Sample> {
    let mut samples = Vec::new();
    let n_servers = shared.servers.len().to_u64().unwrap_or(1);
    let deadline = shared.end + DRAIN;
    let mut i = w;
    loop {
        let nanos = u128::from(i) * 1_000_000_000 / u128::from(shared.rate);
        let sched = shared.start + Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX));
        if sched >= shared.end || Instant::now() >= shared.end + DRAIN {
            break;
        }
        sleep_until(sched).await;
        let server = usize::try_from(i % n_servers).unwrap_or(0);
        let generation = usize::from(sched >= shared.switch);
        let pool_idx = usize::try_from(i % POOL_SIZE.to_u64().unwrap_or(1)).unwrap_or(0);
        let (Some(srv), Some(body)) = (
            shared.servers.get(server),
            shared.pools.get(generation).and_then(|p| p.get(pool_idx)),
        ) else {
            break;
        };
        let t0 = Instant::now();
        let mut ok = post_ok(&srv.client, &srv.decrypt_url, body.clone(), deadline).await;
        let t1 = Instant::now();
        if ok {
            ok = post_ok(
                &srv.client,
                &srv.encrypt_url,
                shared.encrypt_body.clone(),
                deadline,
            )
            .await;
        }
        let t2 = Instant::now();
        if sched >= shared.measure_start {
            samples.push(Sample {
                t_us: us(sched - shared.measure_start),
                done_us: us(t2.saturating_duration_since(shared.measure_start)),
                server,
                generation,
                ok,
                decrypt_us: us(t1 - t0),
                message_us: us(t2.saturating_duration_since(sched)),
            });
        }
        i += shared.workers;
    }
    samples
}

fn write_file(name: &str, content: &str) -> KmsCliResult<()> {
    let dir = criterion_home();
    fs::create_dir_all(&dir)
        .map_err(|e| KmsCliError::Default(format!("Create {}: {e}", dir.display())))?;
    let path = dir.join(name);
    fs::write(&path, content)
        .map_err(|e| KmsCliError::Default(format!("Write {}: {e}", path.display())))
}

/// Run the scenario and write `cek_switch_timeline.json`, `cek_switch_summary.json` and
/// `cek_switch_samples.csv` to the criterion home.
pub(super) fn run(
    rt: &Runtime,
    client: &KmsClient,
    args: &CekSwitchArgs,
    warmup: Duration,
    duration: Duration,
    plaintext_size: usize,
) -> KmsCliResult<()> {
    let (Some(rsa_kid), Some(aes_kid)) = (args.rsa_kid.as_deref(), args.aes_kid.as_deref()) else {
        return Err(KmsCliError::Default(
            "--cek-switch requires --cek-switch-rsa-kid and --cek-switch-aes-kid".to_owned(),
        ));
    };
    if args.rate == 0 || args.workers == 0 {
        return Err(KmsCliError::Default(
            "--cek-switch-rate and --cek-switch-workers must be > 0".to_owned(),
        ));
    }
    if args.switch_at == 0 || args.switch_at >= duration.as_secs() {
        return Err(KmsCliError::Default(
            "--cek-switch-at must be in 1..--time".to_owned(),
        ));
    }

    let urls: Vec<String> = std::iter::once(client.config.http_config.server_url.clone())
        .chain(args.urls.iter().cloned())
        .map(|u| u.trim_end_matches('/').to_owned())
        .collect();
    let mut servers = Vec::with_capacity(urls.len());
    for url in &urls {
        let mut config = client.config.clone();
        config.http_config.server_url.clone_from(url);
        servers.push(Server {
            client: KmsClient::new_with_config(config)
                .map_err(|e| KmsCliError::Default(e.to_string()))?,
            decrypt_url: format!("{url}/v1/crypto/decrypt"),
            encrypt_url: format!("{url}/v1/crypto/encrypt"),
        });
    }

    let public_key = rt
        .block_on(client.get(Get::new(
            UniqueIdentifier::TextString(rsa_kid.to_owned()),
            false,
            None,
            None,
        )))
        .map_err(|e| KmsCliError::Default(format!("cannot fetch RSA public key {rsa_kid}: {e}")))?
        .object;
    let protected = jose_protected_header(args.alg.jwa(), rsa_kid)?;
    let plaintext = vec![1_u8; plaintext_size];
    let mut pools = Vec::with_capacity(2);
    for _generation in 0..2 {
        let (cek, encrypted_key) = jose_wrap_new_cek(&public_key, args.alg.hash())?;
        pools.push(
            (0..POOL_SIZE)
                .map(|_| jose_jwe_decrypt_body(&protected, &cek, &encrypted_key, &plaintext))
                .collect::<KmsCliResult<Vec<_>>>()?,
        );
    }
    let encrypt_body: Bytes = serde_json::to_vec(&JoseEncReq {
        kid: aes_kid.to_owned(),
        alg: "dir",
        enc: "A256GCM",
        data: b64url(&plaintext),
        aad: None,
    })
    .map_err(|e| KmsCliError::Default(format!("JOSE encrypt JSON serialization: {e}")))?
    .into();

    let start = Instant::now() + Duration::from_millis(100);
    let measure_start = start + warmup;
    let shared = Arc::new(Shared {
        servers,
        pools,
        encrypt_body,
        rate: u64::from(args.rate),
        workers: args.workers.to_u64().unwrap_or(1),
        start,
        measure_start,
        switch: measure_start + Duration::from_secs(args.switch_at),
        end: measure_start + duration,
    });
    eprintln!(
        "[cek-switch] {} msg/s over {} server(s), {} workers, warmup {}s, measurement {}s, CEK switch at +{}s",
        args.rate,
        urls.len(),
        args.workers,
        warmup.as_secs(),
        duration.as_secs(),
        args.switch_at
    );

    let mut samples = rt.block_on(async {
        let mut set = JoinSet::new();
        for w in 0..shared.workers {
            set.spawn(run_worker(w, Arc::clone(&shared)));
        }
        let mut samples = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(s) => samples.extend(s),
                Err(e) => eprintln!("[cek-switch] Warning: a worker failed: {e}"),
            }
        }
        samples
    });
    samples.sort_by_key(|s| s.t_us);

    let duration_ms = duration.as_millis().to_u64().unwrap_or(u64::MAX);
    let (timeline, per_server) =
        summarize(&samples, urls.len(), args.switch_at * 1000, duration_ms);
    let completed = samples
        .iter()
        .filter(|s| s.ok && s.done_us < us(duration))
        .count();
    let rate_achieved =
        completed.to_f64().unwrap_or(f64::NAN) / duration.as_secs().to_f64().unwrap_or(f64::NAN);
    let scheduled = duration.as_secs() * u64::from(args.rate);
    let unsent = scheduled.saturating_sub(samples.len().to_u64().unwrap_or(0));
    if rate_achieved < 0.95 * f64::from(args.rate) {
        eprintln!(
            "[cek-switch] WARNING: achieved {rate_achieved:.0} msg/s < 95% of target {} ({unsent} unsent); raise --cek-switch-workers or run the client on another host",
            args.rate
        );
    }
    for s in &per_server {
        eprintln!(
            "[cek-switch] {}: pre p99={:.1}ms | first 1s p99={:.1}ms max={:.1}ms | peak={:.1}ms | recovery={}ms | slow={} | errors={}",
            s.server,
            s.pre_switch.message_p99_ms,
            s.post_switch_1s.message_p99_ms,
            s.post_switch_1s.message_max_ms,
            s.peak_message_ms,
            s.recovery_ms
                .map_or_else(|| "none".to_owned(), |r| r.to_string()),
            s.slow_messages,
            s.errors
        );
    }

    let mut jsonl = String::new();
    for bucket in &timeline {
        jsonl.push_str(
            &serde_json::to_string(bucket)
                .map_err(|e| KmsCliError::Default(format!("timeline serialization: {e}")))?,
        );
        jsonl.push('\n');
    }
    write_file("cek_switch_timeline.json", &jsonl)?;

    let summary = Summary {
        urls,
        alg: args.alg.jwa(),
        rate_target: args.rate,
        workers: args.workers,
        plaintext_size,
        warmup_s: warmup.as_secs(),
        duration_s: duration.as_secs(),
        switch_at_s: args.switch_at,
        bucket_ms: BUCKET_MS,
        rate_achieved,
        unsent,
        per_server,
    };
    write_file(
        "cek_switch_summary.json",
        &serde_json::to_string_pretty(&summary)
            .map_err(|e| KmsCliError::Default(format!("summary serialization: {e}")))?,
    )?;

    let mut csv = String::from("t_ms,server,generation,ok,decrypt_ms,message_ms\n");
    for s in &samples {
        writeln!(
            csv,
            "{:.3},kms{},{},{},{:.3},{:.3}",
            ms(s.t_us),
            s.server + 1,
            s.generation,
            s.ok,
            ms(s.decrypt_us),
            ms(s.message_us)
        )
        .map_err(|e| KmsCliError::Default(format!("samples serialization: {e}")))?;
    }
    write_file("cek_switch_samples.csv", &csv)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ::clap::Parser as _;
    use cosmian_kms_client::jose::JoseKeyReq;
    use serial_test::serial;
    use test_kms_server::start_default_test_kms_server;

    use super::{Sample, criterion_home, summarize};
    use crate::actions::bench::types::BenchAction;

    fn sample(t_ms: u64, message_ms: u64) -> Sample {
        Sample {
            t_us: t_ms * 1000,
            done_us: t_ms * 1000 + message_ms * 1000,
            server: 0,
            generation: 0,
            ok: true,
            decrypt_us: message_ms * 500,
            message_us: message_ms * 1000,
        }
    }

    #[test]
    fn summarize_recovery() {
        // 1 ms messages, except 50 ms during the first 300 ms after the switch (2 s).
        let samples: Vec<Sample> = (0..1000)
            .map(|k| k * 10)
            .map(|t| sample(t, if (2000..2300).contains(&t) { 50 } else { 1 }))
            .collect();
        let (timeline, summaries) = summarize(&samples, 1, 2000, 10_000);
        let all = summaries.first().unwrap();
        assert_eq!(all.server, "all");
        assert_eq!(all.recovery_ms, Some(300));
        assert_eq!(all.slow_messages, 30);
        let at_switch = timeline
            .iter()
            .find(|b| b.server == "all" && b.t_ms == 2000)
            .unwrap();
        assert!((at_switch.stats.message_p99_ms - 50.0).abs() < f64::EPSILON);
        assert_eq!(summaries[1].server, "kms1");
    }

    /// Without any pre-switch baseline (e.g. the sender never reached the window) there is
    /// no recovery to report.
    #[test]
    fn summarize_no_baseline_no_recovery() {
        let samples: Vec<Sample> = (0..500).map(|k| sample(3000 + k * 10, 1)).collect();
        let (_, summaries) = summarize(&samples, 1, 2000, 10_000);
        assert_eq!(summaries[0].recovery_ms, None);
    }

    #[tokio::test]
    #[serial(bench_files)]
    async fn cek_switch_end_to_end() {
        let ctx = start_default_test_kms_server().await;
        let owner = ctx.get_owner_client();
        let rsa = owner
            .jose_create_key(JoseKeyReq {
                kty: "RSA",
                alg: Some("RSA-OAEP-256"),
                crv: None,
                bits: Some(2048),
            })
            .await
            .unwrap();
        let aes = owner
            .jose_create_key(JoseKeyReq {
                kty: "oct",
                alg: Some("A256GCM"),
                crv: None,
                bits: None,
            })
            .await
            .unwrap();
        let url = owner.config.http_config.server_url.clone();
        let action = BenchAction::try_parse_from([
            "bench",
            "--cek-switch",
            "--cek-switch-url",
            &url,
            "--cek-switch-rsa-kid",
            &rsa.kid_public.unwrap(),
            "--cek-switch-aes-kid",
            &aes.kid,
            "--cek-switch-alg",
            "RSA-OAEP-256",
            "--cek-switch-rate",
            "50",
            "--cek-switch-workers",
            "4",
            "--cek-switch-at",
            "1",
            "--time",
            "3",
            "--warmup-time",
            "1",
            "--load-plaintext-size",
            "64",
        ])
        .unwrap();
        action.process(owner).await.unwrap();
        let summary: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(criterion_home().join("cek_switch_summary.json")).unwrap(),
        )
        .unwrap();
        let per_server = summary["per_server"].as_array().unwrap();
        assert_eq!(per_server[0]["errors"], 0);
        assert!(per_server[0]["samples"].as_u64().unwrap() >= 100);
        assert_eq!(per_server[1]["server"], "kms1");
        assert_eq!(per_server[2]["server"], "kms2");
    }
}
