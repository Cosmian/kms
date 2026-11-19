use std::{
    borrow::Cow,
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use actix_web::{
    HttpRequest, HttpResponse, get,
    web::{Data, Query},
};
use cosmian_kms_interfaces::InterfaceResult;
use cosmian_kms_server_database::MainDbKind;
use cosmian_logger::{info, warn};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::{core::KMS, result::KResult};

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
enum HealthStatus {
    Up,
    Degraded,
    Down,
}

#[derive(Serialize, Debug)]
struct DependencyHealth {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<Cow<'static, str>>,
    status: HealthStatus,
    latency_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Serialize, Debug)]
struct Dependencies {
    database: DependencyHealth,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hsm: Vec<DependencyHealth>,
    /// Only present when the KMIP socket server is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    kmip: Option<DependencyHealth>,
}

#[derive(Serialize, Debug)]
pub(crate) struct HealthResponse {
    status: HealthStatus,
    latency_ms: u128,
    dependencies: Dependencies,
}

#[derive(Deserialize)]
struct HealthQuery {
    /// Answer HTTP 503 when the node is `DEGRADED` too, so that a load balancer takes it out of
    /// its pool.
    #[serde(default)]
    strict: bool,
}

/// Health endpoint for load balancers and service dependency checks.
///
/// Returns JSON with a global UP/DEGRADED/DOWN status and per-dependency status.
///
/// Notes:
/// - Each HSM slot is probed with a bounded wait (see `HSM_PROBE_TIMEOUT`); an HSM that does
///   not answer in time makes the node `DEGRADED`, never a hanging health check.
/// - When the KMIP socket server is enabled, a socket server task that has ended makes the node
///   `DEGRADED`.
/// - `DEGRADED` answers HTTP 200, or HTTP 503 with `?strict=true`. `DOWN` always answers 503.
/// - For SQL databases, performs a lightweight `SELECT 1`.
/// - For Redis-Findex (non-FIPS builds), performs a lightweight health check.
#[get("/health")]
pub(crate) async fn get_health(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    query: Query<HealthQuery>,
) -> KResult<HttpResponse> {
    info!("GET /health {}", kms.get_user(&req));

    let start = Instant::now();

    let (db_dep, hsm_deps) = health_dependencies(&kms).await;
    let kmip_dep = kmip_socket_dependency(&kms);
    let global_status = overall_status(db_dep.status, &hsm_deps, kmip_dep.as_ref());

    let response = HealthResponse {
        status: global_status,
        latency_ms: start.elapsed().as_millis(),
        dependencies: Dependencies {
            database: db_dep,
            hsm: hsm_deps,
            kmip: kmip_dep,
        },
    };

    let http_response = if is_unavailable(response.status, query.strict) {
        actix_web::HttpResponse::ServiceUnavailable().json(response)
    } else {
        actix_web::HttpResponse::Ok().json(response)
    };

    Ok(http_response)
}

fn dependency(
    name: impl Into<Cow<'static, str>>,
    start: Instant,
    check: Result<(), String>,
) -> DependencyHealth {
    DependencyHealth {
        name: Some(name.into()),
        status: if check.is_ok() {
            HealthStatus::Up
        } else {
            HealthStatus::Down
        },
        latency_ms: start.elapsed().as_millis(),
        message: check.err(),
    }
}

/// Longest time `/health` waits for the database to answer. A database that accepts the connection
/// but never replies must report `DOWN` (HTTP 503), not leave the probe of a load balancer hanging.
const DB_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Longest time `/health` waits for one HSM slot to answer.
const HSM_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// What the public `/health` says when the database check fails: the error itself (driver, host,
/// user, SQL state, file paths...) goes to the server log only.
const DB_ERROR_PUBLIC: &str = "database check failed (details in the server log)";

/// What the public `/health` says when an HSM call fails: the PKCS#11 error goes to the server
/// log only.
const HSM_ERROR_PUBLIC: &str = "the HSM returned an error (details in the server log)";

/// Log the detail of a failed check and return the fixed text that `/health` may show.
fn log_and_redact(what: &str, detail: impl std::fmt::Display, public: &'static str) -> String {
    warn!("health check: {what}: {detail}");
    public.to_owned()
}

async fn probe_database(
    timeout: Duration,
    check: impl Future<Output = Result<(), String>>,
) -> Result<(), String> {
    tokio::time::timeout(timeout, check)
        .await
        .unwrap_or_else(|_| Err(format!("no answer within {} ms", timeout.as_millis())))
}

/// How long the answer of an HSM slot probe is reused by later `/health` calls.
const HSM_PROBE_TTL: Duration = Duration::from_secs(2);

/// State of the probes of one HSM slot.
#[derive(Default)]
struct SlotProbe {
    /// A probe that did not answer in time. Its blocking PKCS#11 call cannot be cancelled, so no
    /// new probe is started on this slot until it ends: repeated health checks cannot pile up
    /// blocked threads.
    in_flight: Option<JoinHandle<InterfaceResult<()>>>,
    /// Last probe result and when it was obtained.
    last: Option<(Instant, Result<(), String>)>,
}

/// Shared probe state of one HSM slot.
type SharedSlotProbe = Arc<tokio::sync::Mutex<SlotProbe>>;

/// Probe state of every HSM slot (keyed by instance index and slot ID), shared by all `/health`
/// calls of a node.
#[derive(Default)]
pub(crate) struct HsmProbes(Mutex<HashMap<(usize, usize), SharedSlotProbe>>);

impl HsmProbes {
    fn slot(&self, instance: usize, slot: usize) -> SharedSlotProbe {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry((instance, slot))
            .or_default()
            .clone()
    }
}

fn probe_result(joined: Result<InterfaceResult<()>, tokio::task::JoinError>) -> Result<(), String> {
    joined
        .map_err(|e| log_and_redact("HSM probe task", e, HSM_ERROR_PUBLIC))?
        .map_err(|e| log_and_redact("HSM", e, HSM_ERROR_PUBLIC))
}

/// Run `check` for one slot with a bounded wait, at most one probe in flight, and a short cache.
async fn probe_slot<F, Fut>(
    state: &tokio::sync::Mutex<SlotProbe>,
    timeout: Duration,
    ttl: Duration,
    check: F,
) -> Result<(), String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = InterfaceResult<()>> + Send + 'static,
{
    let mut probe = state.lock().await;

    if probe
        .in_flight
        .as_ref()
        .is_some_and(JoinHandle::is_finished)
        && let Some(finished) = probe.in_flight.take()
    {
        probe.last = Some((Instant::now(), probe_result(finished.await)));
    }
    if probe.in_flight.is_some() {
        return Err("the previous probe is still waiting for the HSM".to_owned());
    }
    if let Some((at, result)) = &probe.last
        && at.elapsed() < ttl
    {
        return result.clone();
    }

    let mut handle = tokio::spawn(check());
    let result = match tokio::time::timeout(timeout, &mut handle).await {
        Ok(joined) => probe_result(joined),
        Err(_elapsed) => {
            probe.in_flight = Some(handle);
            Err(format!("no answer within {} ms", timeout.as_millis()))
        }
    };
    probe.last = Some((Instant::now(), result.clone()));
    result
}

async fn check_hsm(kms: &KMS, index: usize, slots: Vec<usize>) -> Result<(), String> {
    let hsm = kms
        .hsm_instances
        .get(index)
        .ok_or("HSM instance is not initialized")?;
    join_all(slots.into_iter().map(|slot| {
        let state = kms.hsm_probes.slot(index, slot);
        let hsm = hsm.clone();
        async move {
            probe_slot(
                &state,
                HSM_PROBE_TIMEOUT,
                HSM_PROBE_TTL,
                move || async move { hsm.check_slot(slot).await },
            )
            .await
            .map_err(|e| format!("slot {slot}: {e}"))
        }
    }))
    .await
    .into_iter()
    .collect()
}

async fn health_dependencies(kms: &Arc<KMS>) -> (DependencyHealth, Vec<DependencyHealth>) {
    let db_name = match kms.database.main_db_kind() {
        MainDbKind::Sqlite => "sqlite",
        MainDbKind::Postgres => "postgres",
        MainDbKind::Mysql => "mysql",
        #[cfg(feature = "non-fips")]
        MainDbKind::RedisFindex => "redis-findex",
    };

    // Both probes run concurrently so a silent database and a silent HSM cost 2 s, not 4 s.
    let database = async {
        let start = Instant::now();
        let check = probe_database(DB_PROBE_TIMEOUT, async {
            kms.database
                .health_check()
                .await
                .map_err(|e| log_and_redact(db_name, e, DB_ERROR_PUBLIC))
        })
        .await;
        dependency(db_name, start, check)
    };

    let hsm_dependencies = join_all(kms.params.hsm_instances.iter().enumerate().map(
        |(index, instance)| async move {
            let start = Instant::now();
            let slots = instance.slot_passwords.keys().copied().collect();
            let check = check_hsm(kms, index, slots).await;
            dependency(instance.prefix.clone(), start, check)
        },
    ));

    tokio::join!(database, hsm_dependencies)
}

fn overall_status(
    database: HealthStatus,
    hsm: &[DependencyHealth],
    kmip: Option<&DependencyHealth>,
) -> HealthStatus {
    if database == HealthStatus::Down {
        HealthStatus::Down
    } else if hsm
        .iter()
        .chain(kmip)
        .any(|dependency| dependency.status == HealthStatus::Down)
    {
        HealthStatus::Degraded
    } else {
        HealthStatus::Up
    }
}

/// Whether `/health` answers HTTP 503: always when `DOWN`, and when `DEGRADED` in strict mode.
fn is_unavailable(status: HealthStatus, strict: bool) -> bool {
    status == HealthStatus::Down || (strict && status == HealthStatus::Degraded)
}

/// The KMIP socket server runs in one task for the whole life of the process: it only ends when
/// it fails, and the node then no longer serves KMIP over TCP although HTTP still answers.
fn kmip_socket_check(task: Option<&JoinHandle<()>>) -> Result<(), String> {
    if task.is_some_and(|task| !task.is_finished()) {
        Ok(())
    } else {
        Err("the KMIP socket server is not running (details in the server log)".to_owned())
    }
}

fn kmip_socket_dependency(kms: &KMS) -> Option<DependencyHealth> {
    kms.params.start_socket_server.then(|| {
        dependency(
            "kmip",
            Instant::now(),
            kmip_socket_check(kms.socket_server_task.get()),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use cosmian_kms_interfaces::InterfaceError;

    use super::*;

    const TIMEOUT: Duration = Duration::from_millis(50);
    const TTL: Duration = Duration::from_millis(100);

    #[tokio::test]
    async fn error_details_are_logged_not_returned() {
        let detail =
            "password authentication failed for user \"kms\" at 10.0.0.5:5432, slot 1 rc=0x30";

        let hsm_error = probe_result(Ok(Err(InterfaceError::Default(detail.to_owned()))));
        assert_eq!(hsm_error, Err(HSM_ERROR_PUBLIC.to_owned()));

        let aborted = tokio::spawn(std::future::pending::<InterfaceResult<()>>());
        aborted.abort();
        assert_eq!(
            probe_result(aborted.await),
            Err(HSM_ERROR_PUBLIC.to_owned())
        );

        assert_eq!(
            log_and_redact("postgres", detail, DB_ERROR_PUBLIC),
            DB_ERROR_PUBLIC
        );
    }

    #[tokio::test]
    async fn hung_hsm_times_out_and_is_never_probed_twice() {
        let state = tokio::sync::Mutex::new(SlotProbe::default());
        let started = Arc::new(AtomicUsize::new(0));
        let hang = || {
            let started = started.clone();
            move || async move {
                started.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<InterfaceResult<()>>().await
            }
        };

        let first = probe_slot(&state, TIMEOUT, TTL, hang()).await;
        assert!(first.is_err_and(|e| e.contains("no answer")));
        // Later calls (after the cache expired) must not start another probe.
        tokio::time::sleep(TTL * 2).await;
        let second = probe_slot(&state, TIMEOUT, TTL, hang()).await;
        assert!(second.is_err_and(|e| e.contains("still waiting")));
        assert_eq!(started.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn probe_result_is_cached_for_the_ttl() {
        let state = tokio::sync::Mutex::new(SlotProbe::default());
        let started = Arc::new(AtomicUsize::new(0));
        let ok = || {
            let started = started.clone();
            move || async move {
                started.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        };

        probe_slot(&state, TIMEOUT, TTL, ok())
            .await
            .expect("first probe");
        probe_slot(&state, TIMEOUT, TTL, ok())
            .await
            .expect("cached probe");
        assert_eq!(started.load(Ordering::SeqCst), 1);
        tokio::time::sleep(TTL * 2).await;
        probe_slot(&state, TIMEOUT, TTL, ok())
            .await
            .expect("probe after TTL");
        assert_eq!(started.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn silent_database_reports_down_instead_of_hanging() {
        let hung = probe_database(TIMEOUT, std::future::pending()).await;
        assert_eq!(hung, Err("no answer within 50 ms".to_owned()));

        assert_eq!(probe_database(TIMEOUT, async { Ok(()) }).await, Ok(()));
        assert_eq!(
            probe_database(TIMEOUT, async { Err("refused".to_owned()) }).await,
            Err("refused".to_owned())
        );
    }

    #[test]
    fn hsm_failure_degrades_but_database_failure_is_down() {
        let failed_hsm = [DependencyHealth {
            name: Some("hsm::test".into()),
            status: HealthStatus::Down,
            latency_ms: 2,
            message: Some("slot unavailable".to_owned()),
        }];

        assert_eq!(
            overall_status(HealthStatus::Up, &failed_hsm, None),
            HealthStatus::Degraded
        );
        assert_eq!(
            overall_status(HealthStatus::Down, &failed_hsm, None),
            HealthStatus::Down
        );
        assert_eq!(
            overall_status(HealthStatus::Up, &[], None),
            HealthStatus::Up
        );
    }

    #[tokio::test]
    async fn ended_kmip_socket_server_degrades_the_node() {
        let running = tokio::spawn(std::future::pending::<()>());
        assert_eq!(kmip_socket_check(Some(&running)), Ok(()));
        running.abort();

        let ended = tokio::spawn(async {});
        while !ended.is_finished() {
            tokio::task::yield_now().await;
        }
        assert!(kmip_socket_check(Some(&ended)).is_err());
        assert!(kmip_socket_check(None).is_err());

        let kmip_down = dependency("kmip", Instant::now(), kmip_socket_check(None));
        assert_eq!(
            overall_status(HealthStatus::Up, &[], Some(&kmip_down)),
            HealthStatus::Degraded
        );
    }

    #[test]
    fn strict_mode_turns_degraded_into_unavailable() {
        assert!(!is_unavailable(HealthStatus::Up, true));
        assert!(!is_unavailable(HealthStatus::Degraded, false));
        assert!(is_unavailable(HealthStatus::Degraded, true));
        assert!(is_unavailable(HealthStatus::Down, false));
    }
}
