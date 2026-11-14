use std::{borrow::Cow, sync::Arc, time::Instant};

use actix_web::{HttpRequest, HttpResponse, get, web::Data};
use cosmian_kms_interfaces::HSM;
use cosmian_kms_server_database::MainDbKind;
use cosmian_logger::info;
use serde::Serialize;

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
}

#[derive(Serialize, Debug)]
pub(crate) struct HealthResponse {
    status: HealthStatus,
    latency_ms: u128,
    dependencies: Dependencies,
}

/// Health endpoint for load balancers and service dependency checks.
///
/// Returns JSON with a global UP/DOWN status and per-dependency status.
///
/// Notes:
/// - For SQL databases, performs a lightweight `SELECT 1`.
/// - For Redis-Findex (non-FIPS builds), performs a lightweight health check.
#[get("/health")]
pub(crate) async fn get_health(req: HttpRequest, kms: Data<Arc<KMS>>) -> KResult<HttpResponse> {
    info!("GET /health {}", kms.get_user(&req));

    let start = Instant::now();

    let (db_dep, hsm_deps) = health_dependencies(&kms).await;
    let global_status = overall_status(db_dep.status, &hsm_deps);

    let response = HealthResponse {
        status: global_status,
        latency_ms: start.elapsed().as_millis(),
        dependencies: Dependencies {
            database: db_dep,
            hsm: hsm_deps,
        },
    };

    let http_response = match response.status {
        HealthStatus::Up | HealthStatus::Degraded => actix_web::HttpResponse::Ok().json(response),
        HealthStatus::Down => actix_web::HttpResponse::ServiceUnavailable().json(response),
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

async fn check_hsm<'a>(
    hsm: Option<&Arc<dyn HSM + Send + Sync>>,
    slots: impl Iterator<Item = &'a usize>,
) -> Result<(), String> {
    let hsm = hsm.ok_or("HSM instance is not initialized")?;
    for slot in slots {
        hsm.check_slot(*slot)
            .await
            .map_err(|e| format!("slot {slot}: {e}"))?;
    }
    Ok(())
}

async fn health_dependencies(kms: &Arc<KMS>) -> (DependencyHealth, Vec<DependencyHealth>) {
    let db_name = match kms.database.main_db_kind() {
        MainDbKind::Sqlite => "sqlite",
        MainDbKind::Postgres => "postgres",
        MainDbKind::Mysql => "mysql",
        #[cfg(feature = "non-fips")]
        MainDbKind::RedisFindex => "redis-findex",
    };

    let start = Instant::now();
    let database = dependency(db_name, start, kms.database.health_check().await);

    let mut hsm_dependencies = Vec::with_capacity(kms.params.hsm_instances.len());
    for (index, instance) in kms.params.hsm_instances.iter().enumerate() {
        let start = Instant::now();
        let check = check_hsm(kms.hsm_instances.get(index), instance.slot_passwords.keys()).await;
        hsm_dependencies.push(dependency(instance.prefix.clone(), start, check));
    }

    (database, hsm_dependencies)
}

fn overall_status(database: HealthStatus, hsm: &[DependencyHealth]) -> HealthStatus {
    if database == HealthStatus::Down {
        HealthStatus::Down
    } else if hsm
        .iter()
        .any(|dependency| dependency.status == HealthStatus::Down)
    {
        HealthStatus::Degraded
    } else {
        HealthStatus::Up
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsm_failure_degrades_but_database_failure_is_down() {
        let failed_hsm = [DependencyHealth {
            name: Some("hsm::test".into()),
            status: HealthStatus::Down,
            latency_ms: 2,
            message: Some("slot unavailable".to_owned()),
        }];

        assert_eq!(
            overall_status(HealthStatus::Up, &failed_hsm),
            HealthStatus::Degraded
        );
        assert_eq!(
            overall_status(HealthStatus::Down, &failed_hsm),
            HealthStatus::Down
        );
        assert_eq!(overall_status(HealthStatus::Up, &[]), HealthStatus::Up);
    }
}
