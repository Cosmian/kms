use std::{sync::Arc, time::Instant};

use actix_web::{HttpRequest, HttpResponse, get, web::Data};
use cosmian_kms_server_database::MainDbKind;
use cosmian_logger::info;
use serde::Serialize;

use crate::{core::KMS, result::KResult};

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
enum HealthStatus {
    Up,
    Down,
}

#[derive(Serialize, Debug)]
struct DependencyHealth {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    status: HealthStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Serialize, Debug)]
struct Dependencies {
    database: DependencyHealth,
    #[serde(skip_serializing_if = "Option::is_none")]
    audit: Option<DependencyHealth>,
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

    let db_dep = health_dependencies(&kms).await;
    let audit_dep = audit_dependency(&kms);
    let global_status = if db_dep.status == HealthStatus::Up
        && audit_dep
            .as_ref()
            .is_none_or(|d| d.status == HealthStatus::Up)
    {
        HealthStatus::Up
    } else {
        HealthStatus::Down
    };

    let response = HealthResponse {
        status: global_status,
        latency_ms: start.elapsed().as_millis(),
        dependencies: Dependencies {
            database: db_dep,
            audit: audit_dep,
        },
    };

    let http_response = match response.status {
        HealthStatus::Up => actix_web::HttpResponse::Ok().json(response),
        HealthStatus::Down => actix_web::HttpResponse::ServiceUnavailable().json(response),
    };

    Ok(http_response)
}

async fn health_dependencies(kms: &Arc<KMS>) -> DependencyHealth {
    let db_name = match kms.database.main_db_kind() {
        MainDbKind::Sqlite => "sqlite",
        MainDbKind::Postgres => "postgres",
        MainDbKind::Mysql => "mysql",
        #[cfg(feature = "non-fips")]
        MainDbKind::RedisFindex => "redis-findex",
    };

    let db_check = kms.database.health_check().await;

    match db_check {
        Ok(()) => DependencyHealth {
            name: Some(db_name.to_owned()),
            status: HealthStatus::Up,
            message: None,
        },
        Err(e) => DependencyHealth {
            name: Some(db_name.to_owned()),
            status: HealthStatus::Down,
            message: Some(e),
        },
    }
}

/// `None` when audit logging isn't configured — the endpoint omits the dependency
/// entirely rather than reporting a misleading status for a disabled feature.
fn audit_dependency(kms: &KMS) -> Option<DependencyHealth> {
    kms.audit_store.as_ref().map(|store| {
        if store.is_healthy() {
            DependencyHealth {
                name: Some("audit".to_owned()),
                status: HealthStatus::Up,
                message: None,
            }
        } else {
            DependencyHealth {
                name: Some("audit".to_owned()),
                status: HealthStatus::Down,
                message: Some("writer task has stopped; audit logging is disabled".to_owned()),
            }
        }
    })
}
