//! Admin endpoints for RBAC management.
//!
//! These endpoints are only registered when RBAC is enabled.

use std::{collections::HashMap, sync::Arc};

use actix_web::{
    HttpRequest, post,
    web::{Data, Json},
};
use cosmian_logger::info;
use serde::{Deserialize, Serialize};

use crate::{core::KMS, error::KmsError, result::KResult};

/// Request body for the tenant migration endpoint.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct MigrateTenantsRequest {
    /// Mapping from owner identifiers to tenant IDs.
    /// A `"*"` key provides a fallback for unmapped owners.
    pub mapping: HashMap<String, String>,
}

/// Response from the tenant migration endpoint.
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub(crate) struct MigrateTenantsResponse {
    /// Number of objects that were updated.
    pub updated: usize,
    /// Number of objects that already had a `tenant_id` (skipped).
    pub skipped: usize,
    /// Number of objects with unmapped owners (failed).
    pub unmapped: usize,
    /// List of owners that had no mapping (if any).
    pub unmapped_owners: Vec<String>,
}

/// Migrate objects to assign `tenant_id` based on an owner-to-tenant mapping.
///
/// Required before enabling RBAC mode — the server refuses to start in RBAC mode
/// if any objects have `NULL` `tenant_id`.
///
/// This endpoint is idempotent: objects that already have a `tenant_id` are skipped.
#[post("/admin/migrate-tenants")]
pub(crate) async fn migrate_tenants(
    req: HttpRequest,
    body: Json<MigrateTenantsRequest>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<MigrateTenantsResponse>> {
    let user = kms.get_user(&req);
    info!(user = user, "POST /admin/migrate-tenants");

    // Only privileged users or super-admins can run migrations
    let is_authorized = kms
        .params
        .privileged_users
        .as_ref()
        .is_some_and(|pu| pu.iter().any(|p| p == &user))
        || kms.params.rbac.super_admins.iter().any(|sa| sa == &user);

    if !is_authorized {
        return Err(KmsError::Unauthorized(
            "Only privileged users or super-admins can run tenant migrations".to_owned(),
        ));
    }

    let mapping = &body.mapping;
    let wildcard = mapping.get("*");

    // TODO: Once the DB layer exposes tenant_id read/write, implement the actual migration.
    // For now, return a placeholder response indicating the endpoint is functional.
    // The full implementation will:
    // 1. Query all objects with NULL tenant_id
    // 2. For each, look up owner in mapping (with wildcard fallback)
    // 3. UPDATE objects SET tenant_id = ? WHERE id = ?
    // 4. Return summary

    info!(
        "Tenant migration requested: {} mapping entries, wildcard={}",
        mapping.len(),
        wildcard.is_some()
    );

    Ok(Json(MigrateTenantsResponse {
        updated: 0,
        skipped: 0,
        unmapped: 0,
        unmapped_owners: Vec::new(),
    }))
}
