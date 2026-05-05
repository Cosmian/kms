use std::{collections::HashMap, sync::Arc};

use actix_web::{
    HttpRequest, delete, get, post,
    web::{Data, Json, Path},
};
use cosmian_logger::info;
use serde::{Deserialize, Serialize};

use crate::{core::KMS, error::KmsError, result::KResult};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for assigning or removing a role.
#[derive(Debug, Deserialize)]
pub(crate) struct RoleRequest {
    /// The user to assign/remove the role to/from.
    pub user_id: String,
    /// The role name (e.g. "administrator", "operator", "auditor", "readonly").
    pub role: String,
}

/// Response for a successful role operation.
#[derive(Debug, Serialize)]
pub(crate) struct RoleResponse {
    pub success: bool,
    pub message: String,
}

/// A single role assignment entry.
#[derive(Debug, Serialize)]
pub(crate) struct RoleAssignment {
    pub user_id: String,
    pub role: String,
}

// ---------------------------------------------------------------------------
// Helpers — only administrators (privileged users) may manage roles
// ---------------------------------------------------------------------------

fn require_admin(kms: &KMS, user: &str) -> KResult<()> {
    let is_admin = kms
        .params
        .privileged_users
        .as_ref()
        .is_some_and(|pu| pu.contains(&user.to_owned()));

    if !is_admin {
        return Err(KmsError::Unauthorized(
            "Only privileged users may manage RBAC roles".to_owned(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// Assign a role to a user.
///
/// `POST /rbac/roles`
///
/// Only privileged users (administrators) may call this endpoint.
#[post("/rbac/roles")]
pub(crate) async fn assign_role(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<RoleRequest>,
) -> KResult<Json<RoleResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "assign_role");
    let _enter = span.enter();

    let caller = kms.get_user(&req);
    require_admin(&kms, &caller)?;

    info!(
        user = caller,
        target_user = body.user_id,
        role = body.role,
        "POST /rbac/roles — assign"
    );

    kms.database
        .assign_role(&body.user_id, &body.role)
        .await
        .map_err(|e| KmsError::ServerError(format!("Failed to assign role: {e}")))?;

    Ok(Json(RoleResponse {
        success: true,
        message: format!("Role '{}' assigned to user '{}'", body.role, body.user_id),
    }))
}

/// Remove a role from a user.
///
/// `DELETE /rbac/roles`
///
/// Only privileged users (administrators) may call this endpoint.
#[delete("/rbac/roles")]
pub(crate) async fn remove_role(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<RoleRequest>,
) -> KResult<Json<RoleResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "remove_role");
    let _enter = span.enter();

    let caller = kms.get_user(&req);
    require_admin(&kms, &caller)?;

    info!(
        user = caller,
        target_user = body.user_id,
        role = body.role,
        "DELETE /rbac/roles — remove"
    );

    kms.database
        .remove_role(&body.user_id, &body.role)
        .await
        .map_err(|e| KmsError::ServerError(format!("Failed to remove role: {e}")))?;

    Ok(Json(RoleResponse {
        success: true,
        message: format!("Role '{}' removed from user '{}'", body.role, body.user_id),
    }))
}

/// List roles assigned to a specific user.
///
/// `GET /rbac/roles/{user_id}`
///
/// Only privileged users (administrators) may call this endpoint.
#[get("/rbac/roles/{user_id}")]
pub(crate) async fn list_user_roles(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
) -> KResult<Json<Vec<String>>> {
    let span = tracing::span!(tracing::Level::ERROR, "list_user_roles");
    let _enter = span.enter();

    let caller = kms.get_user(&req);
    require_admin(&kms, &caller)?;

    let target_user = path.into_inner();
    info!(
        user = caller,
        target_user = target_user,
        "GET /rbac/roles/{target_user}"
    );

    let roles = kms
        .database
        .list_user_roles(&target_user)
        .await
        .map_err(|e| KmsError::ServerError(format!("Failed to list user roles: {e}")))?;

    Ok(Json(roles))
}

/// List all role assignments across all users.
///
/// `GET /rbac/roles`
///
/// Only privileged users (administrators) may call this endpoint.
#[get("/rbac/roles")]
pub(crate) async fn list_all_roles(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<Vec<RoleAssignment>>> {
    let span = tracing::span!(tracing::Level::ERROR, "list_all_roles");
    let _enter = span.enter();

    let caller = kms.get_user(&req);
    require_admin(&kms, &caller)?;

    info!(user = caller, "GET /rbac/roles");

    let assignments: HashMap<String, Vec<String>> = kms
        .database
        .list_all_role_assignments()
        .await
        .map_err(|e| KmsError::ServerError(format!("Failed to list role assignments: {e}")))?;

    let mut result: Vec<RoleAssignment> = Vec::new();
    for (user_id, roles) in assignments {
        for role in roles {
            result.push(RoleAssignment {
                user_id: user_id.clone(),
                role,
            });
        }
    }

    // Sort for deterministic output
    result.sort_by(|a, b| a.user_id.cmp(&b.user_id).then(a.role.cmp(&b.role)));

    Ok(Json(result))
}

/// Check whether RBAC enforcement is enabled on this server.
///
/// `GET /rbac/status`
///
/// This endpoint is accessible to all authenticated users.
#[get("/rbac/status")]
pub(crate) async fn rbac_status(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<RbacStatusResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "rbac_status");
    let _enter = span.enter();

    let caller = kms.get_user(&req);
    info!(user = caller, "GET /rbac/status");

    Ok(Json(RbacStatusResponse {
        enabled: kms.rbac_engine.is_some(),
        engine: if kms.rbac_engine.is_some() {
            if kms.params.rbac.opa_url.is_some() {
                "external_opa".to_owned()
            } else {
                "embedded_regorus".to_owned()
            }
        } else {
            "none".to_owned()
        },
    }))
}

/// RBAC status information.
#[derive(Debug, Serialize)]
pub(crate) struct RbacStatusResponse {
    /// Whether RBAC enforcement is active.
    pub enabled: bool,
    /// The engine type: `"embedded_regorus"`, `"external_opa"`, or `"none"`.
    pub engine: String,
}
