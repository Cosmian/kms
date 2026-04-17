use std::sync::Arc;

use actix_web::{
    HttpRequest, delete, get, post, put,
    web::{Data, Json, Path},
};
use cosmian_kms_access::access::SuccessResponse;
use cosmian_kms_access::rbac::{
    AssignRoleRequest, CreateRoleRequest, EffectivePermissionsResponse, Role,
    RoleHierarchyEdgesResponse, RoleHierarchyListResponse, RoleHierarchyTreeResponse,
    RolePermissionEntry, RolePermissionsRequest, RolePermissionsResponse, RoleResponse,
    RoleUsersResponse, RolesListResponse, UpdateRoleRequest,
};
use cosmian_logger::{debug, info};

use crate::{core::KMS, result::KResult};

// ── Handlers ────────────────────────────────────────────────────────────

/// Create a new role
#[post("/roles")]
pub(crate) async fn create_role(
    req: HttpRequest,
    body: Json<CreateRoleRequest>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<RoleResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "create_role");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let body = body.into_inner();
    info!(user = user, role_id = body.id, "POST /roles");

    let role = Role {
        id: body.id,
        name: body.name,
        description: body.description,
        builtin: false,
    };
    kms.database.create_role(&role).await?;
    debug!("Role created: {}", role.id);

    Ok(Json(RoleResponse { role }))
}

/// List all roles
#[get("/roles")]
pub(crate) async fn list_roles(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<RolesListResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "list_roles");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    info!(user = user, "GET /roles");

    let roles = kms.database.list_roles().await?;
    Ok(Json(RolesListResponse { roles }))
}

/// Get a role by ID (includes permissions and assigned users)
#[get("/roles/{role_id}")]
pub(crate) async fn get_role(
    req: HttpRequest,
    role_id: Path<String>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<RoleResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "get_role");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let role_id = role_id.into_inner();
    info!(user = user, role_id = role_id, "GET /roles/{role_id}");

    let role = kms.database.get_role(&role_id).await?;
    Ok(Json(RoleResponse { role }))
}

/// Update a role's name/description
#[put("/roles/{role_id}")]
pub(crate) async fn update_role(
    req: HttpRequest,
    role_id: Path<String>,
    body: Json<UpdateRoleRequest>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "update_role");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let role_id = role_id.into_inner();
    let body = body.into_inner();
    info!(user = user, role_id = role_id, "PUT /roles/{role_id}");

    let role = Role {
        id: role_id.clone(),
        name: body.name,
        description: body.description,
        builtin: false,
    };
    kms.database.update_role(&role).await?;

    Ok(Json(SuccessResponse {
        success: format!("Role '{role_id}' updated"),
    }))
}

/// Delete a role
#[delete("/roles/{role_id}")]
pub(crate) async fn delete_role(
    req: HttpRequest,
    role_id: Path<String>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "delete_role");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let role_id = role_id.into_inner();
    info!(user = user, role_id = role_id, "DELETE /roles/{role_id}");

    // Prevent deletion of built-in roles
    let existing = kms.database.get_role(&role_id).await?;
    if existing.builtin {
        return Err(crate::error::KmsError::InvalidRequest(format!(
            "Cannot delete built-in role '{role_id}'"
        )));
    }
    kms.database.delete_role(&role_id).await?;

    Ok(Json(SuccessResponse {
        success: format!("Role '{role_id}' deleted"),
    }))
}

/// Add permissions to a role
#[post("/roles/{role_id}/permissions")]
pub(crate) async fn add_role_permissions(
    req: HttpRequest,
    role_id: Path<String>,
    body: Json<RolePermissionsRequest>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "add_role_permissions");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let role_id = role_id.into_inner();
    let body = body.into_inner();
    info!(
        user = user,
        role_id = role_id,
        "POST /roles/{role_id}/permissions"
    );

    kms.database
        .assign_permissions_to_role(&role_id, &body.object_id, body.operations)
        .await?;

    Ok(Json(SuccessResponse {
        success: format!("Permissions added to role '{role_id}'"),
    }))
}

/// Remove permissions from a role
#[delete("/roles/{role_id}/permissions")]
pub(crate) async fn remove_role_permissions(
    req: HttpRequest,
    role_id: Path<String>,
    body: Json<RolePermissionsRequest>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "remove_role_permissions");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let role_id = role_id.into_inner();
    let body = body.into_inner();
    info!(
        user = user,
        role_id = role_id,
        "DELETE /roles/{role_id}/permissions"
    );

    kms.database
        .remove_permissions_from_role(&role_id, &body.object_id, body.operations)
        .await?;

    Ok(Json(SuccessResponse {
        success: format!("Permissions removed from role '{role_id}'"),
    }))
}

/// List permissions of a role
#[get("/roles/{role_id}/permissions")]
pub(crate) async fn list_role_permissions(
    req: HttpRequest,
    role_id: Path<String>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<RolePermissionsResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "list_role_permissions");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let role_id = role_id.into_inner();
    info!(
        user = user,
        role_id = role_id,
        "GET /roles/{role_id}/permissions"
    );

    let perms = kms.database.list_role_permissions(&role_id).await?;
    let permissions = perms
        .into_iter()
        .map(|(object_id, operations)| RolePermissionEntry {
            object_id,
            operations,
        })
        .collect();

    Ok(Json(RolePermissionsResponse { permissions }))
}

/// Assign a role to one or more users
#[post("/roles/{role_id}/users")]
pub(crate) async fn assign_role_to_users(
    req: HttpRequest,
    role_id: Path<String>,
    body: Json<AssignRoleRequest>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "assign_role_to_users");
    let _enter = span.enter();

    let granter = kms.get_user(&req);
    let role_id = role_id.into_inner();
    let body = body.into_inner();
    info!(
        user = granter,
        role_id = role_id,
        "POST /roles/{role_id}/users"
    );

    for user_id in &body.user_ids {
        kms.database
            .assign_role_to_user(user_id, &role_id, &granter)
            .await?;
    }

    Ok(Json(SuccessResponse {
        success: format!(
            "Role '{role_id}' assigned to {} user(s)",
            body.user_ids.len()
        ),
    }))
}

/// Revoke a role from a user
#[delete("/roles/{role_id}/users/{user_id}")]
pub(crate) async fn revoke_role_from_user(
    req: HttpRequest,
    path: Path<(String, String)>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "revoke_role_from_user");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let (role_id, target_user) = path.into_inner();
    info!(
        user = user,
        role_id = role_id,
        target = target_user,
        "DELETE /roles/{role_id}/users/{target_user}"
    );

    kms.database
        .revoke_role_from_user(&target_user, &role_id)
        .await?;

    Ok(Json(SuccessResponse {
        success: format!("Role '{role_id}' revoked from '{target_user}'"),
    }))
}

/// List users assigned to a role
#[get("/roles/{role_id}/users")]
pub(crate) async fn list_role_users(
    req: HttpRequest,
    role_id: Path<String>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<RoleUsersResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "list_role_users");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let role_id = role_id.into_inner();
    info!(user = user, role_id = role_id, "GET /roles/{role_id}/users");

    let users = kms.database.list_role_users(&role_id).await?;
    Ok(Json(RoleUsersResponse { users }))
}

/// List roles assigned to the current user (or a specific user)
#[get("/users/{user_id}/roles")]
pub(crate) async fn list_user_roles(
    req: HttpRequest,
    user_id: Path<String>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<RolesListResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "list_user_roles");
    let _enter = span.enter();

    let caller = kms.get_user(&req);
    let target_user = user_id.into_inner();
    info!(
        user = caller,
        target = target_user,
        "GET /users/{target_user}/roles"
    );

    let roles = kms.database.list_user_roles(&target_user).await?;
    Ok(Json(RolesListResponse { roles }))
}

/// Get effective permissions for a user on a specific object
#[get("/users/{user_id}/effective-permissions/{object_id}")]
pub(crate) async fn get_effective_permissions(
    req: HttpRequest,
    path: Path<(String, String)>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<EffectivePermissionsResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "get_effective_permissions");
    let _enter = span.enter();

    let caller = kms.get_user(&req);
    let (target_user, object_id) = path.into_inner();
    info!(
        user = caller,
        target = target_user,
        object_id = object_id,
        "GET /users/{target_user}/effective-permissions/{object_id}"
    );

    // Gather direct grants and role-based grants
    let direct = kms
        .database
        .list_user_operations_on_object(&object_id, &target_user, false)
        .await?;
    let role_based = kms
        .database
        .role_based_operations_on_object(&object_id, &target_user)
        .await?;

    let operations = match kms.params.rbac.enforcement_mode {
        cosmian_kms_access::rbac::RbacEnforcementMode::Additive => {
            // Union: any permission source is sufficient
            let mut ops = direct;
            ops.extend(role_based);
            ops
        }
        cosmian_kms_access::rbac::RbacEnforcementMode::Restrictive => {
            // Role ceiling: if the user has roles, direct grants are capped
            // at what the roles allow. If no roles, fall back to direct grants only.
            if role_based.is_empty() {
                direct
            } else {
                // Intersection: only keep operations that appear in the role set
                direct
                    .into_iter()
                    .filter(|op| role_based.contains(op))
                    .collect::<std::collections::HashSet<_>>()
                    .union(&role_based)
                    .cloned()
                    .collect()
            }
        }
    };

    Ok(Json(EffectivePermissionsResponse { operations }))
}

// ── Hierarchy endpoints ─────────────────────────────────────────────────

/// Add a hierarchy edge: senior inherits junior's permissions
#[post("/roles/{senior_id}/juniors/{junior_id}")]
pub(crate) async fn add_hierarchy_edge(
    req: HttpRequest,
    path: Path<(String, String)>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "add_hierarchy_edge");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let (senior_id, junior_id) = path.into_inner();
    info!(
        user = user,
        senior = senior_id,
        junior = junior_id,
        "POST /roles/{senior_id}/juniors/{junior_id}"
    );

    kms.database
        .add_hierarchy_edge(&senior_id, &junior_id)
        .await?;
    Ok(Json(SuccessResponse {
        success: format!("Hierarchy edge added: '{senior_id}' → '{junior_id}'"),
    }))
}

/// Remove a hierarchy edge
#[delete("/roles/{senior_id}/juniors/{junior_id}")]
pub(crate) async fn remove_hierarchy_edge(
    req: HttpRequest,
    path: Path<(String, String)>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "remove_hierarchy_edge");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let (senior_id, junior_id) = path.into_inner();
    info!(
        user = user,
        senior = senior_id,
        junior = junior_id,
        "DELETE /roles/{senior_id}/juniors/{junior_id}"
    );

    kms.database
        .remove_hierarchy_edge(&senior_id, &junior_id)
        .await?;
    Ok(Json(SuccessResponse {
        success: format!("Hierarchy edge removed: '{senior_id}' → '{junior_id}'"),
    }))
}

/// List direct junior roles
#[get("/roles/{role_id}/juniors")]
pub(crate) async fn list_junior_roles(
    req: HttpRequest,
    role_id: Path<String>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<RoleHierarchyListResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "list_junior_roles");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let role_id = role_id.into_inner();
    info!(user = user, role_id = role_id, "GET /roles/{role_id}/juniors");

    let roles = kms.database.list_junior_roles(&role_id).await?;
    Ok(Json(RoleHierarchyListResponse { roles }))
}

/// List direct senior roles
#[get("/roles/{role_id}/seniors")]
pub(crate) async fn list_senior_roles(
    req: HttpRequest,
    role_id: Path<String>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<RoleHierarchyListResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "list_senior_roles");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let role_id = role_id.into_inner();
    info!(user = user, role_id = role_id, "GET /roles/{role_id}/seniors");

    let roles = kms.database.list_senior_roles(&role_id).await?;
    Ok(Json(RoleHierarchyListResponse { roles }))
}

/// Get the full hierarchy tree rooted at a role
#[get("/roles/{role_id}/hierarchy")]
pub(crate) async fn get_role_hierarchy_tree(
    req: HttpRequest,
    role_id: Path<String>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<RoleHierarchyTreeResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "get_role_hierarchy_tree");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    let role_id = role_id.into_inner();
    info!(user = user, role_id = role_id, "GET /roles/{role_id}/hierarchy");

    let tree = kms.database.get_role_hierarchy_tree(&role_id).await?;
    Ok(Json(RoleHierarchyTreeResponse { tree }))
}

/// Get all hierarchy edges in the system
#[get("/roles-hierarchy")]
pub(crate) async fn list_all_hierarchy_edges(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<RoleHierarchyEdgesResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "list_all_hierarchy_edges");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    info!(user = user, "GET /roles-hierarchy");

    let edges = kms.database.list_all_hierarchy_edges().await?;
    Ok(Json(RoleHierarchyEdgesResponse { edges }))
}
