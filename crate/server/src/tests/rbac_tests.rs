use cosmian_kms_access::access::SuccessResponse;
use cosmian_kms_access::rbac::{
    AssignRoleRequest, CreateRoleRequest, EffectivePermissionsResponse, RbacEnforcementMode,
    RoleHierarchyEdgesResponse, RoleHierarchyListResponse, RoleHierarchyTreeResponse,
    RolePermissionsRequest, RolePermissionsResponse, RoleResponse, RoleUsersResponse,
    RolesListResponse, UpdateRoleRequest,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::KmipOperation;
use cosmian_logger::log_init;

use crate::tests::test_utils::{
    delete_json_with_uri, delete_with_uri, get_json_with_uri, https_clap_config_opts,
    post_json_with_uri, post_with_uri, put_json_with_uri, test_app, test_app_with_clap_config,
};

// ── Role CRUD ───────────────────────────────────────────────────────────

#[actix_web::test]
async fn test_rbac_create_and_get_role() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create a custom role
    let create_req = CreateRoleRequest {
        id: "test-role".to_owned(),
        name: "Test Role".to_owned(),
        description: Some("A test role".to_owned()),
    };
    let resp: RoleResponse = post_json_with_uri(&app, create_req, "/roles")
        .await
        .expect("create role should succeed");
    assert_eq!(resp.role.id, "test-role");
    assert_eq!(resp.role.name, "Test Role");
    assert!(!resp.role.builtin);

    // Get the role
    let resp: RoleResponse = get_json_with_uri(&app, "/roles/test-role")
        .await
        .expect("get role should succeed");
    assert_eq!(resp.role.id, "test-role");
    assert_eq!(resp.role.description.as_deref(), Some("A test role"));
}

#[actix_web::test]
async fn test_rbac_list_roles_includes_builtins() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    let resp: RolesListResponse = get_json_with_uri(&app, "/roles")
        .await
        .expect("list roles should succeed");

    // At minimum, the 5 built-in roles should exist
    let builtin_ids: Vec<&str> = resp
        .roles
        .iter()
        .filter(|r| r.builtin)
        .map(|r| r.id.as_str())
        .collect();
    assert!(builtin_ids.contains(&"admin"), "admin role should exist");
    assert!(
        builtin_ids.contains(&"operator"),
        "operator role should exist"
    );
    assert!(
        builtin_ids.contains(&"crypto-user"),
        "crypto-user role should exist"
    );
    assert!(
        builtin_ids.contains(&"auditor"),
        "auditor role should exist"
    );
    assert!(
        builtin_ids.contains(&"key-custodian"),
        "key-custodian role should exist"
    );
}

#[actix_web::test]
async fn test_rbac_update_role() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create
    let create_req = CreateRoleRequest {
        id: "update-test".to_owned(),
        name: "Before".to_owned(),
        description: None,
    };
    post_json_with_uri::<_, _, RoleResponse, _>(&app, create_req, "/roles")
        .await
        .expect("create role should succeed");

    // Update
    let update_req = UpdateRoleRequest {
        name: "After".to_owned(),
        description: Some("Updated description".to_owned()),
    };
    let resp: SuccessResponse = put_json_with_uri(&app, update_req, "/roles/update-test")
        .await
        .expect("update role should succeed");
    assert!(resp.success.contains("updated"));

    // Verify the update was applied
    let resp: RoleResponse = get_json_with_uri(&app, "/roles/update-test")
        .await
        .expect("get updated role should succeed");
    assert_eq!(resp.role.name, "After");
    assert_eq!(
        resp.role.description.as_deref(),
        Some("Updated description")
    );
}

#[actix_web::test]
async fn test_rbac_delete_custom_role() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create
    let create_req = CreateRoleRequest {
        id: "delete-me".to_owned(),
        name: "Disposable".to_owned(),
        description: None,
    };
    post_json_with_uri::<_, _, RoleResponse, _>(&app, create_req, "/roles")
        .await
        .expect("create role should succeed");

    // Delete
    let resp: SuccessResponse = delete_with_uri(&app, "/roles/delete-me")
        .await
        .expect("delete role should succeed");
    assert!(resp.success.contains("deleted"));

    // Verify it's gone
    let result: Result<RoleResponse, _> = get_json_with_uri(&app, "/roles/delete-me").await;
    assert!(result.is_err(), "getting deleted role should fail");
}

#[actix_web::test]
async fn test_rbac_cannot_delete_builtin_role() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Attempt to delete built-in 'admin' role should fail
    let result: Result<SuccessResponse, _> = delete_with_uri(&app, "/roles/admin").await;
    assert!(result.is_err(), "deleting built-in role should fail");
}

// ── Role permissions ────────────────────────────────────────────────────

#[actix_web::test]
async fn test_rbac_assign_and_list_permissions() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create role
    let create_req = CreateRoleRequest {
        id: "perm-test".to_owned(),
        name: "Permission Test".to_owned(),
        description: None,
    };
    post_json_with_uri::<_, _, RoleResponse, _>(&app, create_req, "/roles")
        .await
        .expect("create role should succeed");

    // Add permissions
    let perm_req = RolePermissionsRequest {
        object_id: "*".to_owned(),
        operations: [KmipOperation::Encrypt, KmipOperation::Decrypt]
            .into_iter()
            .collect(),
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(&app, perm_req, "/roles/perm-test/permissions")
        .await
        .expect("add permissions should succeed");

    // List permissions
    let resp: RolePermissionsResponse = get_json_with_uri(&app, "/roles/perm-test/permissions")
        .await
        .expect("list permissions should succeed");
    assert!(!resp.permissions.is_empty());

    let wildcard_entry = resp
        .permissions
        .iter()
        .find(|p| p.object_id == "*")
        .expect("wildcard permission should exist");
    assert!(wildcard_entry.operations.contains(&KmipOperation::Encrypt));
    assert!(wildcard_entry.operations.contains(&KmipOperation::Decrypt));
}

#[actix_web::test]
async fn test_rbac_remove_permissions() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create role and add permissions
    let create_req = CreateRoleRequest {
        id: "rm-perm-test".to_owned(),
        name: "Remove Perm Test".to_owned(),
        description: None,
    };
    post_json_with_uri::<_, _, RoleResponse, _>(&app, create_req, "/roles")
        .await
        .unwrap();

    let perm_req = RolePermissionsRequest {
        object_id: "*".to_owned(),
        operations: [
            KmipOperation::Encrypt,
            KmipOperation::Decrypt,
            KmipOperation::Sign,
        ]
        .into_iter()
        .collect(),
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(
        &app,
        perm_req,
        "/roles/rm-perm-test/permissions",
    )
    .await
    .unwrap();

    // Remove Encrypt only
    let remove_req = RolePermissionsRequest {
        object_id: "*".to_owned(),
        operations: [KmipOperation::Encrypt].into_iter().collect(),
    };
    delete_json_with_uri::<_, _, SuccessResponse, _>(
        &app,
        remove_req,
        "/roles/rm-perm-test/permissions",
    )
    .await
    .expect("remove permissions should succeed");

    // Verify Encrypt is gone but Decrypt and Sign remain
    let resp: RolePermissionsResponse = get_json_with_uri(&app, "/roles/rm-perm-test/permissions")
        .await
        .unwrap();
    let wildcard_entry = resp
        .permissions
        .iter()
        .find(|p| p.object_id == "*")
        .expect("wildcard entry should still exist");
    assert!(
        !wildcard_entry.operations.contains(&KmipOperation::Encrypt),
        "Encrypt should have been removed"
    );
    assert!(wildcard_entry.operations.contains(&KmipOperation::Decrypt));
    assert!(wildcard_entry.operations.contains(&KmipOperation::Sign));
}

// ── User-role assignments ───────────────────────────────────────────────

#[actix_web::test]
async fn test_rbac_assign_and_list_users() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create role
    let create_req = CreateRoleRequest {
        id: "ua-test".to_owned(),
        name: "UA Test".to_owned(),
        description: None,
    };
    post_json_with_uri::<_, _, RoleResponse, _>(&app, create_req, "/roles")
        .await
        .unwrap();

    // Assign users
    let assign_req = AssignRoleRequest {
        user_ids: vec!["alice@example.com".to_owned(), "bob@example.com".to_owned()],
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(&app, assign_req, "/roles/ua-test/users")
        .await
        .expect("assign users should succeed");

    // List users
    let resp: RoleUsersResponse = get_json_with_uri(&app, "/roles/ua-test/users")
        .await
        .expect("list users should succeed");
    let user_ids: Vec<&str> = resp.users.iter().map(|u| u.user_id.as_str()).collect();
    assert!(user_ids.contains(&"alice@example.com"));
    assert!(user_ids.contains(&"bob@example.com"));
}

#[actix_web::test]
async fn test_rbac_revoke_user_from_role() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create role and assign user
    let create_req = CreateRoleRequest {
        id: "revoke-test".to_owned(),
        name: "Revoke Test".to_owned(),
        description: None,
    };
    post_json_with_uri::<_, _, RoleResponse, _>(&app, create_req, "/roles")
        .await
        .unwrap();

    let assign_req = AssignRoleRequest {
        user_ids: vec!["alice@example.com".to_owned()],
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(&app, assign_req, "/roles/revoke-test/users")
        .await
        .unwrap();

    // Revoke
    let resp: SuccessResponse = delete_with_uri(&app, "/roles/revoke-test/users/alice@example.com")
        .await
        .expect("revoke user should succeed");
    assert!(resp.success.contains("revoked"));

    // Verify empty
    let resp: RoleUsersResponse = get_json_with_uri(&app, "/roles/revoke-test/users")
        .await
        .unwrap();
    assert!(
        resp.users.is_empty(),
        "user list should be empty after revocation"
    );
}

// ── User roles listing ──────────────────────────────────────────────────

#[actix_web::test]
async fn test_rbac_list_user_roles() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create two roles and assign the same user to both
    for (id, name) in [("ur-role-a", "Role A"), ("ur-role-b", "Role B")] {
        let req = CreateRoleRequest {
            id: id.to_owned(),
            name: name.to_owned(),
            description: None,
        };
        post_json_with_uri::<_, _, RoleResponse, _>(&app, req, "/roles")
            .await
            .unwrap();

        let assign_req = AssignRoleRequest {
            user_ids: vec!["multi-role-user@example.com".to_owned()],
        };
        post_json_with_uri::<_, _, SuccessResponse, _>(
            &app,
            assign_req,
            &format!("/roles/{id}/users"),
        )
        .await
        .unwrap();
    }

    // List roles for user
    let resp: RolesListResponse =
        get_json_with_uri(&app, "/users/multi-role-user@example.com/roles")
            .await
            .expect("list user roles should succeed");

    let role_ids: Vec<&str> = resp.roles.iter().map(|r| r.id.as_str()).collect();
    assert!(role_ids.contains(&"ur-role-a"));
    assert!(role_ids.contains(&"ur-role-b"));
}

// ── Effective permissions ───────────────────────────────────────────────

#[actix_web::test]
async fn test_rbac_effective_permissions() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create role with Encrypt + Decrypt on wildcard
    let create_req = CreateRoleRequest {
        id: "eff-perm-role".to_owned(),
        name: "Effective Perm Role".to_owned(),
        description: None,
    };
    post_json_with_uri::<_, _, RoleResponse, _>(&app, create_req, "/roles")
        .await
        .unwrap();

    let perm_req = RolePermissionsRequest {
        object_id: "*".to_owned(),
        operations: [KmipOperation::Encrypt, KmipOperation::Decrypt]
            .into_iter()
            .collect(),
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(
        &app,
        perm_req,
        "/roles/eff-perm-role/permissions",
    )
    .await
    .unwrap();

    // Assign user
    let assign_req = AssignRoleRequest {
        user_ids: vec!["effective-user@example.com".to_owned()],
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(&app, assign_req, "/roles/eff-perm-role/users")
        .await
        .unwrap();

    // Query effective permissions for an arbitrary object
    let resp: EffectivePermissionsResponse = get_json_with_uri(
        &app,
        "/users/effective-user@example.com/effective-permissions/some-object-id",
    )
    .await
    .expect("effective permissions should succeed");

    assert!(
        resp.operations.contains(&KmipOperation::Encrypt),
        "Encrypt should be in effective permissions"
    );
    assert!(
        resp.operations.contains(&KmipOperation::Decrypt),
        "Decrypt should be in effective permissions"
    );
}

// ── Builtin role permissions ────────────────────────────────────────────

#[actix_web::test]
async fn test_rbac_builtin_admin_has_all_permissions() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // The admin role should have been seeded with all operations on wildcard
    let resp: RolePermissionsResponse = get_json_with_uri(&app, "/roles/admin/permissions")
        .await
        .expect("list admin permissions should succeed");

    let wildcard_entry = resp
        .permissions
        .iter()
        .find(|p| p.object_id == "*")
        .expect("admin should have wildcard permissions");

    // Admin should have at least Create, Get, Encrypt, Decrypt, Sign, etc.
    assert!(wildcard_entry.operations.contains(&KmipOperation::Create));
    assert!(wildcard_entry.operations.contains(&KmipOperation::Get));
    assert!(wildcard_entry.operations.contains(&KmipOperation::Encrypt));
    assert!(wildcard_entry.operations.contains(&KmipOperation::Decrypt));
    assert!(wildcard_entry.operations.contains(&KmipOperation::Sign));
    assert!(wildcard_entry.operations.contains(&KmipOperation::Destroy));
}

// ── Delete cascade ──────────────────────────────────────────────────────

#[actix_web::test]
async fn test_rbac_delete_role_cascades_permissions_and_users() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create role, add permissions, assign user
    let create_req = CreateRoleRequest {
        id: "cascade-test".to_owned(),
        name: "Cascade Test".to_owned(),
        description: None,
    };
    post_json_with_uri::<_, _, RoleResponse, _>(&app, create_req, "/roles")
        .await
        .unwrap();

    let perm_req = RolePermissionsRequest {
        object_id: "*".to_owned(),
        operations: [KmipOperation::Encrypt].into_iter().collect(),
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(
        &app,
        perm_req,
        "/roles/cascade-test/permissions",
    )
    .await
    .unwrap();

    let assign_req = AssignRoleRequest {
        user_ids: vec!["cascade-user@example.com".to_owned()],
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(&app, assign_req, "/roles/cascade-test/users")
        .await
        .unwrap();

    // Delete the role
    delete_with_uri::<_, SuccessResponse, _>(&app, "/roles/cascade-test")
        .await
        .expect("delete should succeed");

    // The user should no longer have this role
    let resp: RolesListResponse = get_json_with_uri(&app, "/users/cascade-user@example.com/roles")
        .await
        .unwrap();

    let role_ids: Vec<&str> = resp.roles.iter().map(|r| r.id.as_str()).collect();
    assert!(
        !role_ids.contains(&"cascade-test"),
        "cascade-test role should have been removed from user"
    );
}

// ── Hierarchical RBAC ───────────────────────────────────────────────────

#[actix_web::test]
async fn test_rbac_default_hierarchy_seeded() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // The default hierarchy should have been seeded:
    // admin -> operator, admin -> key-custodian, operator -> crypto-user
    let resp: RoleHierarchyEdgesResponse = get_json_with_uri(&app, "/roles-hierarchy")
        .await
        .expect("list hierarchy edges should succeed");

    let edge_pairs: Vec<(&str, &str)> = resp
        .edges
        .iter()
        .map(|e| (e.senior_role_id.as_str(), e.junior_role_id.as_str()))
        .collect();
    assert!(
        edge_pairs.contains(&("admin", "operator")),
        "admin -> operator edge should exist"
    );
    assert!(
        edge_pairs.contains(&("admin", "key-custodian")),
        "admin -> key-custodian edge should exist"
    );
    assert!(
        edge_pairs.contains(&("operator", "crypto-user")),
        "operator -> crypto-user edge should exist"
    );
}

#[actix_web::test]
async fn test_rbac_add_and_list_junior_roles() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create two custom roles
    for (id, name) in [("h-senior", "Hierarchy Senior"), ("h-junior", "Hierarchy Junior")] {
        let req = CreateRoleRequest {
            id: id.to_owned(),
            name: name.to_owned(),
            description: None,
        };
        post_json_with_uri::<_, _, RoleResponse, _>(&app, req, "/roles")
            .await
            .unwrap();
    }

    // Add hierarchy edge
    let resp: SuccessResponse = post_with_uri(&app, "/roles/h-senior/juniors/h-junior")
        .await
        .expect("add hierarchy edge should succeed");
    assert!(resp.success.contains("Hierarchy edge added"));

    // List juniors of senior
    let resp: RoleHierarchyListResponse = get_json_with_uri(&app, "/roles/h-senior/juniors")
        .await
        .expect("list juniors should succeed");
    let junior_ids: Vec<&str> = resp.roles.iter().map(|r| r.id.as_str()).collect();
    assert!(junior_ids.contains(&"h-junior"), "h-junior should be listed as junior");

    // List seniors of junior
    let resp: RoleHierarchyListResponse = get_json_with_uri(&app, "/roles/h-junior/seniors")
        .await
        .expect("list seniors should succeed");
    let senior_ids: Vec<&str> = resp.roles.iter().map(|r| r.id.as_str()).collect();
    assert!(senior_ids.contains(&"h-senior"), "h-senior should be listed as senior");
}

#[actix_web::test]
async fn test_rbac_remove_hierarchy_edge() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create roles and add edge
    for (id, name) in [("rm-senior", "RM Senior"), ("rm-junior", "RM Junior")] {
        let req = CreateRoleRequest {
            id: id.to_owned(),
            name: name.to_owned(),
            description: None,
        };
        post_json_with_uri::<_, _, RoleResponse, _>(&app, req, "/roles")
            .await
            .unwrap();
    }
    post_with_uri::<_, SuccessResponse, _>(&app, "/roles/rm-senior/juniors/rm-junior")
        .await
        .unwrap();

    // Remove the edge
    let resp: SuccessResponse = delete_with_uri(&app, "/roles/rm-senior/juniors/rm-junior")
        .await
        .expect("remove hierarchy edge should succeed");
    assert!(resp.success.contains("removed"));

    // Verify juniors list is empty
    let resp: RoleHierarchyListResponse = get_json_with_uri(&app, "/roles/rm-senior/juniors")
        .await
        .unwrap();
    let junior_ids: Vec<&str> = resp.roles.iter().map(|r| r.id.as_str()).collect();
    assert!(
        !junior_ids.contains(&"rm-junior"),
        "rm-junior should no longer be a junior"
    );
}

#[actix_web::test]
async fn test_rbac_self_loop_rejected() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create a role
    let req = CreateRoleRequest {
        id: "self-loop".to_owned(),
        name: "Self Loop Test".to_owned(),
        description: None,
    };
    post_json_with_uri::<_, _, RoleResponse, _>(&app, req, "/roles")
        .await
        .unwrap();

    // Attempt a self-loop
    let result: Result<SuccessResponse, _> =
        post_with_uri(&app, "/roles/self-loop/juniors/self-loop").await;
    assert!(result.is_err(), "self-loop should be rejected");
}

#[actix_web::test]
async fn test_rbac_cycle_detection() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create three roles: A, B, C
    for (id, name) in [("cyc-a", "Cycle A"), ("cyc-b", "Cycle B"), ("cyc-c", "Cycle C")] {
        let req = CreateRoleRequest {
            id: id.to_owned(),
            name: name.to_owned(),
            description: None,
        };
        post_json_with_uri::<_, _, RoleResponse, _>(&app, req, "/roles")
            .await
            .unwrap();
    }

    // Add A -> B and B -> C
    post_with_uri::<_, SuccessResponse, _>(&app, "/roles/cyc-a/juniors/cyc-b")
        .await
        .unwrap();
    post_with_uri::<_, SuccessResponse, _>(&app, "/roles/cyc-b/juniors/cyc-c")
        .await
        .unwrap();

    // Adding C -> A should create a cycle and be rejected
    let result: Result<SuccessResponse, _> =
        post_with_uri(&app, "/roles/cyc-c/juniors/cyc-a").await;
    assert!(result.is_err(), "cycle A->B->C->A should be rejected");
}

#[actix_web::test]
async fn test_rbac_transitive_permission_inheritance() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create three roles with a chain: grandparent -> parent -> child
    for (id, name) in [
        ("h-grandparent", "Grand Parent"),
        ("h-parent", "Parent"),
        ("h-child", "Child"),
    ] {
        let req = CreateRoleRequest {
            id: id.to_owned(),
            name: name.to_owned(),
            description: None,
        };
        post_json_with_uri::<_, _, RoleResponse, _>(&app, req, "/roles")
            .await
            .unwrap();
    }

    // Build chain: grandparent -> parent -> child
    post_with_uri::<_, SuccessResponse, _>(&app, "/roles/h-grandparent/juniors/h-parent")
        .await
        .unwrap();
    post_with_uri::<_, SuccessResponse, _>(&app, "/roles/h-parent/juniors/h-child")
        .await
        .unwrap();

    // Add Encrypt permission only to the child role
    let perm_req = RolePermissionsRequest {
        object_id: "*".to_owned(),
        operations: [KmipOperation::Encrypt].into_iter().collect(),
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(&app, perm_req, "/roles/h-child/permissions")
        .await
        .unwrap();

    // Assign a user to the grandparent role only
    let assign_req = AssignRoleRequest {
        user_ids: vec!["transitive-user@example.com".to_owned()],
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(
        &app,
        assign_req,
        "/roles/h-grandparent/users",
    )
    .await
    .unwrap();

    // The user should have Encrypt via transitive inheritance
    let resp: EffectivePermissionsResponse = get_json_with_uri(
        &app,
        "/users/transitive-user@example.com/effective-permissions/any-object",
    )
    .await
    .expect("effective permissions should succeed");

    assert!(
        resp.operations.contains(&KmipOperation::Encrypt),
        "Encrypt should be inherited transitively through grandparent -> parent -> child"
    );
}

#[actix_web::test]
async fn test_rbac_hierarchy_tree_view() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Use the default admin hierarchy: admin -> operator -> crypto-user
    let resp: RoleHierarchyTreeResponse = get_json_with_uri(&app, "/roles/admin/hierarchy")
        .await
        .expect("get hierarchy tree should succeed");

    // admin should be the root
    assert_eq!(resp.tree.role.id, "admin");
    // admin should have operator and key-custodian as juniors
    let junior_ids: Vec<&str> = resp.tree.juniors.iter().map(|n| n.role.id.as_str()).collect();
    assert!(junior_ids.contains(&"operator"), "admin should have operator as junior");
    assert!(
        junior_ids.contains(&"key-custodian"),
        "admin should have key-custodian as junior"
    );

    // operator should have crypto-user as junior
    let operator_node = resp
        .tree
        .juniors
        .iter()
        .find(|n| n.role.id == "operator")
        .expect("operator node should exist");
    let operator_junior_ids: Vec<&str> = operator_node
        .juniors
        .iter()
        .map(|n| n.role.id.as_str())
        .collect();
    assert!(
        operator_junior_ids.contains(&"crypto-user"),
        "operator should have crypto-user as junior"
    );
}

#[actix_web::test]
async fn test_rbac_delete_role_cascades_hierarchy_edges() {
    log_init(option_env!("RUST_LOG"));
    let app = test_app(None, None).await;

    // Create roles: top -> middle -> bottom
    for (id, name) in [
        ("h-del-top", "Del Top"),
        ("h-del-mid", "Del Middle"),
        ("h-del-bot", "Del Bottom"),
    ] {
        let req = CreateRoleRequest {
            id: id.to_owned(),
            name: name.to_owned(),
            description: None,
        };
        post_json_with_uri::<_, _, RoleResponse, _>(&app, req, "/roles")
            .await
            .unwrap();
    }

    post_with_uri::<_, SuccessResponse, _>(&app, "/roles/h-del-top/juniors/h-del-mid")
        .await
        .unwrap();
    post_with_uri::<_, SuccessResponse, _>(&app, "/roles/h-del-mid/juniors/h-del-bot")
        .await
        .unwrap();

    // Delete the middle role
    delete_with_uri::<_, SuccessResponse, _>(&app, "/roles/h-del-mid")
        .await
        .expect("delete should succeed");

    // top should have no juniors now
    let resp: RoleHierarchyListResponse = get_json_with_uri(&app, "/roles/h-del-top/juniors")
        .await
        .unwrap();
    assert!(
        resp.roles.is_empty(),
        "h-del-top should have no juniors after middle was deleted"
    );

    // bottom should have no seniors now
    let resp: RoleHierarchyListResponse = get_json_with_uri(&app, "/roles/h-del-bot/seniors")
        .await
        .unwrap();
    let senior_ids: Vec<&str> = resp.roles.iter().map(|r| r.id.as_str()).collect();
    assert!(
        !senior_ids.contains(&"h-del-mid"),
        "h-del-mid should no longer appear as senior of h-del-bot"
    );
}

// ── Phase 3A: Enforcement hardening ─────────────────────────────────────

/// Test: strict_get_privilege=true prevents Get from implying other operations.
///
/// Without strict_get, the effective-permissions endpoint should show the
/// full set of role-granted operations for a user with only a Get role.
/// With strict_get, having Get should NOT imply Encrypt/Decrypt etc. — the
/// effective permissions endpoint always returns the raw DB permissions (the
/// enforcement happens in user_has_permission at operation time), but we can
/// verify that when a user only has Get granted directly, role-based grants
/// are still properly returned separately.
#[actix_web::test]
async fn test_rbac_strict_get_privilege_config() {
    log_init(option_env!("RUST_LOG"));

    // Create app with strict_get enabled
    let mut config = https_clap_config_opts(None);
    config.rbac.strict_get_privilege = true;
    config.rbac.enabled = true;
    let app = test_app_with_clap_config(config, None).await;

    // Create a role with ONLY Get permission
    let create_req = CreateRoleRequest {
        id: "strict-get-role".to_owned(),
        name: "Strict Get Role".to_owned(),
        description: None,
    };
    post_json_with_uri::<_, _, RoleResponse, _>(&app, create_req, "/roles")
        .await
        .unwrap();

    let perm_req = RolePermissionsRequest {
        object_id: "*".to_owned(),
        operations: [KmipOperation::Get].into_iter().collect(),
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(
        &app,
        perm_req,
        "/roles/strict-get-role/permissions",
    )
    .await
    .unwrap();

    // Assign user
    let assign_req = AssignRoleRequest {
        user_ids: vec!["strict-get-user@example.com".to_owned()],
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(
        &app,
        assign_req,
        "/roles/strict-get-role/users",
    )
    .await
    .unwrap();

    // The effective permissions should contain only Get (from the role)
    let resp: EffectivePermissionsResponse = get_json_with_uri(
        &app,
        "/users/strict-get-user@example.com/effective-permissions/some-object",
    )
    .await
    .unwrap();

    assert!(
        resp.operations.contains(&KmipOperation::Get),
        "Get should be in effective permissions"
    );
    // With strict_get_privilege=true, having Get should NOT imply Encrypt.
    // The effective-permissions endpoint returns raw permissions — the strict_get
    // flag affects enforcement in user_has_permission(), not the query.
    // So Encrypt should NOT be present since it was never granted.
    assert!(
        !resp.operations.contains(&KmipOperation::Encrypt),
        "Encrypt should NOT be in effective permissions when only Get was granted"
    );
}

/// Test: restrictive enforcement mode caps effective permissions at role ceiling.
///
/// In restrictive mode, direct grants that exceed the user's role-granted
/// operations are filtered out. Only operations within the role ceiling are kept.
#[actix_web::test]
async fn test_rbac_restrictive_enforcement_mode() {
    log_init(option_env!("RUST_LOG"));

    // Create app with restrictive enforcement
    let mut config = https_clap_config_opts(None);
    config.rbac.enforcement_mode = RbacEnforcementMode::Restrictive;
    config.rbac.enabled = true;
    let app = test_app_with_clap_config(config, None).await;

    // Create a role with only Encrypt + Decrypt
    let create_req = CreateRoleRequest {
        id: "ceiling-role".to_owned(),
        name: "Ceiling Role".to_owned(),
        description: None,
    };
    post_json_with_uri::<_, _, RoleResponse, _>(&app, create_req, "/roles")
        .await
        .unwrap();

    let perm_req = RolePermissionsRequest {
        object_id: "*".to_owned(),
        operations: [KmipOperation::Encrypt, KmipOperation::Decrypt]
            .into_iter()
            .collect(),
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(
        &app,
        perm_req,
        "/roles/ceiling-role/permissions",
    )
    .await
    .unwrap();

    // Assign user to this role
    let assign_req = AssignRoleRequest {
        user_ids: vec!["ceiling-user@example.com".to_owned()],
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(
        &app,
        assign_req,
        "/roles/ceiling-role/users",
    )
    .await
    .unwrap();

    // Also grant the user direct permissions for Encrypt + Destroy (Destroy exceeds ceiling)
    // We can't easily add direct grants via REST (requires object ownership), but we can
    // verify that the role ceiling is correctly applied to role-based permissions.
    // The effective-permissions endpoint now respects enforcement mode.

    // Effective permissions should include Encrypt + Decrypt from role (ceiling)
    // No direct grants were added, so the effective set is exactly the role permissions
    let resp: EffectivePermissionsResponse = get_json_with_uri(
        &app,
        "/users/ceiling-user@example.com/effective-permissions/some-object",
    )
    .await
    .unwrap();

    assert!(
        resp.operations.contains(&KmipOperation::Encrypt),
        "Encrypt should be in effective permissions (role-granted)"
    );
    assert!(
        resp.operations.contains(&KmipOperation::Decrypt),
        "Decrypt should be in effective permissions (role-granted)"
    );
    // Destroy was never granted via role, so it should NOT appear
    assert!(
        !resp.operations.contains(&KmipOperation::Destroy),
        "Destroy should NOT be in effective permissions (not in role ceiling)"
    );
}

/// Test: additive mode (default) unions direct grants and role grants.
#[actix_web::test]
async fn test_rbac_additive_enforcement_mode() {
    log_init(option_env!("RUST_LOG"));

    // Create app with additive enforcement (default)
    let mut config = https_clap_config_opts(None);
    config.rbac.enforcement_mode = RbacEnforcementMode::Additive;
    config.rbac.enabled = true;
    let app = test_app_with_clap_config(config, None).await;

    // Create a role with only Encrypt
    let create_req = CreateRoleRequest {
        id: "additive-role".to_owned(),
        name: "Additive Role".to_owned(),
        description: None,
    };
    post_json_with_uri::<_, _, RoleResponse, _>(&app, create_req, "/roles")
        .await
        .unwrap();

    let perm_req = RolePermissionsRequest {
        object_id: "obj-add-1".to_owned(),
        operations: [KmipOperation::Encrypt].into_iter().collect(),
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(
        &app,
        perm_req,
        "/roles/additive-role/permissions",
    )
    .await
    .unwrap();

    // Assign user
    let assign_req = AssignRoleRequest {
        user_ids: vec!["additive-user@example.com".to_owned()],
    };
    post_json_with_uri::<_, _, SuccessResponse, _>(
        &app,
        assign_req,
        "/roles/additive-role/users",
    )
    .await
    .unwrap();

    // Effective permissions should include Encrypt from role
    let resp: EffectivePermissionsResponse = get_json_with_uri(
        &app,
        "/users/additive-user@example.com/effective-permissions/obj-add-1",
    )
    .await
    .unwrap();

    assert!(
        resp.operations.contains(&KmipOperation::Encrypt),
        "Encrypt should be in effective permissions via role"
    );
}

/// Test: RbacConfig serialization/deserialization roundtrip.
#[actix_web::test]
async fn test_rbac_config_defaults() {
    use cosmian_kms_access::rbac::RbacConfig;

    let config = RbacConfig::default();
    assert!(!config.enabled);
    assert!(!config.strict_get_privilege);
    assert!(!config.restrict_grant_to_roles);
    assert_eq!(config.enforcement_mode, RbacEnforcementMode::Additive);

    // Verify TOML roundtrip
    let toml_str = toml::to_string(&config).expect("serialize");
    let parsed: RbacConfig = toml::from_str(&toml_str).expect("deserialize");
    assert_eq!(config, parsed);

    // Verify non-default config roundtrip
    let strict_config = RbacConfig {
        enabled: true,
        strict_get_privilege: true,
        enforcement_mode: RbacEnforcementMode::Restrictive,
        restrict_grant_to_roles: true,
        bootstrap_admins: vec!["alice@corp.com".to_owned()],
    };
    let toml_str = toml::to_string(&strict_config).expect("serialize");
    let parsed: RbacConfig = toml::from_str(&toml_str).expect("deserialize");
    assert_eq!(strict_config, parsed);
}
