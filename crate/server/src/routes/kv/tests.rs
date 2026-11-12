//! HTTP-level tests of the KV v2-compatible API (issue #863).
//!
//! Requests go through a real actix `App` built with [`configure_routes`] and
//! [`configure_mount_routes`], exactly as the server mounts them. Authentication middlewares are
//! replaced by a test-only `from_fn` middleware reading `TEST_USER_HEADER` into the same
//! `AuthenticatedUser` extension the production middlewares populate, so every request runs as
//! the identity the test names.

use std::collections::HashSet;

use actix_web::{
    App, HttpMessage,
    body::{BoxBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse},
    http::{Method, StatusCode},
    middleware::{Next, from_fn},
    test::{TestRequest, call_service, init_service, read_body},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::State, kmip_2_1::KmipOperation,
};
use serde_json::{Value, json};

use super::{
    metadata::{
        KV_METADATA_TAG, MAX_KV_PATH_LENGTH, create_object, meta_tag, path_metadata_uid,
        save_metadata, sweep_expired_versions_at, ttl_active_tag,
    },
    *,
};
use crate::{
    middlewares::{AuthMethod, AuthenticatedUser},
    tests::test_utils::{https_clap_config, test_kms, test_kms_with_config},
};

const TEST_USER_HEADER: &str = "x-test-user";
const DENIED: &str = r#"{"errors":["permission denied"]}"#;

async fn inject_test_user<B: MessageBody + 'static>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    if let Some(user) = req
        .headers()
        .get(TEST_USER_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        req.extensions_mut().insert(AuthenticatedUser {
            username: UserId::from(user),
            auth_method: AuthMethod::DefaultUser,
        });
    }
    next.call(req)
        .await
        .map(ServiceResponse::map_into_boxed_body)
}

async fn kv_app(
    kms: Arc<KMS>,
) -> impl Service<
    actix_http::Request,
    Response = ServiceResponse<impl MessageBody>,
    Error = actix_web::Error,
> {
    init_service(
        App::new()
            .app_data(Data::new(kms))
            .wrap(from_fn(inject_test_user))
            .service(web::scope("/kv").configure(configure_routes))
            .service(web::scope("/v1/sys/internal/ui/mounts").configure(configure_mount_routes)),
    )
    .await
}

async fn test_kms_instance() -> Arc<KMS> {
    test_kms().await.expect("test KMS starts")
}

/// Send `request` as `user`; return the status and the raw body.
async fn send_raw<S, B>(app: &S, request: TestRequest, user: &str) -> (StatusCode, String)
where
    S: Service<actix_http::Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let response = call_service(
        app,
        request.insert_header((TEST_USER_HEADER, user)).to_request(),
    )
    .await;
    let status = response.status();
    let body = read_body(response).await;
    (
        status,
        String::from_utf8(body.to_vec()).expect("UTF-8 response body"),
    )
}

/// Send `request` as `user`; return the status and the JSON body (`null` when empty).
async fn send<S, B>(app: &S, request: TestRequest, user: &str) -> (StatusCode, Value)
where
    S: Service<actix_http::Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let (status, body) = send_raw(app, request, user).await;
    let value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&body).expect("JSON response body")
    };
    (status, value)
}

fn put_request(path: &str, data: &Value, options: &Value) -> TestRequest {
    TestRequest::put()
        .uri(&format!("/kv/data/{path}"))
        .set_json(json!({ "data": data, "options": options }))
}

fn get_request(path: &str) -> TestRequest {
    TestRequest::get().uri(&format!("/kv/data/{path}"))
}

fn list_method() -> Method {
    Method::from_bytes(b"LIST").expect("LIST is a valid method token")
}

async fn path_metadata(kms: &KMS, path: &str) -> (ObjectWithMetadata, PathMetadata) {
    find_metadata(kms, path)
        .await
        .expect("metadata lookup succeeds")
        .expect("path exists")
}

async fn grant(kms: &KMS, path: &str, user: &str, operations: &[KmipOperation]) {
    let (owm, _) = path_metadata(kms, path).await;
    kms.database
        .grant_operations(
            owm.id(),
            &UserId::from(user),
            operations.iter().copied().collect(),
        )
        .await
        .expect("grant is recorded");
}

fn unix_now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

#[test]
fn list_entry_names() {
    assert_eq!(
        list_entry_name("myapp", "myapp/config"),
        Some("config".to_owned())
    );
    assert_eq!(
        list_entry_name("myapp", "myapp/db/password"),
        Some("db/".to_owned())
    );
    assert_eq!(list_entry_name("myapp", "myapp"), None);
    assert_eq!(list_entry_name("myapp", "other/config"), None);
    assert_eq!(list_entry_name("myapp", "myapplication/config"), None);
    assert_eq!(
        list_entry_name("myapp/", "myapp/config"),
        Some("config".to_owned())
    );
    assert_eq!(list_entry_name("", "top/x"), Some("top/".to_owned()));
}

#[tokio::test]
async fn arbitrary_json_round_trips_through_put_and_get() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    let secret = json!({"s": "v", "n": 1.5, "i": -3, "b": false, "z": null,
        "a": [1, "two", {"three": [3]}], "o": {"deep": {"er": "x"}}});

    let (status, body) = send(
        &app,
        put_request("myapp/config", &secret, &json!({})),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["version"], 1);

    let (status, body) = send(&app, get_request("myapp/config"), "alice").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["data"], secret);
    assert_eq!(body["data"]["metadata"]["version"], 1);

    // The metadata sits at the UID derived from the server key; nothing else locates it.
    let (owm, metadata) = path_metadata(&kms, "myapp/config").await;
    let key = kms.internal_uid_key().await.expect("internal UID key");
    assert_eq!(
        owm.id(),
        path_metadata_uid(key, "myapp/config", 0).expect("UID derivation")
    );
    assert_eq!(metadata.generation, 0);
}

#[tokio::test]
async fn versions_are_kept_and_version_zero_is_the_latest() {
    let app = kv_app(test_kms_instance().await).await;
    for value in ["one", "two"] {
        let (status, _) = send(
            &app,
            TestRequest::post()
                .uri("/kv/data/myapp/versioned")
                .set_json(json!({"data": {"v": value}})),
            "alice",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    for (uri, version, value) in [
        ("/kv/data/myapp/versioned", 2, "two"),
        ("/kv/data/myapp/versioned?version=0", 2, "two"),
        ("/kv/data/myapp/versioned?version=1", 1, "one"),
    ] {
        let (status, body) = send(&app, TestRequest::get().uri(uri), "alice").await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_eq!(body["data"]["metadata"]["version"], version, "{uri}");
        assert_eq!(body["data"]["data"]["v"], value, "{uri}");
    }
    let (status, _) = send(
        &app,
        TestRequest::get().uri("/kv/data/myapp/versioned?version=3"),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn check_and_set_is_enforced() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    let path = "myapp/cas";

    // A first write with a CAS other than 0 creates nothing.
    let (status, _) = send(
        &app,
        put_request(path, &json!({"v": 1}), &json!({"cas": 5})),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(find_metadata(&kms, path).await.expect("lookup").is_none());

    let (status, _) = send(
        &app,
        put_request(path, &json!({"v": 1}), &json!({"cas": 0})),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // cas=0 means "create only".
    let (status, _) = send(
        &app,
        put_request(path, &json!({"v": 2}), &json!({"cas": 0})),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = send(
        &app,
        put_request(path, &json!({"v": 2}), &json!({"cas": 1})),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // A stale CAS is refused and changes nothing.
    let (status, body) = send(
        &app,
        put_request(path, &json!({"v": 3}), &json!({"cas": 1})),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (_, body) = send(&app, get_request(path), "alice").await;
    assert_eq!(body["data"]["data"]["v"], 2);
    assert_eq!(path_metadata(&kms, path).await.1.current_version, 2);
}

/// A write based on a stale metadata read never overwrites a newer one, including after the path
/// was hard-deleted and re-created.
#[tokio::test]
async fn stale_metadata_writes_conflict() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    let path = "myapp/stale";
    send(
        &app,
        put_request(path, &json!({"v": 1}), &json!({})),
        "alice",
    )
    .await;
    let (stale_owm, stale_metadata) = path_metadata(&kms, path).await;

    send(
        &app,
        put_request(path, &json!({"v": 2}), &json!({})),
        "alice",
    )
    .await;
    assert!(matches!(
        save_metadata(&kms, &stale_owm, &stale_metadata).await,
        Err(KvApiError::Conflict(_))
    ));

    let (current_owm, current_metadata) = path_metadata(&kms, path).await;
    let (status, _) = send(
        &app,
        TestRequest::delete().uri(&format!("/kv/metadata/{path}")),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    send(
        &app,
        put_request(path, &json!({"v": "new"}), &json!({})),
        "alice",
    )
    .await;
    assert!(matches!(
        save_metadata(&kms, &current_owm, &current_metadata).await,
        Err(KvApiError::Conflict(_))
    ));
    let (_, body) = send(&app, get_request(path), "alice").await;
    assert_eq!(body["data"]["data"]["v"], "new");
    assert_eq!(body["data"]["metadata"]["version"], 1);
}

/// Concurrent first writes of one path never lose a version: each either lands as its own
/// version or is refused with a conflict.
#[tokio::test]
async fn concurrent_first_writes_never_lose_a_version() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    let path = "myapp/race";
    let responses = futures::future::join_all((0..8).map(|i| {
        send(
            &app,
            put_request(path, &json!({"writer": i}), &json!({})),
            "alice",
        )
    }))
    .await;
    let written = responses
        .iter()
        .filter(|(status, _)| *status == StatusCode::OK)
        .count();
    assert!(written >= 1);
    for (status, body) in &responses {
        assert!(
            *status == StatusCode::OK || *status == StatusCode::CONFLICT,
            "{status}: {body}"
        );
    }
    let (_, metadata) = path_metadata(&kms, path).await;
    let statuses: Vec<_> = responses
        .iter()
        .map(|(status, _)| status.as_u16())
        .collect();
    assert_eq!(
        metadata.current_version,
        u64::try_from(written).expect("count fits u64"),
        "statuses {statuses:?}, stored versions {:?}",
        metadata.versions.keys().collect::<Vec<_>>()
    );
    assert_eq!(metadata.versions.len(), written, "statuses {statuses:?}");
}

#[tokio::test]
async fn absent_and_forbidden_paths_answer_identically() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms).await;
    send(
        &app,
        put_request("alice/secret", &json!({"k": "v"}), &json!({})),
        "alice",
    )
    .await;

    for (existing, missing) in [
        (get_request("alice/secret"), get_request("alice/missing")),
        (
            TestRequest::get().uri("/kv/metadata/alice/secret"),
            TestRequest::get().uri("/kv/metadata/alice/missing"),
        ),
        (
            TestRequest::delete().uri("/kv/data/alice/secret"),
            TestRequest::delete().uri("/kv/data/alice/missing"),
        ),
        (
            TestRequest::delete().uri("/kv/metadata/alice/secret"),
            TestRequest::delete().uri("/kv/metadata/alice/missing"),
        ),
    ] {
        let denied = send_raw(&app, existing, "bob").await;
        let absent = send_raw(&app, missing, "bob").await;
        assert_eq!(denied, (StatusCode::FORBIDDEN, DENIED.to_owned()));
        assert_eq!(absent, denied);
    }
    // Bob's attempts changed nothing.
    let (status, body) = send(&app, get_request("alice/secret"), "alice").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["data"]["k"], "v");
}

/// Writing into a path another identity owns requires both an `Import` grant and an explicit
/// `expected_owner` naming that owner, so nobody's secret lands in a pre-claimed path.
#[tokio::test]
async fn foreign_writes_require_a_grant_and_the_expected_owner() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    let path = "team/db";
    // Mallory pre-claims the path and grants alice write access, unsolicited.
    send(
        &app,
        put_request(path, &json!({"k": "bait"}), &json!({})),
        "mallory",
    )
    .await;
    grant(
        &kms,
        path,
        "alice",
        &[KmipOperation::Import, KmipOperation::Get],
    )
    .await;

    for options in [
        json!({}),
        json!({"expected_owner": "alice"}),
        json!({"expected_owner": "carol"}),
    ] {
        let (status, body) = send_raw(
            &app,
            put_request(path, &json!({"k": "alice's"}), &options),
            "alice",
        )
        .await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::FORBIDDEN, DENIED),
            "{options}"
        );
    }
    // Without the grant, naming the owner is not enough.
    let (status, _) = send(
        &app,
        put_request(
            path,
            &json!({"k": "x"}),
            &json!({"expected_owner": "mallory"}),
        ),
        "bob",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // With both, the intentional shared write lands in mallory's path.
    let (status, _) = send(
        &app,
        put_request(
            path,
            &json!({"k": "shared"}),
            &json!({"expected_owner": "mallory"}),
        ),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (owm, metadata) = path_metadata(&kms, path).await;
    assert_eq!(owm.owner(), "mallory");
    assert_eq!(metadata.current_version, 2);
    // The owner itself may name only itself.
    let (status, _) = send(
        &app,
        put_request(
            path,
            &json!({"k": "x"}),
            &json!({"expected_owner": "alice"}),
        ),
        "mallory",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(
        &app,
        put_request(
            path,
            &json!({"k": "x"}),
            &json!({"expected_owner": "mallory"}),
        ),
        "mallory",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn first_write_expected_owner_must_name_the_caller() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    let (status, _) = send(
        &app,
        put_request(
            "new/path",
            &json!({"k": "v"}),
            &json!({"expected_owner": "bob"}),
        ),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        find_metadata(&kms, "new/path")
            .await
            .expect("lookup")
            .is_none()
    );
    let (status, _) = send(
        &app,
        put_request(
            "new/path",
            &json!({"k": "v"}),
            &json!({"expected_owner": "alice"}),
        ),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(path_metadata(&kms, "new/path").await.0.owner(), "alice");
}

/// A `Get` grant reads; it neither writes nor deletes, and grants are per path.
#[tokio::test]
async fn get_grant_is_read_only_and_per_path() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    send(
        &app,
        put_request("shared/readonly", &json!({"k": "original"}), &json!({})),
        "alice",
    )
    .await;
    send(
        &app,
        put_request("shared/other", &json!({"k": "other"}), &json!({})),
        "alice",
    )
    .await;
    grant(&kms, "shared/readonly", "bob", &[KmipOperation::Get]).await;

    let (status, body) = send(&app, get_request("shared/readonly"), "bob").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["data"]["k"], "original");
    let (status, _) = send(
        &app,
        TestRequest::get().uri("/kv/metadata/shared/readonly"),
        "bob",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&app, get_request("shared/other"), "bob").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    for request in [
        put_request(
            "shared/readonly",
            &json!({"k": "evil"}),
            &json!({"expected_owner": "alice"}),
        ),
        TestRequest::delete().uri("/kv/data/shared/readonly"),
        TestRequest::delete().uri("/kv/metadata/shared/readonly"),
    ] {
        let (status, _) = send(&app, request, "bob").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (_, body) = send(&app, get_request("shared/readonly"), "alice").await;
    assert_eq!(body["data"]["data"]["k"], "original");
    assert_eq!(body["data"]["metadata"]["deletion_time"], "");
}

/// A `Locate` grant discloses the path name and bookkeeping, never the secret.
#[tokio::test]
async fn locate_grant_lists_without_exposing_the_secret() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    send(
        &app,
        put_request("apps/visible", &json!({"k": "v"}), &json!({})),
        "alice",
    )
    .await;
    send(
        &app,
        put_request("apps/hidden", &json!({"k": "v"}), &json!({})),
        "alice",
    )
    .await;

    let (status, _) = send(
        &app,
        TestRequest::get().uri("/kv/metadata/apps?list=true"),
        "bob",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    grant(&kms, "apps/visible", "bob", &[KmipOperation::Locate]).await;
    let (status, body) = send(
        &app,
        TestRequest::get().uri("/kv/metadata/apps?list=true"),
        "bob",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["keys"], json!(["visible"]));
    let (status, body) = send(
        &app,
        TestRequest::get().uri("/kv/metadata/apps/visible"),
        "bob",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["current_version"], 1);
    let (status, _) = send(&app, get_request("apps/visible"), "bob").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_returns_child_keys_with_both_verbs_and_404_when_empty() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms).await;
    for path in [
        "myapp/config",
        "myapp/db/password",
        "myapplication/x",
        "top",
    ] {
        send(
            &app,
            put_request(path, &json!({"k": "v"}), &json!({})),
            "alice",
        )
        .await;
    }
    let expected = json!(["config", "db/"]);
    let (status, body) = send(
        &app,
        TestRequest::get().uri("/kv/metadata/myapp?list=true"),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["keys"], expected);
    let (status, body) = send(
        &app,
        TestRequest::default()
            .method(list_method())
            .uri("/kv/metadata/myapp/"),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["keys"], expected);
    let (_, body) = send(
        &app,
        TestRequest::get().uri("/kv/metadata/?list=true"),
        "alice",
    )
    .await;
    assert_eq!(
        body["data"]["keys"],
        json!(["myapp/", "myapplication/", "top"])
    );

    let (status, body) = send(
        &app,
        TestRequest::get().uri("/kv/metadata/nothing?list=true"),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["errors"].is_array());
}

/// Objects that merely carry KV tags (whoever created them) never stand in for a path's
/// metadata or versions: only the server-keyed metadata UID does.
#[tokio::test]
async fn forged_kv_tags_neither_grant_nor_block_access() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    let path = "victim/key";
    let forged_uid = Uuid::new_v4().to_string();
    create_object(
        &kms,
        &forged_uid,
        &UserId::from("mallory"),
        br#"{"k":"forged"}"#,
        &[
            meta_tag(path),
            KV_METADATA_TAG.to_owned(),
            version_tag(path, 1),
        ],
    )
    .await
    .expect("forged object is created");
    kms.database
        .grant_operations(
            &forged_uid,
            &UserId::from("alice"),
            HashSet::from([KmipOperation::Get]),
        )
        .await
        .expect("grant is recorded");

    // The path is still free: alice sees nothing there and becomes its owner by writing it.
    let (status, _) = send(&app, get_request(path), "alice").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(
        &app,
        put_request(path, &json!({"k": "real"}), &json!({})),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (owm, _) = path_metadata(&kms, path).await;
    assert_eq!(owm.owner(), "alice");
    assert_ne!(owm.id(), forged_uid);
    let (_, body) = send(&app, get_request(path), "alice").await;
    assert_eq!(body["data"]["data"]["k"], "real");
    // Mallory's forged object gives her nothing on alice's path.
    let (status, _) = send(&app, get_request(path), "mallory").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn soft_delete_hides_only_the_latest_version() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms).await;
    let path = "myapp/soft";
    for v in ["one", "two"] {
        send(
            &app,
            put_request(path, &json!({"v": v}), &json!({})),
            "alice",
        )
        .await;
    }
    let (status, _) = send(
        &app,
        TestRequest::delete().uri(&format!("/kv/data/{path}")),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&app, get_request(path), "alice").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = send(
        &app,
        TestRequest::get().uri(&format!("/kv/data/{path}?version=1")),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["data"]["v"], "one");
    let (_, body) = send(
        &app,
        TestRequest::get().uri(&format!("/kv/metadata/{path}")),
        "alice",
    )
    .await;
    assert_ne!(body["data"]["versions"]["2"]["deletion_time"], "");
}

/// A hard delete wipes every version's bytes and drops TTL candidates; re-creating the path
/// starts a new generation that does not see the old versions.
#[tokio::test]
async fn hard_delete_wipes_versions_and_recreation_starts_fresh() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    let path = "myapp/hard";
    send(
        &app,
        put_request(path, &json!({"v": "one"}), &json!({"ttl": "1h"})),
        "alice",
    )
    .await;
    send(
        &app,
        put_request(path, &json!({"v": "two"}), &json!({})),
        "alice",
    )
    .await;
    let (old_owm, old_metadata) = path_metadata(&kms, path).await;

    let (status, _) = send(
        &app,
        TestRequest::delete().uri(&format!("/kv/metadata/{path}")),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(find_metadata(&kms, path).await.expect("lookup").is_none());
    for entry in old_metadata.versions.values() {
        let version = kms
            .database
            .retrieve_object(&entry.object_uid)
            .await
            .expect("retrieve")
            .expect("version row is kept");
        assert_eq!(version.state(), State::Destroyed);
        assert_eq!(secret_bytes(&version).expect("secret bytes"), b"");
    }
    let ttl_tag = ttl_active_tag(kms.internal_uid_key().await.expect("key")).expect("tag");
    assert!(
        kms.database
            .list_uids_for_tags(&HashSet::from([ttl_tag]))
            .await
            .expect("tag lookup")
            .is_empty()
    );

    let (status, _) = send(&app, get_request(path), "alice").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    send(
        &app,
        put_request(path, &json!({"v": "fresh"}), &json!({})),
        "alice",
    )
    .await;
    let (new_owm, new_metadata) = path_metadata(&kms, path).await;
    assert_ne!(new_owm.id(), old_owm.id());
    assert_eq!(new_metadata.generation, 1);
    let (_, body) = send(&app, get_request(path), "alice").await;
    assert_eq!(body["data"]["data"]["v"], "fresh");
    assert_eq!(body["data"]["metadata"]["version"], 1);
    let (status, _) = send(
        &app,
        TestRequest::get().uri(&format!("/kv/data/{path}?version=2")),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // The previous generation's TTL never touches the new one.
    let swept = sweep_expired_versions_at(&kms, unix_now() + 7_200)
        .await
        .expect("sweep");
    assert_eq!(swept, 0);
}

/// Expiry is enforced on read even when no sweep ran.
#[tokio::test]
async fn expired_versions_are_unreadable_before_the_sweep() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    let path = "myapp/expiring";
    send(
        &app,
        put_request(path, &json!({"v": "short"}), &json!({"ttl": "1h"})),
        "alice",
    )
    .await;
    let (owm, mut metadata) = path_metadata(&kms, path).await;
    metadata.versions.get_mut(&1).expect("version 1").expires_at = Some(unix_now() - 1);
    save_metadata(&kms, &owm, &metadata)
        .await
        .expect("metadata is saved");

    let (status, _) = send(&app, get_request(path), "alice").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn ttl_sweep_destroys_only_expired_versions() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    let path = "myapp/ttl";
    send(
        &app,
        put_request(path, &json!({"v": "short"}), &json!({"ttl": "5m"})),
        "alice",
    )
    .await;
    send(
        &app,
        put_request(path, &json!({"v": "kept"}), &json!({})),
        "alice",
    )
    .await;

    assert_eq!(
        sweep_expired_versions_at(&kms, unix_now())
            .await
            .expect("sweep"),
        0
    );
    let (status, _) = send(
        &app,
        TestRequest::get().uri(&format!("/kv/data/{path}?version=1")),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let later = unix_now() + 3_600;
    assert_eq!(
        sweep_expired_versions_at(&kms, later).await.expect("sweep"),
        1
    );
    assert_eq!(
        sweep_expired_versions_at(&kms, later).await.expect("sweep"),
        0
    );
    let (_, metadata) = path_metadata(&kms, path).await;
    let entry = &metadata.versions[&1];
    assert!(entry.destroyed);
    let version = kms
        .database
        .retrieve_object(&entry.object_uid)
        .await
        .expect("retrieve")
        .expect("version row is kept");
    assert_eq!(version.state(), State::Destroyed);
    assert_eq!(secret_bytes(&version).expect("secret bytes"), b"");
    let (status, _) = send(
        &app,
        TestRequest::get().uri(&format!("/kv/data/{path}?version=1")),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, body) = send(&app, get_request(path), "alice").await;
    assert_eq!(body["data"]["data"]["v"], "kept");
}

/// An object carrying a path's version tag and the TTL tag, but not recorded by the path, is
/// reported by the sweep and never destroys the real version.
#[tokio::test]
async fn sweep_rejects_unrecorded_ttl_candidates() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    let path = "team/db";
    send(
        &app,
        put_request(path, &json!({"k": "victim"}), &json!({})),
        "alice",
    )
    .await;
    let ttl_tag = ttl_active_tag(kms.internal_uid_key().await.expect("key")).expect("tag");
    create_object(
        &kms,
        &Uuid::new_v4().to_string(),
        &UserId::from("mallory"),
        br#"{"k":"forged"}"#,
        &[version_tag(path, 1), ttl_tag],
    )
    .await
    .expect("forged candidate is created");

    sweep_expired_versions_at(&kms, unix_now() + 3_600)
        .await
        .unwrap_err();
    let (status, body) = send(&app, get_request(path), "alice").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["data"]["k"], "victim");
}

#[tokio::test]
async fn invalid_ttls_are_rejected_without_creating_the_path() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    for ttl in [
        "0",
        "0s",
        "-1",
        "-5m",
        "abc",
        "1w",
        "",
        "18446744073709551615d",
    ] {
        let (status, body) = send(
            &app,
            put_request("myapp/ttl", &json!({"k": "v"}), &json!({"ttl": ttl})),
            "alice",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{ttl:?}: {body}");
    }
    assert!(
        find_metadata(&kms, "myapp/ttl")
            .await
            .expect("lookup")
            .is_none()
    );
}

#[tokio::test]
async fn writes_beyond_the_version_cap_are_refused_without_pruning() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    let path = "myapp/capped";
    send(
        &app,
        put_request(path, &json!({"v": 1}), &json!({})),
        "alice",
    )
    .await;
    let (owm, mut metadata) = path_metadata(&kms, path).await;
    let first = metadata.versions[&1].clone();
    let filler = u64::try_from(MAX_KV_VERSIONS).expect("cap fits u64");
    for version in 2..=filler {
        metadata.versions.insert(version, first.clone());
    }
    save_metadata(&kms, &owm, &metadata)
        .await
        .expect("metadata is saved");

    let (status, body) = send(
        &app,
        put_request(path, &json!({"v": 2}), &json!({})),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (_, metadata) = path_metadata(&kms, path).await;
    assert_eq!(metadata.versions.len(), MAX_KV_VERSIONS);
    assert_eq!(metadata.current_version, 1);
}

#[tokio::test]
async fn invalid_paths_are_rejected() {
    let app = kv_app(test_kms_instance().await).await;
    let too_long = "a".repeat(MAX_KV_PATH_LENGTH + 1);
    for path in ["", too_long.as_str()] {
        let (status, _) = send(
            &app,
            put_request(path, &json!({"k": "v"}), &json!({})),
            "alice",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}", path.len());
    }
}

/// With roles configured, an Operator without the `Create` right can neither create a path nor
/// update one it was granted: every write stores a new managed object.
#[tokio::test]
async fn writes_require_the_create_right_under_roles() {
    let mut config = https_clap_config();
    config.roles.crypto_officer_users = Some(vec!["officer@example.com".to_owned()]);
    let kms = test_kms_with_config(config).await.expect("test KMS starts");
    let app = kv_app(kms.clone()).await;

    let (status, body) = send_raw(
        &app,
        put_request("ops/new", &json!({"k": "v"}), &json!({})),
        "operator",
    )
    .await;
    assert_eq!((status, body.as_str()), (StatusCode::FORBIDDEN, DENIED));
    assert!(
        find_metadata(&kms, "ops/new")
            .await
            .expect("lookup")
            .is_none()
    );

    let (status, _) = send(
        &app,
        put_request("ops/shared", &json!({"k": "v1"}), &json!({})),
        "officer@example.com",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    grant(&kms, "ops/shared", "operator", &[KmipOperation::Import]).await;
    let (status, body) = send_raw(
        &app,
        put_request(
            "ops/shared",
            &json!({"k": "v2"}),
            &json!({"expected_owner": "officer@example.com"}),
        ),
        "operator",
    )
    .await;
    assert_eq!((status, body.as_str()), (StatusCode::FORBIDDEN, DENIED));
}

/// KMIP `Create` must refuse internal `_`-prefixed tags for every object type it can make, so
/// that nobody can forge a `_kv::` tag to fill the TTL sweep's candidate set or to claim version
/// slots of a path. A plain user tag is still accepted.
#[tokio::test]
async fn kmip_create_rejects_forged_kv_tags() {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attributes, kmip_objects::ObjectType, kmip_operations::Create,
        kmip_types::CryptographicAlgorithm,
    };

    let kms = test_kms().await.expect("test KMS starts");
    let user = UserId::from("alice");
    let create_with_tag = |object_type, algorithm, tag: String| {
        let mut attributes = Attributes {
            cryptographic_algorithm: algorithm,
            ..Default::default()
        };
        attributes
            .set_tags(kms.vendor_id(), HashSet::from([tag]))
            .expect("tags are set");
        Create {
            object_type,
            attributes,
            protection_storage_masks: None,
        }
    };

    let object_types = [
        (ObjectType::SymmetricKey, Some(CryptographicAlgorithm::AES)),
        (ObjectType::SecretData, None),
        (ObjectType::PrivateKey, Some(CryptographicAlgorithm::DSA)),
        (ObjectType::PGPKey, Some(CryptographicAlgorithm::Ed25519)),
    ];
    for (object_type, algorithm) in object_types {
        for forged in [
            version_tag("myapp/forged", 1),
            meta_tag("myapp/forged"),
            KV_METADATA_TAG.to_owned(),
        ] {
            let request = create_with_tag(object_type, algorithm, forged.clone());
            assert!(
                kms.create(request, &user).await.is_err(),
                "a Create of {object_type:?} carrying `{forged}` must be refused"
            );
        }
    }

    let allowed = create_with_tag(ObjectType::SecretData, None, "myapp".to_owned());
    kms.create(allowed, &user)
        .await
        .expect("a plain user tag is accepted");
}

/// Integrity failures answer a generic 500 and never return the foreign object's data.
#[tokio::test]
async fn metadata_pointing_at_a_foreign_object_fails_closed() {
    let kms = test_kms_instance().await;
    let app = kv_app(kms.clone()).await;
    let path = "myapp/integrity";
    send(
        &app,
        put_request(path, &json!({"k": "mine"}), &json!({})),
        "alice",
    )
    .await;
    let foreign_uid = Uuid::new_v4().to_string();
    create_object(
        &kms,
        &foreign_uid,
        &UserId::from("mallory"),
        br#"{"k":"theirs"}"#,
        &[version_tag(path, 1)],
    )
    .await
    .expect("foreign object is created");
    let (owm, mut metadata) = path_metadata(&kms, path).await;
    metadata
        .versions
        .get_mut(&1)
        .expect("version 1")
        .object_uid
        .clone_from(&foreign_uid);
    save_metadata(&kms, &owm, &metadata)
        .await
        .expect("metadata is saved");

    for request in [
        get_request(path),
        TestRequest::delete().uri(&format!("/kv/metadata/{path}")),
    ] {
        let (status, body) = send_raw(&app, request, "alice").await;
        assert_eq!(
            (status, body.as_str()),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"errors":["internal error"]}"#
            )
        );
    }
    let foreign = kms
        .database
        .retrieve_object(&foreign_uid)
        .await
        .expect("retrieve")
        .expect("foreign object is kept");
    assert!(
        !matches!(
            foreign.state(),
            State::Destroyed | State::Destroyed_Compromised
        ),
        "the foreign object must not be destroyed"
    );
    assert_eq!(secret_bytes(&foreign).expect("bytes"), br#"{"k":"theirs"}"#);
}

#[tokio::test]
async fn malformed_requests_use_the_errors_envelope_without_echo() {
    let app = kv_app(test_kms_instance().await).await;
    for (request, status) in [
        (
            TestRequest::put()
                .uri("/kv/data/myapp/x")
                .insert_header(("content-type", "application/json"))
                .set_payload(r#"{"data": {"k": "s3cr3t-value""#),
            StatusCode::BAD_REQUEST,
        ),
        (
            TestRequest::put()
                .uri("/kv/data/myapp/x")
                .set_json(json!({"data": "s3cr3t-value"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            TestRequest::get().uri("/kv/data/myapp/x?version=abc"),
            StatusCode::BAD_REQUEST,
        ),
        (
            TestRequest::patch().uri("/kv/data/myapp/x"),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            TestRequest::get().uri("/kv/unknown/route"),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let (actual, body) = send_raw(&app, request, "alice").await;
        assert_eq!(actual, status, "{body}");
        let body: Value = serde_json::from_str(&body).expect("JSON error body");
        assert!(body["errors"].is_array(), "{body}");
        assert!(!body.to_string().contains("s3cr3t"), "{body}");
    }
}

#[tokio::test]
async fn preflight_reports_kv_v2_only_for_the_mount() {
    let app = kv_app(test_kms_instance().await).await;
    for uri in [
        "/v1/sys/internal/ui/mounts/kv",
        "/v1/sys/internal/ui/mounts/kv/myapp/config",
    ] {
        let (status, body) = send(&app, TestRequest::get().uri(uri), "alice").await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_eq!(body["data"]["path"], "kv/");
        assert_eq!(body["data"]["type"], "kv");
        assert_eq!(body["data"]["options"]["version"], "2");
    }
    let (status, body) = send(
        &app,
        TestRequest::get().uri("/v1/sys/internal/ui/mounts/transit/keys/x"),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["errors"].is_array());
}
