use actix_web::{App, http::StatusCode, test, web::Data};
use cosmian_logger::log_init;

use crate::{
    cron::update_cluster_heartbeat, middlewares::ensure_auth_middleware, routes, tests::test_utils,
};

#[tokio::test]
async fn test_health_endpoint_ok() {
    log_init(option_env!("RUST_LOG"));

    let app = test_utils::test_app(None).await;

    let response: serde_json::Value = test_utils::get_json_with_uri(&app, "/health")
        .await
        .expect("health endpoint should return 200 OK");

    assert_eq!(response["status"], "UP");
    assert!(response.get("latency_ms").is_some());
    assert!(response["latency_ms"].is_u64());
    assert!(response.get("dependencies").is_some());
    assert!(response["dependencies"].get("database").is_some());
    assert_eq!(response["dependencies"]["database"]["status"], "UP");
    assert!(response["dependencies"]["database"]["latency_ms"].is_u64());
    assert!(response["dependencies"].get("hsm").is_none());
}

#[tokio::test]
async fn test_cluster_status_lists_heartbeating_node_as_leader() {
    log_init(option_env!("RUST_LOG"));

    let kms = test_utils::test_kms().await.expect("instantiate KMS");
    // The first heartbeat registers the node; with no live leader, the node elects itself.
    update_cluster_heartbeat(&kms).await;
    update_cluster_heartbeat(&kms).await;

    let app = test_utils::test_app_with_kms(kms.clone(), None).await;
    let response: serde_json::Value = test_utils::get_json_with_uri(&app, "/cluster/status")
        .await
        .expect("cluster status endpoint should return 200 OK");

    assert_eq!(response["leader"], kms.node_id.as_str());
    let nodes = response["nodes"].as_array().expect("nodes array");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0]["node_id"], kms.node_id.as_str());
    assert_eq!(nodes[0]["leader"], true);
    assert_eq!(nodes[0]["version"], env!("CARGO_PKG_VERSION"));
    assert!(nodes[0]["last_heartbeat"].is_i64());
}

#[tokio::test]
async fn test_cluster_status_requires_authentication() {
    log_init(option_env!("RUST_LOG"));

    let kms = test_utils::test_kms().await.expect("instantiate KMS");
    let app = test::init_service(
        App::new()
            .app_data(Data::new(kms.clone()))
            .service(routes::cluster::get_cluster_status)
            .wrap(ensure_auth_middleware(kms.clone(), true)),
    )
    .await;

    let (status, _body) = test_utils::get_json_raw(&app, "/cluster/status").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_root_redirects_to_ui() {
    log_init(option_env!("RUST_LOG"));

    let app = test_utils::test_app(None).await;

    let response = actix_web::test::TestRequest::get()
        .uri("/")
        .send_request(&app)
        .await;

    assert!(response.status().is_redirection());
    let location = response
        .headers()
        .get(actix_web::http::header::LOCATION)
        .expect("redirect should include Location header")
        .to_str()
        .expect("Location header should be valid UTF-8");
    assert_eq!(location, "/ui");

    let response: serde_json::Value = test_utils::get_json_with_uri(&app, "/health")
        .await
        .expect("health endpoint should return 200 OK");

    assert_eq!(response["status"], "UP");
    assert!(response.get("latency_ms").is_some());
    assert!(response["latency_ms"].is_u64());
    assert!(response.get("dependencies").is_some());
    assert!(response["dependencies"].get("database").is_some());
    assert_eq!(response["dependencies"]["database"]["status"], "UP");
    assert!(response["dependencies"]["database"]["latency_ms"].is_u64());
}
