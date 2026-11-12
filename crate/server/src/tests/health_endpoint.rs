use cosmian_logger::log_init;

use crate::tests::test_utils;

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
async fn test_cluster_status_endpoint_returns_node_list_and_leader() {
    log_init(option_env!("RUST_LOG"));

    let app = test_utils::test_app(None).await;
    let response: serde_json::Value = test_utils::get_json_with_uri(&app, "/cluster/status")
        .await
        .expect("cluster status endpoint should return 200 OK");

    assert!(response["nodes"].is_array());
    assert!(response["leader"].is_null());
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
