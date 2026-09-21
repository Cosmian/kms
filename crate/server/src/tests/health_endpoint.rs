use cosmian_logger::log_init;

use crate::tests::test_utils::{self, https_clap_config};

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
}

/// The audit dependency is omitted from `/health` when audit logging isn't configured —
/// the default state exercised by every other test in this file.
#[tokio::test]
async fn test_health_endpoint_omits_audit_dependency_when_disabled() {
    log_init(option_env!("RUST_LOG"));

    let app = test_utils::test_app(None).await;

    let response: serde_json::Value = test_utils::get_json_with_uri(&app, "/health")
        .await
        .expect("health endpoint should return 200 OK");

    assert!(response["dependencies"].get("audit").is_none());
}

/// A live audit writer is reported as an `UP` dependency, and does not itself flip the
/// overall status to `DOWN`.
#[tokio::test]
async fn test_health_endpoint_reports_audit_dependency_when_enabled() {
    log_init(option_env!("RUST_LOG"));

    let audit_path = std::env::temp_dir().join(format!(
        "kms_health_endpoint_audit_test_{}.jsonl",
        std::process::id()
    ));
    std::fs::remove_file(&audit_path).ok();

    let mut clap_config = https_clap_config();
    clap_config.audit.audit_enable = true;
    clap_config.audit.file.audit_file_path = Some(audit_path.clone());
    clap_config.audit.audit_channel_capacity = 128;

    let app = Box::pin(test_utils::test_app_with_clap_config(clap_config)).await;

    let response: serde_json::Value = test_utils::get_json_with_uri(&app, "/health")
        .await
        .expect("health endpoint should return 200 OK");

    assert_eq!(response["status"], "UP");
    assert_eq!(response["dependencies"]["audit"]["name"], "audit");
    assert_eq!(response["dependencies"]["audit"]["status"], "UP");

    std::fs::remove_file(&audit_path).ok();
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
}
