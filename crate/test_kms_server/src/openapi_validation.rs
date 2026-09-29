//! Validates that the KMS server serves the `OpenAPI` specification correctly.

use crate::{init_test_logging, start_default_test_kms_server};

/// Verify that `GET /openapi.yaml` returns a valid `OpenAPI` 3.1 document.
#[tokio::test]
async fn test_openapi_yaml_endpoint() -> Result<(), String> {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("failed to build reqwest client: {e}"))?;

    let url = format!(
        "{}/openapi.yaml",
        ctx.owner_client_config.http_config.server_url
    );
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET /openapi.yaml failed: {e}"))?;

    if response.status() != 200 {
        return Err(format!("expected status 200, got {}", response.status()));
    }

    let content_type = response
        .headers()
        .get("content-type")
        .ok_or("missing content-type header")?
        .to_str()
        .map_err(|e| format!("invalid content-type header: {e}"))?;

    if !content_type.contains("application/yaml") {
        return Err(format!("unexpected content-type: {content_type}"));
    }

    let body = response
        .text()
        .await
        .map_err(|e| format!("failed to read body: {e}"))?;

    if !body.contains("openapi: 3.1.0") {
        return Err("missing openapi version".to_owned());
    }
    if !body.contains("title: Cosmian KMS") {
        return Err("missing title".to_owned());
    }
    if body.len() <= 50_000 {
        return Err(format!("spec body too small: {} bytes", body.len()));
    }

    Ok(())
}

/// Verify that `GET /swagger` returns the Swagger UI HTML page.
#[tokio::test]
async fn test_swagger_ui_endpoint() -> Result<(), String> {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("failed to build reqwest client: {e}"))?;

    let url = format!("{}/swagger", ctx.owner_client_config.http_config.server_url);
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET /swagger failed: {e}"))?;

    if response.status() != 200 {
        return Err(format!("expected status 200, got {}", response.status()));
    }

    let content_type = response
        .headers()
        .get("content-type")
        .ok_or("missing content-type header")?
        .to_str()
        .map_err(|e| format!("invalid content-type header: {e}"))?;

    if !content_type.contains("text/html") {
        return Err(format!("unexpected content-type: {content_type}"));
    }

    let body = response
        .text()
        .await
        .map_err(|e| format!("failed to read body: {e}"))?;

    if !body.contains("/openapi.yaml") {
        return Err("HTML should reference /openapi.yaml".to_owned());
    }
    if !body.contains("swagger-ui") {
        return Err("HTML should contain swagger-ui div".to_owned());
    }
    if !body.contains("Cosmian KMS") {
        return Err("HTML should contain page title".to_owned());
    }

    Ok(())
}
