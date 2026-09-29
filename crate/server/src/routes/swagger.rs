use std::sync::Arc;

use actix_web::{HttpResponse, get, web::Data};
use clap::crate_version;

use crate::{core::KMS, result::KResult};

/// Serve the raw `OpenAPI` 3.1 schema (YAML) with the server URL and version injected dynamically.
#[get("/openapi.yaml")]
pub(crate) async fn get_openapi_yaml(kms: Data<Arc<KMS>>) -> KResult<HttpResponse> {
    const SCHEMA: &str = include_str!("../../documentation/openapi.yaml");

    // When a public URL is explicitly configured, replace the relative `url: /`
    // with the absolute URL so the spec is self-contained when downloaded.
    // Otherwise keep the relative URL — Swagger UI resolves it against its own
    // origin, which avoids CORS issues with bind addresses like 0.0.0.0.
    let schema = kms.params.kms_public_url.as_ref().map_or_else(
        || SCHEMA.to_owned(),
        |public_url| SCHEMA.replacen("url: /", &format!("url: {public_url}"), 1),
    );

    let schema = schema.replacen(
        "version: 5.0.0",
        &format!("version: {}", crate_version!()),
        1,
    );

    Ok(HttpResponse::Ok()
        .content_type("application/yaml")
        .body(schema))
}

/// Serve the vendored Swagger UI JavaScript bundle (swagger-ui-dist 5.18.2).
#[get("/swagger-ui-bundle.js")]
pub(crate) async fn get_swagger_ui_js() -> HttpResponse {
    const JS: &str = include_str!("../../documentation/swagger-ui/swagger-ui-bundle.js");
    HttpResponse::Ok()
        .content_type("application/javascript; charset=utf-8")
        .insert_header(("Cache-Control", "public, max-age=86400"))
        .body(JS)
}

/// Serve the vendored Swagger UI stylesheet (swagger-ui-dist 5.18.2).
#[get("/swagger-ui.css")]
pub(crate) async fn get_swagger_ui_css() -> HttpResponse {
    const CSS: &str = include_str!("../../documentation/swagger-ui/swagger-ui.css");
    HttpResponse::Ok()
        .content_type("text/css; charset=utf-8")
        .insert_header(("Cache-Control", "public, max-age=86400"))
        .body(CSS)
}

/// Serve a Swagger UI HTML page that loads the schema from `/openapi.yaml`.
///
/// All assets (JS, CSS) are served locally from this server — no external CDN dependency.
/// A strict Content-Security-Policy header restricts sources to 'self' only.
#[get("/swagger")]
pub(crate) async fn get_swagger_ui() -> KResult<HttpResponse> {
    let html = "\
        <!DOCTYPE html>\n\
        <html lang=\"en\">\n\
        <head>\n\
          <meta charset=\"UTF-8\" />\n\
          <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n\
          <title>Cosmian KMS \u{2014} API</title>\n\
          <link rel=\"stylesheet\" href=\"/swagger-ui.css\" />\n\
        </head>\n\
        <body>\n\
          <div id=\"swagger-ui\"></div>\n\
          <script src=\"/swagger-ui-bundle.js\"></script>\n\
          <script>\n\
            SwaggerUIBundle({\n\
              url: \"/openapi.yaml\",\n\
              dom_id: \"#swagger-ui\",\n\
              presets: [SwaggerUIBundle.presets.apis],\n\
              layout: \"BaseLayout\",\n\
              deepLinking: true,\n\
              displayRequestDuration: true,\n\
              filter: true,\n\
            });\n\
          </script>\n\
        </body>\n\
        </html>";
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .insert_header((
            "Content-Security-Policy",
            "default-src 'none'; \
             script-src 'self' 'unsafe-inline'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; \
             connect-src 'self'; \
             frame-ancestors 'none'",
        ))
        .body(html))
}
