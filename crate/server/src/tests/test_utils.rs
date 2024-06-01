#![allow(clippy::unwrap_used, clippy::print_stdout, clippy::expect_used)]

use std::{env::temp_dir, path::PathBuf, sync::Arc};

use actix_http::Request;
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceResponse},
    http::StatusCode,
    test::{self, call_service, read_body},
    web::{self, Data},
    App,
};
use cosmian_kmip::kmip::ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV};
use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

use super::google_cse::utils::google_cse_auth;
use crate::{
    config::{ClapConfig, HttpConfig, MainDBConfig, ServerParams},
    core::KMS,
    kms_bail,
    result::KResult,
    routes,
};

#[allow(dead_code)]
pub(crate) fn https_clap_config() -> ClapConfig {
    https_clap_config_opts(None)
}

pub(crate) fn https_clap_config_opts(google_cse_kacls_url: Option<String>) -> ClapConfig {
    let tmp_dir = temp_dir();
    let uuid = Uuid::new_v4();
    let sqlite_path = tmp_dir.join(format!("{uuid}.sqlite"));
    if sqlite_path.exists() {
        std::fs::remove_file(&sqlite_path).unwrap();
    }

    ClapConfig {
        http: HttpConfig {
            https_p12_file: Some(PathBuf::from("src/tests/kmserver.acme.com.p12")),
            https_p12_password: Some("password".to_owned()),
            ..Default::default()
        },
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            database_url: None,
            sqlite_path,
            clear_database: true,
            ..Default::default()
        },
        google_cse_kacls_url,
        ..Default::default()
    }
}

pub(crate) async fn test_app(
    google_cse_kacls_url: Option<String>,
) -> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error> {
    let clap_config = https_clap_config_opts(google_cse_kacls_url);

    let server_params = ServerParams::try_from(clap_config).unwrap();

    let kms_server = Arc::new(
        KMS::instantiate(server_params)
            .await
            .expect("cannot instantiate KMS server"),
    );

    let mut app = App::new()
        .app_data(Data::new(kms_server.clone()))
        .service(routes::kmip::kmip)
        .service(routes::access::grant_access)
        .service(routes::access::revoke_access);

    let google_cse_jwt_config = google_cse_auth()
        .await
        .expect("cannot setup Google CSE auth");

    // The scope for the Google Client-Side Encryption endpoints served from /google_cse
    let google_cse_scope = web::scope("/google_cse")
        .app_data(Data::new(Some(google_cse_jwt_config)))
        .service(routes::google_cse::get_status)
        .service(routes::google_cse::wrap)
        .service(routes::google_cse::unwrap)
        .service(routes::google_cse::private_key_sign)
        .service(routes::google_cse::private_key_decrypt)
        .service(routes::google_cse::privileged_wrap)
        .service(routes::google_cse::privileged_unwrap)
        .service(routes::google_cse::privileged_private_key_decrypt)
        .service(routes::google_cse::digest)
        .service(routes::google_cse::rewrap);

    app = app.service(google_cse_scope);

    test::init_service(app).await
}

pub(crate) async fn post<B, O, R, S>(app: &S, operation: O) -> KResult<R>
where
    O: Serialize,
    R: DeserializeOwned,
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let req = test::TestRequest::post()
        .uri("/kmip/2_1")
        // .insert_header(("Authorization", format!("Bearer {AUTH0_TOKEN}")))
        .set_json(to_ttlv(&operation)?)
        .to_request();
    let res = call_service(app, req).await;
    if res.status() != StatusCode::OK {
        kms_bail!(
            "{}",
            String::from_utf8(read_body(res).await.to_vec()).unwrap_or_else(|_| "[N/A".to_owned())
        );
    }
    let body = read_body(res).await;
    let json: TTLV = serde_json::from_slice(&body)?;
    let result: R = from_ttlv(&json)?;
    Ok(result)
}

pub(crate) async fn post_with_uri<B, O, R, S>(app: &S, operation: O, uri: &str) -> KResult<R>
where
    O: Serialize,
    R: DeserializeOwned,
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let req = test::TestRequest::post()
        .uri(uri)
        // .insert_header(("Authorization", format!("Bearer {AUTH0_TOKEN}")))
        .set_json(&operation)
        .to_request();
    let res = call_service(app, req).await;
    if res.status() != StatusCode::OK {
        kms_bail!(
            "{}",
            String::from_utf8(read_body(res).await.to_vec()).unwrap_or_else(|_| "[N/A".to_owned())
        );
    }
    let body = read_body(res).await;
    Ok(serde_json::from_slice(&body)?)
}

pub(crate) async fn get_with_uri<B, R, S>(app: &S, uri: &str) -> KResult<R>
where
    R: DeserializeOwned,
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let req = test::TestRequest::get().uri(uri).to_request();
    let res = call_service(app, req).await;
    if res.status() != StatusCode::OK {
        kms_bail!(
            "{}",
            String::from_utf8(read_body(res).await.to_vec()).unwrap_or_else(|_| "[N/A".to_owned())
        );
    }
    let body = read_body(res).await;
    Ok(serde_json::from_slice(&body)?)
}
