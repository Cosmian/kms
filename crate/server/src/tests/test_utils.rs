#![allow(clippy::unwrap_used, clippy::print_stdout, clippy::expect_used)]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use actix_http::Request;
use actix_web::{
    App,
    body::MessageBody,
    dev::{Service, ServiceResponse},
    http::StatusCode,
    test::{self, call_service, read_body},
    web::{self, Data},
};
use cosmian_kmip::ttlv::{TTLV, from_ttlv, to_ttlv};
use serde::{Serialize, de::DeserializeOwned};
use time::{OffsetDateTime, format_description::well_known::Iso8601};
use tracing::info;

use super::google_cse::utils::google_cse_auth;
use crate::{
    config::{ClapConfig, MainDBConfig, ServerParams, SocketServerConfig, TlsConfig},
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
    // Set the absolute path of the project directory
    let project_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(Path::new("test_data/sqlite"));

    // get the current date and time as an ISO 8601 string usinf OffsetDateTime
    let now = OffsetDateTime::now_utc().format(&Iso8601::DEFAULT).unwrap();

    let sqlite_path = project_dir.join(format!("{now}.sqlite"));
    if sqlite_path.exists() {
        std::fs::remove_file(&sqlite_path).unwrap();
    }

    ClapConfig {
        socket_server: SocketServerConfig {
            socket_server_start: true,
            ..Default::default()
        },
        tls: TlsConfig {
            tls_p12_file: Some(PathBuf::from(
                "../../test_data/client_server/server/kmserver.acme.com.p12",
            )),
            tls_p12_password: Some("password".to_owned()),
            clients_ca_cert_file: Some(PathBuf::from("../../test_data/client_server/ca/ca.crt")),
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
    privileged_users: Option<Vec<String>>,
) -> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error> {
    let clap_config = https_clap_config_opts(google_cse_kacls_url);

    let server_params = Arc::new(ServerParams::try_from(clap_config).unwrap());

    let kms_server = Arc::new(
        KMS::instantiate(server_params)
            .await
            .expect("cannot instantiate KMS server"),
    );

    let mut app = App::new()
        .app_data(Data::new(kms_server.clone()))
        .app_data(web::Data::new(privileged_users))
        .service(routes::kmip::kmip_2_1_json)
        .service(routes::kmip::kmip)
        .service(routes::access::list_owned_objects)
        .service(routes::access::list_access_rights_obtained)
        .service(routes::access::list_accesses)
        .service(routes::access::grant_access)
        .service(routes::access::revoke_access)
        .service(routes::access::get_create_access)
        .service(routes::access::get_privileged_access);

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

pub(crate) async fn post_2_1<B, O, R, S>(app: &S, operation: O) -> KResult<R>
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
    let ttlv: TTLV = serde_json::from_slice(&body)?;
    let result: R = from_ttlv(ttlv)?;
    Ok(result)
}

pub(crate) async fn post_json_with_uri<B, O, R, S>(app: &S, operation: O, uri: &str) -> KResult<R>
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
    info!("Response: {:?}", res.status());
    let body = read_body(res).await;
    Ok(serde_json::from_slice(&body)?)
}

pub(crate) async fn get_json_with_uri<B, R, S>(app: &S, uri: &str) -> KResult<R>
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
