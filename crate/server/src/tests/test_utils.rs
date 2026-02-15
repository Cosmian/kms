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
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_2_1::{kmip_operations::LocateResponse, kmip_types::UniqueIdentifier},
    ttlv::{TTLV, from_ttlv, to_ttlv},
};
use cosmian_logger::info;
use serde::{Serialize, de::DeserializeOwned};
use time::{OffsetDateTime, format_description::well_known::Iso8601};

use super::google_cse::utils::google_cse_auth;
use crate::{
    config::{
        ClapConfig, GoogleCseConfig, MainDBConfig, ServerParams, SocketServerConfig, TlsConfig,
    },
    core::KMS,
    kms_bail,
    result::KResult,
    routes,
    start_kms_server::handle_google_cse_rsa_keypair,
};

pub(crate) fn https_clap_config() -> ClapConfig {
    https_clap_config_opts(None)
}

pub(crate) fn https_clap_config_opts(kms_public_url: Option<String>) -> ClapConfig {
    let sqlite_path = get_tmp_sqlite_path();

    // In FIPS mode, disable TLS with P12 certificates since PKCS12KDF is not FIPS-approved
    #[cfg(not(feature = "non-fips"))]
    let tls_config = TlsConfig::default();

    #[cfg(feature = "non-fips")]
    let tls_config = TlsConfig {
        tls_p12_file: Some(PathBuf::from(
            "../../test_data/certificates/client_server/server/kmserver.acme.com.p12",
        )),
        tls_p12_password: Some("password".to_owned()),
        clients_ca_cert_file: Some(PathBuf::from(
            "../../test_data/certificates/client_server/ca/ca.crt",
        )),
        tls_cipher_suites: None,
    };

    ClapConfig {
        socket_server: SocketServerConfig {
            socket_server_start: true,
            ..Default::default()
        },
        tls: tls_config,
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            database_url: None,
            sqlite_path,
            clear_database: false,
            ..Default::default()
        },
        kms_public_url,
        google_cse_config: GoogleCseConfig {
            google_cse_enable: true,
            google_cse_disable_tokens_validation: true,
            google_cse_incoming_url_whitelist: None,
            google_cse_migration_key: None,
        },
        ..Default::default()
    }
}

pub(crate) fn get_tmp_sqlite_path() -> PathBuf {
    // Set the absolute path of the project directory
    let project_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Cannot get parent directory of CARGO_MANIFEST_DIR")
        .parent()
        .expect("Cannot get parent of parent directory of CARGO_MANIFEST_DIR")
        .join(Path::new("test_data").join("sqlite"));

    // Create the directory if it doesn't exist
    if !project_dir.exists() {
        std::fs::create_dir_all(&project_dir).expect("Failed to create test_data/sqlite directory");
    }

    // get the current date and time as an ISO 8601 string using OffsetDateTime
    let now = OffsetDateTime::now_utc().format(&Iso8601::DEFAULT).unwrap();
    // replace the ":" with "-" to make it a valid filename
    let name = now.replace(':', "-");

    // Add thread ID to ensure uniqueness when tests run in parallel
    let thread_id = std::thread::current().id();

    project_dir.join(format!("{name}_{thread_id:?}.sqlite"))
}

/// Creates a test application instance with KMIP and Google CSE capabilities.
///
/// # Arguments
///
/// * `kms_public_url` - Optional public URL for the KMS server
/// * `privileged_users` - Optional list of users with elevated permissions
///
/// # Google CSE Support
///
/// The test app includes Google Client-Side Encryption (CSE) endpoints
///
/// The app automatically generates and manages RSA keypairs for JWT authentication:
/// - Private key stored as `google_cse_rsa`
/// - Public key stored as  `google_cse_rsa_pk` and exposed via `/google_cse/certs`
pub(crate) async fn test_app(
    kms_public_url: Option<String>,
    privileged_users: Option<Vec<String>>,
) -> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error> {
    let clap_config = https_clap_config_opts(kms_public_url);

    let server_params =
        Arc::new(ServerParams::try_from(clap_config).expect("cannot create server params"));

    let kms_server = Arc::new(
        KMS::instantiate(server_params.clone())
            .await
            .expect("cannot instantiate KMS server"),
    );

    // Handle Google RSA Keypair for CSE Kacls migration
    if server_params.google_cse.google_cse_enable {
        handle_google_cse_rsa_keypair(&kms_server, &server_params)
            .await
            .expect("start KMS server: failed managing Google CSE RSA Keypair");
    }

    let mut app = App::new()
        .app_data(Data::new(kms_server.clone()))
        .app_data(Data::new(privileged_users))
        .service(routes::root_redirect::root_redirect_to_ui)
        .service(routes::health::get_health)
        .service(routes::get_version)
        .service(routes::kmip::kmip_2_1_json)
        .service(routes::kmip::kmip)
        .service(routes::access::list_owned_objects)
        .service(routes::access::list_access_rights_obtained)
        .service(routes::access::list_accesses)
        .service(routes::access::grant_access)
        .service(routes::access::revoke_access)
        .service(routes::access::get_create_access)
        .service(routes::access::get_privileged_access);

    let google_cse_jwt_config = google_cse_auth(None)
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
        .service(routes::google_cse::certs)
        .service(routes::google_cse::rewrap)
        .service(routes::google_cse::delegate);

    app = app.service(google_cse_scope);

    test::init_service(app).await
}

/// Creates a test application instance using an explicit `ClapConfig`.
///
/// This is useful for end-to-end KMIP policy tests that need to tune allowlists
/// and enforcement settings and then validate behavior through the HTTP stack.
pub(crate) async fn test_app_with_clap_config(
    clap_config: ClapConfig,
    privileged_users: Option<Vec<String>>,
) -> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error> {
    let server_params =
        Arc::new(ServerParams::try_from(clap_config).expect("cannot create server params"));

    let kms_server = Arc::new(
        KMS::instantiate(server_params.clone())
            .await
            .expect("cannot instantiate KMS server"),
    );

    if server_params.google_cse.google_cse_enable {
        handle_google_cse_rsa_keypair(&kms_server, &server_params)
            .await
            .expect("start KMS server: failed managing Google CSE RSA Keypair");
    }

    let mut app = App::new()
        .app_data(Data::new(kms_server.clone()))
        .app_data(Data::new(privileged_users))
        .service(routes::root_redirect::root_redirect_to_ui)
        .service(routes::health::get_health)
        .service(routes::get_version)
        .service(routes::kmip::kmip_2_1_json)
        .service(routes::kmip::kmip)
        .service(routes::access::list_owned_objects)
        .service(routes::access::list_access_rights_obtained)
        .service(routes::access::list_accesses)
        .service(routes::access::grant_access)
        .service(routes::access::revoke_access)
        .service(routes::access::get_create_access)
        .service(routes::access::get_privileged_access);

    let google_cse_jwt_config = google_cse_auth(None)
        .await
        .expect("cannot setup Google CSE auth");

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
        .service(routes::google_cse::certs)
        .service(routes::google_cse::rewrap)
        .service(routes::google_cse::delegate);

    app = app.service(google_cse_scope);

    test::init_service(app).await
}

pub(crate) async fn post_2_1<B, O, R, S>(app: &S, operation: O) -> KResult<R>
where
    O: Serialize,
    R: DeserializeOwned + 'static,
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

    // Some KMIP operations (e.g., Locate) return a structured response payload.
    // Tests historically deserialize `LocateResponse` directly into `Vec<UniqueIdentifier>`.
    // Prefer decoding the proper response type and extracting the list.
    if std::any::TypeId::of::<R>() == std::any::TypeId::of::<Vec<UniqueIdentifier>>() {
        let locate: LocateResponse = from_ttlv(ttlv)?;
        // Safety: guarded by TypeId check.
        let v: Vec<UniqueIdentifier> = locate.unique_identifier.unwrap_or_default();
        // Convert Vec<UniqueIdentifier> -> R without requiring R: From<_>
        let boxed: Box<dyn std::any::Any> = Box::new(v);
        return Ok(*boxed.downcast::<R>().expect("TypeId matched"));
    }

    Ok(from_ttlv(ttlv)?)
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
