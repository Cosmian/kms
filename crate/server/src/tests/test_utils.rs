use std::{env::temp_dir, path::PathBuf, sync::Arc};

use actix_http::Request;
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceResponse},
    test,
    web::Data,
    App,
};
use cosmian_kmip::kmip::ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV};
use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

use crate::{
    config::{db::DBConfig, http::HTTPConfig, ClapConfig, ServerConfig},
    result::KResult,
    routes, KMSServer,
};

pub fn https_clap_config() -> ClapConfig {
    let tmp_dir = temp_dir();
    let uuid = Uuid::new_v4();
    let sqlite_path = tmp_dir.join(format!("{uuid}.sqlite"));
    if sqlite_path.exists() {
        std::fs::remove_file(&sqlite_path).unwrap();
    }

    ClapConfig {
        http: HTTPConfig {
            https_p12_file: Some(PathBuf::from("src/tests/kmserver.acme.com.p12")),
            https_p12_password: "password".to_string(),
            ..Default::default()
        },
        db: DBConfig {
            database_type: "sqlite".to_string(),
            database_url: None,
            sqlite_path,
            clear_database: true,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub async fn test_app()
-> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error> {
    let clap_config = https_clap_config();

    let server_config = ServerConfig::try_from(&clap_config).await.unwrap();

    let kms_server = Arc::new(
        KMSServer::instantiate(server_config)
            .await
            .expect("cannot instantiate KMS server"),
    );

    test::init_service(
        App::new()
            .app_data(Data::new(kms_server.clone()))
            .service(routes::kmip)
            .service(routes::grant_access)
            .service(routes::revoke_access),
    )
    .await
}

pub async fn post<B, O, R, S>(app: &S, operation: O) -> KResult<R>
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
    let body = test::call_and_read_body(&app, req).await;
    let json: TTLV = serde_json::from_slice(&body)?;
    let result: R = from_ttlv(&json)?;
    Ok(result)
}
