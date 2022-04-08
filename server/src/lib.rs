mod auth;
pub mod config;
pub mod error;
mod kmip;
mod kmip_endpoint;
mod middlewares;
pub mod result;

use std::sync::Arc;

use actix_web::{middleware::Condition, web::Data, App, HttpServer};
use config::{hostname, jwks, port};
use kmip::kmip_server::KMSServer;
use middlewares::auth::Auth;

pub async fn start_server() -> eyre::Result<()> {
    let kms_server = Arc::new(KMSServer::instantiate().await?);

    HttpServer::new(move || {
        App::new()
            .wrap(Condition::new(jwks().is_some(), Auth))
            .app_data(Data::new(kms_server.clone()))
            .service(kmip_endpoint::kmip)
            .service(kmip_endpoint::access_insert)
            .service(kmip_endpoint::access_delete)
    })
    .bind(format!("{}:{}", hostname(), port()))?
    .run()
    .await
    .map_err(Into::into)
}
