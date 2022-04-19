pub mod config;
mod core;
mod database;
pub mod error;

mod middlewares;
pub mod result;
mod routes;

use std::sync::Arc;
pub mod log_utils;

use actix_web::{middleware::Condition, web::Data, App, HttpServer};
use config::{hostname, jwks, port};
use database::KMSServer;
use middlewares::auth::Auth;

use crate::routes::endpoint;

pub async fn start_server() -> eyre::Result<()> {
    let kms_server = Arc::new(KMSServer::instantiate().await?);

    HttpServer::new(move || {
        App::new()
            .wrap(Condition::new(jwks().is_some(), Auth))
            .app_data(Data::new(kms_server.clone()))
            .service(endpoint::kmip)
            .service(endpoint::access_insert)
            .service(endpoint::access_delete)
    })
    .bind(format!("{}:{}", hostname(), port()))?
    .run()
    .await
    .map_err(Into::into)
}
