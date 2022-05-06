pub mod config;
mod core;
mod database;
pub mod error;

mod middlewares;
pub mod result;
mod routes;

use std::sync::Arc;
pub mod log_utils;

use actix_web::{
    middleware::Condition,
    web::{Data, JsonConfig, PayloadConfig},
    App, HttpServer,
};
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
            .app_data(PayloadConfig::new(10_000_000_000))
            .app_data(JsonConfig::default().limit(10_000_000_000))
            .service(endpoint::kmip)
            .service(endpoint::list_owned_objects)
            .service(endpoint::list_shared_objects)
            .service(endpoint::list_accesses)
            .service(endpoint::insert_access)
            .service(endpoint::delete_access)
    })
    .bind(format!("{}:{}", hostname(), port()))?
    .run()
    .await
    .map_err(Into::into)
}
