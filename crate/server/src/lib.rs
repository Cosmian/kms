//! The lib is mostly useful for the CLI tests but
//! since it is declared, all the modules in other Files
//! will be resolved against the lib. So everything is exported

pub mod bootstrap_server;
pub mod config;
pub mod core;
pub mod database;
pub mod error;
pub mod kms_server;
pub mod middlewares;
pub mod result;
pub mod routes;

use std::{pin::Pin, sync::mpsc};

use actix_web::dev::ServerHandle;
use bootstrap_server::start_kms_server_using_bootstrap_server;
use config::ServerParams;
pub use database::KMSServer;
use futures::Future;
use kms_server::start_kms_server;
use result::KResult;

#[cfg(test)]
mod tests;

pub fn start_server(
    server_params: ServerParams,
    kms_server_handle_tx: Option<mpsc::Sender<ServerHandle>>,
) -> Pin<Box<dyn Future<Output = KResult<()>>>> {
    if server_params.bootstrap_server_params.use_bootstrap_server {
        Box::pin(start_kms_server_using_bootstrap_server(
            server_params,
            kms_server_handle_tx,
        ))
    } else {
        Box::pin(start_kms_server(server_params, kms_server_handle_tx))
    }
}
