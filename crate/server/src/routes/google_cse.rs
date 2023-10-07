use std::sync::Arc;

use actix_web::{
    get,
    web::{Data, Json},
    HttpRequest,
};
use clap::crate_version;
use tracing::info;

use crate::{result::KResult, KMSServer};

/// Get the status for Google CSE
#[get("/status")]
pub async fn get_status(req: HttpRequest, kms: Data<Arc<KMSServer>>) -> KResult<Json<String>> {
    info!("XXXX GET /status {}", kms.get_user(req)?);
    Ok(Json(crate_version!().to_string()))
}

/// Get the status for Google CSE
#[get("/blah")]
pub async fn say_blah(req: HttpRequest, kms: Data<Arc<KMSServer>>) -> KResult<Json<String>> {
    info!("XXXX GET /blah {}", kms.get_user(req)?);
    Ok(Json(crate_version!().to_string()))
}
