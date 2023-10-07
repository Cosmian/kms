use std::sync::Arc;

use actix_web::{
    get,
    web::{Data, Json},
    HttpRequest,
};
use clap::crate_version;
use serde::Serialize;
use tracing::info;

use crate::{result::KResult, KMSServer};

// {
//   "server_type": "KACLS",
//   "vendor_id": "Test",
//   "version": "demo",
//   "name": "K8 reference",
//   "operations_supported": [
//     "wrap", "unwrap", "privilegedunwrap",
//     "privatekeydecrypt", "privatekeysign", "privilegedprivatekeydecrypt"
//   ]
// }

#[derive(Serialize, Debug)] // Debug is required by ok_json()
pub struct StatusResponse {
    pub server_type: String,
    pub vendor_id: String,
    pub version: String,
    pub name: String,
    pub operations_supported: Vec<String>,
}

/// Get the status for Google CSE
#[get("/status")]
pub async fn get_status(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<StatusResponse>> {
    info!("GET /google_cse/status {}", kms.get_user(req)?);
    let response = Json(StatusResponse {
        server_type: "KACLS".to_string(),
        vendor_id: "Cosmian".to_string(),
        version: crate_version!().to_string(),
        name: "Cosmian KMS".to_string(),
        operations_supported: vec![
            "wrap".to_string(),
            "unwrap".to_string(),
            // "privilegedunwrap".to_string(),
            // "privatekeydecrypt".to_string(),
            // "privatekeysign".to_string(),
            // "privilegedprivatekeydecrypt".to_string(),
        ],
    });
    println!("response: {:?}", response);
    Ok(response)
}

/// Get the status for Google CSE
#[get("/blah")]
pub async fn say_blah(req: HttpRequest, kms: Data<Arc<KMSServer>>) -> KResult<Json<String>> {
    info!("XXXX GET /blah {}", kms.get_user(req)?);
    Ok(Json(crate_version!().to_string()))
}
