use std::{path::PathBuf, sync::Arc};

use actix_multipart::Multipart;
use actix_web::{
    http::header,
    post,
    web::{Data, Json},
    HttpRequest,
};
use cosmian_kms_utils::access::SuccessResponse;
use futures::StreamExt;
use openssl::pkcs12::Pkcs12;
use serde::Deserialize;
use tracing::warn;

use crate::{
    bootstrap_server::start::{BootstrapServer, BootstrapServerMessage},
    config::DbParams,
    error::KmsError,
    kms_error,
    result::KResult,
};

#[derive(Debug, Clone, Deserialize)]
pub struct RedisFindexConfig {
    pub url: String,
    pub master_password: String,
    pub findex_label: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UrlConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PathConfig {
    pub path: String,
}

#[post("/pkcs12")]
pub async fn receive_pkcs12(
    req: HttpRequest,
    mut payload: Multipart,
    bootstrap_server: Data<Arc<BootstrapServer>>,
) -> KResult<Json<SuccessResponse>> {
    // print the request content-type
    match req.headers().get(header::CONTENT_TYPE) {
        Some(content_type) => {
            // match the content_type to multipart/form-data
            if content_type.as_bytes().starts_with(b"multipart/form-data") {
                println!("content-type: multipart/form-data");
            } else {
                println!("another content-type: {:#?}", content_type);
            }
        }
        None => println!("content-type: None"),
    };

    // Extract the bytes from a multipart/form-data payload
    // and return them as a `Vec<u8>`.
    let mut bytes = Vec::new();
    while let Some(field) = payload.next().await {
        let mut field =
            field.map_err(|e| kms_error!("Failed reading multipart/form-data field: {e}"))?;
        // we want to read the field/part which has a content-type of application/octet-stream
        if let Some(content_type) = field.content_type() {
            if *content_type == mime::APPLICATION_OCTET_STREAM {
                while let Some(chunk) = field.next().await {
                    let data = chunk.map_err(|e| {
                        kms_error!("Failed reading the bytes form the multipart/form-data: {e}")
                    })?;
                    bytes.extend_from_slice(&data);
                }
            }
        }
    }

    // Parse the PKCS#12
    let pkcs12 = Pkcs12::from_der(&bytes)
        .map_err(|e| kms_error!("Error reading PKCS#12 from DER: {}", e))?;
    // Verify the PKCS 12 by extracting the certificate, private key and chain
    let p12 = pkcs12
        .parse2("")
        .map_err(|e| kms_error!("Error parsing PKCS#12: {}", e))?;
    let cert = p12
        .cert
        .as_ref()
        .ok_or_else(|| kms_error!("Missing certificate"))?;
    let subject_name = cert.subject_name().to_owned()?;
    let _pkey = p12
        .pkey
        .as_ref()
        .ok_or_else(|| kms_error!("Missing private key"))?;

    // Send the parsed PKCS12 to the main thread on the tx channel
    bootstrap_server
        .bs_msg_tx
        .send(BootstrapServerMessage::PKCS12(p12))
        .map_err(|e| kms_error!("failed sending the PKCS12 to the main thread: {e}"))?;

    //flag the db params as supplied
    *bootstrap_server
        .pkcs12_supplied
        .write()
        .expect("PKCS12 supplied lock poisoned") = true;

    let response = SuccessResponse {
        success: format!(
            "PKCS#12 of {} bytes with CN:{:#?}, received",
            bytes.len(),
            subject_name.as_ref()
        ),
    };
    Ok(Json(response))
}

/// Send the DbParams to the main thread on the tx channel,
/// flag the db params as supplied, and return a success response
fn process_db_params(
    bootstrap_server: Data<Arc<BootstrapServer>>,
    db_params: DbParams,
) -> KResult<Json<SuccessResponse>> {
    let config_name = match db_params {
        DbParams::Sqlite(_) => "Sqlite",
        DbParams::SqliteEnc(_) => "Sqlite Enc.",
        DbParams::Postgres(_) => "PostgreSQL",
        DbParams::Mysql(_) => "MySql/MariaDB",
        DbParams::RedisFindex(_, _, _) => "Redis-Findex",
    };

    // Send the Redis-Findex configuration to the main thread on the tx channel
    bootstrap_server
        .bs_msg_tx
        .send(BootstrapServerMessage::DbParams(db_params))
        .map_err(|e| {
            kms_error!(
                "failed sending the {} configuration to the main thread: {}",
                &config_name,
                e
            )
        })?;

    //flag the db params as supplied
    *bootstrap_server
        .db_params_supplied
        .write()
        .expect("db params supplied lock poisoned") = true;

    Ok(Json(SuccessResponse {
        success: format!("Successfully received {} configuration", config_name),
    }))
}

/// Supply a Redis-Findex Configuration to the bootstrap server
#[post("/redis-findex")]
pub async fn redis_findex_config(
    _req: HttpRequest,
    config: Json<RedisFindexConfig>,
    bootstrap_server: Data<Arc<BootstrapServer>>,
) -> KResult<Json<SuccessResponse>> {
    let config = config.into_inner();
    let db_params = DbParams::redis_findex_db_params(
        &config.url,
        &config.master_password,
        &config.findex_label,
    )?;

    process_db_params(bootstrap_server, db_params)
}

/// Supply a PostgreSQL Configuration to the bootstrap server
#[post("/postgresql")]
pub async fn postgresql_config(
    _req: HttpRequest,
    config: Json<UrlConfig>,
    bootstrap_server: Data<Arc<BootstrapServer>>,
) -> KResult<Json<SuccessResponse>> {
    let config = config.into_inner();
    let db_params = DbParams::Postgres(config.url);

    process_db_params(bootstrap_server, db_params)
}

/// Supply a MySQL/MariaDB Configuration to the bootstrap server
#[post("/mysql")]
pub async fn mysql_config(
    _req: HttpRequest,
    config: Json<UrlConfig>,
    bootstrap_server: Data<Arc<BootstrapServer>>,
) -> KResult<Json<SuccessResponse>> {
    let config = config.into_inner();
    let db_params = DbParams::Mysql(config.url);

    process_db_params(bootstrap_server, db_params)
}

/// Supply a Sqlite Configuration to the bootstrap server
#[post("/sqlite")]
pub async fn sqlite_config(
    _req: HttpRequest,
    config: Json<PathConfig>,
    bootstrap_server: Data<Arc<BootstrapServer>>,
) -> KResult<Json<SuccessResponse>> {
    let config = config.into_inner();
    let db_params = DbParams::Sqlite(PathBuf::from(&config.path));

    process_db_params(bootstrap_server, db_params)
}

/// Supply a SqliteEnc Configuration to the bootstrap server
#[post("/sqlite-enc")]
pub async fn sqlite_enc_config(
    _req: HttpRequest,
    config: Json<PathConfig>,
    bootstrap_server: Data<Arc<BootstrapServer>>,
) -> KResult<Json<SuccessResponse>> {
    let config = config.into_inner();
    let db_params = DbParams::SqliteEnc(PathBuf::from(&config.path));

    process_db_params(bootstrap_server, db_params)
}

#[derive(Debug, Clone, Deserialize)]
pub struct StartKmsServer {
    pub clear_database: Option<bool>,
}

/// Start the KMS server with the option to clear the database
#[post("/start")]
pub async fn start_kms_server_config(
    _req: HttpRequest,
    config: Json<StartKmsServer>,
    bootstrap_server: Data<Arc<BootstrapServer>>,
) -> KResult<Json<SuccessResponse>> {
    let config = config.into_inner();
    let clear_database = config.clear_database.unwrap_or(false);

    // check if DB params have been supplied
    if !*bootstrap_server
        .db_params_supplied
        .read()
        .expect("db params supplied lock poisoned")
    {
        return Err(KmsError::InvalidRequest(
            "The KMS will not start: please provide Database parameters to the bootstrap server \
             first."
                .to_string(),
        ))
    }

    let mut warnings = String::new();
    // issue a warning of no PKCS12 is supplied
    if !*bootstrap_server
        .pkcs12_supplied
        .read()
        .expect("pkcs12 supplied lock poisoned")
    {
        let warning = "No PKCS12 file has been supplied. The KMS will start in plain HTTP mode.";
        warnings += warning;
        warn!(warning)
    }

    // issue a warning if the database will be cleared
    if clear_database {
        let warning = "The KMS database will be erased.";
        warnings += warning;
        warn!(warning)
    }

    // Send the Start KMS server configuration to the main thread on the tx channel
    bootstrap_server
        .bs_msg_tx
        .send(BootstrapServerMessage::StartKmsServer(clear_database))
        .map_err(|e| {
            kms_error!("failed sending the Start KMS server configuration to the main thread: {e}")
        })?;

    let warnings = if warnings.is_empty() {
        "".to_string()
    } else {
        format!(" with warnings: {}", warnings)
    };
    Ok(Json(SuccessResponse {
        success: "Starting KMS server configuration".to_string() + warnings.as_str(),
    }))
}
