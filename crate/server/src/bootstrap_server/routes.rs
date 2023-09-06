use std::{path::PathBuf, sync::Arc};

use actix_multipart::Multipart;
use actix_web::{
    post,
    web::{Data, Json},
    HttpRequest,
};
use cosmian_kms_utils::access::SuccessResponse;
use futures::StreamExt;
use openssl::pkcs12::Pkcs12;
use serde::Deserialize;
use tracing::warn;
use url::Url;

use crate::{
    bootstrap_server::server::{BootstrapServer, BootstrapServerMessage},
    config::DbParams,
    database::redis::RedisWithFindex,
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

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordConfig {
    pub password: String,
}

///
#[post("/pkcs12")]
pub async fn receive_pkcs12(
    _req: HttpRequest,
    mut payload: Multipart,
    bootstrap_server: Data<Arc<BootstrapServer>>,
) -> KResult<Json<SuccessResponse>> {
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

    *bootstrap_server
        .pkcs12_received
        .write()
        .expect("PKCS12 received lock poisoned") = Some(pkcs12);

    let response = SuccessResponse {
        success: format!("PKCS#12 of {} bytes received", bytes.len(),),
    };
    Ok(Json(response))
}

/// Supply a PKCS12 password if it is a non-empty string
#[post("/pkcs12-password")]
pub async fn pkcs12_password(
    _req: HttpRequest,
    config: Json<PasswordConfig>,
    bootstrap_server: Data<Arc<BootstrapServer>>,
) -> KResult<Json<SuccessResponse>> {
    let config = config.into_inner();

    *bootstrap_server
        .pkcs12_password_received
        .write()
        .expect("PKCS12 password received lock poisoned") = Some(config.password.to_owned());

    let response = SuccessResponse {
        success: "PKCS#12 password received".to_string(),
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
    let url = Url::parse(&config.url)?;
    let master_key = RedisWithFindex::master_key_from_password(&config.master_password)?;
    let label = config.findex_label.into_bytes();
    let db_params = DbParams::RedisFindex(url, master_key, label);

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
    let url = Url::parse(&config.url)?;
    let db_params = DbParams::Postgres(url);

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
    let url = Url::parse(&config.url)?;
    let db_params = DbParams::Mysql(url);

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

    maybe_parse_and_send_pkcs12(bootstrap_server.get_ref().clone())?;

    // check if DB params have been supplied
    if !*bootstrap_server
        .db_params_supplied
        .read()
        .expect("db params supplied lock poisoned")
    {
        return Err(KmsError::InvalidRequest(
            "The KMS will not start: please provide database parameters to the bootstrap server \
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
        let warning =
            "No PKCS12 file has been supplied, therefore the KMS will start in plain HTTP mode.";
        warnings += " ";
        warnings += warning;
        warn!(warning)
    }

    // issue a warning if the database will be cleared
    if clear_database {
        let warning = "The KMS database will be erased.";
        warnings += " ";
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
        format!(" with warnings:{}", warnings)
    };
    Ok(Json(SuccessResponse {
        success: "Starting the KMS server".to_string() + warnings.as_str(),
    }))
}

fn maybe_parse_and_send_pkcs12(bootstrap_server: Arc<BootstrapServer>) -> KResult<()> {
    if let Some(pkcs12) = bootstrap_server
        .pkcs12_received
        .read()
        .expect("pkcs12 received lock poisoned")
        .as_ref()
    {
        // determine the password to use
        let password = bootstrap_server
            .pkcs12_password_received
            .read()
            .expect("pkcs12 received lock poisoned")
            .as_ref()
            .map(|s| s.to_owned())
            .unwrap_or_default();

        // Verify the PKCS 12 by extracting the certificate, private key and chain
        let p12 = pkcs12.parse2(&password).map_err(|e| {
            kms_error!(
                "Error parsing PKCS#12: {}. Did you supply the correct password?",
                e
            )
        })?;
        p12.cert
            .as_ref()
            .ok_or_else(|| kms_error!("Missing certificate"))?;
        p12.pkey
            .as_ref()
            .ok_or_else(|| kms_error!("Missing private key"))?;

        // Send the parsed PKCS12 to the main thread on the tx channel
        bootstrap_server
            .bs_msg_tx
            .send(BootstrapServerMessage::Pkcs12(p12))
            .map_err(|e| kms_error!("failed sending the PKCS12 to the main thread: {e}"))?;

        //flag the db params as supplied
        *bootstrap_server
            .pkcs12_supplied
            .write()
            .expect("PKCS12 supplied lock poisoned") = true;
    }

    Ok(())
}
