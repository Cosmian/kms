use std::sync::Arc;

use actix_web::{
    get, post,
    web::{Data, Json},
    HttpRequest, HttpResponse, HttpResponseBuilder,
};
use clap::crate_version;
use http::{header, StatusCode};
use tracing::{error, info, warn};

use crate::{database::KMSServer, error::KmsError, result::KResult};

pub mod access;
pub mod kmip;
pub mod tee;

impl actix_web::error::ResponseError for KmsError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let message = self.to_string();

        if status_code >= StatusCode::INTERNAL_SERVER_ERROR {
            error!("{status_code} - {message}");
        } else {
            warn!("{status_code} - {message}");
        }

        HttpResponseBuilder::new(status_code)
            .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
            .body(message)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            KmsError::RouteNotFound(_) => StatusCode::NOT_FOUND,

            KmsError::Unauthorized(_) => StatusCode::UNAUTHORIZED,

            KmsError::DatabaseError(_)
            | KmsError::TeeAttestationError(_)
            | KmsError::ConversionError(_)
            | KmsError::CryptographicError(_)
            | KmsError::Redis(_)
            | KmsError::Findex(_)
            | KmsError::Certificate(_)
            | KmsError::RatlsError(_)
            | KmsError::ServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,

            KmsError::KmipError(..)
            | KmsError::NotSupported(_)
            | KmsError::UnsupportedProtectionMasks
            | KmsError::UnsupportedPlaceholder
            | KmsError::InconsistentOperation(..)
            | KmsError::InvalidRequest(_)
            | KmsError::ItemNotFound(_)
            | KmsError::UrlError(_) => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }
}

/// Add a new group to the KMS = add a new database
#[post("/new_database")]
pub async fn add_new_database(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    info!("GET /new_database {}", kms.get_user(req)?);
    Ok(Json(kms.add_new_database().await?))
}

/// Get the KMS version
#[get("/version")]
pub async fn get_version(req: HttpRequest, kms: Data<Arc<KMSServer>>) -> KResult<Json<String>> {
    info!("GET /version {}", kms.get_user(req)?);
    Ok(Json(crate_version!().to_string()))
}
