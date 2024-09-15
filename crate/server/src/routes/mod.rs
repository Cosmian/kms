use std::sync::Arc;

use actix_web::{
    get,
    http::{header, StatusCode},
    post,
    web::{Data, Json},
    HttpRequest, HttpResponse, HttpResponseBuilder,
};
use clap::crate_version;
use tracing::{error, info, warn};

use crate::{database::KMSServer, error::KmsError, result::KResult};

pub mod access;
pub mod google_cse;
pub mod kmip;
pub mod ms_dke;

impl actix_web::error::ResponseError for KmsError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::RouteNotFound(_) => StatusCode::NOT_FOUND,

            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,

            Self::DatabaseError(_)
            | Self::ConversionError(_)
            | Self::CryptographicError(_)
            | Self::Redis(_)
            | Self::Findex(_)
            | Self::Certificate(_)
            | Self::ServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,

            Self::KmipError(..)
            | Self::NotSupported(_)
            | Self::UnsupportedProtectionMasks
            | Self::UnsupportedPlaceholder
            | Self::InconsistentOperation(..)
            | Self::InvalidRequest(_)
            | Self::ItemNotFound(_)
            | Self::ClientConnectionError(_)
            | Self::UrlError(_) => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }

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
}

/// Add a new group to the KMS = add a new database
#[post("/new_database")]
pub(crate) async fn add_new_database(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    info!("GET /new_database {}", kms.get_user(&req));
    Ok(Json(kms.add_new_database().await?))
}

/// Get the KMS version
#[get("/version")]
pub(crate) async fn get_version(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    info!("GET /version {}", kms.get_user(&req));
    Ok(Json(format!(
        "{} ({})",
        crate_version!().to_owned(),
        openssl::version::version()
    )))
}
