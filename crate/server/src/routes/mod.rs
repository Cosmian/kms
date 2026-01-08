use std::{path::PathBuf, sync::Arc};

use actix_files::NamedFile;
use actix_web::{
    HttpRequest, HttpResponse, HttpResponseBuilder, Result, get,
    http::{
        StatusCode,
        header::{self, ContentDisposition, DispositionParam, DispositionType},
    },
    web::{Data, Json},
};
use clap::crate_version;
use cosmian_logger::{error, info, warn};

use crate::{core::KMS, error::KmsError, result::KResult};

pub mod access;
pub mod google_cse;
pub mod kmip;
pub mod ms_dke;
pub mod ui_auth;

impl actix_web::error::ResponseError for KmsError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::RouteNotFound(_) => StatusCode::NOT_FOUND,

            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,

            Self::Database(_)
            | Self::ConversionError(_)
            | Self::CryptographicError(_)
            | Self::Redis(_)
            | Self::Findex(_)
            | Self::Certificate(_)
            | Self::Tls(_)
            | Self::ServerError(_)
            | Self::Default(_) => StatusCode::INTERNAL_SERVER_ERROR,

            Self::Kmip21Error(..)
            | Self::Kmip14Error(..)
            | Self::NotSupported(_)
            | Self::UnsupportedProtectionMasks
            | Self::UnsupportedPlaceholder
            | Self::InconsistentOperation(..)
            | Self::InvalidRequest(_)
            | Self::ItemNotFound(_)
            | Self::ClientConnectionError(_)
            | Self::UnsupportedAlgorithm(_)
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

/// Get the KMS version
#[get("/version")]
pub(crate) async fn get_version(req: HttpRequest, kms: Data<Arc<KMS>>) -> KResult<Json<String>> {
    info!("GET /version {}", kms.get_user(&req));
    Ok(Json(format!(
        "{} ({}-{})",
        crate_version!().to_owned(),
        openssl::version::version(),
        if cfg!(feature = "non-fips") {
            "non-FIPS"
        } else {
            "FIPS"
        }
    )))
}

#[get("/download-cli")]
pub(crate) async fn download_cli(req: HttpRequest, kms: Data<Arc<KMS>>) -> Result<NamedFile> {
    info!("GET /download-cli {}", kms.get_user(&req));

    // Path to the actual file on disk you want to serve
    let path: PathBuf = "./resources/tarballs/my-cli-tool.tar.gz".into();

    // Open the file (returns io::Error -> converted into actix_web::Error via ?)
    let file = NamedFile::open(path)?;

    // Set Content-Disposition: attachment; filename="my-cli-tool.tar.gz"
    let cd = ContentDisposition {
        disposition: DispositionType::Attachment,
        parameters: vec![DispositionParam::Filename(String::from(
            "my-cli-tool.tar.gz",
        ))],
    };

    Ok(file.set_content_disposition(cd))
}
