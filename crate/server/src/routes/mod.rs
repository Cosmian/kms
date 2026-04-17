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
use serde::Serialize;

use crate::{core::KMS, error::KmsError, result::KResult};

const CLI_ARCHIVE_FOLDER: &str = "./resources";
const CLI_ARCHIVE_FILE_NAME: &str = "cli.zip";

pub mod access;
pub mod aws_xks;
pub(crate) mod azure_ekm;
pub mod google_cse;
pub mod health;
pub mod kmip;
pub mod ms_dke;
pub mod roles;
pub mod root_redirect;
pub mod ui_auth;
mod utils;

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

#[derive(Serialize)]
struct HsmInfo {
    configured: bool,
    model: Option<String>,
    slots: Vec<usize>,
}

#[derive(Serialize)]
struct ServerInfo {
    version: String,
    fips_mode: bool,
    hsm: HsmInfo,
}

/// Get high-level server information: version, FIPS mode, and HSM status.
/// This endpoint is public (no authentication required) so the UI can query it before login.
#[get("/server-info")]
pub(crate) async fn get_server_info(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<ServerInfo>> {
    info!("GET /server-info {}", kms.get_user(&req));
    let fips_mode = !cfg!(feature = "non-fips");
    let mut slots: Vec<usize> = kms.params.slot_passwords.keys().copied().collect();
    slots.sort_unstable();
    Ok(Json(ServerInfo {
        version: format!(
            "{} ({}-{})",
            crate_version!().to_owned(),
            openssl::version::version(),
            if cfg!(feature = "non-fips") {
                "non-FIPS"
            } else {
                "FIPS"
            }
        ),
        fips_mode,
        hsm: HsmInfo {
            configured: kms.params.hsm_model.is_some(),
            model: kms.params.hsm_model.clone(),
            slots,
        },
    }))
}

pub(crate) async fn cli_archive_download(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> Result<NamedFile> {
    info!("GET /download-cli {}", kms.get_user(&req));

    // Path to the actual file on disk you want to serve
    let path: PathBuf = PathBuf::from(CLI_ARCHIVE_FOLDER).join(CLI_ARCHIVE_FILE_NAME);

    // Open the file (returns io::Error -> converted into actix_web::Error via ?)
    let file = NamedFile::open(path)?;

    // Set Content-Disposition: attachment; filename="cli.zip"
    let cd = ContentDisposition {
        disposition: DispositionType::Attachment,
        parameters: vec![DispositionParam::Filename(String::from(
            CLI_ARCHIVE_FILE_NAME,
        ))],
    };

    Ok(file.set_content_disposition(cd))
}

pub(crate) async fn cli_archive_exists() -> HttpResponse {
    let path = PathBuf::from(CLI_ARCHIVE_FOLDER).join(CLI_ARCHIVE_FILE_NAME);
    let exists = tokio::fs::metadata(path).await.is_ok();

    // For HEAD, no body — return 200 or 404 with appropriate headers only.
    if exists {
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::NotFound().finish()
    }
}
