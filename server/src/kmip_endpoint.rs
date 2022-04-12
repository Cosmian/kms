use std::sync::Arc;

use actix_web::{
    delete, post,
    web::{Data, Json},
    HttpMessage, HttpRequest, HttpResponse, HttpResponseBuilder,
};
use cosmian_kmip::kmip::{
    access::{Access, ResponseSuccess},
    kmip_operations::{
        Create, CreateKeyPair, Decrypt, Destroy, Encrypt, Get, GetAttributes, Import, Locate,
        ReKeyKeyPair, Revoke,
    },
    ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV},
};
use http::{header, StatusCode};
use tracing::{debug, error, warn};

use crate::{
    error::KmsError,
    kmip::kmip_server::{server::kmip_server::KmipServer, KMSServer},
    kms_bail,
    middlewares::auth::AuthClaim,
    result::KResult,
};

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
            Self::RouteNotFound(_) => StatusCode::NOT_FOUND,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::ServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::KmipError(..) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::NotSupported(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::UnsupportedProtectionMasks => StatusCode::UNPROCESSABLE_ENTITY,
            Self::UnsupportedPlaceholder => StatusCode::UNPROCESSABLE_ENTITY,
            Self::InvalidRequest(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::ItemNotFound(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Generate KMIP generic key pair
#[post("/kmip/2_1")]
pub async fn kmip(
    req_http: HttpRequest,
    item: Json<TTLV>,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<TTLV>> {
    let ttlv_req = item.into_inner();
    let owner = get_owner(req_http)?;

    debug!("POST /kmip. Request: {:?}", ttlv_req.tag.as_str());

    let ttlv_resp = match ttlv_req.tag.as_str() {
        "Create" => {
            let req = from_ttlv::<Create>(&ttlv_req)?;
            let resp = kms_client.create(req, &owner).await?;
            to_ttlv(&resp)?
        }
        "CreateKeyPair" => {
            let req = from_ttlv::<CreateKeyPair>(&ttlv_req)?;
            let resp = kms_client.create_key_pair(req, &owner).await?;
            to_ttlv(&resp)?
        }
        "Decrypt" => {
            let req = from_ttlv::<Decrypt>(&ttlv_req)?;
            let resp = kms_client.decrypt(req, &owner).await?;
            to_ttlv(&resp)?
        }
        "Encrypt" => {
            let req = from_ttlv::<Encrypt>(&ttlv_req)?;
            let resp = kms_client.encrypt(req, &owner).await?;
            to_ttlv(&resp)?
        }
        "Get" => {
            let req = from_ttlv::<Get>(&ttlv_req)?;
            let resp = kms_client.get(req, &owner).await?;
            to_ttlv(&resp)?
        }
        "GetAttributes" => {
            let req = from_ttlv::<GetAttributes>(&ttlv_req)?;
            let resp = kms_client.get_attributes(req, &owner).await?;
            to_ttlv(&resp)?
        }
        "Import" => {
            let req = from_ttlv::<Import>(&ttlv_req)?;
            let resp = kms_client.import(req, &owner).await?;
            to_ttlv(&resp)?
        }
        "Revoke" => {
            let req = from_ttlv::<Revoke>(&ttlv_req)?;
            let resp = kms_client.revoke(req, &owner).await?;
            to_ttlv(&resp)?
        }
        "Locate" => {
            let req = from_ttlv::<Locate>(&ttlv_req)?;
            let resp = kms_client.locate(req, &owner).await?;
            to_ttlv(&resp)?
        }
        "ReKeyKeyPair" => {
            let req = from_ttlv::<ReKeyKeyPair>(&ttlv_req)?;
            let resp = kms_client.rekey_keypair(req, &owner).await?;
            to_ttlv(&resp)?
        }
        "Destroy" => {
            let req = from_ttlv::<Destroy>(&ttlv_req)?;
            let resp = kms_client.destroy(req, &owner).await?;
            to_ttlv(&resp)?
        }
        x => kms_bail!(KmsError::RouteNotFound(format!("Operation: {x}"))),
    };
    Ok(Json(ttlv_resp))
}

/// Add an access authorization for an object, given a `userid`
#[post("/access")]
pub async fn access_insert(
    req: HttpRequest,
    access: Json<Access>,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<ResponseSuccess>> {
    let access = access.into_inner();
    let owner = get_owner(req)?;

    kms_client.insert_access(&access, &owner).await?;

    Ok(Json(ResponseSuccess {
        success: format!("Access for {} successfully added", access.userid),
    }))
}

/// Revoke an access authorization for an object, given a `userid`
#[delete("/access")]
pub async fn access_delete(
    req: HttpRequest,
    access: Json<Access>,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<ResponseSuccess>> {
    let access = access.into_inner();
    let owner = get_owner(req)?;

    kms_client.delete_access(&access, &owner).await?;

    Ok(Json(ResponseSuccess {
        success: format!("Access for {} successfully deleted", access.userid),
    }))
}

fn get_owner(req_http: HttpRequest) -> KResult<String> {
    match req_http.extensions().get::<AuthClaim>() {
        Some(claim) => Ok(claim.email.clone()),
        None => Err(KmsError::Unauthorized(
            "No valid auth claim owner (email) from JWT".to_owned(),
        )),
    }
}
