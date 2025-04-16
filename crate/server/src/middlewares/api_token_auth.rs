use std::{rc::Rc, sync::Arc};

use actix_service::Service;
use actix_web::{
    Error, HttpResponse,
    body::{BoxBody, EitherBody},
    dev::{ServiceRequest, ServiceResponse},
    http::header,
};
use base64::Engine;
use cosmian_kmip::{
    kmip_0::kmip_types::{ErrorReason, State},
    kmip_2_1::kmip_objects::ObjectType,
};
use tracing::{debug, error, trace};

use crate::{core::KMS, error::KmsError, result::KResult};

pub(crate) async fn manage_api_token_request<S, B>(
    service: Rc<S>,
    kms_server: Arc<KMS>,
    req: ServiceRequest,
) -> Result<ServiceResponse<EitherBody<B, BoxBody>>, Error>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    match manage_api_token(kms_server, &req).await {
        Ok(()) => Ok(service.call(req).await?.map_into_left_body()),
        Err(e) => {
            error!("{:?} {} 401 unauthorized: {e:?}", req.method(), req.path(),);
            Ok(req
                .into_response(HttpResponse::Unauthorized().finish())
                .map_into_right_body())
        }
    }
}

async fn get_api_token(kms: &Arc<KMS>, api_token_id: &str) -> KResult<String> {
    let owm = kms
        .database
        .retrieve_object(api_token_id, None)
        .await?
        .ok_or_else(|| {
            KmsError::Kmip21Error(
                ErrorReason::Item_Not_Found,
                format!("The symmetric key of unique identifier {api_token_id} could not be found"),
            )
        })?;
    // only symmetric keys
    if owm.object().object_type() != ObjectType::SymmetricKey {
        return Err(KmsError::InvalidRequest(format!(
            "The key for API token: {api_token_id} is not a symmetric key",
        )))
    }
    // only active objects
    if owm.state() != State::Active {
        return Err(KmsError::InvalidRequest(format!(
            "The symmetric key for API token: {api_token_id} is not active",
        )))
    }
    // Get the API token bytes in base64
    Ok(base64::engine::general_purpose::STANDARD
        .encode(owm.object().key_block()?.key_bytes()?)
        .to_lowercase())
}

async fn manage_api_token(kms_server: Arc<KMS>, req: &ServiceRequest) -> KResult<()> {
    if let Some(api_token_id) = &kms_server.params.api_token_id {
        trace!("Token authentication using this API token ID: {api_token_id}");
        let api_token = get_api_token(&kms_server, api_token_id.as_str()).await?;

        let client_token = req
            .headers()
            .get(header::AUTHORIZATION)
            .ok_or_else(|| KmsError::InvalidRequest("Missing Authorization header".to_owned()))?
            .to_str()
            .map_err(|e| {
                KmsError::InvalidRequest(format!("Error converting header value to string: {e:?}"))
            })?
            .split("Bearer")
            .collect::<Vec<&str>>();

        if client_token.len() != 2 {
            return Err(KmsError::InvalidRequest(format!(
                "Invalid Authorization header format: expected: \"Bearer <API_TOKEN>\", got \
                 {client_token:?}"
            )));
        }
        let client_token = client_token
            .get(1)
            .ok_or_else(|| {
                KmsError::ServerError(
                    "Missing token after 'Bearer' in Authorization header".to_owned(),
                )
            })?
            .trim_start()
            .to_lowercase();

        trace!("API Token: {api_token}");
        trace!("Client API Token: {client_token}");

        if client_token == api_token.as_str() {
            debug!("Token authentication successful");
            Ok(())
        } else {
            error!(
                "{:?} {} 401 unauthorized: Client and server authentication tokens mismatch",
                req.method(),
                req.path(),
            );
            Err(KmsError::Unauthorized(
                "Client and server authentication tokens mismatch".to_owned(),
            ))
        }
    } else {
        trace!("No API Token provided");
        Ok(())
    }
}
