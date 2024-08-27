use std::{rc::Rc, sync::Arc};

use actix_service::Service;
use actix_web::{
    body::{BoxBody, EitherBody},
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    Error, HttpResponse,
};
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType, kmip_operations::ErrorReason, kmip_types::StateEnumeration,
};
use cosmian_kms_client::access::ObjectOperationType;
use tracing::{debug, error, trace};

use crate::{
    core::KMS, database::object_with_metadata::ObjectWithMetadata, error::KmsError, result::KResult,
};

pub(crate) async fn manage_token_request<S, B>(
    service: Rc<S>,
    kms_server: Arc<KMS>,
    req: ServiceRequest,
) -> Result<ServiceResponse<EitherBody<B, BoxBody>>, Error>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    trace!("API Token Authentication...");
    match manage_token(kms_server, &req).await {
        Ok(()) => {
            trace!("API Token Authentication successful");
            Ok(service.call(req).await?.map_into_left_body())
        }
        Err(e) => {
            error!("{:?} {} 401 unauthorized: {e:?}", req.method(), req.path(),);
            Ok(req
                .into_response(HttpResponse::Unauthorized().finish())
                .map_into_right_body())
        }
    }
}

async fn get_api_token(kms_server: &Arc<KMS>, api_token_id: &str) -> KResult<String> {
    let mut owm_s = kms_server
        .db
        .retrieve(
            api_token_id,
            &kms_server.params.default_username,
            ObjectOperationType::Get,
            None,
        )
        .await?
        .into_values()
        .filter(|owm| {
            // only active objects
            if owm.state != StateEnumeration::Active {
                return false
            }
            // only symmetric keys
            if owm.object.object_type() != ObjectType::SymmetricKey {
                return false
            }
            true
        })
        .collect::<Vec<ObjectWithMetadata>>();

    // there can only be one private key
    let owm = owm_s.pop().ok_or_else(|| {
        KmsError::KmipError(
            ErrorReason::Item_Not_Found,
            format!("The symmetric key of unique identifier  {api_token_id} could not be found"),
        )
    })?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "rekey: get: too many symmetric keys for uid/tags: {api_token_id}",
        )))
    }

    // get the key bytes on hex format. hex is preferred here since exported a symmetric key format is hex.
    Ok(hex::encode(owm.object.key_block()?.key_bytes()?).to_lowercase())
}

async fn manage_token(kms_server: Arc<KMS>, req: &ServiceRequest) -> KResult<()> {
    trace!("Token authentication...");

    match &kms_server.params.api_token_id {
        Some(api_token_id) => {
            let api_token = get_api_token(&kms_server, api_token_id.as_str()).await?;

            let client_token = req
                .headers()
                .get(header::AUTHORIZATION)
                .ok_or_else(|| {
                    KmsError::InvalidRequest("Missing Authorization header".to_string())
                })?
                .to_str()
                .map_err(|e| {
                    KmsError::InvalidRequest(format!(
                        "Error converting header value to string: {e:?}"
                    ))
                })?
                .split("Bearer")
                .collect::<Vec<&str>>();

            if client_token.len() != 2 {
                return Err(KmsError::InvalidRequest(format!(
                    "Invalid Authorization header format: expected: \"Bearer <API_TOKEN>\", got \
                     {client_token:?}"
                )));
            }
            let client_token = client_token[1].trim_start().to_lowercase();
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
                    "Client and server authentication tokens mismatch".to_string(),
                ))
            }
        }
        None => {
            trace!("No API Token provided");
            Ok(())
        }
    }
}
