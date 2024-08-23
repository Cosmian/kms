use std::{rc::Rc, sync::Arc};

use actix_service::Service;
use actix_web::{
    body::{BoxBody, EitherBody},
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    Error, HttpMessage, HttpResponse,
};
use tracing::{debug, error, trace};

use crate::{error::KmsError, result::KResult};

pub(crate) async fn manage_token_request<S, B>(
    service: Rc<S>,
    api_token: Arc<String>,
    req: ServiceRequest,
) -> Result<ServiceResponse<EitherBody<B, BoxBody>>, Error>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    trace!("API Token Authentication...");
    match manage_token(&api_token, &req) {
        Ok(auth_claim) => {
            req.extensions_mut().insert(auth_claim);
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        }
        Err(e) => {
            error!("{:?} {} 401 unauthorized: {e:?}", req.method(), req.path(),);
            Ok(req
                .into_response(HttpResponse::Unauthorized().finish())
                .map_into_right_body())
        }
    }
}

pub(crate) fn manage_token(api_token: &Arc<String>, req: &ServiceRequest) -> KResult<bool> {
    trace!("Token authentication...");
    let client_token = req
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or_else(|| KmsError::InvalidRequest("Missing Authorization header".to_string()))?
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

    if client_token[1].trim_start() == api_token.as_str() {
        debug!("Token authentication successful");
        Ok(true)
    } else {
        error!(
            "{:?} {} 401 unauthorized: Client and server authentication tokens mismatch",
            req.method(),
            req.path(),
        );
        Ok(false)
    }
}
