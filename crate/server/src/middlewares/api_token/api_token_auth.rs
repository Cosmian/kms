//! API Token Authentication Middleware
//!
//! This module handles API token-based authentication for the KMS server.
//! It verifies that incoming requests contain a valid API token in the
//! Authorization header that matches the configured token in the KMS.

use std::sync::Arc;

use actix_web::dev::ServiceRequest;
use base64::Engine;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{ErrorReason, State},
    kmip_2_1::kmip_objects::ObjectType,
};
use cosmian_logger::{debug, error, trace};

use crate::{
    core::KMS, error::KmsError, middlewares::extract_bearer_token, result::KResult,
    routes::enrollment::secrets_equal,
};

/// Fetch the API token (symmetric key) from the database, returned as a lowercase base64 string.
async fn get_api_token(kms: &Arc<KMS>, api_token_id: &str) -> KResult<String> {
    // Retrieve the object from the database
    let owm = kms
        .database
        .retrieve_object_arc(api_token_id)
        .await?
        .ok_or_else(|| {
            KmsError::Kmip21Error(
                ErrorReason::Item_Not_Found,
                format!("The symmetric key of unique identifier {api_token_id} could not be found"),
            )
        })?;

    // Validate that the object is a symmetric key
    if owm.object().object_type() != ObjectType::SymmetricKey {
        return Err(KmsError::InvalidRequest(format!(
            "The key for API token: {api_token_id} is not a symmetric key",
        )));
    }

    // Validate that the key is in active state
    if owm.state() != State::Active {
        return Err(KmsError::InvalidRequest(format!(
            "The symmetric key for API token: {api_token_id} is not active",
        )));
    }

    // Get the API token bytes and encode as base64
    Ok(base64::engine::general_purpose::STANDARD
        .encode(owm.object().key_block()?.key_bytes_ref()?)
        .to_lowercase())
}

/// Validate the `Bearer` token in the request against the configured API token.
pub(super) async fn handle_api_token(kms_server: &Arc<KMS>, req: &ServiceRequest) -> KResult<()> {
    let Some(api_token_id) = &kms_server.params.api_token_id else {
        return Err(KmsError::InvalidRequest(
            "API token authentication is not configured".to_owned(),
        ));
    };

    // Check if API token authentication is configured
    trace!("Token authentication using this API token ID: {api_token_id}");

    // Parse the Authorization header first: a request without a Bearer token is rejected before
    // any database read, so unauthenticated requests cannot trigger key lookups.
    let token_part = extract_bearer_token(req)?;

    // Get the stored API token
    let api_token = get_api_token(kms_server, api_token_id).await?;

    trace!(
        "[api_token_auth] Authorization header received (length: {} chars)",
        token_part.len()
    );

    // Normalize the client token for comparison
    let client_token = token_part.trim().to_lowercase();

    trace!(
        "[api_token_auth] comparing client token ({} chars) with server token",
        client_token.len()
    );

    // Compare the client token with the stored token using constant-time comparison
    // to prevent timing side-channel attacks.
    let tokens_match = secrets_equal(&client_token, &api_token);
    if tokens_match {
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
}

#[cfg(test)]
mod tests {
    use actix_web::test::TestRequest;

    use super::handle_api_token;
    use crate::{
        error::KmsError,
        tests::test_utils::{https_clap_config, test_kms_with_config},
    };

    /// A request without a Bearer token is refused with 401 before the API token key is read:
    /// with an `api_token_id` that matches no object, the error is still `Unauthorized`.
    #[tokio::test]
    async fn api_token_missing_header_skips_db() {
        let mut config = https_clap_config();
        config.http.api_token_id = Some("no-such-api-token-key".to_owned());
        let kms = test_kms_with_config(config).await.unwrap();

        let request = TestRequest::default().to_srv_request();
        let err = handle_api_token(&kms, &request).await.unwrap_err();
        assert!(matches!(err, KmsError::Unauthorized(_)), "{err:?}");

        // With a Bearer token, the missing key is looked up and reported.
        let request = TestRequest::default()
            .insert_header(("Authorization", "Bearer abc"))
            .to_srv_request();
        let err = handle_api_token(&kms, &request).await.unwrap_err();
        assert!(!matches!(err, KmsError::Unauthorized(_)), "{err:?}");
    }
}
