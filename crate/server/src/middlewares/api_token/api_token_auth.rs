//! API Token Authentication Middleware
//!
//! This module handles API token-based authentication for the KMS server.
//! It verifies that incoming requests contain a valid API token in the
//! Authorization header that matches the configured token in the KMS.

use std::sync::Arc;

use actix_web::{dev::ServiceRequest, http::header};
use base64::Engine;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{ErrorReason, State},
    kmip_2_1::kmip_objects::ObjectType,
};
use cosmian_logger::{debug, error, trace};

use crate::{core::KMS, error::KmsError, result::KResult};

/// Retrieves the API token from the KMS database
///
/// Fetches a symmetric key identified by `api_token_id` and returns it as a
/// base64-encoded string which serves as the API token.
///
/// # Parameters
/// * `kms` - The KMS server instance
/// * `api_token_id` - The unique identifier for the symmetric key used as the API token
///
/// # Returns
/// * `Ok(String)` - The base64-encoded symmetric key (API token)
/// * `Err(KmsError)` - If the token cannot be retrieved or is invalid
async fn get_api_token(kms: &Arc<KMS>, api_token_id: &str) -> KResult<String> {
    // Retrieve the object from the database
    let owm = kms
        .database
        .retrieve_object(api_token_id)
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
        .encode(owm.object().key_block()?.key_bytes()?)
        .to_lowercase())
}

/// Validates the API token in the request against the configured token
///
/// This is the core authentication logic that:
/// 1. Checks if API token authentication is configured
/// 2. Extracts the token from the Authorization header
/// 3. Compares it with the stored token
///
/// # Parameters
/// * `kms_server` - The KMS server instance
/// * `req` - The incoming HTTP request
///
/// # Returns
/// * `Ok(())` - If authentication is successful or not required
/// * `Err(KmsError)` - If authentication fails
pub(super) async fn handle_api_token(kms_server: &Arc<KMS>, req: &ServiceRequest) -> KResult<()> {
    let Some(api_token_id) = kms_server.params.api_token_id.clone() else {
        return Err(KmsError::InvalidRequest(
            "API token authentication is not configured".to_owned(),
        ));
    };

    // Check if API token authentication is configured
    trace!("Token authentication using this API token ID: {api_token_id}");

    // Get the stored API token
    let api_token = get_api_token(kms_server, api_token_id.as_str()).await?;

    // Extract the token from the Authorization header
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or_else(|| KmsError::InvalidRequest("Missing Authorization header".to_owned()))?
        .to_str()
        .map_err(|e| {
            KmsError::InvalidRequest(format!("Error converting header value to string: {e:?}"))
        })?;

    trace!(
        "[api_token_auth] Authorization header received: {}",
        auth_header
    );

    // Support case-insensitive bearer scheme and robust splitting
    let mut parts = auth_header.splitn(2, ' ');
    let scheme = parts.next().unwrap_or("");
    let token_part = parts.next().unwrap_or("");
    if !scheme.eq_ignore_ascii_case("Bearer") || token_part.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "Invalid Authorization header format: expected: \"Bearer <API_TOKEN>\", got: {auth_header}"
        )));
    }

    // Normalize the client token for comparison
    let client_token = token_part.trim().to_lowercase();

    trace!(
        "[api_token_auth] token preview (client/server): {}/{}",
        client_token.chars().take(8).collect::<String>(),
        api_token.chars().take(8).collect::<String>()
    );

    // Compare the client token with the stored token
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
}
