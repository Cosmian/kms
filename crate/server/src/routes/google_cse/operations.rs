use std::sync::Arc;

use actix_web::HttpRequest;
use base64::{engine::general_purpose, Engine};
use clap::crate_version;
use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyWrappingData, KeyWrappingSpecification},
    kmip_types::{self, CryptographicAlgorithm, EncodingOption, UniqueIdentifier},
};
use cosmian_kms_utils::crypto::symmetric::create_symmetric_key;
use serde::{Deserialize, Serialize};

use super::GoogleCseConfig;
use crate::{
    core::operations::{unwrap_key, wrap_key},
    result::KResult,
    routes::google_cse::jwt::validate_tokens,
    KMSServer,
};

#[derive(Serialize, Debug)]
pub struct StatusResponse {
    pub server_type: String,
    pub vendor_id: String,
    pub version: String,
    pub name: String,
    pub operations_supported: Vec<String>,
}

pub fn get_status() -> StatusResponse {
    StatusResponse {
        server_type: "KACLS".to_string(),
        vendor_id: "Cosmian".to_string(),
        version: crate_version!().to_string(),
        name: "Cosmian KMS".to_string(),
        operations_supported: vec![
            "wrap".to_string(),
            "unwrap".to_string(),
            "digest".to_string(),
            // "privilegedunwrap".to_string(),
            // "privatekeydecrypt".to_string(),
            // "privatekeysign".to_string(),
            // "privilegedprivatekeydecrypt".to_string(),
        ],
    }
}

#[derive(Deserialize, Debug)]
pub struct WrapRequest {
    pub authentication: String,
    pub authorization: String,
    pub key: String,
    pub reason: String,
}

#[derive(Serialize, Debug)]
pub struct WrapResponse {
    pub wrapped_key: String,
}

/// Returns encrypted Data Encryption Key (DEK) and associated data.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
pub async fn wrap(
    req_http: HttpRequest,
    wrap_request: WrapRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<WrapResponse> {
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;

    let application = if wrap_request.reason.contains("Meet") {
        "meet"
    } else {
        "drive"
    };

    // the possible roles to wrap a key
    let roles = &["writer", "upgrader"];

    let user = validate_tokens(
        &wrap_request.authentication,
        &wrap_request.authorization,
        cse_config,
        application,
        roles,
    )
    .await?;

    // decode the DEK and create a KMIP object from the key bytes
    let mut dek = create_symmetric_key(
        &general_purpose::STANDARD.decode(&wrap_request.key)?,
        CryptographicAlgorithm::AES,
    );

    wrap_key(
        dek.key_block_mut()?,
        &KeyWrappingSpecification {
            wrapping_method: kmip_types::WrappingMethod::Encrypt,
            encoding_option: Some(EncodingOption::NoEncoding),
            encryption_key_information: Some(kmip_types::EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString("[\"google_cse\"]".to_string()),
                cryptographic_parameters: Some(kmip_types::CryptographicParameters {
                    ..Default::default()
                }),
            }),
            ..Default::default()
        },
        kms,
        &user,
        database_params.as_ref(),
    )
    .await?;

    // re-extract the bytes from the key
    let wrapped_dek = dek.key_block()?.key_bytes()?;

    Ok(WrapResponse {
        wrapped_key: general_purpose::STANDARD.encode(wrapped_dek),
    })
}

#[derive(Deserialize, Debug)]
pub struct UnwrapRequest {
    pub authentication: String,
    pub authorization: String,
    pub reason: String,
    pub wrapped_key: String,
}

#[derive(Serialize, Debug)]
pub struct UnwrapResponse {
    pub key: String,
}

/// Decrypt the Data Encryption Key (DEK) and associated data.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
pub async fn unwrap(
    req_http: HttpRequest,
    unwrap_request: UnwrapRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<UnwrapResponse> {
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;

    let application = if unwrap_request.reason.contains("Meet") {
        "meet"
    } else {
        "drive"
    };

    // the possible roles to unwrap a key
    let roles = &["writer", "reader"];

    let user = validate_tokens(
        &unwrap_request.authentication,
        &unwrap_request.authorization,
        cse_config,
        application,
        roles,
    )
    .await?;

    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    let mut wrapped_dek = create_symmetric_key(
        &general_purpose::STANDARD.decode(&unwrap_request.wrapped_key)?,
        CryptographicAlgorithm::AES,
    );
    // add key wrapping parameters to the wrapped key
    wrapped_dek.key_block_mut()?.key_wrapping_data = Some(KeyWrappingData {
        wrapping_method: kmip_types::WrappingMethod::Encrypt,
        encryption_key_information: Some(kmip_types::EncryptionKeyInformation {
            unique_identifier: UniqueIdentifier::TextString("[\"google_cse\"]".to_string()),
            cryptographic_parameters: None,
        }),
        encoding_option: Some(EncodingOption::NoEncoding),
        ..Default::default()
    });

    unwrap_key(
        wrapped_dek.key_block_mut()?,
        kms,
        &user,
        database_params.as_ref(),
    )
    .await?;

    // re-extract the bytes from the key
    let dek = wrapped_dek.key_block()?.key_bytes()?;

    Ok(UnwrapResponse {
        key: general_purpose::STANDARD.encode(dek),
    })
}
