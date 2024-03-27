use std::sync::Arc;

use actix_web::HttpRequest;
use base64::{engine::general_purpose, Engine};
use clap::crate_version;
use cosmian_kmip::{
    crypto::symmetric::create_symmetric_key_kmip_object,
    kmip::{
        kmip_data_structures::{KeyWrappingData, KeyWrappingSpecification},
        kmip_types::{self, CryptographicAlgorithm, EncodingOption, UniqueIdentifier},
    },
};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    sign::Signer,
};
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

#[must_use]
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
            "status".to_string(),
            // "privilegedunwrap".to_string(),
            // "privatekeydecrypt".to_string(),
            "privatekeysign".to_string(),
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
        Some(roles),
    )
    .await?;

    // decode the DEK and create a KMIP object from the key bytes
    let mut dek = create_symmetric_key_kmip_object(
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
                cryptographic_parameters: Some(Box::new(kmip_types::CryptographicParameters {
                    ..Default::default()
                })),
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
        Some(roles),
    )
    .await?;

    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    let mut wrapped_dek = create_symmetric_key_kmip_object(
        &general_purpose::STANDARD.decode(&unwrap_request.wrapped_key)?,
        CryptographicAlgorithm::AES,
    );
    // add key wrapping parameters to the wrapped key
    wrapped_dek.key_block_mut()?.key_wrapping_data = Some(Box::new(KeyWrappingData {
        wrapping_method: kmip_types::WrappingMethod::Encrypt,
        encryption_key_information: Some(kmip_types::EncryptionKeyInformation {
            unique_identifier: UniqueIdentifier::TextString("[\"google_cse\"]".to_string()),
            cryptographic_parameters: None,
        }),
        encoding_option: Some(EncodingOption::NoEncoding),
        ..Default::default()
    }));

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

/// Request to perform a private key signature.
/// The `digest` is signed using unwrapped `wrapped_private_key`,
/// and using `algorithm`.
///
/// Technical specifications of components from this request
/// can be found here: https://support.google.com/a/answer/7300887
#[derive(Serialize, Deserialize, Debug)]
pub struct PrivateKeySignRequest {
    pub authentication: String,
    pub authorization: String,
    /// The algorithm that was used to encrypt the Data Encryption Key (DEK) in envelope encryption.
    pub algorithm: String,
    /// Base64-encoded message digest.
    /// The digest of the DER encoded SignedAttributes.
    /// This value is unpadded. Max size: 128B
    pub digest: String,

    /// The format of the private key or the wrapped private key is up to
    /// the Key Access Control List Service (KACLS) implementation.
    /// On the client and on the Gmail side, this is treated as an opaque blob.
    // pub e_key: String,

    /// The salt length to use, if the signature algorithm is RSASSA-PSS.
    /// If the signature algorithm is not RSASSA-PSS, this field is ignored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsa_pss_salt_length: Option<i32>,
    pub reason: String,
    pub wrapped_private_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrivateKeySignResponse {
    pub signature: String,
}

/// Unwraps a wrapped private key and then signs the digest provided by the client.
///
/// See Google documentation:
/// - Private Key Sign endpoint: https://developers.google.com/workspace/cse/reference/private-key-sign
/// - S/MIME certificate profiles: https://support.google.com/a/answer/7300887
pub async fn private_key_sign(
    req_http: HttpRequest,
    private_key_sign_request: PrivateKeySignRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<PrivateKeySignResponse> {
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;

    let user = validate_tokens(
        &private_key_sign_request.authentication,
        &private_key_sign_request.authorization,
        cse_config,
        "gmail",
        None,
    )
    .await?;

    tracing::debug!(
        "private_key_sign_request.wrapped_private_key: {:?}",
        private_key_sign_request.wrapped_private_key
    );
    // Unwrap private key which has been previously wrapped using AES

    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    let mut wrapped_dek = create_symmetric_key_kmip_object(
        &general_purpose::STANDARD.decode(&private_key_sign_request.wrapped_private_key)?,
        CryptographicAlgorithm::AES,
    );

    tracing::debug!("add key wrapping data substruct");
    // add key wrapping parameters to the wrapped key
    wrapped_dek.key_block_mut()?.key_wrapping_data = Some(
        KeyWrappingData {
            wrapping_method: kmip_types::WrappingMethod::Encrypt,
            encryption_key_information: Some(kmip_types::EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString("google_cse".to_string()),
                cryptographic_parameters: None,
            }),
            encoding_option: Some(EncodingOption::TTLVEncoding),
            ..Default::default()
        }
        .into(),
    );

    tracing::debug!("unwrap private key");
    unwrap_key(
        wrapped_dek.key_block_mut()?,
        kms,
        &user,
        database_params.as_ref(),
    )
    .await?;

    tracing::debug!("unwrapped private key");

    // re-extract the bytes from the key
    let dek = wrapped_dek.key_block()?.key_bytes()?;

    tracing::debug!("sign with the private key");

    // Sign with the unwrapped RSA private key
    let rsa_private_key = Rsa::<Private>::private_key_from_der(&dek)?;
    let keypair = PKey::from_rsa(rsa_private_key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &keypair)?;
    signer.update(private_key_sign_request.digest.as_bytes())?;
    let signature = signer.sign_to_vec()?;

    Ok(PrivateKeySignResponse {
        signature: general_purpose::STANDARD.encode(signature),
    })
}
