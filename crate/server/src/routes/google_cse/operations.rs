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
    md::Md,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
};
use serde::{Deserialize, Serialize};
use tracing::debug;
use zeroize::Zeroizing;

use super::GoogleCseConfig;
use crate::{
    core::{
        extra_database_params::ExtraDatabaseParams,
        operations::{unwrap_key, wrap_key},
    },
    kms_ensure,
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
    pub kacls_url: String,
    pub operations_supported: Vec<String>,
}

/// Returns the status of the server.
///
/// # Returns
/// - `StatusResponse`: The status of the server.
#[must_use]
pub fn get_status(kacls_url: &str) -> StatusResponse {
    debug!("get_status");
    StatusResponse {
        server_type: "KACLS".to_owned(),
        vendor_id: "Cosmian".to_owned(),
        version: crate_version!().to_owned(),
        name: "Cosmian KMS".to_owned(),
        kacls_url: kacls_url.to_owned(),
        operations_supported: vec![
            "digest".to_owned(),
            "privatekeydecrypt".to_owned(),
            "privatekeysign".to_owned(),
            "privilegedprivatekeydecrypt".to_owned(),
            "privilegedunwrap".to_owned(),
            "privilegedwrap".to_owned(),
            "rewrap".to_owned(),
            "status".to_owned(),
            "unwrap".to_owned(),
            "wrap".to_owned(),
            "wrapprivatekey".to_owned(),
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

/// Wraps a Data Encryption Key (DEK) using the specified authentication and authorization tokens.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
/// # Arguments
/// - `req_http`: The HTTP request.
/// - `wrap_request`: The wrap request.
/// - `cse_config`: The Google CSE configuration.
/// - `kms`: The KMS server.
///
/// # Returns
/// - `WrapResponse`: The wrapped key.
///
/// # Errors
/// This function can return an error if there is a problem with the encryption process or if the tokens validation fails.
pub async fn wrap(
    req_http: HttpRequest,
    wrap_request: WrapRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<WrapResponse> {
    debug!("wrap: entering");
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;

    let application = if wrap_request.reason.contains("Meet") {
        "meet"
    } else {
        "drive"
    };
    debug!("wrap: entering on application: {application}");

    // the possible roles to wrap a key
    let roles = &["writer", "upgrader"];

    debug!("wrap: validate_tokens");
    let user = validate_tokens(
        &wrap_request.authentication,
        &wrap_request.authorization,
        cse_config,
        application,
        Some(roles),
    )
    .await?;

    // decode the DEK and create a KMIP object from the key bytes
    debug!("wrap: create KMIP dek object");
    let mut dek = create_symmetric_key_kmip_object(
        &general_purpose::STANDARD.decode(&wrap_request.key)?,
        CryptographicAlgorithm::AES,
    );

    debug!("wrap: wrap dek");
    wrap_key(
        dek.key_block_mut()?,
        &KeyWrappingSpecification {
            wrapping_method: kmip_types::WrappingMethod::Encrypt,
            encoding_option: Some(EncodingOption::NoEncoding),
            encryption_key_information: Some(kmip_types::EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString("[\"google_cse\"]".to_owned()),
                cryptographic_parameters: Some(Box::default()),
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

    debug!("wrap: exiting with success");
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

/// Unwraps a wrapped Data Encryption Key (DEK) using the specified authentication and authorization tokens.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
/// # Arguments
/// - `req_http`: The HTTP request.
/// - `unwrap_request`: The unwrap request.
/// - `cse_config`: The Google CSE configuration.
/// - `kms`: The KMS server.
///
/// # Returns
/// - `UnwrapResponse`: The unwrapped key.
///
/// # Errors
/// This function can return an error if there is a problem with the decryption process or if the tokens validation fails.
pub async fn unwrap(
    req_http: HttpRequest,
    unwrap_request: UnwrapRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<UnwrapResponse> {
    debug!("unwrap: entering");
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;

    let application = if unwrap_request.reason.contains("Meet") {
        "meet"
    } else {
        "drive"
    };
    debug!("unwrap: entering with application {application}");

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
    debug!("unwrap: validate_tokens");

    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    debug!("unwrap: create wrapped_dek KMIP object");
    let mut wrapped_dek = create_symmetric_key_kmip_object(
        &general_purpose::STANDARD.decode(&unwrap_request.wrapped_key)?,
        CryptographicAlgorithm::AES,
    );
    // add key wrapping parameters to the wrapped key
    wrapped_dek.key_block_mut()?.key_wrapping_data = Some(Box::new(KeyWrappingData {
        wrapping_method: kmip_types::WrappingMethod::Encrypt,
        encryption_key_information: Some(kmip_types::EncryptionKeyInformation {
            unique_identifier: UniqueIdentifier::TextString("[\"google_cse\"]".to_owned()),
            cryptographic_parameters: None,
        }),
        encoding_option: Some(EncodingOption::NoEncoding),
        ..Default::default()
    }));

    debug!("unwrap: unwrap key");
    unwrap_key(
        wrapped_dek.key_block_mut()?,
        kms,
        &user,
        database_params.as_ref(),
    )
    .await?;

    // re-extract the bytes from the key
    let dek = wrapped_dek.key_block()?.key_bytes()?;

    debug!("unwrap: exiting with success");
    Ok(UnwrapResponse {
        key: general_purpose::STANDARD.encode(dek),
    })
}

/// Request to perform a private key signature.
/// The `digest` is signed using unwrapped `wrapped_private_key`,
/// and using `algorithm`.
///
/// Technical specifications of components from this request
/// can be found here: <https://support.google.com/a/answer/7300887>
#[derive(Serialize, Deserialize, Debug)]
pub struct PrivateKeySignRequest {
    pub authentication: String,
    pub authorization: String,
    /// The algorithm that was used to encrypt the Data Encryption Key (DEK) in envelope encryption.
    pub algorithm: String,
    /// Base64-encoded message digest.
    /// The digest of the DER encoded `SignedAttributes`.
    /// This value is unpadded. Max size: 128B
    pub digest: String,

    /// The salt length to use, if the signature algorithm is RSASSA-PSS.
    /// If the signature algorithm is not RSASSA-PSS, this field is ignored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsa_pss_salt_length: Option<i32>,
    /// A passthrough JSON string providing additional context about the operation. The JSON provided should be sanitized before being displayed. Max size: 1 KB.
    pub reason: String,
    /// The base64-encoded wrapped private key. Max size: 8 KB.
    pub wrapped_private_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrivateKeySignResponse {
    pub signature: String,
}

/// Unwraps a wrapped private key and then signs the digest provided by the client.
///
/// See Google documentation:
/// - Private Key Sign endpoint: <https://developers.google.com/workspace/cse/reference/private-key-sign>
/// - S/MIME certificate profiles: <https://support.google.com/a/answer/7300887>
/// # Arguments
/// - `req_http`: The HTTP request.
/// - `request`: The private key sign request.
/// - `cse_config`: The Google CSE configuration.
/// - `kms`: The KMS server.
///
/// # Returns
/// - `PrivateKeySignResponse`: The signature.
///
/// # Errors
/// This function can return an error if there is a problem with the encryption process or if the tokens validation fails.
pub async fn private_key_sign(
    req_http: HttpRequest,
    request: PrivateKeySignRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<PrivateKeySignResponse> {
    debug!("private_key_sign: entering");
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;

    debug!("private_key_sign: validate_tokens");
    let user = validate_tokens(
        &request.authentication,
        &request.authorization,
        cse_config,
        "gmail",
        None,
    )
    .await?;

    debug!("private_key_sign: check algorithm");
    kms_ensure!(
        request.algorithm == "SHA256withRSA",
        "Only SHA256withRSA is supported"
    );

    // Unwrap private key which has been previously wrapped using AES
    let dek = cse_symmetric_unwrap(request.wrapped_private_key, user, kms, database_params).await?;

    // Sign with the unwrapped RSA private key
    debug!("private_key_sign: from_rsa");
    let private_key = PKey::from_rsa(Rsa::<Private>::private_key_from_der(&dek)?)?;

    debug!("private_key_sign: build signer");
    let mut ctx = PkeyCtx::new(&private_key)?;
    ctx.sign_init()?;
    ctx.set_rsa_padding(Padding::PKCS1)?;
    ctx.set_signature_md(Md::sha256())?;
    let digest = general_purpose::STANDARD.decode(request.digest)?;
    let allocation_size = ctx.sign(&digest, None)?;

    let mut signature = vec![0_u8; allocation_size];
    let signature_size = ctx.sign(&digest, Some(&mut *signature))?;
    debug!("private_key_sign: signature {signature_size}");
    kms_ensure!(
        allocation_size == signature_size,
        "private_key_sign: allocation_size MUST be equal to signature_size"
    );

    debug!(
        "private_key_sign: exiting with success: {}",
        general_purpose::STANDARD.encode(signature.clone())
    );
    Ok(PrivateKeySignResponse {
        signature: general_purpose::STANDARD.encode(signature),
    })
}

/// Request to perform a `encryption key` decryption
///
/// The `encrypted_data_encryption_key` will be decrypted with the
/// `wrapped_private_key` (once decrypted)
#[derive(Serialize, Deserialize, Debug)]
pub struct PrivateKeyDecryptRequest {
    pub authentication: String,
    pub authorization: String,
    /// The algorithm that was used to encrypt the Data Encryption Key (DEK) in envelope encryption.
    pub algorithm: String,
    /// Base64-encoded encrypted content encryption key, which is encrypted with the public key associated with the private key. Max size: 1 KB.
    pub encrypted_data_encryption_key: String,
    /// Base64-encoded label L, if the algorithm is RSAES-OAEP. If the algorithm is not RSAES-OAEP, this field is ignored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsa_oaep_label: Option<String>,
    /// A passthrough JSON string providing additional context about the operation. The JSON provided should be sanitized before being displayed. Max size: 1 KB.
    pub reason: String,
    /// The base64-encoded wrapped private key. Max size: 8 KB.
    pub wrapped_private_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrivateKeyDecryptResponse {
    /// A base64-encoded data encryption key.
    pub data_encryption_key: String,
}

/// Unwraps a wrapped private key and then decrypts the content encryption key that is encrypted to the public key.
///
/// See Google documentation:
/// - Private Key Decrypt endpoint: <https://developers.google.com/workspace/cse/reference/private-key-decrypt>
///
/// # Arguments
/// - `req_http`: The HTTP request.
/// - `request`: The private key decrypt request.
/// - `cse_config`: The Google CSE configuration.
/// - `kms`: The KMS server.
///
/// # Returns
/// - `PrivateKeyDecryptResponse`: The decrypted data encryption key.
///
/// # Errors
/// This function can return an error if there is a problem with the decryption process or if the tokens validation fails.
pub async fn private_key_decrypt(
    req_http: HttpRequest,
    request: PrivateKeyDecryptRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<PrivateKeyDecryptResponse> {
    debug!("private_key_decrypt: entering");
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;

    debug!("private_key_decrypt: validate_tokens");
    let user = validate_tokens(
        &request.authentication,
        &request.authorization,
        cse_config,
        "gmail",
        None,
    )
    .await?;

    debug!("private_key_decrypt: check algorithm");
    kms_ensure!(
        request.algorithm == "RSA/ECB/PKCS1Padding",
        "Only RSA/ECB/PKCS1Padding is supported"
    );

    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    debug!("private_key_decrypt: decode encrypted_dek");
    let encrypted_dek = general_purpose::STANDARD.decode(&request.encrypted_data_encryption_key)?;

    // Unwrap private key which has been previously wrapped using AES
    let dek = cse_symmetric_unwrap(request.wrapped_private_key, user, kms, database_params).await?;

    // Decrypt with the unwrapped RSA private key
    debug!("private_key_decrypt: from_rsa");
    let private_key = PKey::from_rsa(Rsa::<Private>::private_key_from_der(&dek)?)?;

    // Perform RSA PKCS1 decryption.
    let mut ctx = PkeyCtx::new(&private_key)?;
    ctx.decrypt_init()?;
    ctx.set_rsa_padding(Padding::PKCS1)?;
    if let Some(label) = request.rsa_oaep_label {
        ctx.set_rsa_oaep_label(label.as_bytes())?;
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
    }
    let allocation_size = ctx.decrypt(&encrypted_dek, None)?;
    debug!("privatekeydecrypt: allocation_size: {allocation_size}");
    let mut plaintext = vec![0_u8; allocation_size];
    let decrypt_size = ctx.decrypt(&encrypted_dek, Some(&mut *plaintext))?;

    debug!("private_key_decrypt: exiting with success: decrypt_size: {decrypt_size}");
    let response = PrivateKeyDecryptResponse {
        data_encryption_key: general_purpose::STANDARD.encode(&plaintext[0..decrypt_size]),
    };
    Ok(response)
}

/// Unwraps a private key
///
/// # Arguments
///
/// * `wrapped_private_key` - A base64-encoded string representing the wrapped private key.
/// * `user` - A string identifying the user associated with the key.
/// * `kms` - the KMS Server instance
/// * `database_params` - An optional `ExtraDatabaseParams` containing additional parameters for database operations.
///
/// # Returns
///
/// The decrypted key bytes
///
/// # Errors
///
/// Returns an error if decoding base64 fails, adding key wrapping data fails, unwrapping the key fails, or extracting the key bytes fails.
///
async fn cse_symmetric_unwrap(
    wrapped_private_key: String,
    user: String,
    kms: &Arc<KMSServer>,
    database_params: Option<ExtraDatabaseParams>,
) -> KResult<Zeroizing<Vec<u8>>> {
    debug!("cse_unwrap: decode base64 wrapped_dek");
    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    let mut wrapped_dek = create_symmetric_key_kmip_object(
        &general_purpose::STANDARD.decode(&wrapped_private_key)?,
        CryptographicAlgorithm::AES,
    );

    debug!("cse_unwrap: add key wrapping data substruct");
    // add key wrapping parameters to the wrapped key
    wrapped_dek.key_block_mut()?.key_wrapping_data = Some(
        KeyWrappingData {
            wrapping_method: kmip_types::WrappingMethod::Encrypt,
            encryption_key_information: Some(kmip_types::EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString("google_cse".to_owned()),
                cryptographic_parameters: None,
            }),
            encoding_option: Some(EncodingOption::TTLVEncoding),
            ..Default::default()
        }
        .into(),
    );

    debug!("cse_unwrap: unwrap private key");
    unwrap_key(
        wrapped_dek.key_block_mut()?,
        kms,
        &user,
        database_params.as_ref(),
    )
    .await?;

    debug!("cse_unwrap: unwrapped private key");

    // re-extract the bytes from the key
    let dek = wrapped_dek.key_block()?.key_bytes()?;
    Ok(dek)
}
