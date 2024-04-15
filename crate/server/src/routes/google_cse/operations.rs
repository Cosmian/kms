use std::sync::Arc;

use actix_web::HttpRequest;
use base64::{engine::general_purpose, Engine};
use clap::crate_version;
use cosmian_kmip::{
    crypto::{
        rsa::rsa_oaep_aes_gcm::rsa_oaep_aes_gcm_decrypt,
        symmetric::create_symmetric_key_kmip_object,
    },
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
    debug!("get_status");
    StatusResponse {
        server_type: "KACLS".to_string(),
        vendor_id: "Cosmian".to_string(),
        version: crate_version!().to_string(),
        name: "Cosmian KMS".to_string(),
        operations_supported: vec![
            "digest".to_string(),
            "privatekeydecrypt".to_string(),
            "privatekeysign".to_string(),
            "privilegedprivatekeydecrypt".to_string(),
            "privilegedunwrap".to_string(),
            "privilegedwrap".to_string(),
            "rewrap".to_string(),
            "status".to_string(),
            "unwrap".to_string(),
            "wrap".to_string(),
            "wrapprivatekey".to_string(),
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
                unique_identifier: UniqueIdentifier::TextString("[\"google_cse\"]".to_string()),
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
            unique_identifier: UniqueIdentifier::TextString("[\"google_cse\"]".to_string()),
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
/// can be found here: https://support.google.com/a/answer/7300887
#[derive(Serialize, Deserialize, Debug)]
pub struct PrivateKeySignRequest {
    pub authentication: String,
    pub authorization: String,
    /// The algorithm that was used to encrypt the Data Encryption Key (DEK) in envelope encryption.
    pub algorithm: String, //TODO: unhandled for now
    /// Base64-encoded message digest.
    /// The digest of the DER encoded SignedAttributes.
    /// This value is unpadded. Max size: 128B
    pub digest: String,

    /// The format of the private key or the wrapped private key is up to
    /// the Key Access Control List Service (KACLS) implementation.
    /// On the client and on the Gmail side, this is treated as an opaque blob.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e_key: Option<String>,

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
/// - Private Key Sign endpoint: https://developers.google.com/workspace/cse/reference/private-key-sign
/// - S/MIME certificate profiles: https://support.google.com/a/answer/7300887
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

    // Unwrap private key which has been previously wrapped using AES

    debug!("private_key_sign: decode base64 wrapped_dek");
    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    let mut wrapped_dek = create_symmetric_key_kmip_object(
        &general_purpose::STANDARD.decode(&request.wrapped_private_key)?,
        CryptographicAlgorithm::AES,
    );

    debug!("private_key_sign: add key wrapping data substruct");
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

    debug!("private_key_sign: unwrap private key");
    unwrap_key(
        wrapped_dek.key_block_mut()?,
        kms,
        &user,
        database_params.as_ref(),
    )
    .await?;

    debug!("private_key_sign: unwrapped private key");

    // re-extract the bytes from the key
    let dek = wrapped_dek.key_block()?.key_bytes()?;

    debug!("private_key_sign: sign with the private key");

    // Sign with the unwrapped RSA private key
    debug!("private_key_sign: private_key_from_der");
    let rsa_private_key = Rsa::<Private>::private_key_from_der(&dek)?;
    debug!("private_key_sign: from_rsa");
    let private_key = PKey::from_rsa(rsa_private_key)?;
    debug!("private_key_sign: build signer");
    let mut pkey_context = PkeyCtx::new(&private_key)?;
    pkey_context.sign_init()?;
    pkey_context.set_rsa_padding(Padding::PKCS1)?;
    pkey_context.set_signature_md(Md::sha256())?;
    let digest = general_purpose::STANDARD.decode(request.digest)?;
    let signature_size = pkey_context.sign(&digest, None)?;

    let mut signature = vec![0_u8; signature_size];
    let signature_size = pkey_context.sign(&digest, Some(&mut *signature))?;
    debug!("private_key_sign: signature {signature_size}");

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
    pub algorithm: String, //TODO: unhandled for now
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
/// - Private Key Decrypt endpoint: https://developers.google.com/workspace/cse/reference/private-key-decrypt
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

    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    debug!("private_key_decrypt: decode encrypted_dek");
    let encrypted_dek = general_purpose::STANDARD.decode(&request.encrypted_data_encryption_key)?;

    // Unwrap private key which has been previously wrapped using AES

    debug!("private_key_decrypt: decode base64 wrapped_dek");
    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    let mut wrapped_dek = create_symmetric_key_kmip_object(
        &general_purpose::STANDARD.decode(&request.wrapped_private_key)?,
        CryptographicAlgorithm::AES,
    );

    debug!("private_key_decrypt: add key wrapping data substruct");
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

    debug!("private_key_decrypt: unwrap private key");
    unwrap_key(
        wrapped_dek.key_block_mut()?,
        kms,
        &user,
        database_params.as_ref(),
    )
    .await?;

    debug!("private_key_decrypt: unwrapped private key");

    // re-extract the bytes from the key
    let dek = wrapped_dek.key_block()?.key_bytes()?;

    debug!("private_key_decrypt: decrypt with the private key");

    // Decrypt with the unwrapped RSA private key
    debug!("private_key_decrypt: private_key_from_der");
    let rsa_private_key = Rsa::<Private>::private_key_from_der(&dek)?;
    debug!("private_key_decrypt: from_rsa");
    let private_key = PKey::from_rsa(rsa_private_key)?;

    debug!("private_key_decrypt: build aad");
    let rsa_oaep_label: Option<&[u8]> = request
        .rsa_oaep_label
        .as_ref()
        .map(std::string::String::as_bytes);

    debug!("private_key_decrypt: {:?}", rsa_oaep_label);
    let plaintext = match rsa_oaep_label {
        Some(rsa_oaep_label) => rsa_oaep_aes_gcm_decrypt(
            &private_key,
            kmip_types::HashingAlgorithm::SHA256,
            &encrypted_dek,
            Some(rsa_oaep_label),
        )?
        .to_vec(),
        None => {
            // Perform RSA PKCS1 decryption.
            let mut ctx = PkeyCtx::new(&private_key)?;
            ctx.decrypt_init()?;
            ctx.set_rsa_padding(Padding::PKCS1)?;

            let decrypt_size = ctx.decrypt(&encrypted_dek, None)?;
            debug!("privatekeydecrypt: decrypt_size: {decrypt_size}");

            let mut plaintext = vec![0_u8; decrypt_size];
            let decrypt_size = ctx.decrypt(&encrypted_dek, Some(&mut *plaintext))?;
            debug!("privatekeydecrypt: decrypt_size: {decrypt_size}");
            debug!("privatekeydecrypt: plaintext: {plaintext:?}");
            plaintext[0..decrypt_size].to_vec()
        }
    };

    debug!("private_key_decrypt: exiting with success");

    let response = PrivateKeyDecryptResponse {
        data_encryption_key: general_purpose::STANDARD.encode(plaintext),
    };
    Ok(response)
}
