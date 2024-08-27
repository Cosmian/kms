use std::sync::Arc;

use actix_web::HttpRequest;
use base64::{engine::general_purpose, Engine};
use clap::crate_version;
use cosmian_kmip::{
    crypto::symmetric::create_symmetric_key_kmip_object,
    kmip::{
        kmip_data_structures::KeyWrappingData,
        kmip_operations::{Decrypt, Encrypt},
        kmip_types::{self, CryptographicAlgorithm, EncodingOption, UniqueIdentifier},
    },
};
use openssl::{
    hash::MessageDigest,
    md::Md,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
    sign::Signer,
};
use serde::{Deserialize, Serialize};
use tracing::debug;
use zeroize::Zeroizing;

use super::GoogleCseConfig;
use crate::{
    core::{
        extra_database_params::ExtraDatabaseParams,
        operations::{decrypt, encrypt, unwrap_key},
    },
    error::KmsError,
    kms_ensure,
    result::KResult,
    routes::google_cse::jwt::{
        validate_cse_authentication_token, validate_cse_authorization_token, validate_tokens,
    },
    KMSServer,
};

const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;

fn get_hash_algorithm(algorithm: &str) -> Result<MessageDigest, KmsError> {
    match algorithm {
        "sha-256" => Ok(MessageDigest::sha256()),
        "md-5" => Ok(MessageDigest::md5()),
        "sha-1" => Ok(MessageDigest::sha1()),
        "sha-224" => Ok(MessageDigest::sha224()),
        "sha-384" => Ok(MessageDigest::sha384()),
        "sha-512" => Ok(MessageDigest::sha512()),
        "sha3-224" => Ok(MessageDigest::sha3_224()),
        "sha3-256" => Ok(MessageDigest::sha3_256()),
        "sha3-384" => Ok(MessageDigest::sha3_384()),
        "sha3-512" => Ok(MessageDigest::sha3_512()),
        _ => Err(KmsError::InvalidRequest(
            "Invalid spki hash algorithm - can handle : sha-256, md-5, sha-1, sha-224, sha-384, \
             sha-512, sha3-224, sha3-256, sha3-384, sha3-512"
                .to_string(),
        )),
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct StatusResponse {
    pub server_type: String,
    pub vendor_id: String,
    pub version: String,
    pub name: String,
    pub kacls_url: String,
    pub operations_supported: Vec<String>,
}

#[must_use]
pub fn get_status(kacls_url: &str) -> StatusResponse {
    debug!("get_status");
    StatusResponse {
        server_type: "KACLS".to_string(),
        vendor_id: "Cosmian".to_string(),
        version: crate_version!().to_string(),
        name: "Cosmian KMS".to_string(),
        kacls_url: kacls_url.to_string(),
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

#[derive(Serialize, Deserialize, Debug)]
pub struct WrapRequest {
    pub authentication: String,
    pub authorization: String,
    pub key: String,
    pub reason: String,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct WrapResponse {
    pub wrapped_key: String,
}

/// Returns encrypted Data Encryption Key (DEK) and associated data.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
pub async fn wrap(
    wrap_request: WrapRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<WrapResponse> {
    debug!("wrap: entering");
    let application = if wrap_request.reason.contains("Meet") {
        "meet"
    } else {
        "drive"
    };

    // the possible roles to wrap a key
    let roles = &["writer", "upgrader"];

    debug!("wrap: validate_tokens");
    let token_extracted_content = validate_tokens(
        &wrap_request.authentication,
        &wrap_request.authorization,
        cse_config,
        application,
        Some(roles),
    )
    .await?;

    debug!("wrap: wrap dek");
    let encryption_request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString("google_cse".to_string())),
        cryptographic_parameters: None,
        data: Some(general_purpose::STANDARD.decode(&wrap_request.key)?.into()),
        iv_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: token_extracted_content.resource_name,
    };
    let dek = encrypt(kms, encryption_request, &token_extracted_content.user, None).await?;

    // re-extract the bytes from the key
    let data = dek.data.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - missing data.".to_string())
    })?;
    let iv_counter_nonce = dek.iv_counter_nonce.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - missing nonce.".to_string())
    })?;
    let authenticated_encryption_tag = dek.authenticated_encryption_tag.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - authenticated encryption tag.".to_string())
    })?;

    let wrapped_dek = [data, iv_counter_nonce, authenticated_encryption_tag].concat();

    debug!("wrap: exiting with success");
    Ok(WrapResponse {
        wrapped_key: general_purpose::STANDARD.encode(wrapped_dek),
    })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UnwrapRequest {
    pub authentication: String,
    pub authorization: String,
    pub reason: String,
    pub wrapped_key: String,
}

#[derive(Deserialize, Serialize, Debug)]
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
    let application = if unwrap_request.reason.contains("Meet") {
        "meet"
    } else {
        "drive"
    };

    // the possible roles to unwrap a key
    let roles = &["writer", "reader"];

    debug!("unwrap: validate_tokens");
    let token_extracted_content = validate_tokens(
        &unwrap_request.authentication,
        &unwrap_request.authorization,
        cse_config,
        application,
        Some(roles),
    )
    .await?;

    debug!("unwrap: unwrap key");
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let data = cse_symmetric_key_unwrap(
        unwrap_request.wrapped_key,
        token_extracted_content.user,
        token_extracted_content.resource_name,
        kms,
        database_params,
    )
    .await?;
    debug!("unwrap: exiting with success");
    Ok(UnwrapResponse {
        key: general_purpose::STANDARD.encode(data),
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
pub async fn private_key_sign(
    req_http: HttpRequest,
    request: PrivateKeySignRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<PrivateKeySignResponse> {
    debug!("private_key_sign: entering");
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;

    debug!("private_key_sign: validate_tokens");
    let roles: &[&str; 1] = &["signer"];

    let token_extracted_content = validate_tokens(
        &request.authentication,
        &request.authorization,
        cse_config,
        "gmail",
        Some(roles),
    )
    .await?;

    debug!("private_key_sign: check algorithm");
    kms_ensure!(
        request.algorithm == "SHA256withRSA",
        "Only SHA256withRSA is supported"
    );

    // Unwrap private key which has been previously wrapped using AES
    let dek = cse_private_key_unwrap(
        request.wrapped_private_key,
        token_extracted_content.user,
        kms,
        database_params,
    )
    .await?;

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
pub async fn private_key_decrypt(
    req_http: HttpRequest,
    request: PrivateKeyDecryptRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<PrivateKeyDecryptResponse> {
    debug!("private_key_decrypt: entering");
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;

    debug!("private_key_decrypt: validate_tokens");
    let roles: &[&str; 1] = &["decrypter"];

    let token_extracted_content = validate_tokens(
        &request.authentication,
        &request.authorization,
        cse_config,
        "gmail",
        Some(roles),
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
    let private_key_der = cse_private_key_unwrap(
        request.wrapped_private_key,
        token_extracted_content.user,
        kms,
        database_params,
    )
    .await?;

    // Decrypt with the unwrapped RSA private key
    debug!("private_key_decrypt: from_rsa");
    let private_key = PKey::from_rsa(Rsa::<Private>::private_key_from_der(&private_key_der)?)?;

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
    let mut dek = vec![0_u8; allocation_size];
    let decrypt_size = ctx.decrypt(&encrypted_dek, Some(&mut *dek))?;

    debug!("private_key_decrypt: exiting with success: decrypt_size: {decrypt_size}");
    let response = PrivateKeyDecryptResponse {
        data_encryption_key: general_purpose::STANDARD.encode(&dek[0..decrypt_size]),
    };
    Ok(response)
}

#[derive(Deserialize, Debug)]
pub struct DigestRequest {
    pub authorization: String,
    pub wrapped_key: String,
    pub reason: String,
}

#[derive(Serialize, Debug)]
pub struct DigestResponse {
    pub resource_key_hash: String,
}

/// Digest
/// Takes a Data Encryption Key (DEK) wrapped with the wrap API, and returns the base64 encoded resource key hash
/// /// See [doc](https://developers.google.com/workspace/cse/reference/digest) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
///
pub async fn digest(
    req_http: HttpRequest,
    digest_request: DigestRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<DigestResponse> {
    let application = if digest_request.reason.contains("Meet") {
        "meet"
    } else {
        "drive"
    };
    debug!("cse_digest: validate_authorization_token");

    let roles = ["verifier"];
    let authorization_token = validate_cse_authorization_token(
        &digest_request.authorization,
        cse_config,
        application,
        Some(&roles),
    )
    .await?;

    let perimeter_id = authorization_token.perimeter_id.unwrap_or(String::new());
    let resource_name = authorization_token.resource_name.ok_or_else(|| {
        KmsError::Unauthorized("Invalid authorization token - missing resource_name.".to_string())
    })?;

    let user = authorization_token.email.ok_or_else(|| {
        KmsError::Unauthorized("Authorization token should contain an email".to_string())
    })?;

    debug!("cse_digest: encode base64 wrapped_dek");
    // Create the data string for HMAC
    let data = format!("ResourceKeyDigest:{resource_name}:{perimeter_id}");
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;

    let dek_data = cse_symmetric_key_unwrap(
        digest_request.wrapped_key,
        user,
        Some(resource_name.into_bytes()),
        kms,
        database_params,
    )
    .await?;

    // Create a PKey object from the unwrapped DEK
    let key = PKey::hmac(&dek_data)?;

    // Create a Signer object for HMAC-SHA256
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;

    // Input the data into the signer
    signer.update(data.as_bytes())?;

    // Finalize the HMAC and retrieve the resulting bytes
    let hmac_result = signer.sign_to_vec()?;

    // Encode the result as a base64 string
    let base64_result = general_purpose::STANDARD.encode(hmac_result);

    Ok(DigestResponse {
        resource_key_hash: base64_result,
    })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrivilegedWrapRequest {
    pub authentication: String,
    pub key: String,
    pub perimeter_id: String,
    pub resource_name: String,
    pub reason: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PrivilegedWrapResponse {
    pub wrapped_key: String,
}

/// Returns a wrapped Data Encryption Key (DEK) and associated data. Use this method to encrypt data imported to Google Drive in bulk by a domain administrator.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/privileged-wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
pub async fn privileged_wrap(
    privileged_wrap_request: PrivilegedWrapRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<PrivilegedWrapResponse> {
    debug!("privileged-wrap: validate authentication token");
    let user = validate_cse_authentication_token(
        &privileged_wrap_request.authentication,
        cse_config,
        true,
    )
    .await?;

    debug!("privileged-wrap: wrap dek");
    let resource_name = privileged_wrap_request.resource_name.into_bytes();
    let encryption_request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString("google_cse".to_string())),
        cryptographic_parameters: None,
        data: Some(
            general_purpose::STANDARD
                .decode(&privileged_wrap_request.key)?
                .into(),
        ),
        iv_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: Some(resource_name),
    };
    let dek = encrypt(kms, encryption_request, &user, None).await?;

    // re-extract the bytes from the key
    let data = dek.data.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - missing data.".to_string())
    })?;
    let iv_counter_nonce = dek.iv_counter_nonce.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - missing nonce.".to_string())
    })?;
    let authenticated_encryption_tag = dek.authenticated_encryption_tag.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - authenticated encryption tag.".to_string())
    })?;

    let wrapped_dek = [data, iv_counter_nonce, authenticated_encryption_tag].concat();

    debug!("privileged-wrap: exiting with success");
    Ok(PrivilegedWrapResponse {
        wrapped_key: general_purpose::STANDARD.encode(wrapped_dek),
    })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrivilegedUnwrapRequest {
    pub authentication: String,
    pub reason: String,
    pub resource_name: String,
    pub wrapped_key: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PrivilegedUnwrapResponse {
    pub key: String,
}

/// Decrypts data exported from Google in a privileged context. Previously known as `TakeoutUnwrap`. Returns the Data Encryption Key (DEK) that was wrapped using wrap without checking the original document or file access control list (ACL).
///
/// See [doc](https://developers.google.com/workspace/cse/reference/privileged-unwrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
pub async fn privileged_unwrap(
    req_http: HttpRequest,
    privileged_unwrap_request: PrivilegedUnwrapRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<PrivilegedUnwrapResponse> {
    debug!("privileged_unwrap: entering");

    let user = validate_cse_authentication_token(
        &privileged_unwrap_request.authentication,
        cse_config,
        false,
    )
    .await?;
    let resource_name = privileged_unwrap_request.resource_name.into_bytes();
    debug!("privileged_unwrap: validate_tokens");

    debug!("privileged_unwrap: unwrap key");
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let data = cse_symmetric_key_unwrap(
        privileged_unwrap_request.wrapped_key,
        user,
        Some(resource_name),
        kms,
        database_params,
    )
    .await?;

    debug!("privileged_unwrap: exiting with success");
    Ok(PrivilegedUnwrapResponse {
        key: general_purpose::STANDARD.encode(data),
    })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrivilegedPrivateKeyDecryptRequest {
    pub authentication: String,
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
    /// Standard base64-encoded digest of the DER-encoded `SubjectPublicKeyInfo` of the private key being accessed.
    pub spki_hash: String,
    /// Algorithm used to produce `spki_hash`. Can be "SHA-256".
    pub spki_hash_algorithm: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrivilegedPrivateKeyDecryptResponse {
    /// A base64-encoded data encryption key.
    pub data_encryption_key: String,
}

/// Unwraps a wrapped private key and then decrypts the content encryption key that is encrypted to the public key.
///
/// See Google documentation:
/// - Private Key Decrypt endpoint: <https://developers.google.com/workspace/cse/reference/private-key-decrypt>
pub async fn privileged_private_key_decrypt(
    req_http: HttpRequest,
    request: PrivilegedPrivateKeyDecryptRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<PrivilegedPrivateKeyDecryptResponse> {
    debug!("privileged_private_key_decrypt: entering");
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;

    debug!("privileged_private_key_decrypt: validate_tokens");
    let user = validate_cse_authentication_token(&request.authentication, cse_config, true).await?;

    debug!("privileged_private_key_decrypt: check algorithm");
    kms_ensure!(
        request.algorithm == "RSA/ECB/PKCS1Padding",
        "Only RSA/ECB/PKCS1Padding is supported"
    );

    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    debug!("privileged_private_key_decrypt: decode encrypted_dek");
    let encrypted_dek = general_purpose::STANDARD.decode(&request.encrypted_data_encryption_key)?;

    // Unwrap private key which has been previously wrapped using AES
    let private_key_der =
        cse_private_key_unwrap(request.wrapped_private_key, user, kms, database_params).await?;

    // Decrypt with the unwrapped RSA private key
    debug!("privileged_private_key_decrypt: from_rsa");
    let private_key = PKey::from_rsa(Rsa::<Private>::private_key_from_der(&private_key_der)?)?;

    // Get the associated public key to compare digest spki
    let public_key_der = private_key.public_key_to_der()?;
    // Compute the hash of the DER-encoded public key using SHA-256
    let spki_algorithm = get_hash_algorithm(&request.spki_hash_algorithm.to_lowercase())?;
    let digest = openssl::hash::hash(spki_algorithm, &public_key_der)?;
    let spki_hash = general_purpose::STANDARD.encode(digest);
    kms_ensure!(
        spki_hash == request.spki_hash,
        KmsError::CryptographicError(
            "spki_hash does not match with the associated privated key.".to_string()
        )
    );

    // Perform RSA PKCS1 decryption.
    let mut ctx = PkeyCtx::new(&private_key)?;
    ctx.decrypt_init()?;
    ctx.set_rsa_padding(Padding::PKCS1)?;
    if let Some(label) = request.rsa_oaep_label {
        ctx.set_rsa_oaep_label(label.as_bytes())?;
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
    }
    let allocation_size = ctx.decrypt(&encrypted_dek, None)?;
    debug!("privileged_private_key_decrypt: allocation_size: {allocation_size}");
    let mut dek = vec![0_u8; allocation_size];
    let decrypt_size = ctx.decrypt(&encrypted_dek, Some(&mut *dek))?;

    debug!("privileged_private_key_decrypt: exiting with success: decrypt_size: {decrypt_size}");
    let response = PrivilegedPrivateKeyDecryptResponse {
        data_encryption_key: general_purpose::STANDARD.encode(&dek[0..decrypt_size]),
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
async fn cse_private_key_unwrap(
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
                unique_identifier: UniqueIdentifier::TextString("google_cse".to_string()),
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

/// Decrypts a symmetric key
/// Tries to decrypt it, using the `resource_name`. If it fails, key might be wrapped without it,
/// so we try to unwrap it as it was done initially.
///
/// # Arguments
///
/// * `wrapped_key` - A base64-encoded string representing the wrapped key.
/// * `user` - A string identifying the user associated with the key.
/// * `resource_name` - Bytes identifying the resource the key has been made for.
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
async fn cse_symmetric_key_unwrap(
    wrapped_key: String,
    user: String,
    resource_name: Option<Vec<u8>>,
    kms: &Arc<KMSServer>,
    database_params: Option<ExtraDatabaseParams>,
) -> KResult<Zeroizing<Vec<u8>>> {
    let wrapped_key_bytes = general_purpose::STANDARD.decode(&wrapped_key)?;
    let len = wrapped_key_bytes.len();
    if len < TAG_LENGTH + NONCE_LENGTH {
        return Err(KmsError::InvalidRequest(
            "Invalid wrapped key - insufficient length.".to_string(),
        ));
    }
    let authenticated_tag = &wrapped_key_bytes[len - TAG_LENGTH..];
    let iv_counter_nonce = &wrapped_key_bytes[len - (TAG_LENGTH + NONCE_LENGTH)..len - TAG_LENGTH];
    let ciphertext = &wrapped_key_bytes[..len - (TAG_LENGTH + NONCE_LENGTH)];

    let decryption_request = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString("google_cse".to_string())),
        cryptographic_parameters: None,
        data: Some(ciphertext.to_vec()),
        iv_counter_nonce: Some(iv_counter_nonce.to_vec()),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: resource_name,
        authenticated_encryption_tag: Some(authenticated_tag.to_vec()),
    };
    let dek = decrypt(kms, decryption_request, &user, None).await;
    let data = if let Ok(decrypted_key) = dek {
        decrypted_key.data.ok_or_else(|| {
            KmsError::InvalidRequest("Invalid unwrapped key - missing data.".to_string())
        })?
    } else {
        // If decrypting key fails, try to unwrap it as it was done initially
        debug!("unwrap: key decryption fails, try to unwrap it instead");

        let mut wrapped_dek = create_symmetric_key_kmip_object(
            &general_purpose::STANDARD.decode(&wrapped_key)?,
            CryptographicAlgorithm::AES,
        );
        wrapped_dek.key_block_mut()?.key_wrapping_data = Some(Box::new(KeyWrappingData {
            wrapping_method: kmip_types::WrappingMethod::Encrypt,
            encryption_key_information: Some(kmip_types::EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString("google_cse".to_string()),
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
        wrapped_dek.key_block()?.key_bytes()?
    };
    Ok(data)
}
