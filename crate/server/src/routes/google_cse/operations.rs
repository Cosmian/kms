use std::sync::Arc;

use base64::{engine::general_purpose, Engine};
use clap::crate_version;
use cosmian_kmip::kmip::{
    kmip_operations::{Decrypt, Encrypt},
    kmip_types::{BlockCipherMode, CryptographicParameters, UniqueIdentifier},
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
use tracing::{debug, trace};
use zeroize::Zeroizing;

use super::GoogleCseConfig;
use crate::{
    core::operations::{decrypt, encrypt},
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
pub(crate) const GOOGLE_CSE_ID: &str = "google_cse";

#[derive(PartialEq, Eq)]
pub enum Role {
    Reader,
    Signer,
    Writer,
    Upgrader,
    Migrator,
    Verifier,
    Decrypter,
}

impl Role {
    #[must_use]
    pub const fn as_role_str(role: &Self) -> &str {
        match role {
            Self::Reader => "reader",
            Self::Signer => "signer",
            Self::Writer => "writer",
            Self::Upgrader => "upgrader",
            Self::Migrator => "migrator",
            Self::Verifier => "verifier",
            Self::Decrypter => "decrypter",
        }
    }
}

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
                .to_owned(),
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

/// Wraps a Data Encryption Key (DEK) using the specified authentication and authorization tokens.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
/// # Arguments
/// - `request`: The wrap request.
/// - `cse_config`: The Google CSE configuration.
/// - `kms`: The KMS server.
///
/// # Returns
/// - `WrapResponse`: The wrapped key.
///
/// # Errors
/// This function can return an error if there is a problem with the encryption process or if the tokens validation fails.
pub async fn wrap(
    request: WrapRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<WrapResponse> {
    debug!("wrap: entering");

    let application = get_application(&request.reason);

    // the possible roles to wrap a key
    let roles = &[Role::Writer, Role::Upgrader];

    debug!("wrap: validate_tokens");
    let token_extracted_content = validate_tokens(
        &request.authentication,
        &request.authorization,
        cse_config,
        &application,
        Some(roles),
    )
    .await?;

    debug!("wrap: wrap dek");
    let encryption_request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned())),
        cryptographic_parameters: None,
        data: Some(general_purpose::STANDARD.decode(&request.key)?.into()),
        iv_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: token_extracted_content.resource_name,
    };
    let dek = encrypt(kms, encryption_request, &token_extracted_content.user, None).await?;

    // re-extract the bytes from the key
    let data = dek.data.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - missing data.".to_owned())
    })?;
    let iv_counter_nonce = dek.iv_counter_nonce.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - missing nonce.".to_owned())
    })?;
    let authenticated_encryption_tag = dek.authenticated_encryption_tag.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - authenticated encryption tag.".to_owned())
    })?;

    let mut wrapped_dek = Vec::with_capacity(
        iv_counter_nonce.len() + data.len() + authenticated_encryption_tag.len(),
    );
    wrapped_dek.extend_from_slice(&iv_counter_nonce);
    wrapped_dek.extend_from_slice(&data);
    wrapped_dek.extend_from_slice(&authenticated_encryption_tag);

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

fn get_application(reason: &str) -> String {
    trace!("get_application: reason: {reason}");
    let application = if reason.contains("Meet") {
        "meet".to_owned()
    } else if reason.contains("calendar") {
        "calendar".to_owned()
    } else {
        "drive".to_owned()
    };
    trace!("get_application: application: {application}");
    application
}

/// Unwraps a wrapped Data Encryption Key (DEK) using the specified authentication and authorization tokens.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
/// # Arguments
/// - `req_http`: The HTTP request.
/// - `request`: The unwrap request.
/// - `cse_config`: The Google CSE configuration.
/// - `kms`: The KMS server.
///
/// # Returns
/// - `UnwrapResponse`: The unwrapped key.
///
/// # Errors
/// This function can return an error if there is a problem with the decryption process or if the tokens validation fails.
pub async fn unwrap(
    request: UnwrapRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<UnwrapResponse> {
    debug!("unwrap: entering");

    let application = get_application(&request.reason);

    // the possible roles to unwrap a key
    let roles = &[Role::Writer, Role::Reader];

    debug!("unwrap: validate_tokens");
    let token_extracted_content = validate_tokens(
        &request.authentication,
        &request.authorization,
        cse_config,
        &application,
        Some(roles),
    )
    .await?;

    debug!("unwrap: unwrap key");
    let data = cse_wrapped_key_decrypt(
        request.wrapped_key,
        UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        token_extracted_content.user,
        token_extracted_content.resource_name,
        kms,
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
    request: PrivateKeySignRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<PrivateKeySignResponse> {
    debug!("private_key_sign: entering");
    let roles: &[Role; 1] = &[Role::Signer];

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
    let private_key_der = cse_wrapped_key_decrypt(
        request.wrapped_private_key,
        UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        token_extracted_content.user,
        None,
        kms,
    )
    .await?;

    // Sign with the unwrapped RSA private key
    debug!("private_key_sign: from_rsa");
    let private_key = PKey::from_rsa(Rsa::<Private>::private_key_from_der(&private_key_der)?)?;

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
    request: PrivateKeyDecryptRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<PrivateKeyDecryptResponse> {
    debug!("private_key_decrypt: entering");
    let roles: &[Role; 1] = &[Role::Decrypter];

    let token_extracted_content = validate_tokens(
        &request.authentication,
        &request.authorization,
        cse_config,
        "gmail",
        Some(roles),
    )
    .await?;

    kms_ensure!(
        request.algorithm == "RSA/ECB/PKCS1Padding",
        "Only RSA/ECB/PKCS1Padding is supported"
    );

    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    debug!(
        "private_key_decrypt: request.encrypted_data_encryption_key: {}",
        request.encrypted_data_encryption_key
    );
    let encrypted_dek = general_purpose::STANDARD.decode(&request.encrypted_data_encryption_key)?;

    debug!("private_key_decrypt: [OK] base64 of encrypted_dek has been removed");
    // Unwrap private key which has been previously wrapped using AES
    let private_key_der = cse_wrapped_key_decrypt(
        request.wrapped_private_key,
        UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        token_extracted_content.user,
        None,
        kms,
    )
    .await?;

    debug!(
        "private_key_decrypt: [OK] private_key_der {}",
        general_purpose::STANDARD.encode(private_key_der.clone()),
    );

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
    debug!("private_key_decrypt: allocation_size: {allocation_size}");
    let mut dek = vec![0_u8; allocation_size];
    let decrypt_size = ctx.decrypt(&encrypted_dek, Some(&mut *dek))?;

    debug!("private_key_decrypt: exiting with success: decrypt_size: {decrypt_size}");
    let response = PrivateKeyDecryptResponse {
        data_encryption_key: general_purpose::STANDARD.encode(
            dek.get(0..decrypt_size).ok_or_else(|| {
                KmsError::InvalidRequest("Failed to get decrypted data".to_owned())
            })?,
        ),
    };
    Ok(response)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DigestRequest {
    pub authorization: String,
    pub wrapped_key: String,
    pub reason: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct DigestResponse {
    pub resource_key_hash: String,
}

/// Digest
/// Takes a Data Encryption Key (DEK) wrapped with the wrap API, and returns the base64 encoded resource key hash
/// See [doc](https://developers.google.com/workspace/cse/reference/digest) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
///
/// # Errors
/// Will return `KmsError` if if authentication with tokens is incorrect, or if decryption or digest creation fails
pub async fn digest(
    request: DigestRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<DigestResponse> {
    let application = get_application(&request.reason);

    debug!("digest: validate_authorization_token");

    let roles = [Role::Verifier];
    let authorization_token = validate_cse_authorization_token(
        &request.authorization,
        cse_config,
        &application,
        Some(&roles),
    )
    .await?;

    let perimeter_id = authorization_token.perimeter_id.unwrap_or_default();
    let resource_name = authorization_token.resource_name.unwrap_or_default();
    let user = authorization_token.email.ok_or_else(|| {
        KmsError::Unauthorized("Authorization token should contain an email".to_owned())
    })?;

    debug!("cse_digest: encode base64 wrapped_dek");
    let dek_data = cse_wrapped_key_decrypt(
        request.wrapped_key,
        UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        user,
        Some(resource_name.clone().into_bytes()),
        kms,
    )
    .await?;

    let base64_digest = compute_resource_key_hash(&resource_name, &perimeter_id, &dek_data)?;

    Ok(DigestResponse {
        resource_key_hash: base64_digest,
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
///
/// # Errors
/// Will return `KmsError` if if authentication with tokens is incorrect, or if encryption fails
pub async fn privileged_wrap(
    request: PrivilegedWrapRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<PrivilegedWrapResponse> {
    debug!("privileged-wrap: validate authentication token");
    let user = validate_cse_authentication_token(&request.authentication, cse_config, true).await?;

    debug!("privileged-wrap: wrap dek");
    let resource_name = request.resource_name.into_bytes();
    let encryption_request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned())),
        cryptographic_parameters: None,
        data: Some(general_purpose::STANDARD.decode(&request.key)?.into()),
        iv_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: Some(resource_name),
    };
    let dek = encrypt(kms, encryption_request, &user, None).await?;

    // re-extract the bytes from the key
    let data = dek.data.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - missing data.".to_owned())
    })?;
    let iv_counter_nonce = dek.iv_counter_nonce.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - missing nonce.".to_owned())
    })?;
    let authenticated_encryption_tag = dek.authenticated_encryption_tag.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - authenticated encryption tag.".to_owned())
    })?;

    let mut wrapped_dek = Vec::with_capacity(
        iv_counter_nonce.len() + data.len() + authenticated_encryption_tag.len(),
    );
    wrapped_dek.extend_from_slice(&iv_counter_nonce);
    wrapped_dek.extend_from_slice(&data);
    wrapped_dek.extend_from_slice(&authenticated_encryption_tag);

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
///
/// # Errors
/// Will return `KmsError` if if authentication with tokens is incorrect, or if decryption fails
pub async fn privileged_unwrap(
    request: PrivilegedUnwrapRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<PrivilegedUnwrapResponse> {
    debug!("privileged_unwrap: entering");

    let user =
        validate_cse_authentication_token(&request.authentication, cse_config, false).await?;
    let resource_name = request.resource_name.into_bytes();
    debug!("privileged_unwrap: validate_tokens");

    debug!("privileged_unwrap: unwrap key");
    let data: Zeroizing<Vec<u8>> = cse_wrapped_key_decrypt(
        request.wrapped_key,
        UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        user,
        Some(resource_name),
        kms,
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
///
/// # Errors
/// Will return `KmsError` if if authentication with tokens is incorrect, or if decryption fails
pub async fn privileged_private_key_decrypt(
    request: PrivilegedPrivateKeyDecryptRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<PrivilegedPrivateKeyDecryptResponse> {
    debug!("privileged_private_key_decrypt: entering");
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
    let private_key_der = cse_wrapped_key_decrypt(
        request.wrapped_private_key,
        UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        user,
        None,
        kms,
    )
    .await?;

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
            "spki_hash does not match with the associated private key.".to_owned()
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
        data_encryption_key: general_purpose::STANDARD.encode(
            dek.get(0..decrypt_size).ok_or_else(|| {
                KmsError::InvalidRequest("Failed to get decrypted data".to_owned())
            })?,
        ),
    };
    Ok(response)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RewrapRequest {
    pub authorization: String,
    pub original_kacls_url: String,
    pub reason: String,
    pub wrapped_key: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RewrapResponse {
    pub resource_key_hash: String,
    pub wrapped_key: String,
}

/// Migrate from the old Key Access Control List Service (KACLS1) to the newer KACLS (KACLS2). It takes a Data Encryption Key (DEK) wrapped with KACLS1's wrap API, and returns a DEK wrapped with KACLS2's wrap API.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/rewrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
///
/// # Errors
/// Will return `KmsError` if if authentication with tokens is incorrect, or if encryption fails
pub async fn rewrap(
    request: RewrapRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMSServer>,
) -> KResult<RewrapResponse> {
    debug!("rewrap: entering");

    let application = get_application(&request.reason);
    let roles = [Role::Migrator];
    let authorization_token = validate_cse_authorization_token(
        &request.authorization,
        cse_config,
        &application,
        Some(&roles),
    )
    .await?;

    let perimeter_id = authorization_token.perimeter_id.unwrap_or_default();
    let resource_name = authorization_token.resource_name.unwrap_or_default();
    let user = authorization_token.email.ok_or_else(|| {
        KmsError::Unauthorized("Authorization token should contain an email".to_owned())
    })?;

    debug!("rewrap: unwrap key using imported original KMS wrapping key");
    let unwrapped_data: Zeroizing<Vec<u8>> = cse_wrapped_key_decrypt(
        request.wrapped_key,
        // We consider that the key used by the previous KMS to wrap elements was imported under
        // the original_kacls_url as an ID
        UniqueIdentifier::TextString(request.original_kacls_url),
        user.clone(),
        Some(resource_name.clone().into_bytes()),
        kms,
    )
    .await?;

    debug!("rewrap: wrap key using current KMS");
    let encryption_request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned())),
        cryptographic_parameters: None,
        data: Some(unwrapped_data.clone()),
        iv_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: Some(resource_name.clone().into_bytes()),
    };
    let encrypt_response = encrypt(kms, encryption_request, &user, None).await?;

    // re-extract the bytes from the key
    let data = encrypt_response.data.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - missing data.".to_owned())
    })?;
    let iv_counter_nonce = encrypt_response.iv_counter_nonce.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - missing nonce.".to_owned())
    })?;
    let authenticated_encryption_tag =
        encrypt_response
            .authenticated_encryption_tag
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "Invalid wrapped key - authenticated encryption tag.".to_owned(),
                )
            })?;

    let mut wrapped_key = Vec::with_capacity(
        iv_counter_nonce.len() + data.len() + authenticated_encryption_tag.len(),
    );
    wrapped_key.extend_from_slice(&iv_counter_nonce);
    wrapped_key.extend_from_slice(&data);
    wrapped_key.extend_from_slice(&authenticated_encryption_tag);

    debug!("rewrap: encode base64 wrapped_key to generate resource_key_hash");
    let base64_digest = compute_resource_key_hash(&resource_name, &perimeter_id, &unwrapped_data)?;

    debug!("rewrap: exiting with success");
    Ok(RewrapResponse {
        resource_key_hash: base64_digest,
        wrapped_key: general_purpose::STANDARD.encode(wrapped_key),
    })
}

/// Decrypts a wrapped key
/// Tries to decrypt it, using the `resource_name` if present. If it fails, key might be wrapped without it,
/// so we try to unwrap it as it was done initially.
///
/// # Arguments
/// * `wrapped_key` - A base64-encoded string representing the wrapped key.
/// * `user` - A string identifying the user associated with the key.
/// * `resource_name` - Bytes identifying the resource the key has been made for.
/// * `kms` - the KMS Server instance
/// * `database_params` - An optional `ExtraDatabaseParams` containing additional parameters for database operations.
///
/// # Returns
/// The decrypted key bytes
///
/// # Errors
/// Returns an error if decoding base64 fails, adding key wrapping data fails, unwrapping the key fails, or extracting the key bytes fails.
///
async fn cse_wrapped_key_decrypt(
    wrapped_key: String,
    wrapping_key_id: UniqueIdentifier,
    user: String,
    resource_name: Option<Vec<u8>>,
    kms: &Arc<KMSServer>,
) -> KResult<Zeroizing<Vec<u8>>> {
    debug!("cse_wrapped_key_decrypt: wrapped_key: {wrapped_key}");
    let wrapped_key_bytes = general_purpose::STANDARD.decode(&wrapped_key)?;
    let len = wrapped_key_bytes.len();
    if len < TAG_LENGTH + NONCE_LENGTH {
        return Err(KmsError::InvalidRequest(
            "Invalid wrapped key - insufficient length.".to_owned(),
        ));
    }
    let iv_counter_nonce = wrapped_key_bytes.get(..NONCE_LENGTH).ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - missing nonce.".to_owned())
    })?;
    let ciphertext = wrapped_key_bytes
        .get(NONCE_LENGTH..len - TAG_LENGTH)
        .ok_or_else(|| {
            KmsError::InvalidRequest("Invalid wrapped key - missing ciphertext.".to_owned())
        })?;
    let authenticated_tag = wrapped_key_bytes.get(len - TAG_LENGTH..).ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - missing authenticated tag.".to_owned())
    })?;

    trace!(
        "cse_wrapped_key_decrypt: iv_counter_nonce: {}, ciphertext: {}, authenticated_tag: {}",
        general_purpose::STANDARD.encode(iv_counter_nonce),
        general_purpose::STANDARD.encode(ciphertext),
        general_purpose::STANDARD.encode(authenticated_tag)
    );

    let decryption_request = Decrypt {
        unique_identifier: Some(wrapping_key_id),
        cryptographic_parameters: Some(CryptographicParameters {
            block_cipher_mode: Some(BlockCipherMode::GCM),
            ..Default::default()
        }),
        data: Some(ciphertext.to_vec()),
        iv_counter_nonce: Some(iv_counter_nonce.to_vec()),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: resource_name,
        authenticated_encryption_tag: Some(authenticated_tag.to_vec()),
    };
    let key = decrypt(kms, decryption_request, &user, None).await?;

    let data = key.data.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid decrypted key - missing data.".to_owned())
    })?;
    Ok(data)
}

/// Compute resource key hash
/// The resource key hash is a mechanism allowing Google to verify the integrity of the wrapped encryption keys without having access to the keys.
///
/// Generating the resource key hash requires access to the unwrapped key including the DEK, the `resource_name` and the `perimeter_id` specified during the key wrapping operation.

// We use the cryptographic function HMAC-SHA256 with unwrapped_dek as a key and the concatenation of metadata as data ("ResourceKeyDigest:", resource_name, ":", perimeter_id). The resource_name and perimeter_id should be UTF-8 encoded strings.
///
/// # Arguments
/// * `resource_name` - Bytes identifying the resource the key has been made for.
/// * `perimeter_id` - An optional value tied to the document location that can be used to choose which perimeter is checked when unwrapping
/// * `unwrapped_key_bytes` - An optional `ExtraDatabaseParams` containing additional parameters for database operations.
///
/// # Returns
/// The digest of a given key
///
/// # Errors
/// Returns an error if encoding base64 fails, or if signing key fails.
///
fn compute_resource_key_hash(
    resource_name: &str,
    perimeter_id: &str,
    unwrapped_key_bytes: &Zeroizing<Vec<u8>>,
) -> KResult<String> {
    let data = format!("ResourceKeyDigest:{resource_name}:{perimeter_id}");

    // Create a PKey object from the unwrapped DEK
    let key = PKey::hmac(unwrapped_key_bytes)?;

    // Create a Signer object for HMAC-SHA256
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;

    // Input the data into the signer
    signer.update(data.as_bytes())?;

    // Finalize the HMAC and retrieve the resulting bytes
    let hmac_result: Vec<u8> = signer.sign_to_vec()?;

    // Encode the result as a base64 string
    Ok(general_purpose::STANDARD.encode(hmac_result))
}
