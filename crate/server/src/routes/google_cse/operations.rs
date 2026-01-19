use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::Arc,
};

use base64::{
    Engine,
    engine::{general_purpose, general_purpose::URL_SAFE_NO_PAD},
};
use chrono::{Duration, Utc};
use clap::crate_version;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{BlockCipherMode, KeyWrapType},
        kmip_2_1::{
            kmip_data_structures::{KeyMaterial, KeyValue},
            kmip_objects::ObjectType,
            kmip_operations::{Decrypt, Encrypt, Get},
            kmip_types::{CryptographicParameters, KeyFormatType, UniqueIdentifier},
        },
    },
    cosmian_kms_crypto::{CryptoResultHelper, crypto::rsa::sign_rsa_digest_with_algorithm},
};
use cosmian_logger::{debug, trace};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use openssl::{
    hash::MessageDigest,
    md::Md,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
    sign::Signer,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::GoogleCseConfig;
use crate::{
    core::{
        KMS,
        operations::{decrypt, encrypt},
    },
    error::KmsError,
    kms_ensure,
    result::KResult,
    routes::google_cse::{
        build_google_cse_url,
        jwt::{
            validate_cse_authentication_token, validate_cse_authorization_token, validate_tokens,
        },
    },
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
    pub const fn str(role: &Self) -> &str {
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
        ],
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PublicKeyElements {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
    pub n: String,
    pub e: String,
    pub kid: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct CertsResponse {
    keys: Vec<PublicKeyElements>,
}

/// Returns the public key to decode KACLS token for migration.
///
/// # Returns
/// - `CertsResponse`: The elements of RSA public key.
/// # Errors
/// - Error is raised when public RSA key can't be found
pub async fn display_rsa_public_key(
    kms: &Arc<KMS>,
    current_kacls_url: &str,
) -> KResult<CertsResponse> {
    debug!("get rsa public key on {current_kacls_url}");
    let get_request = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(format!(
            "{GOOGLE_CSE_ID}_rsa_pk"
        ))),
        key_format_type: Some(KeyFormatType::TransparentRSAPublicKey),
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        key_compression_type: None,
        key_wrapping_specification: None,
    };
    let resp = kms.get(get_request, &kms.params.default_username).await?;
    if resp.object_type == ObjectType::PublicKey {
        match &resp.object.key_block()?.key_value {
            Some(KeyValue::Structure { key_material, .. }) => match key_material {
                KeyMaterial::TransparentRSAPublicKey {
                    modulus,
                    public_exponent,
                } => Ok(CertsResponse {
                    keys: vec![PublicKeyElements {
                        kty: "RSA".to_owned(),
                        use_: "sig".to_owned(),
                        alg: "RS256".to_owned(),
                        n: URL_SAFE_NO_PAD.encode(modulus.to_bytes_be().1),
                        e: URL_SAFE_NO_PAD.encode(public_exponent.to_bytes_be().1),
                        kid: calculate_hash::<str>(current_kacls_url).to_string(),
                    }],
                }),
                _ => Err(KmsError::InvalidRequest(
                    "Invalid RSA Public key fetch. No exponent and modulus".to_owned(),
                )),
            },
            _ => Err(KmsError::InvalidRequest(
                "Expected structured KeyValue for RSA public key".to_owned(),
            )),
        }
    } else {
        Err(KmsError::InvalidRequest(
            "Invalid RSA Public key fetch.".to_owned(),
        ))
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

/// Validates the provided authentication and authorization tokens, and extracts the content.
///
/// This function takes the authentication and authorization tokens from the request,
/// along with the CSE configuration, application context, and optional roles. It performs
/// validation on the tokens and extracts the relevant content if the validation is successful.
async fn get_user_and_resource_name(
    roles: &[Role],
    authentication_token: &str,
    authorization_token: &str,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMS>,
) -> KResult<(String, Option<Vec<u8>>)> {
    if kms.params.google_cse.google_cse_disable_tokens_validation {
        debug!("no token validation");
        Ok((kms.params.default_username.clone(), None))
    } else {
        debug!("validate_tokens");
        let token_extracted_content = validate_tokens(
            authentication_token,
            authorization_token,
            kms,
            cse_config,
            Some(roles),
        )
        .await?;
        Ok((
            token_extracted_content.user,
            token_extracted_content.resource_name,
        ))
    }
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
    kms: &Arc<KMS>,
) -> KResult<WrapResponse> {
    debug!("entering");

    // the possible roles to wrap a key
    let roles = &[Role::Writer, Role::Upgrader];

    // get the user and resource name
    let (user, resource_name) = get_user_and_resource_name(
        roles,
        &request.authentication,
        &request.authorization,
        cse_config,
        kms,
    )
    .await?;

    debug!("wrap dek");
    let wrapped_dek = cse_key_encrypt(request.key, user, resource_name, kms).await?;

    debug!("exiting with success");
    Ok(WrapResponse {
        wrapped_key: wrapped_dek,
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
    kms: &Arc<KMS>,
) -> KResult<UnwrapResponse> {
    debug!("entering");

    // the possible roles to unwrap a key
    let roles = &[Role::Writer, Role::Reader];

    // get the user and resource name
    let (user, resource_name) = get_user_and_resource_name(
        roles,
        &request.authentication,
        &request.authorization,
        cse_config,
        kms,
    )
    .await?;

    debug!("unwrap key");
    let data = cse_wrapped_key_decrypt(
        request.wrapped_key,
        UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        user,
        resource_name,
        kms,
    )
    .await?;
    debug!("exiting with success");
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
    kms: &Arc<KMS>,
) -> KResult<PrivateKeySignResponse> {
    debug!("entering");
    let roles: &[Role; 1] = &[Role::Signer];

    // get the user and resource name
    let (user, _resource_name) = get_user_and_resource_name(
        roles,
        &request.authentication,
        &request.authorization,
        cse_config,
        kms,
    )
    .await?;

    debug!("decrypt private key");
    // Unwrap private key which has been previously wrapped using AES
    let private_key_der = cse_wrapped_key_decrypt(
        request.wrapped_private_key,
        UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        user,
        None,
        kms,
    )
    .await?;

    let signature = sign_rsa_digest_with_algorithm(
        &private_key_der,
        &request.algorithm,
        &request.digest,
        request.rsa_pss_salt_length,
    )?;

    debug!(
        "exiting with success: {}",
        general_purpose::STANDARD.encode(&signature)
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
    kms: &Arc<KMS>,
) -> KResult<PrivateKeyDecryptResponse> {
    debug!("entering");
    let roles: &[Role; 1] = &[Role::Decrypter];

    // get the user and resource name
    let (user, _resource_name) = get_user_and_resource_name(
        roles,
        &request.authentication,
        &request.authorization,
        cse_config,
        kms,
    )
    .await?;

    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    debug!(
        "request.encrypted_data_encryption_key: {}",
        request.encrypted_data_encryption_key
    );
    let encrypted_dek = general_purpose::STANDARD.decode(&request.encrypted_data_encryption_key)?;

    debug!("[OK] base64 of encrypted_dek has been removed");
    // Unwrap private key which has been previously wrapped using AES
    let private_key_der = cse_wrapped_key_decrypt(
        request.wrapped_private_key,
        UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        user,
        None,
        kms,
    )
    .await?;

    debug!(
        "[OK] recovered private_key DER bytes (len: {}). Perform RSA decryption",
        private_key_der.len()
    );

    // Decrypt with the unwrapped RSA private key
    // Assume the bytes are PKCS#1 DER encoded; if not, assume the bytes are PKCS#1 DER Encoded.
    // From openssl documentation, `private_key_from_der` should be able to auto-detect formats.
    let private_key = match PKey::private_key_from_der(&private_key_der) {
        Ok(private_key) => private_key,
        Err(_) => PKey::from_rsa(
            Rsa::<Private>::private_key_from_der(&private_key_der)
                .context("failed converting PKCS#1 DER bytes to RSA private key")?,
        )
        .context("failed to create PKey from RSA private key")?,
    };

    // Perform RSA decryption.
    let mut ctx = PkeyCtx::new(&private_key)?;
    ctx.decrypt_init()?;
    if request.algorithm == "RSA/ECB/PKCS1Padding" {
        ctx.set_rsa_padding(Padding::PKCS1)?;
    } else {
        if let Some(label) = request.rsa_oaep_label {
            ctx.set_rsa_oaep_label(label.as_bytes())?;
        }
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        let md = match request.algorithm.as_str() {
            "RSA/ECB/OAEPwithSHA-1andMGF1Padding" => Md::sha1(),
            "RSA/ECB/OAEPwithSHA-256andMGF1Padding" => Md::sha256(),
            "RSA/ECB/OAEPwithSHA-512andMGF1Padding" => Md::sha512(),
            _ => {
                return Err(KmsError::InvalidRequest(
                    "Decryption algorithm not handled.".to_owned(),
                ));
            }
        };
        ctx.set_rsa_oaep_md(md)?;
        ctx.set_rsa_mgf1_md(md)?;
    }
    let allocation_size = ctx.decrypt(&encrypted_dek, None)?;
    debug!("allocation_size: {allocation_size}");
    let mut dek = vec![0_u8; allocation_size];
    let decrypt_size = ctx.decrypt(&encrypted_dek, Some(&mut *dek))?;

    debug!("exiting with success: decrypt_size: {decrypt_size}");
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
///
/// Takes a Data Encryption Key (DEK) wrapped with the wrap API, and returns the base64 encoded resource key hash
/// See [doc](https://developers.google.com/workspace/cse/reference/digest) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
///
/// # Errors
/// Will return `KmsError` if if authentication with tokens is incorrect, or if decryption or digest creation fails
pub async fn digest(
    request: DigestRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMS>,
) -> KResult<DigestResponse> {
    debug!("entering");

    let google_cse_kacls_url = build_google_cse_url(kms.params.kms_public_url.as_deref())?;

    let authorization_token = validate_cse_authorization_token(
        &request.authorization,
        &google_cse_kacls_url,
        cse_config,
        Some(&[Role::Verifier]),
    )
    .await?;

    let perimeter_id = authorization_token.perimeter_id.unwrap_or_default();
    let resource_name = authorization_token.resource_name.unwrap_or_default();
    let user = authorization_token.email.ok_or_else(|| {
        KmsError::Unauthorized("Authorization token should contain an email".to_owned())
    })?;

    debug!("encode base64 wrapped_dek");
    let dek_data = cse_wrapped_key_decrypt(
        request.wrapped_key,
        UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        user,
        Some(resource_name.clone().into_bytes()),
        kms,
    )
    .await?;

    let resource_key_hash = compute_resource_key_hash(&resource_name, &perimeter_id, &dek_data)?;

    Ok(DigestResponse { resource_key_hash })
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
    kms: &Arc<KMS>,
) -> KResult<PrivilegedWrapResponse> {
    debug!("entering");

    let google_cse_kacls_url = build_google_cse_url(kms.params.kms_public_url.as_deref())?;

    let user = validate_cse_authentication_token(
        &request.authentication,
        cse_config,
        &google_cse_kacls_url,
        &kms.params.default_username,
        None,
    )
    .await?;

    debug!("wrap dek");
    let resource_name = request.resource_name.into_bytes();
    let wrapped_dek = cse_key_encrypt(request.key, user, Some(resource_name), kms).await?;

    debug!("exiting with success");
    Ok(PrivilegedWrapResponse {
        wrapped_key: wrapped_dek,
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

/// Decrypts data exported from Google in a privileged context. Previously known as `TakeoutUnwrap`.
///
/// Returns the Data Encryption Key (DEK) that was wrapped using wrap without checking the original document or file access control list (ACL).
/// See [doc](https://developers.google.com/workspace/cse/reference/privileged-unwrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
///
/// # Errors
/// Will return `KmsError` if if authentication with tokens is incorrect or if decryption fails
pub async fn privileged_unwrap(
    request: PrivilegedUnwrapRequest,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMS>,
) -> KResult<PrivilegedUnwrapResponse> {
    debug!("entering");
    let user = if kms.params.google_cse.google_cse_disable_tokens_validation {
        debug!("Authentication token check: validation disabled");
        kms.params.default_username.clone()
    } else {
        let google_cse_kacls_url = build_google_cse_url(kms.params.kms_public_url.as_deref())?;
        validate_cse_authentication_token(
            &request.authentication,
            cse_config,
            &google_cse_kacls_url,
            &kms.params.default_username,
            Some(request.resource_name.clone()),
        )
        .await?
    };
    let resource_name = request.resource_name.clone();

    debug!("unwrap key");
    let data: Zeroizing<Vec<u8>> = cse_wrapped_key_decrypt(
        request.wrapped_key,
        UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        user,
        Some(resource_name.into_bytes()),
        kms,
    )
    .await?;

    debug!("exiting with success");
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
    kms: &Arc<KMS>,
) -> KResult<PrivilegedPrivateKeyDecryptResponse> {
    debug!("entering");
    let google_cse_kacls_url = build_google_cse_url(kms.params.kms_public_url.as_deref())?;

    let user = validate_cse_authentication_token(
        &request.authentication,
        cse_config,
        &google_cse_kacls_url,
        &kms.params.default_username,
        None,
    )
    .await?;

    debug!("check algorithm");

    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    debug!("decode encrypted_dek");
    let encrypted_dek = general_purpose::STANDARD.decode(&request.encrypted_data_encryption_key)?;

    // Unwrap private key which has been previously wrapped using AES-GCM
    let private_key_der = cse_wrapped_key_decrypt(
        request.wrapped_private_key,
        UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        user,
        None,
        kms,
    )
    .await?;

    // Decrypt with the unwrapped RSA private key
    debug!("from_rsa");
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

    // Perform RSA decryption.
    let mut ctx = PkeyCtx::new(&private_key)?;
    ctx.decrypt_init()?;
    if request.algorithm == "RSA/ECB/PKCS1Padding" {
        ctx.set_rsa_padding(Padding::PKCS1)?;
    } else {
        if let Some(label) = request.rsa_oaep_label {
            ctx.set_rsa_oaep_label(label.as_bytes())?;
        }
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        let md = match request.algorithm.as_str() {
            "RSA/ECB/OAEPwithSHA-1andMGF1Padding" => Md::sha1(),
            "RSA/ECB/OAEPwithSHA-256andMGF1Padding" => Md::sha256(),
            "RSA/ECB/OAEPwithSHA-512andMGF1Padding" => Md::sha512(),
            _ => {
                return Err(KmsError::InvalidRequest(
                    "Decryption algorithm not handled.".to_owned(),
                ));
            }
        };
        ctx.set_rsa_oaep_md(md)?;
        ctx.set_rsa_mgf1_md(md)?;
    }
    let allocation_size = ctx.decrypt(&encrypted_dek, None)?;
    debug!("allocation_size: {allocation_size}");
    let mut dek = vec![0_u8; allocation_size];
    let decrypt_size = ctx.decrypt(&encrypted_dek, Some(&mut *dek))?;

    debug!("exiting with success: decrypt_size: {decrypt_size}");
    let response = PrivilegedPrivateKeyDecryptResponse {
        data_encryption_key: general_purpose::STANDARD.encode(
            dek.get(0..decrypt_size).ok_or_else(|| {
                KmsError::InvalidRequest("Failed to get decrypted data".to_owned())
            })?,
        ),
    };
    Ok(response)
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    aud: String,
    exp: usize,
    iat: usize,
    kacls_url: String,
    resource_name: String,
}

fn calculate_hash<T: Hash + ?Sized>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

/// Create a signed JSON Web Token (JWT) for authenticating a KACLS migration request.
///
/// This token includes standard claims such as `iss` (issuer), `aud` (audience), `iat` (issued at),
/// and `exp` (expiration), as well as custom claims like `kacls_url` and `resource_name`.
/// The JWT is signed using the RS256 algorithm with the provided RSA private key in DER format.
///
/// The `kid` (key ID) header is set to a hash of the current KACLS URL, allowing the receiving
/// service to select the correct public key for validation.
///
/// This token is intended to be sent to the original KACLS server to authorize access to the wrapped DEK
/// during migration.
///
/// # Arguments
///
/// * `private_key_bytes` - The RSA private key in DER format used to sign the token.
/// * `current_kacls_url` - The base URL of the currently running KACLS service (used as issuer).
/// * `original_kacls_url` - The base URL of the original KACLS service (used in a custom claim).
/// * `resource_name` - The name of the encrypted resource (used in a custom claim).
///
/// # Errors
///
/// Returns `KmsError` if the current timestamp cannot be converted to a `usize`, or if JWT
/// encoding fails due to invalid key format or internal serialization errors.
pub fn create_jwt(
    private_key_bytes: &[u8],
    current_kacls_url: &str,
    original_kacls_url: &str,
    resource_name: &str,
) -> KResult<String> {
    let now = Utc::now();
    let claims = Claims {
        iss: current_kacls_url.to_owned(),
        aud: "kacls-migration".to_owned(),
        kacls_url: original_kacls_url.to_owned(),
        resource_name: resource_name.to_owned(),
        iat: usize::try_from(now.timestamp())?,
        exp: usize::try_from((now + Duration::minutes(60)).timestamp())?,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(calculate_hash::<str>(current_kacls_url).to_string());

    let encoding_key = EncodingKey::from_rsa_der(private_key_bytes);

    let token = encode(&header, &claims, &encoding_key)
        .map_err(|e| KmsError::Default(format!("Error encoding token: {e}")))?;
    Ok(token)
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

/// Migrate from the old Key Access Control List Service (original KACLS) to the newer KACLS2.
///
/// This function takes a Data Encryption Key (DEK) wrapped with KACLS1's wrap API and returns
/// a DEK wrapped with KACLS2's wrap API.
///
/// See the [CSE Rewrap documentation](https://developers.google.com/workspace/cse/reference/rewrap)
/// and [Encrypt & Decrypt guide](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
/// for more details.
///
/// # Errors
/// Returns `KmsError` if authentication fails, the key material is invalid, or if encryption fails.
pub async fn rewrap(
    request: RewrapRequest,
    kacls_url: &str,
    cse_config: &Arc<Option<GoogleCseConfig>>,
    kms: &Arc<KMS>,
) -> KResult<RewrapResponse> {
    debug!("entering");

    // Authorization & identity
    let roles = [Role::Migrator];
    let google_cse_kacls_url = build_google_cse_url(kms.params.kms_public_url.as_deref())?;
    let token = validate_cse_authorization_token(
        &request.authorization,
        &google_cse_kacls_url,
        cse_config,
        Some(&roles),
    )
    .await?;

    let perimeter_id = token.perimeter_id.unwrap_or_default();
    let resource_name = token.resource_name.unwrap_or_default();
    let user = token.email.ok_or_else(|| {
        KmsError::Unauthorized("Authorization token must contain an email.".to_owned())
    })?;

    // Fetch RSA private key from current KMS
    debug!("retrieving RSA private key from KMS");
    let get_request = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(format!("{GOOGLE_CSE_ID}_rsa"))),
        key_format_type: Some(KeyFormatType::PKCS1),
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        key_compression_type: None,
        key_wrapping_specification: None,
    };

    let response = kms.get(get_request, &kms.params.default_username).await?;

    let private_key_bytes = match response.object_type {
        ObjectType::PrivateKey => match &response.object.key_block()?.key_value {
            Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(bytes),
                ..
            }) => bytes,
            _ => {
                return Err(KmsError::InvalidRequest(
                    "Expected ByteString key material for RSA private key.".to_owned(),
                ));
            }
        },
        _ => {
            return Err(KmsError::InvalidRequest(
                "Invalid RSA Private key ID. Not an RSA Private key.".to_owned(),
            ));
        }
    };

    // Create JWT for original KACLS
    let jwt = create_jwt(
        private_key_bytes,
        kacls_url,
        &request.original_kacls_url,
        &resource_name,
    )?;
    debug!("Generated JWT for original KACLS: {jwt:?}");

    // Call privileged unwrap on original KACLS
    let unwrap_request = PrivilegedUnwrapRequest {
        authentication: jwt,
        wrapped_key: request.wrapped_key.clone(),
        reason: request.reason.clone(),
        resource_name: resource_name.clone(),
    };

    let unwrapped_key = Client::new()
        .post(format!("{}/privilegedunwrap", request.original_kacls_url))
        .json(&unwrap_request)
        .send()
        .await?
        .error_for_status()?
        .json::<PrivilegedUnwrapResponse>()
        .await?
        .key;

    // Wrap with current KMS (KACLS2)
    debug!("re-wrapping key with current KMS");
    let resource_name_bytes = resource_name.clone().into_bytes();
    let re_wrapped_key =
        cse_key_encrypt(unwrapped_key.clone(), user, Some(resource_name_bytes), kms).await?;

    // Compute resource key hash
    debug!("computing resource_key_hash");
    let resource_key_hash = compute_resource_key_hash(
        &resource_name,
        &perimeter_id,
        &general_purpose::STANDARD.decode(&unwrapped_key)?.into(),
    )?;

    debug!("success");
    Ok(RewrapResponse {
        resource_key_hash,
        wrapped_key: re_wrapped_key,
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
///
/// # Returns
/// The decrypted key bytes
///
/// # Errors
/// Returns an error if decoding base64 fails, adding key wrapping data fails, unwrapping the key fails, or extracting the key bytes fails.
async fn cse_wrapped_key_decrypt(
    wrapped_key: String,
    wrapping_key_id: UniqueIdentifier,
    user: String,
    resource_name: Option<Vec<u8>>,
    kms: &Arc<KMS>,
) -> KResult<Zeroizing<Vec<u8>>> {
    debug!("wrapped_key: {wrapped_key}");
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
        "iv_counter_nonce: {}, ciphertext: {}, authenticated_tag: {}",
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
        i_v_counter_nonce: Some(iv_counter_nonce.to_vec()),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: resource_name,
        authenticated_encryption_tag: Some(authenticated_tag.to_vec()),
    };
    let key = Box::pin(decrypt(kms, decryption_request, &user)).await?;

    let data = key.data.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid decrypted key - missing data.".to_owned())
    })?;
    Ok(data)
}

/// Encrypt a key
/// Tries to encrypt it, using the `resource_name`.
///
/// # Arguments
/// * `key` - A base64-encoded string representing the key to wrap.
/// * `user` - A string identifying the user associated with the key.
/// * `resource_name` - Bytes identifying the resource the key has been made for.
/// * `kms` - the KMS Server instance
///
/// # Returns
/// The encrypted key bytes
///
/// # Errors
/// Returns an error if decoding base64 fails, encrypting the key fails, or extracting the key bytes fails.
async fn cse_key_encrypt(
    key: String,
    user: String,
    resource_name: Option<Vec<u8>>,
    kms: &Arc<KMS>,
) -> KResult<String> {
    let encryption_request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned())),
        cryptographic_parameters: None,
        data: Some(general_purpose::STANDARD.decode(&key)?.into()),
        i_v_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: resource_name,
    };
    let dek = Box::pin(encrypt(kms, encryption_request, &user)).await?;

    // re-extract the bytes from the key
    let data = dek.data.ok_or_else(|| {
        KmsError::InvalidRequest("Invalid wrapped key - missing data.".to_owned())
    })?;
    let iv_counter_nonce = dek.i_v_counter_nonce.ok_or_else(|| {
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

    Ok(general_purpose::STANDARD.encode(wrapped_dek))
}

/// Compute resource key hash
///
/// The resource key hash is a mechanism allowing Google to verify the integrity of the wrapped encryption keys without having access to the keys.
///
/// Generating the resource key hash requires access to the unwrapped key including the DEK, the `resource_name` and the `perimeter_id` specified during the key wrapping operation.
/// We use the cryptographic function HMAC-SHA256 with `unwrapped_dek` as a key and the concatenation of metadata as data ("`ResourceKeyDigest`:", `resource_name`, ":", `perimeter_id`). The `resource_name` and `perimeter_id` should be UTF-8 encoded strings.
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
pub fn compute_resource_key_hash(
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
    let hmac_result = signer.sign_to_vec()?;

    // Encode the result as a base64 string
    Ok(general_purpose::STANDARD.encode(hmac_result))
}
