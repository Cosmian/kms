use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::{KmsClient, KmsClientError};

// ─── b64url helper ─────────────────────────────────────────────────────────

/// Encode bytes as base64url (no padding) for JOSE payloads.
#[must_use]
pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

// ─── Key creation ──────────────────────────────────────────────────────────

/// Request body for `POST /v1/crypto/keys`.
#[derive(Clone, Copy, Serialize)]
pub struct JoseKeyReq {
    /// Key type: `"oct"`, `"EC"`, `"RSA"`, or (non-FIPS) `"OKP"`.
    pub kty: &'static str,
    /// JWA algorithm identifier (e.g. `"A256GCM"`, `"ES256"`, `"RS256"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<&'static str>,
    /// Curve name for EC/OKP keys (e.g. `"P-256"`, `"Ed25519"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<&'static str>,
    /// Key size in bits for RSA keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<usize>,
}

/// Response from `POST /v1/crypto/keys`.
#[derive(Deserialize, Serialize)]
pub struct JoseKeyResp {
    /// Key identifier for the newly created key.
    pub kid: String,
    /// Public key identifier (set for asymmetric key pairs).
    #[serde(default)]
    pub kid_public: Option<String>,
}

// ─── Encrypt / Decrypt ─────────────────────────────────────────────────────

/// Request body for `POST /v1/crypto/encrypt`.
#[derive(Clone, Serialize)]
pub struct JoseEncReq {
    /// Key identifier of the wrapping or direct-encryption key.
    pub kid: String,
    /// Key management algorithm (e.g. `"dir"`, `"RSA-OAEP"`).
    pub alg: &'static str,
    /// Content encryption algorithm (e.g. `"A256GCM"`).
    pub enc: &'static str,
    /// Base64url-encoded plaintext.
    pub data: String,
    /// Optional additional authenticated data (base64url).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

/// Response from `POST /v1/crypto/encrypt`.
#[derive(Deserialize, Serialize)]
pub struct JoseEncResp {
    /// Base64url-encoded JWE protected header.
    pub protected: String,
    /// Base64url-encoded encrypted content encryption key.
    pub encrypted_key: String,
    /// Base64url-encoded initialization vector.
    pub iv: String,
    /// Base64url-encoded ciphertext.
    pub ciphertext: String,
    /// Base64url-encoded authentication tag.
    pub tag: String,
    /// Additional authenticated data (if provided in request).
    #[serde(default)]
    pub aad: Option<String>,
}

/// Request body for `POST /v1/crypto/decrypt`.
#[derive(Clone, Serialize)]
pub struct JoseDecryptReq {
    /// Base64url-encoded JWE protected header.
    pub protected: String,
    /// Base64url-encoded encrypted content encryption key.
    pub encrypted_key: String,
    /// Base64url-encoded initialization vector.
    pub iv: String,
    /// Base64url-encoded ciphertext.
    pub ciphertext: String,
    /// Base64url-encoded authentication tag.
    pub tag: String,
    /// Additional authenticated data (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

/// Response from `POST /v1/crypto/decrypt`.
#[derive(Deserialize, Serialize)]
pub struct JoseDecryptResp {
    /// Key identifier that was used for decryption.
    pub kid: String,
    /// Base64url-encoded decrypted plaintext.
    pub data: String,
}

// ─── Sign / Verify ─────────────────────────────────────────────────────────

/// Request body for `POST /v1/crypto/sign`.
#[derive(Clone, Serialize)]
pub struct JoseSignReq {
    /// Key identifier of the signing key.
    pub kid: String,
    /// JWA signature algorithm (e.g. `"ES256"`, `"RS256"`).
    pub alg: &'static str,
    /// Base64url-encoded data to sign.
    pub data: String,
}

/// Response from `POST /v1/crypto/sign`.
#[derive(Deserialize, Serialize)]
pub struct JoseSignResp {
    /// Base64url-encoded JWS protected header.
    pub protected: String,
    /// Base64url-encoded signature.
    pub signature: String,
}

/// Request body for `POST /v1/crypto/verify`.
#[derive(Clone, Serialize)]
pub struct JoseVerifyReq {
    /// Base64url-encoded JWS protected header.
    pub protected: String,
    /// Base64url-encoded signed data.
    pub data: String,
    /// Base64url-encoded signature to verify.
    pub signature: String,
}

/// Response from `POST /v1/crypto/verify`.
#[derive(Deserialize, Serialize)]
pub struct JoseVerifyResp {
    /// Key identifier that was used for verification.
    pub kid: String,
    /// Whether the signature is valid.
    pub valid: bool,
}

// ─── MAC ───────────────────────────────────────────────────────────────────

/// Request body for `POST /v1/crypto/mac`.
///
/// When `mac` is `None` the server computes a new MAC; when `Some` the server
/// verifies the provided MAC against the data.
#[derive(Clone, Serialize)]
pub struct JoseMacReq {
    /// Key identifier of the HMAC key.
    pub kid: String,
    /// JWA MAC algorithm (e.g. `"HS256"`, `"HS384"`, `"HS512"`).
    pub alg: &'static str,
    /// Base64url-encoded data to MAC.
    pub data: String,
    /// Optional MAC value to verify (triggers verification mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

/// Response from `POST /v1/crypto/mac` (compute mode).
#[derive(Deserialize, Serialize)]
pub struct JoseMacComputeResp {
    /// Key identifier.
    pub kid: String,
    /// Base64url-encoded MAC tag.
    pub mac: String,
}

/// Response from `POST /v1/crypto/mac` (verify mode).
#[derive(Deserialize, Serialize)]
pub struct JoseMacVerifyResp {
    /// Key identifier.
    pub kid: String,
    /// Whether the MAC is valid.
    pub valid: bool,
}

// ─── KmsClient JOSE methods ────────────────────────────────────────────────

impl KmsClient {
    /// Create a cryptographic key via the JOSE REST endpoint.
    ///
    /// This is a convenience wrapper around `POST /v1/crypto/keys`.
    pub async fn jose_create_key(&self, req: JoseKeyReq) -> Result<JoseKeyResp, KmsClientError> {
        self.post_no_ttlv("/v1/crypto/keys", Some(&req)).await
    }

    /// Encrypt data via the JOSE REST endpoint.
    ///
    /// This is a convenience wrapper around `POST /v1/crypto/encrypt`.
    pub async fn jose_encrypt(&self, req: JoseEncReq) -> Result<JoseEncResp, KmsClientError> {
        self.post_no_ttlv("/v1/crypto/encrypt", Some(&req)).await
    }

    /// Decrypt data via the JOSE REST endpoint.
    ///
    /// This is a convenience wrapper around `POST /v1/crypto/decrypt`.
    pub async fn jose_decrypt(
        &self,
        req: JoseDecryptReq,
    ) -> Result<JoseDecryptResp, KmsClientError> {
        self.post_no_ttlv("/v1/crypto/decrypt", Some(&req)).await
    }

    /// Sign data via the JOSE REST endpoint.
    ///
    /// This is a convenience wrapper around `POST /v1/crypto/sign`.
    pub async fn jose_sign(&self, req: JoseSignReq) -> Result<JoseSignResp, KmsClientError> {
        self.post_no_ttlv("/v1/crypto/sign", Some(&req)).await
    }

    /// Verify a signature via the JOSE REST endpoint.
    ///
    /// This is a convenience wrapper around `POST /v1/crypto/verify`.
    pub async fn jose_verify(&self, req: JoseVerifyReq) -> Result<JoseVerifyResp, KmsClientError> {
        self.post_no_ttlv("/v1/crypto/verify", Some(&req)).await
    }

    /// Compute a MAC via the JOSE REST endpoint.
    ///
    /// This is a convenience wrapper around `POST /v1/crypto/mac`
    /// with `mac` set to `None`.
    pub async fn jose_mac_compute(
        &self,
        req: JoseMacReq,
    ) -> Result<JoseMacComputeResp, KmsClientError> {
        self.post_no_ttlv("/v1/crypto/mac", Some(&req)).await
    }

    /// Verify a MAC via the JOSE REST endpoint.
    ///
    /// This is a convenience wrapper around `POST /v1/crypto/mac`
    /// with a populated `mac` field.
    pub async fn jose_mac_verify(
        &self,
        req: JoseMacReq,
    ) -> Result<JoseMacVerifyResp, KmsClientError> {
        self.post_no_ttlv("/v1/crypto/mac", Some(&req)).await
    }
}
