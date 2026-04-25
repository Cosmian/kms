use serde::{Deserialize, Serialize};

/// POST /v1/crypto/encrypt — request
#[derive(Debug, Deserialize)]
pub(crate) struct EncryptRequest {
    /// KMS object UID of the symmetric key
    pub(crate) kid: String,
    /// JOSE `alg` identifier — Phase 1: only `"dir"` supported
    pub(crate) alg: String,
    /// JOSE `enc` content-encryption algorithm identifier (e.g. `"A256GCM"`)
    pub(crate) enc: String,
    /// Plaintext as base64url (no padding)
    pub(crate) data: String,
    /// Additional Authenticated Data as base64url (no padding), optional
    pub(crate) aad: Option<String>,
}

/// POST /v1/crypto/encrypt — flattened JWE JSON response
#[derive(Debug, Serialize)]
pub(crate) struct EncryptResponse {
    /// BASE64URL(UTF8(JWE Protected Header))
    pub(crate) protected: String,
    /// Empty string for `dir` key management (no key wrapping)
    pub(crate) encrypted_key: String,
    /// Initialization vector as base64url
    pub(crate) iv: String,
    /// Ciphertext as base64url
    pub(crate) ciphertext: String,
    /// Authentication tag as base64url
    pub(crate) tag: String,
    /// AAD echo — present only when the request included `aad`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) aad: Option<String>,
}

/// POST /v1/crypto/decrypt — flattened JWE JSON request
#[derive(Debug, Deserialize)]
pub(crate) struct DecryptRequest {
    /// BASE64URL(UTF8(JWE Protected Header))
    pub(crate) protected: String,
    /// Ignored for `dir` — must be empty string or absent
    pub(crate) encrypted_key: Option<String>,
    /// Initialization vector as base64url
    pub(crate) iv: String,
    /// Ciphertext as base64url
    pub(crate) ciphertext: String,
    /// Authentication tag as base64url
    pub(crate) tag: String,
    /// Additional Authenticated Data as base64url (same as provided to encrypt), optional
    pub(crate) aad: Option<String>,
}

/// POST /v1/crypto/decrypt — response
#[derive(Debug, Serialize)]
pub(crate) struct DecryptResponse {
    /// KMS object UID of the key used
    pub(crate) kid: String,
    /// Recovered plaintext as base64url
    pub(crate) data: String,
}

/// POST /v1/crypto/sign — request
#[derive(Debug, Deserialize)]
pub(crate) struct SignRequest {
    /// KMS object UID of the private key
    pub(crate) kid: String,
    /// JOSE `alg` identifier (e.g. `"RS256"`, `"ES256"`, `"EdDSA"`)
    pub(crate) alg: String,
    /// Payload bytes as base64url — this becomes the detached JWS payload
    pub(crate) data: String,
}

/// POST /v1/crypto/sign — detached JWS response
#[derive(Debug, Serialize)]
pub(crate) struct SignResponse {
    /// BASE64URL(UTF8(JWS Protected Header))
    pub(crate) protected: String,
    /// Signature over the JWS Signing Input (`ASCII(protected_b64 + "." + payload_b64)`)
    pub(crate) signature: String,
}

/// POST /v1/crypto/verify — request
#[derive(Debug, Deserialize)]
pub(crate) struct VerifyRequest {
    /// BASE64URL(UTF8(JWS Protected Header)) — must contain `alg` and `kid`
    pub(crate) protected: String,
    /// Original payload bytes as base64url
    pub(crate) data: String,
    /// Signature as base64url
    pub(crate) signature: String,
}

/// POST /v1/crypto/verify — response
#[derive(Debug, Serialize)]
pub(crate) struct VerifyResponse {
    /// KMS object UID of the key used for verification
    pub(crate) kid: String,
    /// `true` if signature is valid
    pub(crate) valid: bool,
}

/// POST /v1/crypto/mac — request (compute and verify share this struct)
#[derive(Debug, Deserialize)]
pub(crate) struct MacRequest {
    /// KMS object UID of the HMAC key
    pub(crate) kid: String,
    /// JOSE `alg` identifier (e.g. `"HS256"`, `"HS384"`, `"HS512"`)
    pub(crate) alg: String,
    /// Message bytes as base64url
    pub(crate) data: String,
    /// Expected MAC as base64url — when present, perform verify; when absent, compute
    pub(crate) mac: Option<String>,
}

/// POST /v1/crypto/mac — compute response
#[derive(Debug, Serialize)]
pub(crate) struct MacComputeResponse {
    /// KMS object UID of the key used
    pub(crate) kid: String,
    /// Computed MAC as base64url
    pub(crate) mac: String,
}

/// POST /v1/crypto/mac — verify response
#[derive(Debug, Serialize)]
pub(crate) struct MacVerifyResponse {
    /// KMS object UID of the key used
    pub(crate) kid: String,
    /// `true` if MAC is valid
    pub(crate) valid: bool,
}
