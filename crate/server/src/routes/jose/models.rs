use serde::{Deserialize, Serialize};

use super::algorithm::{JoseAlgorithm, JoseEncAlgorithm};

// ─── Key management ─────────────────────────────────────────────────────────

/// POST /v1/crypto/keys — request body (generate or import a key).
///
/// - **Generate**: provide `kty` + `alg` (and optionally `crv`/`bits`).
/// - **Import**: additionally provide key material fields (`k` for oct; `d`/`x`/`y` for EC;
///   `d`/`n`/`e`/`p`/`q`/`dp`/`dq`/`qi` for RSA).
#[derive(Debug, Deserialize)]
// Other unknown JWK members are ignored on deserialization.
pub(crate) struct KeyCreateRequest {
    /// JWK key type: `"oct"`, `"EC"`, `"RSA"`, `"OKP"`
    pub(crate) kty: String,
    /// JOSE algorithm this key is intended for (e.g. `"HS256"`, `"ES256"`, `"RS256"`)
    pub(crate) alg: Option<String>,
    /// EC/OKP curve: `"P-256"`, `"P-384"`, `"P-521"`, `"Ed25519"`
    pub(crate) crv: Option<String>,
    /// RSA key size in bits (default: 2048)
    pub(crate) bits: Option<usize>,
    // ── Import-only fields (presence triggers import mode) ──
    /// Symmetric key value (base64url, for `kty=oct`)
    pub(crate) k: Option<String>,
    /// EC/RSA/OKP private key (base64url)
    pub(crate) d: Option<String>,
    /// EC/OKP x-coordinate (base64url)
    pub(crate) x: Option<String>,
    /// EC y-coordinate (base64url)
    pub(crate) y: Option<String>,
    /// RSA modulus (base64url)
    pub(crate) n: Option<String>,
    /// RSA public exponent (base64url)
    pub(crate) e: Option<String>,
    /// RSA prime p (base64url)
    pub(crate) p: Option<String>,
    /// RSA prime q (base64url)
    pub(crate) q: Option<String>,
    /// RSA d mod (p-1) (base64url)
    pub(crate) dp: Option<String>,
    /// RSA d mod (q-1) (base64url)
    pub(crate) dq: Option<String>,
    /// RSA CRT coefficient (base64url)
    pub(crate) qi: Option<String>,
    /// Caller-chosen KMS unique identifier (import only)
    pub(crate) kid: Option<String>,
    /// Permitted operations for a public-only RSA import: `encrypt`, `wrapKey`, `verify`
    pub(crate) key_ops: Option<Vec<String>>,
}

impl KeyCreateRequest {
    /// Returns `true` when the request carries key material (import mode): a symmetric
    /// value `k`, a private exponent `d`, or a full RSA public key (`n` and `e`).
    pub(crate) const fn is_import(&self) -> bool {
        self.k.is_some() || self.d.is_some() || (self.n.is_some() && self.e.is_some())
    }
}

/// POST /v1/crypto/keys — response (public JWK + KMS identifiers).
#[derive(Debug, Serialize)]
pub(crate) struct KeyCreateResponse {
    /// KMS unique identifier of the (private/symmetric) key
    pub(crate) kid: String,
    /// KMS unique identifier of the public key (asymmetric only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kid_public: Option<String>,
    /// JWK key type
    pub(crate) kty: String,
    /// Algorithm this key is bound to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) alg: Option<String>,
    /// EC/OKP curve
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) crv: Option<String>,
    /// Permitted key operations
    pub(crate) key_ops: Vec<String>,
    // ── Public coordinates (never private) ──
    /// EC/OKP x-coordinate (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) x: Option<String>,
    /// EC y-coordinate (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) y: Option<String>,
    /// RSA modulus (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) n: Option<String>,
    /// RSA public exponent (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) e: Option<String>,
}

/// POST /v1/crypto/encrypt — request
#[derive(Debug, Deserialize)]
pub(crate) struct EncryptRequest {
    /// KMS object UID of the key (symmetric for `dir`; RSA private or public key for `RSA-OAEP` / `RSA-OAEP-256`)
    pub(crate) kid: String,
    /// JOSE `alg` key-management identifier.
    ///
    /// Supported values:
    /// - `"dir"` — direct AES-GCM encryption with the symmetric key referenced by `kid`
    /// - `"RSA-OAEP"` — RSA-OAEP key wrapping (SHA-1 / MGF1-SHA-1) + AES-GCM content encryption
    /// - `"RSA-OAEP-256"` — RSA-OAEP-256 key wrapping (SHA-256 / MGF1-SHA-256) + AES-GCM content encryption
    pub(crate) alg: JoseAlgorithm,
    /// JOSE `enc` content-encryption algorithm identifier (e.g. `"A256GCM"`)
    pub(crate) enc: JoseEncAlgorithm,
    /// Plaintext as base64url (no padding)
    pub(crate) data: String,
    /// Additional Authenticated Data as base64url (no padding), optional
    pub(crate) aad: Option<String>,
    /// KMS UID of an AES key used as the CEK instead of a random one; RSA-OAEP / RSA-OAEP-256
    /// only. The key leaves the KMS wrapped under `kid`.
    pub(crate) cek_kid: Option<String>,
}

/// POST /v1/crypto/encrypt — flattened JWE JSON response
#[derive(Debug, Serialize)]
pub(crate) struct EncryptResponse {
    /// BASE64URL(UTF8(JWE Protected Header))
    pub(crate) protected: String,
    /// RSA-OAEP wrapped CEK as base64url; empty string for `dir` (no key wrapping)
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
    /// RSA-OAEP wrapped CEK as base64url (required and non-empty for `RSA-OAEP` / `RSA-OAEP-256`); absent or empty for `dir`
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
    pub(crate) alg: JoseAlgorithm,
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
    pub(crate) alg: JoseAlgorithm,
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

// ─── Tag management ────────────────────────────────────────────────────────

/// Request body for `POST /v1/crypto/keys/{kid}/tags` and
/// `DELETE /v1/crypto/keys/{kid}/tags`.
#[derive(Debug, Deserialize)]
pub(crate) struct TagsRequest {
    /// Tags to add or remove. Must be non-empty strings that do not start with
    /// `_` (system-tag prefix).
    pub(crate) tags: Vec<String>,
}

/// Response body for all three tag endpoints.
#[derive(Debug, Serialize)]
pub(crate) struct TagsResponse {
    /// KMS unique identifier of the key.
    pub(crate) kid: String,
    /// Current user-visible tags on the key after the operation (sorted,
    /// system tags — those starting with `_` — are never included).
    pub(crate) tags: Vec<String>,
}

// ─── Key unwrap (import wrapped CEK) ────────────────────────────────────────

/// POST /v1/crypto/keys/unwrap — request body.
///
/// Accepts a subset of a JWE Flattened JSON (`protected` + `encrypted_key`)
/// and imports the unwrapped symmetric key into the KMS without exposing it to
/// the caller.
#[derive(Debug, Deserialize)]
pub(crate) struct KeyUnwrapRequest {
    /// BASE64URL(UTF8(JWE Protected Header)) — must contain `alg`, `enc`, `kid`
    pub(crate) protected: String,
    /// The RSA-OAEP wrapped CEK as base64url
    pub(crate) encrypted_key: String,
}

/// POST /v1/crypto/keys/unwrap — response body.
#[derive(Debug, Serialize)]
pub(crate) struct KeyUnwrapResponse {
    /// KMS unique identifier of the imported symmetric key
    pub(crate) kid: String,
    /// JWK key type (always `"oct"` for symmetric keys)
    pub(crate) kty: String,
    /// JOSE content-encryption algorithm this key is bound to
    pub(crate) alg: String,
    /// Permitted key operations
    pub(crate) key_ops: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::KeyCreateRequest;

    type Summary = (String, Option<String>, Option<usize>, bool);

    fn summary(json: &str) -> Option<Summary> {
        serde_json::from_str::<KeyCreateRequest>(json)
            .ok()
            .map(|r| (r.kty.clone(), r.alg.clone(), r.bits, r.is_import()))
    }

    /// `key_ops` is a standard JWK member that clients may send; it is not consumed
    /// (the permitted operations are always inferred from `alg`), but it must not make
    /// the request fail and must not change how the other members are parsed.
    #[test]
    fn key_create_request_tolerates_key_ops_member() {
        let expected = Some((
            "oct".to_owned(),
            Some("A256GCM".to_owned()),
            Some(256),
            false,
        ));
        assert_eq!(
            summary(r#"{"kty":"oct","alg":"A256GCM","bits":256,"key_ops":["encrypt","decrypt"]}"#),
            expected
        );
        assert_eq!(
            summary(r#"{"kty":"oct","alg":"A256GCM","bits":256}"#),
            expected
        );
    }

    #[test]
    fn key_create_request_with_key_ops_still_detects_import_mode() {
        assert_eq!(
            summary(r#"{"kty":"oct","alg":"HS256","k":"AAAA","key_ops":["sign","verify"]}"#),
            Some(("oct".to_owned(), Some("HS256".to_owned()), None, true))
        );
    }
}
