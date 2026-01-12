//! this module contains the request and response struct formats for the Azure EKM routes
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RequestContext {
    #[serde(default)]
    pub(crate) request_id: Option<String>, // optional per spec
    pub(crate) correlation_id: String,
    pub(crate) pool_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ProxyInfoRequest {
    request_context: RequestContext,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ProxyInfoResponse {
    pub api_version: String,
    pub proxy_vendor: String,
    pub proxy_name: String,
    pub ekm_vendor: String,
    pub ekm_product: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct KeyMetadataRequest {
    request_context: RequestContext,
}

#[derive(Debug, Serialize)]
pub(crate) struct KeyMetadataResponse {
    key_type: String,
    key_size: i32,
    key_ops: [&'static str; 2],
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<String>, // base64url encoded RSA modulus (only for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<String>, // base64url encoded RSA public exponent (only for RSA keys)
}

impl KeyMetadataResponse {
    pub(crate) fn aes() -> Self {
        Self {
            key_type: "oct".to_owned(),
            key_size: 256,
            key_ops: ["wrapKey", "unwrapKey"],
            n: None,
            e: None,
        }
    }

    pub(crate) fn rsa(
        key_size: i32,
        modulus_base64url: String,
        exponent_base64url: String,
    ) -> Self {
        Self {
            key_type: "RSA".to_owned(),
            key_size,
            key_ops: ["wrapKey", "unwrapKey"],
            n: Some(modulus_base64url),
            e: Some(exponent_base64url),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) enum WrapAlgorithm {
    A256KW,
    A256KWP,
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WrapKeyRequest {
    pub(crate) request_context: RequestContext,
    pub(crate) alg: WrapAlgorithm,
    pub(crate) value: String, // base64url encoded key to wrap
}

#[derive(Debug, Serialize)]
pub(crate) struct WrapKeyResponse {
    pub(crate) value: String, // base64url encoded wrapped key
}

#[derive(Debug, Deserialize)]
pub(crate) struct UnwrapKeyRequest {
    pub(crate) request_context: RequestContext,
    pub(crate) alg: WrapAlgorithm,
    pub(crate) value: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct UnwrapKeyResponse {
    pub(crate) value: String, // base64url encoded unwrapped DEK
}
