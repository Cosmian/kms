use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use openssl::x509::X509;
use reqwest::{ClientBuilder, Url};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::error::SgxError;

#[derive(Deserialize)]
enum KeyType {
    #[serde(alias = "RSA")]
    Rsa,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct MicrosoftJwk {
    kid: String,
    kty: KeyType,
    x5c: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct MicrosoftAttestationCollateral {
    qeidcertshash: String,
    qeidcrlhash: String,
    qeidhash: String,
    pub quotehash: String,
    tcbinfocertshash: String,
    tcbinfocrlhash: String,
    tcbinfohash: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct MicrosoftPolicy {
    #[serde(alias = "is-debuggable")]
    is_debuggable: bool,
    #[serde(alias = "product-id")]
    product_id: u32,
    #[serde(alias = "sgx-mrenclave")]
    pub sgx_mrenclave: String,
    #[serde(alias = "sgx-mrsigner")]
    pub sgx_mrsigner: String,
    svn: u32,
    tee: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct MicrosoftAttestation {
    #[serde(alias = "aas-ehd")]
    pub aas_ehd: String,
    pub exp: u64,
    pub iat: u64,
    #[serde(alias = "is-debuggable")]
    is_debuggable: bool,
    iss: String,
    jti: String,
    #[serde(alias = "maa-attestationcollateral")]
    pub maa_attestationcollateral: MicrosoftAttestationCollateral,
    #[serde(alias = "maa-ehd")]
    pub maa_ehd: String,
    nbf: u32,
    #[serde(alias = "product-id")]
    product_id: u32,
    #[serde(alias = "sgx-mrenclave")]
    pub sgx_mrenclave: String,
    #[serde(alias = "sgx-mrsigner")]
    pub sgx_mrsigner: String,
    svn: u32,
    tee: String,
    #[serde(alias = "x-ms-attestation-type")]
    x_ms_attestation_type: String,
    #[serde(alias = "x-ms-policy")]
    x_ms_policy: MicrosoftPolicy,
    #[serde(alias = "x-ms-policy-hash")]
    x_ms_policy_hash: String,
    #[serde(alias = "x-ms-sgx-collateral")]
    pub x_ms_sgx_collateral: MicrosoftAttestationCollateral,
    #[serde(alias = "x-ms-sgx-ehd")]
    pub x_ms_sgx_ehd: String,
    #[serde(alias = "x-ms-sgx-is-debuggable")]
    x_ms_sgx_is_debuggable: bool,
    #[serde(alias = "x-ms-sgx-mrenclave")]
    pub x_ms_sgx_mrenclave: String,
    #[serde(alias = "x-ms-sgx-mrsigner")]
    pub x_ms_sgx_mrsigner: String,
    #[serde(alias = "x-ms-sgx-product-id")]
    x_ms_sgx_product_id: u32,
    #[serde(alias = "x-ms-sgx-report-data")]
    x_ms_sgx_report_data: String,
    #[serde(alias = "x-ms-sgx-svn")]
    x_ms_sgx_svn: u32,
    #[serde(alias = "x-ms-ver")]
    x_ms_ver: String,
}

/// Get the token from microsoft to verify the quote
async fn microsoft_azure_attestation(
    b64quote: &str,
    user_report_data: Option<&[u8]>,
) -> Result<String, SgxError> {
    // Change base64 encoding
    let raw_quote = b64.decode(b64quote)?;
    let b64url_quote = base64_url::encode(&raw_quote);

    // Build the query to Azure RA API.
    let mut payload = Map::new();
    payload.insert("quote".to_string(), Value::String(b64url_quote));

    if let Some(held_data) = user_report_data {
        let mut inner_map = Map::new();
        inner_map.insert(
            "data".to_string(),
            Value::String(base64_url::encode(held_data)),
        );
        inner_map.insert("dataType".to_string(), Value::String("Binary".to_string()));

        payload.insert("runtimeData".to_string(), Value::Object(inner_map));
    }

    let url = Url::parse_with_params(
        "https://sharedneu.neu.attest.azure.net/attest/SgxEnclave",
        HashMap::from([("api-version", "2020-10-01")]),
    )?;

    let response = ClientBuilder::new()
        .build()?
        .post(url)
        .json(&payload)
        .send()
        .await?;

    let status_code = response.status();
    if status_code.is_success() {
        let data = response.json::<Value>().await?;
        return Ok(String::from(data["token"].as_str().ok_or_else(|| {
            SgxError::RemoteAttesterRequestFailed("No token in response".to_string())
        })?))
    }

    Err(SgxError::RemoteAttesterRequestFailed(
        response.text().await?,
    ))
}

/// Get the certificate chains from Microsoft
async fn microsoft_signing_certs() -> Result<Value, SgxError> {
    let response = ClientBuilder::new()
        .build()?
        .get("https://sharedneu.neu.attest.azure.net/certs")
        .send()
        .await?;

    let status_code = response.status();
    if status_code.is_success() {
        return Ok(response.json::<Value>().await?)
    }

    Err(SgxError::RemoteAttesterRequestFailed(
        response.text().await?,
    ))
}

/// Extract the Microsoft attestation from the token using the suitable certificate
async fn verify_jws(token: &str, jwks: Value) -> Result<MicrosoftAttestation, SgxError> {
    // Check the header only because we don't have verify the signature yet
    let header = decode_header(token)?;
    let kid = header.kid.ok_or_else(|| {
        SgxError::RemoteAttesterTokenMalformed("no kid in the jws token".to_string())
    })?;

    let jwks: Vec<MicrosoftJwk> = serde_json::from_value(jwks["keys"].clone())?;

    // Find the certificate to decode the token
    for jwk in jwks.iter() {
        if jwk.kid == kid {
            let x5c = &jwk.x5c[0];
            let raw_cert = b64.decode(x5c)?;
            let x509 = X509::from_der(&raw_cert)?;

            let token_data = decode::<Value>(
                token,
                &DecodingKey::from_rsa_pem(&x509.public_key()?.public_key_to_pem()?)?,
                &Validation::new(Algorithm::RS256),
            )?;

            return Ok(serde_json::from_value::<MicrosoftAttestation>(
                token_data.claims,
            )?)
        }
    }

    Err(SgxError::RemoteAttesterTokenMalformed(
        "can't verify MAA signature".to_string(),
    ))
}

/// Proceed the remote attestion on Microsoft Azure
pub async fn remote_attestation(
    quote: &str,
    user_report_data: Option<&[u8]>,
) -> Result<MicrosoftAttestation, SgxError> {
    let token = microsoft_azure_attestation(quote, user_report_data).await?;
    let certs = microsoft_signing_certs().await?;
    verify_jws(&token, certs).await
}
