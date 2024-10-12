use std::{default::Default, sync::Arc};

use actix_web::{
    get, post,
    web::{Data, Json, Path},
    HttpRequest, HttpResponse,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use clap::crate_version;
use cosmian_kmip::kmip::{
    kmip_data_structures::KeyMaterial,
    kmip_objects::Object,
    kmip_operations::{Decrypt, Get},
    kmip_types::{
        CryptographicAlgorithm, CryptographicParameters, HashingAlgorithm, KeyFormatType,
        KeyWrapType, PaddingMethod, UniqueIdentifier,
    },
};
use num_bigint_dig::BigUint;
use serde::{Deserialize, Serialize};
use tracing::{info, log::trace};
use url::Url;

use crate::{kms_bail, kms_error, result::KResult, KMSServer};

#[derive(Serialize, Debug)]
pub enum KeyType {
    #[serde(rename = "RSA")]
    RSA,
}

#[derive(Deserialize, Serialize, Debug)]
pub enum Algorithm {
    /// The doc says the only supported value is 'RSA-OAEP-256'.
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
    /// The example uses this value...
    #[serde(rename = "RS256")]
    Rs256,
}

#[derive(Serialize, Debug)]
pub struct DkePublicKey {
    /// The key type.
    /// The only supported value is 'RSA'.
    #[serde(rename = "kty")]
    key_type: KeyType,

    /// The public key modulus in base 64 format.
    #[serde(rename = "n")]
    modulus: String,

    /// The public key exponent in base 10 numeric format.
    #[serde(rename = "e")]
    exponent: u32,

    /// The supported algorithm that can be used to encrypt the data.
    /// The only supported value is 'RSA-OAEP-256'.
    #[serde(rename = "alg")]
    algorithm: Algorithm,

    /// The key ID.
    /// A URI that identifies the key that is in use for the key name.  The format is {URI}/{KeyName}/{KeyVersion-Guid}
    /// This URI will be called by the client to decrypt the data by appending /decrypt to the end.
    /// Ex. <https://hostname/KeyName/2BE4E378-1317-4D64-AC44-D75f638F7B29>
    #[serde(rename = "kid")]
    key_id: String,
}

#[derive(Serialize, Debug)]
pub struct DkePublicKeyCache {
    /// Gets the expiration.
    /// This member specifies the expiration date and time in format yyyy-MM-ddTHH:mm:ss -
    ///  after which a locally stored public key will expire and require a call to
    ///  the customer key store to obtain a newer version.
    #[serde(rename = "exp")]
    expiration: String,
}

#[derive(Serialize, Debug)]
pub struct KeyData {
    key: DkePublicKey,
    cache: DkePublicKeyCache,
}

#[get("/version")]
pub(crate) async fn version(
    req_http: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    info!("GET /version {}", kms.get_user(&req_http));
    Ok(Json(crate_version!().to_owned()))
}

#[get("/{key_name}")]
pub(crate) async fn get_key(
    req_http: HttpRequest,
    path: Path<String>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    let mut key_name = path.into_inner();
    if key_name.is_empty() {
        "dke_key".clone_into(&mut key_name);
    }
    match _get_key(&key_name, req_http, &kms).await {
        Ok(key_data) => {
            trace!(
                "GET KEY /{} {:?}",
                key_name,
                serde_json::to_string(&key_data)
            );
            HttpResponse::Ok().json(key_data)
        }
        Err(e) => HttpResponse::from_error(e),
    }
}

async fn _get_key(key_tag: &str, req_http: HttpRequest, kms: &Arc<KMSServer>) -> KResult<KeyData> {
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let user = kms.get_user(&req_http);
    let dke_service_url = kms
        .params
        .ms_dke_service_url
        .as_ref()
        .ok_or_else(|| kms_error!("MS DKE: The MS DKE service URL is not configured"))?;
    let mut dke_service_url = Url::parse(dke_service_url)
        .map_err(|_e| kms_error!("MS DKE: Invalid MS DKE Service URL: {}", dke_service_url))?;
    let op = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(
            serde_json::to_string(&vec![key_tag, "_pk"]).map_err(|e| kms_error!(e))?,
        )),
        key_format_type: Some(KeyFormatType::TransparentRSAPublicKey),
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        key_compression_type: None,
        key_wrapping_specification: None,
    };
    let resp = kms.get(op, &user, database_params.as_ref()).await?;
    match resp.object {
        Object::PublicKey { key_block, .. } => match key_block.key_value.key_material {
            KeyMaterial::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            } => {
                let key_id = resp.unique_identifier.as_str().ok_or_else(|| {
                    kms_error!(
                        "MS DKE: The RSA public key does not have a text unique identifier. This \
                         is not supported"
                    )
                })?;
                let mut existing_path = dke_service_url.path().to_owned();
                // remove the trailing / if any
                if existing_path.ends_with('/') {
                    existing_path.pop();
                }
                dke_service_url.set_path(&format!("{existing_path}/{key_tag}/{key_id}"));
                Ok(KeyData {
                    key: DkePublicKey {
                        key_type: KeyType::RSA,
                        modulus: STANDARD.encode(modulus.to_bytes_be()),
                        exponent: big_uint_to_u32(&public_exponent),
                        algorithm: Algorithm::Rs256,
                        key_id: dke_service_url.to_string(),
                    },
                    cache: DkePublicKeyCache {
                        expiration: {
                            // make the key valid for one day
                            let now = Utc::now();
                            let later = now + Duration::days(1);
                            let formatted = later.format("%Y-%m-%dT%H:%M:%S").to_string();
                            formatted
                        },
                    },
                })
            }
            _ => {
                kms_bail!("MS DKE: Invalid Key Material for a transparent RSA public key")
            }
        },
        _ => kms_bail!("MS DKE: Invalid key type {}", resp.object_type),
    }
}

#[derive(Serialize, Debug)]
pub struct DecryptedData {
    /// The base 64 value of the decrypted bytes
    value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    /// The algorithm used to encrypt the data.
    /// Currently only RSA-OAEP-256 (or RS256 ?) is supported
    #[allow(dead_code)]
    pub alg: Algorithm,
    /// The base 64 value of the encrypted bytes
    pub value: String,
}

#[post("/{key_name}/{key_id}/decrypt")]
pub(crate) async fn decrypt(
    req_http: HttpRequest,
    wrap_request: Json<EncryptedData>,
    path: Path<(String, String)>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    let encrypted_data = wrap_request.into_inner();
    info!("Encrypted Data : {encrypted_data:?}",);
    let (key_name, key_id) = path.into_inner();
    // let _key_id = key_id.into_inner();
    trace!("POST /{}/{}/Decrypt {:?}", key_name, key_id, encrypted_data);
    match _decrypt(&key_name, encrypted_data, req_http, &kms).await {
        Ok(decrypted_data) => HttpResponse::Ok().json(decrypted_data),
        Err(e) => HttpResponse::from_error(e),
    }
}

async fn _decrypt(
    key_tag: &str,
    encrypted_data: EncryptedData,
    req_http: HttpRequest,
    kms: &Arc<KMSServer>,
) -> KResult<DecryptedData> {
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let user = kms.get_user(&req_http);
    let decrypt_request = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(
            serde_json::to_string(&vec![key_tag, "_sk"]).map_err(|e| kms_error!(e))?,
        )),
        data: Some(STANDARD.decode(encrypted_data.value.as_bytes())?),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..CryptographicParameters::default()
        }),
        ..Decrypt::default()
    };
    let response = kms
        .decrypt(decrypt_request, &user, database_params.as_ref())
        .await?;
    Ok(DecryptedData {
        value: STANDARD.encode(
            response
                .data
                .ok_or_else(|| kms_error!("The response does not contain the decrypted data"))?,
        ),
    })
}

#[allow(clippy::indexing_slicing)]
fn big_uint_to_u32(bu: &BigUint) -> u32 {
    let bytes = bu.to_bytes_be();
    let len = bytes.len();
    let min = std::cmp::min(4, len);
    let mut padded = [0_u8; 4];
    padded[4 - min..].copy_from_slice(&bytes[len - min..]);
    u32::from_be_bytes(padded)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use chrono::{DateTime, Utc};
    use num_bigint_dig::BigUint;

    use crate::routes::ms_dke::big_uint_to_u32;

    #[test]
    fn test_big_uint() {
        let bu = BigUint::from(12_u8);
        assert_eq!(1, bu.to_bytes_be().len());
        assert_eq!(12, big_uint_to_u32(&bu));

        let bu = BigUint::from(1_u32 << 31);
        assert_eq!(4, bu.to_bytes_be().len());
        assert_eq!(1_u32 << 31, big_uint_to_u32(&bu));

        let bu = BigUint::from(1_u64 << 32);
        assert_eq!(5, bu.to_bytes_be().len());
        assert_eq!(0, big_uint_to_u32(&bu));
    }

    #[test]
    fn test_date_format() {
        let date_time: DateTime<Utc> = "2020-11-21T21:15:55Z".parse().unwrap();
        assert_eq!(
            "2020-11-21T21:15:55",
            date_time.format("%Y-%m-%dT%H:%M:%S").to_string()
        );
    }
}
