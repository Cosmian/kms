use std::sync::Arc;

use actix_web::{
    get, post,
    web::{Data, Json, Path},
    HttpRequest, HttpResponse,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Local};
use cosmian_kmip::kmip::{
    kmip_data_structures::KeyMaterial,
    kmip_objects::Object,
    kmip_operations::{Get,Decrypt},
    kmip_types::{KeyFormatType, KeyWrapType, UniqueIdentifier},
};
use num_bigint_dig::BigUint;
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::{kms_bail, kms_error, result::KResult, KMSServer};

#[derive(Serialize, Debug)]
enum KeyType {
    #[serde(rename = "RSA")]
    RSA,
}

#[derive(Deserialize, Serialize, Debug)]
enum Algorithm {
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
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
    /// Ex. https://hostname/KeyName/2BE4E378-1317-4D64-AC44-D75f638F7B29
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

#[get("/{key_name}")]
pub async fn get_key(
    req_http: HttpRequest,
    path: Path<String>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    let key_name = path.into_inner();
    match _get_key(&key_name, req_http, &kms).await {
        Ok(key_data) => HttpResponse::Ok().json(key_data),
        Err(e) => HttpResponse::from_error(e),
    }
}

async fn _get_key(key_name: &str, req_http: HttpRequest, kms: &Arc<KMSServer>) -> KResult<KeyData> {
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let user = kms.get_user(req_http)?;
    let op = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(
            "[".to_string() + key_name + "]",
        )),
        key_format_type: Some(KeyFormatType::TransparentRSAPublicKey),
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        key_compression_type: None,
        key_wrapping_specification: None,
    };
    let resp = kms.get(op, &user, database_params.as_ref()).await?;
    match resp.object {
        Object::PrivateKey { key_block, .. } => match key_block.key_value.key_material {
            KeyMaterial::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            } => Ok(KeyData {
                key: DkePublicKey {
                    key_type: KeyType::RSA,
                    modulus: STANDARD.encode(modulus.to_bytes_be()),
                    exponent: big_uint_to_u32(&public_exponent),
                    algorithm: Algorithm::RsaOaep256,
                    key_id: resp.unique_identifier.to_string().ok_or_else(|| {
                        kms_error!(
                            "The RSA public key does nopt have a text unique identifier. This is \
                             not supported"
                        )
                    })?,
                },
                cache: DkePublicKeyCache {
                    expiration: {
                        // make the key valid for one day
                        let now = Local::now();
                        let in_one_day = now + Duration::days(1);
                        let formatted = in_one_day.format("%Y-%m-%dT%H:%M:%S").to_string();
                        formatted
                    },
                },
            }),
            _ => {
                kms_bail!("Invalid Key Material for a transparent RSA private key")
            }
        },
        _ => kms_bail!("Invalid key type {}", resp.object_type),
    }
}

#[derive(Serialize, Debug)]
pub struct DecryptedData {
    /// The base 64 value of the decrypted bytes
    value: String,
}

#[derive(Deserialize, Debug)]
pub struct EncryptedData {
    /// The algorithm used to encrypt the data.
    /// Currently only RSA-OAEP-256 is supported
    alg: Algorithm,
    /// The base 64 value of the encrypted bytes
    value: String,
}

#[post("/{key_name}/{key_id}/Decrypt")]
pub async fn decrypt(
    req_http: HttpRequest,
    wrap_request: Json<EncryptedData>,
    path: Path<(String, String)>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    let encrypted_data = wrap_request.into_inner();
    let (key_name, key_id) = path.into_inner();
    trace!("POST /{}/{}/Decrypt {:?}", key_name, key_id, encrypted_data);
    match _decrypt(&key_name,&key_id, encrypted_data, req_http, &kms).await {
        Ok(decrypted_data) => HttpResponse::Ok().json(decrypted_data),
        Err(e) => HttpResponse::from_error(e),
    }
}

async fn _decrypt(_key_name: &str, key_id: &str, encrypted_data: EncryptedData, req_http: HttpRequest, kms: &Arc<KMSServer>) -> KResult<DecryptedData> {
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let user = kms.get_user(req_http)?;
    let decrypt_request = Decrypt {
        
        unique_identifier: Some(UniqueIdentifier::TextString(
             key_id.to_string() 
        ),
        data: Some(STANDARD.decode(encrypted_data.value.as_bytes())?),
        iv_counter_nonce: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
        cryptographic_parameters: None,
        authenticated_encryption_tag: None,
    };
}

fn big_uint_to_u32(bu: &BigUint) -> u32 {
    let bytes = bu.to_bytes_be();
    let len = bytes.len();
    let min = std::cmp::min(4, len);
    let mut padded = [0u8; 4];
    padded[4 - min..].copy_from_slice(&bytes[len - min..]);
    u32::from_be_bytes(padded)
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use num_bigint_dig::BigUint;

    use crate::routes::ms_dke::big_uint_to_u32;

    #[test]
    fn test() {
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
    fn test_decrypt_sample() {
        let b64_string = "wP4ir0aynve6Cpv3ZcBo5+HDue7OA6ogQetNkql1ptfKXilQ2N6x+wDTszcrJlb672l+ckUV5Gjn+ohhFUh0hx6B3rTNKVyxJiGq8S+MRXrTl0UGjWjFED7fYZ2nYZPigu1VHdm3HgBVZdeR8TMr1uIjDHxhWgen2utnTvacn5r8X079ImwpbhilrYBUvt9q42r/CxRp+axsMY3ozkGYsSZ/vXsgjSN0Nbn+9cwHi+XeE2PcjAOnaxUTKVcxjcZvRE+y2FcwgT+nVfJub4ZvRjz9lAbhdDNUS2ZrisAtHVRWJx1ArAMHH7OYg41LoA9+wmBoB04cEzi3JkJkqNCwtw==";
        let bytes = STANDARD.decode(b64_string.as_bytes()).unwrap();
        let bu = BigUint::from_bytes_be(&bytes);
        // println!("bu: {:?}", bu.to_str_radix(10_u32));
    }
}
