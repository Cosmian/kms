use std::sync::Arc;

use actix_web::{
    get, post,
    web::{Data, Json, Path},
    HttpRequest, HttpResponse,
};
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::{result::KResult, KMSServer};

#[derive(Serialize, Debug)]
struct DkePublicKey {
    /// The key type.
    /// The only supported value is 'RSA'.
    #[serde(rename = "kty")]
    key_type: String,

    /// The public key modulus in base 64 format.
    #[serde(rename = "n")]
    modulus: String,

    /// The public key exponent in base 10 numeric format.
    #[serde(rename = "e")]
    exponent: u32,

    /// The supported algorithm that can be used to encrypt the data.
    /// The only supported value is 'RS256'.
    #[serde(rename = "alg")]
    algorithm: String,

    /// The key ID.
    /// A URI that identifies the key that is in use for the key name.  The format is {URI}/{KeyName}/{KeyVersion-Guid}
    /// This URI will be called by the client to decrypt the data by appending /decrypt to the end.
    /// Ex. https://hostname/KeyName/2BE4E378-1317-4D64-AC44-D75f638F7B29
    #[serde(rename = "kid")]
    key_id: String,
}

#[derive(Serialize, Debug)]
struct DkePublicKeyCache {
    /// Gets the expiration.
    /// This member specifies the expiration date and time in format yyyy-MM-ddTHH:mm:ss -
    ///  after which a locally stored public key will expire and require a call to
    ///  the customer key store to obtain a newer version.
    #[serde(rename = "exp")]
    expiration: String,
}

#[derive(Serialize, Debug)]
struct KeyData {
    key: DkePublicKey,
    cache: DkePublicKeyCache,
}

#[get("/{key_name}")]
pub async fn get_key(path: Path<String>) -> HttpResponse {
    let key_name = path.into_inner();
    match _get_key(&key_name).await {
        Ok(key_data) => HttpResponse::Ok().json(key_data),
        Err(e) => e.into(),
    }
}

async fn _get_key(key_name: &str) -> KResult<KeyData> {
    // Implement your key retrieval logic here
    todo!("Key retrieval logic here")
}

#[derive(Serialize, Debug)]
struct DecryptedData {
    /// The base 64 value of the decrypted bytes
    value: String,
}

#[derive(Deserialize, Debug)]
struct EncryptedData {
    /// The algorithm used to encrypt the data.
    /// Currently only RSA-OAEP-256 is supported
    alg: String,
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
    match _decrypt().await {
        Ok(decrypted_data) => HttpResponse::Ok().json(decrypted_data),
        Err(e) => e.into(),
    }
}

async fn _decrypt() -> KResult<DecryptedData> {
    // Implement your decryption logic here
    todo!("Decryption logic here")
}
