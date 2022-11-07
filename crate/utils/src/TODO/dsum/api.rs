use actix_web::web::{Data, Path};
use common::prelude::CError;
use cosmian_dsum::{recombine, DSum};
use cosmian_kms::kmip_shared::curve_25519;
use cosmian_kms_client::kmip::{
    kmip_data_structures::{KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_operations::{self, ImportResponse},
    kmip_types::Attributes,
};
use num_traits::Num;
use serde::{Deserialize, Serialize};

use crate::prelude::*;

#[allow(non_snake_case)]
fn get_private_key_bytes(
    kms_client: &dyn cosmian_kms_client::Client,
    uid: &str,
) -> Result<Vec<u8>, CError> {
    let response = kms_client.get(&curve_25519::get_private_key_request(uid))?;
    let key_block = match &response.object {
        Object::PrivateKey { key_block } => key_block,
        _ => anyhow::bail!("Expected a KMIP Private Key"),
    };
    let key_material = match &key_block.key_value {
        KeyValue::PlainText { key_material, .. } => key_material,
        _ => {
            return Err(anyhow::anyhow!(
                "The private key should be a plain text key value"
            ))
        }
    };
    //TODO this returns the bytes as provided by Sodium which are the big endian
    // rep. of a big number TODO but this should be checked and precised
    Ok(match &key_material {
        KeyMaterial::TransparentECPrivateKey {
            recommended_curve: _,
            d: D,
        } => D.to_bytes_be(),
        _ => return Err(anyhow::anyhow!("The private key has invalid key material")),
    })
}

#[allow(non_snake_case)]
fn get_public_key_bytes(
    kms_client: &dyn cosmian_kms_client::Client,
    uid: &str,
) -> Result<Vec<u8>, CError> {
    let response = kms_client.get(&curve_25519::get_public_key_request(uid))?;
    let key_block = match &response.object {
        Object::PublicKey { key_block } => key_block,
        _ => anyhow::bail!("Expected a KMIP Public Key"),
    };
    let key_material = match &key_block.key_value {
        KeyValue::PlainText { key_material, .. } => key_material,
        _ => {
            return Err(anyhow::anyhow!(
                "The public key should be a plain text key value"
            ))
        }
    };
    //TODO this returns the bytes as provided by Sodium which are the big endian
    // rep. of a big number
    Ok(match &key_material {
        KeyMaterial::TransparentECPublicKey {
            recommended_curve: _,
            q_string: QString,
        } => QString.clone(),
        _ => return Err(anyhow::anyhow!("The public key has invalid key material")),
    })
}

/// A Key Pair identifiers
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct KeyPairIdentifiers {
    /// The secret key identifier
    pub private_key_id: String,
    /// The public key identifier
    pub public_key_id: String,
}

/// `POST /dsum/create_key_pair`
/// Create a Curve 25519 key pair (256 bits) in the internal KMS
/// Returns the secret key and public key identifiers
#[api_v2_operation]
pub async fn create_key_pair(
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyPairIdentifiers>> {
    let response = kms_client.create_key_pair(&curve_25519::create_key_pair_request())?;
    Ok(Json(KeyPairIdentifiers {
        private_key_id: response.private_key_unique_identifier,
        public_key_id: response.public_key_unique_identifier,
    }))
}

/// A Public or Secret Key represented as a json hex string
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct Key {
    pub key: String,
}

/// `GET /dsum/public_key/{uid}`
/// Get a Curve 25519 public key
/// Returns the public key bytes as an hex string
#[api_v2_operation]
pub async fn get_public_key(
    uid: Path<String>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<Key>> {
    let bytes = get_public_key_bytes(&***kms_client, &uid)?;
    Ok(Json(Key {
        key: hex::encode(bytes),
    }))
}

/// `GET /dsum/private_key/{uid}`
/// Get a Curve 25519 private key
/// Returns the secret key bytes as an hex string
#[api_v2_operation]
pub async fn get_private_key(
    uid: Path<String>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<Key>> {
    let bytes = get_private_key_bytes(&***kms_client, &uid)?;
    Ok(Json(Key {
        key: hex::encode(bytes),
    }))
}

/// `POST /dsum/public_key`
/// Import a Curve 25519 public key with bytes represented as an hex string
/// Returns the uid of the imported key
#[api_v2_operation]
pub async fn import_public_key(
    key: Json<Key>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<ImportResponse>> {
    let bytes = hex::decode(&key.key).context("Failed decoding the public key bytes")?;
    let pk = curve_25519::parse_public_key(&bytes)?;
    let request = kmip_operations::Import {
        unique_identifier: "".to_string(),
        object_type: ObjectType::PublicKey,
        replace_existing: None,
        key_wrap_type: None,
        attributes: Attributes::new(ObjectType::PublicKey),
        object: pk,
    };
    let ir = kms_client.import(request)?;
    Ok(Json(ir))
}

/// Secret Key Update parameters
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct PublicKeyUpdate {
    pub(crate) uid: String,
    pub(crate) key: String,
}

/// `PUT /dsum/public_key`
/// Update a Curve 25519 public key
/// Returns the uid of the updated key
#[api_v2_operation]
pub async fn update_public_key(
    key: Json<PublicKeyUpdate>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<ImportResponse>> {
    let bytes = hex::decode(&key.key).context("Failed decoding the public key bytes")?;
    let pk = curve_25519::parse_public_key(&bytes)?;
    let request = kmip_operations::Import {
        unique_identifier: key.uid.clone(),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: Attributes::new(ObjectType::PublicKey),
        object: pk,
    };
    let ir = kms_client.import(request)?;
    Ok(Json(ir))
}

/// A request to create a secret share of a (distributed) sum
/// All clients participating to the sum must use the same 'label'
/// The public and private keys must be generated using the provided facilities
/// in the `DSum` API. These keys are Curve 25519 256 bit keys. They must all be
/// available in the KMS. The uid in the `pubic_keys` array at index
/// `client_number` must be the public key uid of this client.
/// The value to share must be passed as a radix 10 number in a string. The
/// value and the sum is in Zₚ where p is the modulus of the 25519 curve.
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct SecretShareRequest {
    pub client_number: usize,
    pub private_key_uid: String,
    pub public_keys_uid_s: Vec<String>,
    pub label: String,
    pub value_to_share: String,
}

/// The hex encoded value of a secret share in a `DSum`
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct SecretShareResponse {
    pub share: String,
}

/// `POST /dsum/secret_share`
/// Create a Secret share of a (distributed) sum
/// All clients participating to the sum must use the same 'label'
#[api_v2_operation]
pub async fn secret_share(
    request: Json<SecretShareRequest>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<SecretShareResponse>> {
    // pull private key bytes
    let private_key_bytes = get_private_key_bytes(&***kms_client, &request.private_key_uid)?;
    // pull all public key bytes
    let mut public_keys_bytes: Vec<Vec<u8>> = Vec::with_capacity(request.public_keys_uid_s.len());
    for pk_i in &request.public_keys_uid_s {
        public_keys_bytes.push(get_public_key_bytes(&***kms_client, pk_i)?);
    }
    let dsum = DSum::new(
        request.client_number,
        &private_key_bytes,
        &public_keys_bytes,
    );
    let bi = num_bigint::BigUint::from_str_radix(&request.value_to_share, 10)
        .context("Failed parsing the radix 10 big number")?; //TODO:: StatusCode::BAD_REQUEST,
    Ok(Json(SecretShareResponse {
        share: hex::encode(
            dsum.secret_share(&bi, &request.label)
                .context("Failed secret sharing the value")?,
        ), //TODO: StatusCode::BAD_REQUEST
    }))
}

/// Request to recombine secret shares provided by the different clients.
/// The shares are byte arrays encoded as hex strings
/// This operation simply decode the bytes as Big Integer assuming they are big
/// endian then add them all together modulo the order of the Curve 25519
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct RecombineRequest {
    pub secret_shares: Vec<String>,
}

/// The result of recombining the secret shares provided by the clients
/// expressed as s radix 10 big integer in a string
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct RecombineResponse {
    pub sum: String,
}

/// `PUT /dsum/recombine`
/// Recombine secret shares provided by the different clients.
/// The shares are byte arrays encoded as hex strings
/// This operation simply decode the bytes as Big Integer assuming they are big
/// endian then add them all together modulo the order of the Curve 25519
#[api_v2_operation]
pub async fn recombine_shares(
    request: Json<RecombineRequest>,
) -> ActixResult<Json<RecombineResponse>> {
    // decode shares
    let mut shares: Vec<Vec<u8>> = Vec::with_capacity(request.secret_shares.len());
    for ss in &request.secret_shares {
        shares.push(hex::decode(ss).context(format!("Failed decoding the secret share: {}", ss))?);
        //TODO: BAD_REQUEST
    }
    let sum = recombine(&shares);
    Ok(Json(RecombineResponse {
        sum: sum.to_str_radix(10),
    }))
}
