use std::convert::TryInto;

use actix_web::web::{Data, Path};
use cosmian_kms::kmip_shared::tfhe::TFHEKeyCreateRequest;
use cosmian_kms_client::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{Create, Decrypt, Encrypt, Get},
    kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType, UniqueIdentifier},
};
use serde::{Deserialize, Serialize};
use torus_fhe::{
    tgsw::T32RGSWSample,
    trlwe::{T32RLWESample, TRLWEKey},
    typenum::{U1023, U512},
};

use crate::{prelude::*, FheKey};

//*** Security Parameter
//
// Vector size
type N = U512;
//*** LUT Parameters
type D = U1023;

#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
// We need this type because TFHEKeyCreateRequest does not impl Apiv2Schema
pub(crate) struct GenKey {
    /// Security Parameter
    vector_size: usize,
    /// Parameter (Mersenne Number >= out bits - 1)
    d: usize,
    /// Sigma value
    noise_deviation: f32,
}

/// POST `/fhe/gen_key`
/// Generate a key, and return a handle to it.
#[api_v2_operation]
pub(crate) async fn gen_key(
    value_conf: Json<GenKey>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<UniqueIdentifier>> {
    mk_key(value_conf.into_inner(), kms_client, None).await
}

pub(crate) async fn mk_key(
    value_conf: GenKey,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
    pregenerated_key: Option<TRLWEKey<N, D>>,
) -> ActixResult<Json<UniqueIdentifier>> {
    let GenKey {
        vector_size,
        d,
        noise_deviation,
    } = value_conf;
    let key_request = &TFHEKeyCreateRequest {
        vector_size,
        d,
        noise_deviation,
        pregenerated_key,
    };
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::TFHE),
        key_format_type: Some(KeyFormatType::TFHE),
        vendor_attributes: Some(vec![
            key_request
                .try_into()
                .map_err(|e| anyhow::anyhow!("{}", e))?,
        ]),
        ..Attributes::new(ObjectType::SymmetricKey)
    };
    let res = kms_client
        .create(&Create {
            object_type: ObjectType::SymmetricKey,
            attributes,
            protection_storage_masks: None,
        })
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(Json(res.unique_identifier))
}

/// GET `/fhe/key/{id}`
/// Download the key.
#[api_v2_operation]
pub(crate) async fn get_key(
    id: Path<UniqueIdentifier>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<FheKey>> {
    Ok(Json(FheKey {
        key: retrieve_key(id.into_inner(), kms_client).await?,
    }))
}

async fn retrieve_key(
    id: UniqueIdentifier,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> CResult<TRLWEKey<U512, U1023>> {
    let res = kms_client
        .get(&Get {
            unique_identifier: Some(id),
            key_format_type: None,
            key_wrap_type: None,
            key_compression_type: None,
            key_wrapping_data: None,
        })
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let key = &res.object;
    let key = key
        .key_block()?
        .to_vec()
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(serde_json::from_slice(&key)?)
}

#[derive(Apiv2Schema, Deserialize)]
#[openapi(empty)]
pub struct CreateArg {
    value_conf: GenKey,
    key: TRLWEKey<N, D>,
}

/// POST `/fhe/key`
/// Create a new key
#[api_v2_operation]
pub(crate) async fn create_key(
    key: Json<CreateArg>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<UniqueIdentifier>> {
    let CreateArg { value_conf, key } = key.into_inner();
    mk_key(value_conf, kms_client, Some(key)).await
}

#[derive(Apiv2Schema, Serialize)]
#[openapi(empty)]
pub struct EncryptionResult {
    ind: Vec<T32RGSWSample<D, N, D, N>>,
    tlut: Vec<T32RLWESample<N, D>>,
}

#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub(crate) struct EncryptArg {
    key_id: UniqueIdentifier,
    data: Vec<u32>,
}

#[derive(Apiv2Schema, Serialize)]
#[openapi(empty)]
pub struct EncryptionRes {
    res: T32RLWESample<N, D>,
}

/// POST `/fhe/encrypt`
/// Encrypt a vector of integers for FHE processing.
#[api_v2_operation]
pub(crate) async fn encrypt(
    value_conf: Json<EncryptArg>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<EncryptionRes>> {
    trace!(?value_conf);
    let EncryptArg { data, key_id } = value_conf.into_inner();
    let res = kms_client
        .encrypt(&Encrypt {
            unique_identifier: Some(key_id),
            cryptographic_parameters: None,
            data: Some(serde_json::to_vec(&data).map_err(CError::from)?),
            iv_counter_nonce: None,
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
            authenticated_encryption_additional_data: None,
        })
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    trace!(?res.data);
    let data = res.data.context("encryption with FHE always yields data")?;
    let res = serde_json::from_slice(&data).map_err(CError::from)?;
    Ok(Json(EncryptionRes { res }))
}

#[derive(Apiv2Schema, Deserialize)]
#[openapi(empty)]
pub struct CmuxScal {
    current_bit: T32RGSWSample<D, N, D, N>,
    a: T32RLWESample<N, D>,
    b: T32RLWESample<N, D>,
}

#[derive(Apiv2Schema, Serialize)]
#[openapi(empty)]
pub struct CmuxResult {
    res: T32RLWESample<N, D>,
}

/// POST `/fhe/cmux_scal`
/// 🌈🦄🌈 cryptography magic
#[api_v2_operation]
pub(crate) async fn cmux_scal(value_conf: Json<CmuxScal>) -> ActixResult<Json<CmuxResult>> {
    let CmuxScal { current_bit, a, b } = value_conf.into_inner();
    let res = current_bit.cmux_scal(&a, &b);
    Ok(Json(CmuxResult { res }))
}

#[derive(Apiv2Schema, Deserialize)]
#[openapi(empty)]
pub struct Add {
    a: T32RLWESample<N, D>,
    b: T32RLWESample<N, D>,
}

#[derive(Apiv2Schema, Serialize)]
#[openapi(empty)]
pub struct AddResult {
    res: T32RLWESample<N, D>,
}

/// POST `/fhe/add`
/// 🌈🦄🌈 cryptography magic vector addition
#[api_v2_operation]
pub(crate) async fn add(value_conf: Json<Add>) -> ActixResult<Json<AddResult>> {
    trace!("fhe add");
    let Add { a, b } = value_conf.into_inner();
    let res = a + b;
    Ok(Json(AddResult { res }))
}

#[derive(Apiv2Schema, Deserialize)]
#[openapi(empty)]
pub struct Rotate {
    v: T32RLWESample<N, D>,
    n: usize,
}

#[derive(Apiv2Schema, Serialize)]
#[openapi(empty)]
pub struct RotateResult {
    res: T32RLWESample<N, D>,
}

/// POST `/fhe/rotate`
/// 🌈🦄🌈 cryptography magic vector rotation
#[api_v2_operation]
pub(crate) async fn rotate(value_conf: Json<Rotate>) -> ActixResult<Json<RotateResult>> {
    trace!("fhe rotate");
    let Rotate { v, n } = value_conf.into_inner();
    let res = v.mul_by_x_to_the_power(n);
    Ok(Json(RotateResult { res }))
}

#[derive(Apiv2Schema, Deserialize)]
#[openapi(empty)]
pub struct DecryptPayload {
    value: T32RLWESample<N, D>,
    key_id: UniqueIdentifier,
}

/// POST `/fhe/decrypt`
/// Decrypt a vector of integers after FHE processing.
#[api_v2_operation]
pub(crate) async fn decrypt(
    value_conf: Json<DecryptPayload>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<Vec<u32>>> {
    let DecryptPayload { value, key_id } = value_conf.into_inner();
    let res = kms_client
        .decrypt(&Decrypt {
            unique_identifier: Some(key_id),
            cryptographic_parameters: None,
            data: Some(serde_json::to_vec(&value).map_err(CError::from)?),
            iv_counter_nonce: None,
            init_indicator: None,
            final_indicator: None,
            authenticated_encryption_additional_data: None,
            authenticated_encryption_tag: None,
        })
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let data = res.data.context("decryption with FHE always yields data")?;
    let res = serde_json::from_slice(&data).map_err(CError::from)?;
    Ok(Json(res))
}
