use std::{collections::HashMap, convert::TryFrom};

use actions::LweSecretKeyType;
use actix_http::http::StatusCode;
use actix_web::web::{Data, Path};
use common::prelude::{CError, CResult};
use cosmian_mcfe::lwe;
use num_bigint::BigUint;
use paperclip::actix::{api_v2_operation, web::Json, Apiv2Schema};
use serde::{Deserialize, Serialize};

use super::actions;
use crate::prelude::*;

#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
#[openapi(empty)]
#[serde(untagged)]
pub enum IntOrBigInt {
    Int(u64),
    BigInt(String),
}

impl TryFrom<&IntOrBigInt> for BigUint {
    type Error = CError;

    fn try_from(value: &IntOrBigInt) -> Result<Self, Self::Error> {
        Ok(match value {
            IntOrBigInt::Int(i) => BigUint::from(*i),
            IntOrBigInt::BigInt(s) => biguint_from_bytes(s.as_bytes(), 10)?,
        })
    }
}

impl From<&BigUint> for IntOrBigInt {
    fn from(bi: &BigUint) -> Self {
        IntOrBigInt::BigInt(bi.to_str_radix(10))
    }
}

/// Wrapper around the `parse_bytes` function to return a `CError` with code by
/// default set to 400.
///
///Creates and initializes a `BigUint`. The input slice must contain ascii/utf8
/// characters in [0-9a-zA-Z]. radix must be in the range 2...36. The function
/// `from_str_radix` from the Num trait provides the same logic for &str
/// buffers.
pub fn biguint_from_bytes(bytes: &[u8], radix: u32) -> CResult<BigUint> {
    BigUint::parse_bytes(bytes, radix)
        .context("could not convert input to a big integer")
        .coded(StatusCode::BAD_REQUEST)
}

/// MCFE and DMCFE setup parameters.
/// Public parameters are derived from these
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct Setup {
    /// n: Number of clients
    pub(crate) clients: usize,
    /// m: Length of the message vector (number of elements)
    pub(crate) message_length: usize,
    /// P: Message elements upper bound P i.e. x₁ ∈ {0,..., P-1}ᵐ where i∈{n}
    pub(crate) message_bound: IntOrBigInt,
    /// V: Vectors elements upper bound V i.e. yᵢ ∈ {0,..., V-1}ᵐ where i∈{n}
    pub(crate) vectors_bound: IntOrBigInt,
    /// n₀: size of key (s term)
    pub n0: usize,
}

impl TryFrom<&Setup> for lwe::Setup {
    type Error = CError;

    fn try_from(s: &Setup) -> Result<Self, Self::Error> {
        Ok(lwe::Setup {
            clients: s.clients,
            message_length: s.message_length,
            message_bound: BigUint::try_from(&s.message_bound)?,
            vectors_bound: BigUint::try_from(&s.vectors_bound)?,
            n0: s.n0,
        })
    }
}

impl From<&lwe::Setup> for Setup {
    fn from(s: &lwe::Setup) -> Self {
        Setup {
            clients: s.clients,
            message_length: s.message_length,
            message_bound: (&s.message_bound).into(),
            vectors_bound: (&s.vectors_bound).into(),
            n0: s.n0,
        }
    }
}

/// Public Parameters for the Multi-Client Inner-Product Functional Encryption
/// in the Random-Oracle Model
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct Parameters {
    /// n: Number of clients
    pub(crate) clients: usize,
    /// m: Length of the message vector (number of elements)
    pub(crate) message_length: usize,
    /// P: Message elements upper bound P i.e. x₁ ∈ {0,..., P-1}ᵐ where i∈{n}
    pub(crate) message_bound: String,
    /// V: Vectors elements upper bound V i.e. yᵢ ∈ {0,..., V-1}ᵐ where i∈{n}
    pub(crate) vectors_bound: String,
    /// K: Inner Product elements upper bound i.e. ∑yᵢ.x₁ ∈ {0, K-1}ᵐ  => K =
    /// n.m.P.V
    pub(crate) k: String,
    /// q the modulo of the key
    pub(crate) q: String,
    /// q₀ the modulo the result is reduced to
    pub(crate) q0: String,
    /// n₀: size of key (s term)
    pub(crate) n0: usize,
    /// σ=α.q the standard deviation of the tᵢ term in the key
    pub(crate) sigma: String,
    /// m₀: size of t term in key
    pub(crate) m0: usize,
}

impl From<&lwe::Parameters> for Parameters {
    fn from(p: &lwe::Parameters) -> Self {
        Parameters {
            clients: p.clients,
            message_length: p.message_length,
            message_bound: p.message_bound.to_string(),
            vectors_bound: p.vectors_bound.to_string(),
            k: p.k.to_string(),
            q: p.q.to_string(),
            q0: p.q0.to_string(),
            n0: p.n0,
            sigma: p.sigma.to_string(),
            m0: p.m0,
        }
    }
}

/// `PUT /mcfe/lwe/parameters`
/// Determine all public parameters based on the setup parameters.
/// Returns the parameters
/// used to encrypt messages in the DMCFE scheme
#[api_v2_operation]
pub async fn lwe_parameters(setup: Json<Setup>) -> ActixResult<Json<Parameters>> {
    let lwe_setup = lwe::Setup::try_from(&(*setup))?;
    Ok(Json(Parameters::from(&actions::get_parameters(
        &lwe_setup,
    )?)))
}

/// `PUT /mcfe/lwe/fks_parameters`
/// Determine all public parameters based on the setup parameters.
/// Returns the parameters used to
/// encrypt the functional key shares in the DMCFE scheme
#[api_v2_operation]
pub async fn lwe_fks_parameters(setup: Json<Setup>) -> ActixResult<Json<Parameters>> {
    let lwe_setup = lwe::Setup::try_from(&(*setup))?;
    Ok(Json(Parameters::from(&actions::get_fks_parameters(
        &lwe_setup,
    )?)))
}

/// Key Creation parameters
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct KeyCreate {
    pub(crate) setup: Setup,
    // TODO add wrapping information to secure keys on the KMS side
}

#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct KeyCreateUpdateResponse {
    pub(crate) uid: String,
}

/// (FKS) Secret Key Import parameters
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct SecretKeyImport {
    pub(crate) setup: Setup,
    pub(crate) key: Vec<Vec<String>>,
}

/// Secret Key Update parameters
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct SecretKeyUpdate {
    pub(crate) uid: String,
    pub(crate) setup: Setup,
    pub(crate) key: Vec<Vec<String>>,
}

#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct KeyGetResponse {
    pub(crate) setup: Setup,
    pub(crate) key: Vec<Vec<String>>,
}

// -----------------------
// LWE Secret Key
// -----------------------

//`POST:/mcfe/lwe/secret_key`
// Create and save a DMCFE secret key.
// The key will be saved under the returned `uid`
#[api_v2_operation]
pub async fn create_lwe_secret_key(
    key_create: Json<KeyCreate>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyCreateUpdateResponse>> {
    let lwe_setup = lwe::Setup::try_from(&key_create.setup)?;
    Ok(Json(KeyCreateUpdateResponse {
        uid: actions::create_lwe_secret_key(&lwe_setup, &***kms_client)?, /* &*** :) Deref of
                                                                           * Data(Arc(Box(x))) */
    }))
}

//`POST:/mcfe/lwe/secret_key/import`
// Import and save a DMCFE secret key.
// The key will be saved under the returned `uid`
#[api_v2_operation]
pub async fn import_lwe_secret_key(
    sk_import: Json<SecretKeyImport>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyCreateUpdateResponse>> {
    let lwe_setup = lwe::Setup::try_from(&sk_import.setup)?;
    let sk = lwe::SecretKey(hex_to_big_uint_2(&sk_import.key)?);
    Ok(Json(KeyCreateUpdateResponse {
        uid: actions::import_lwe_secret_key(&lwe_setup, &sk, &***kms_client)?, /* &*** :) Deref of Data(Arc(Box(x))) */
    }))
}

//`PUT:/mcfe/lwe/secret_key`
// Update an existing DMCFE secret key.
// The key will be saved under the returned `uid`
#[api_v2_operation]
pub async fn update_lwe_secret_key(
    sk_update: Json<SecretKeyUpdate>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyCreateUpdateResponse>> {
    let lwe_setup = lwe::Setup::try_from(&sk_update.setup)?;
    Ok(Json(KeyCreateUpdateResponse {
        uid: actions::update_lwe_secret_key(
            &lwe_setup,
            &sk_update.uid,
            &lwe::SecretKey(hex_to_big_uint_2(&sk_update.key)?),
            &***kms_client,
        )?, // &*** :) Deref of Data(Arc(Box(x)))
    }))
}

/// `GET /mcfe/lwe/secret_key/{uid}`
/// Retrieve an MCFE LWE secret key using its `uid`
#[api_v2_operation]
pub async fn get_lwe_secret_key(
    uid: Path<String>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyGetResponse>> {
    let (setup, sk) = actions::get_lwe_key(&uid, LweSecretKeyType::Secret, &***kms_client)?; // &*** :) Deref of Data(Arc(Box(x)))
    Ok(Json(KeyGetResponse {
        setup: Setup::from(&setup),
        key: big_uint_to_hex_2(&sk.0),
    }))
}

// -----------------------
// LWE FKS Secret Key
// -----------------------

//`POST:/mcfe/lwe/fks_secret_key/import`
// Import and save a DMCFE FKS secret key.
// The key will be saved under the returned `uid`
#[api_v2_operation]
pub async fn import_lwe_fks_secret_key(
    sk_import: Json<SecretKeyImport>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyCreateUpdateResponse>> {
    let lwe_setup = lwe::Setup::try_from(&sk_import.setup)?;
    Ok(Json(KeyCreateUpdateResponse {
        uid: actions::import_lwe_fks_secret_key(
            &lwe_setup,
            &lwe::SecretKey(hex_to_big_uint_2(&sk_import.key)?),
            &***kms_client,
        )?, // &*** :) Deref of Data(Arc(Box(x)))
    }))
}

//`PUT:/mcfe/lwe/fks_secret_key`
// Update an existing DMCFE FKS secret key.
#[api_v2_operation]
pub async fn update_lwe_fks_secret_key(
    sk_update: Json<SecretKeyUpdate>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyCreateUpdateResponse>> {
    let lwe_setup = lwe::Setup::try_from(&sk_update.setup)?;
    Ok(Json(KeyCreateUpdateResponse {
        uid: actions::update_lwe_fks_secret_key(
            &lwe_setup,
            &sk_update.uid,
            &lwe::SecretKey(hex_to_big_uint_2(&sk_update.key)?),
            &***kms_client,
        )?, // &*** :) Deref of Data(Arc(Box(x)))
    }))
}

/// `GET /mcfe/lwe/fks_secret_key/{uid}`
/// Retrieve an MCFE LWE secret key using its `uid`
#[api_v2_operation]
pub async fn get_lwe_fks_secret_key(
    uid: Path<String>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyGetResponse>> {
    let (setup, sk) = actions::get_lwe_key(&uid, LweSecretKeyType::FksSecret, &***kms_client)?; // &*** :) Deref of Data(Arc(Box(x)))
    Ok(Json(KeyGetResponse {
        setup: Setup::from(&setup),
        key: big_uint_to_hex_2(&sk.0),
    }))
}

// -----------------------
// LWE Master Secret Key
// -----------------------

/// (FKS) Secret Key Import parameters
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct MasterSecretKeyImport {
    pub(crate) setup: Setup,
    pub(crate) key: Vec<Vec<Vec<String>>>,
}

/// Secret Key Update parameters
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct MasterSecretKeyUpdate {
    pub(crate) uid: String,
    pub(crate) setup: Setup,
    pub(crate) key: Vec<Vec<Vec<String>>>,
}

#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct MasterKeyGetResponse {
    pub(crate) setup: Setup,
    pub(crate) key: Vec<Vec<Vec<String>>>,
}

//`POST:/mcfe/lwe/master_secret_key`
// Create and save a MCFE master secret key.
// The key will be saved under the returned `uid`
#[api_v2_operation]
pub async fn create_lwe_master_secret_key(
    key_create: Json<KeyCreate>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyCreateUpdateResponse>> {
    let lwe_setup = lwe::Setup::try_from(&key_create.setup)?;
    Ok(Json(KeyCreateUpdateResponse {
        uid: actions::create_lwe_master_secret_key(&lwe_setup, &***kms_client)?, /* &*** :) Deref of Data(Arc(Box(x))) */
    }))
}

//`POST:/mcfe/lwe/master_secret_key/import`
// Import and save a MCFE master secret key.
// The key will be saved under the returned `uid`
#[api_v2_operation]
pub async fn import_lwe_master_secret_key(
    sk_import: Json<MasterSecretKeyImport>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyCreateUpdateResponse>> {
    let lwe_setup = lwe::Setup::try_from(&sk_import.setup)?;
    let mut msk: lwe::MasterSecretKey = Vec::with_capacity(sk_import.key.len());
    for usk in &sk_import.key {
        msk.push(lwe::SecretKey(hex_to_big_uint_2(usk)?));
    }
    Ok(Json(KeyCreateUpdateResponse {
        uid: actions::import_lwe_master_secret_key(&lwe_setup, &msk, &***kms_client)?, /* &*** :) Deref of Data(Arc(Box(x))) */
    }))
}

//`PUT:/mcfe/lwe/master_secret_key`
// Update an existing MCFE master secret key.
// The key will be saved under the returned `uid`
#[api_v2_operation]
pub async fn update_lwe_master_secret_key(
    sk_update: Json<MasterSecretKeyUpdate>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyCreateUpdateResponse>> {
    let lwe_setup = lwe::Setup::try_from(&sk_update.setup)?;
    let mut msk: lwe::MasterSecretKey = Vec::with_capacity(sk_update.key.len());
    for usk in &sk_update.key {
        msk.push(lwe::SecretKey(hex_to_big_uint_2(usk)?));
    }
    Ok(Json(KeyCreateUpdateResponse {
        uid: actions::update_lwe_master_secret_key(
            &lwe_setup,
            &sk_update.uid,
            &msk,
            &***kms_client,
        )?, // &*** :) Deref of Data(Arc(Box(x)))
    }))
}

/// `GET /mcfe/lwe/master_secret_key/{uid}`
/// Retrieve an MCFE LWE secret key using its `uid`
#[api_v2_operation]
pub async fn get_lwe_master_secret_key(
    uid: Path<String>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<MasterKeyGetResponse>> {
    let (setup, msk) = actions::get_lwe_master_secret_key(&uid, &***kms_client)?; // &*** :) Deref of Data(Arc(Box(x)))
    let mut key: Vec<Vec<Vec<String>>> = Vec::with_capacity(msk.len());
    for sk in &msk {
        key.push(big_uint_to_hex_2(&sk.0));
    }
    Ok(Json(MasterKeyGetResponse {
        setup: Setup::from(&setup),
        key,
    }))
}

// -----------------------
// LWE Functional Key
// -----------------------

#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct FunctionalKeyGetResponse {
    pub(crate) setup: Setup,
    pub(crate) key: Vec<String>,
}

/// `GET /mcfe/lwe/functional_key/{uid}`
/// Retrieve an MCFE LWE functional key using its `uid`
#[api_v2_operation]
pub async fn get_lwe_functional_key(
    uid: Path<String>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<FunctionalKeyGetResponse>> {
    let (setup, fk) = actions::get_lwe_functional_key(&uid, &***kms_client)?; // &*** :) Deref of Data(Arc(Box(x)))
    Ok(Json(FunctionalKeyGetResponse {
        setup: Setup::from(&setup),
        key: big_uint_to_hex_1(&fk.0),
    }))
}

/// Request to create a functional key for the vectors
/// a a client
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct CreateFunctionalKeyRequest {
    pub(crate) master_secret_key_uid: String,
    pub(crate) vectors: Vec<Vec<IntOrBigInt>>,
}

//`POST:/mcfe/lwe/functional_key`
// Create and save a MCFE master secret key.
// The key will be saved under the returned `uid`
#[api_v2_operation]
pub async fn create_lwe_functional_key(
    key_create: Json<CreateFunctionalKeyRequest>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyCreateUpdateResponse>> {
    Ok(Json(KeyCreateUpdateResponse {
        uid: actions::create_lwe_functional_key(
            &key_create.master_secret_key_uid,
            &int_or_big_int_to_big_uint_2(&key_create.vectors)?,
            &***kms_client,
        )?, // &*** :) Deref of Data(Arc(Box(x)))
    }))
}

/// Functional Key Import parameters
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct FunctionalKeyImport {
    pub(crate) setup: Setup,
    pub(crate) key: Vec<String>,
}

//`POST:/mcfe/lwe/functional_key/import`
// Import and save a DMCFE Functional Key key.
// The key will be saved under the returned `uid`
#[api_v2_operation]
pub async fn import_lwe_functional_key(
    fk_import: Json<FunctionalKeyImport>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyCreateUpdateResponse>> {
    let lwe_setup = lwe::Setup::try_from(&fk_import.setup)?;
    let fk = lwe::FunctionalKey(hex_to_big_uint_1(&fk_import.key)?);
    Ok(Json(KeyCreateUpdateResponse {
        uid: actions::import_lwe_functional_key(&lwe_setup, &fk, &***kms_client)?, /* &*** :) Deref of Data(Arc(Box(x))) */
    }))
}

/// Request to create a functional key share for the vectors
/// a a client
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct CreateFunctionalKeyShareRequest {
    pub(crate) secret_key_uid: String,
    pub(crate) fks_secret_key_uid: String,
    pub(crate) vectors: Vec<Vec<IntOrBigInt>>,
    pub(crate) client: usize,
}

/// `POST:/mcfe/lwe/functional_key/share`
/// Issue a functional key share for the `vectors` where `client` is
/// the index of our vector as client
///
/// The `fks_secret_key` must have been issued with the other clients
/// so that `∑ fks_skᵢ = 0` where `i ∈ {n}` and `n` is the number of clients.
///
/// The `vectors` has `number of clients` vectors of message length`
///
/// Calculated as `fksᵢ = Enc₂(fks_skᵢ, yᵢ.sk, ᵢ, H(y))` where `i` is this
/// client number, `fks_skᵢ` is the functional key share secret key, `sk` is the
/// secret key and `yᵢ` is the vector for that client
#[api_v2_operation]
pub async fn lwe_functional_key_share(
    request: Json<CreateFunctionalKeyShareRequest>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<Vec<String>>> {
    let fks: lwe::FunctionalKeyShare = actions::functional_key_share(
        &request.secret_key_uid,
        &request.fks_secret_key_uid,
        &int_or_big_int_to_big_uint_2(&request.vectors)?,
        request.client,
        &***kms_client,
    )?;
    Ok(Json(big_uint_to_hex_1(&fks.0)))
}

/// Request to recover a functional key from from shares
#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct RecoverFunctionalKeyRequest {
    pub(crate) setup: Setup,
    pub(crate) functional_key_shares: Vec<Vec<String>>,
    pub(crate) vectors: Vec<Vec<IntOrBigInt>>,
}

/// `PUT:/mcfe/lwe/functional_key/recover`
/// Recover a functional key from the functional key shares sent by the clients.
/// All clients must have provided their share.
#[api_v2_operation]
pub async fn recover_lwe_functional_key(
    request: Json<RecoverFunctionalKeyRequest>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<KeyCreateUpdateResponse>> {
    let lwe_setup = lwe::Setup::try_from(&request.setup)?;
    // process functional key shares
    let mut functional_key_shares: Vec<lwe::FunctionalKeyShare> =
        Vec::with_capacity(request.functional_key_shares.len());
    for fks in &request.functional_key_shares {
        functional_key_shares.push(lwe::FunctionalKeyShare(hex_to_big_uint_1(fks)?));
    }
    let functional_key_uid = actions::recover_lwe_functional_key(
        &lwe_setup,
        &functional_key_shares,
        &int_or_big_int_to_big_uint_2(&request.vectors)?,
        &***kms_client,
    )?;
    Ok(Json(KeyCreateUpdateResponse {
        uid: functional_key_uid,
    }))
}

// -----------------------
// LWE Encrypt
// -----------------------

#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct EncryptRequest {
    uid: String,
    labeled_messages: HashMap<String, Vec<IntOrBigInt>>,
}
pub type EncryptResponse = HashMap<String, Vec<String>>;

/// `POST /mcfe/lwe/encrypt/`
/// Encrypt the provided messages
/// using a MCFE Secret Key
#[api_v2_operation]
pub async fn encrypt(
    request: Json<EncryptRequest>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<EncryptResponse>> {
    let mut labels: Vec<&String> = Vec::with_capacity(request.labeled_messages.len());
    let mut labeled_messages: Vec<(Vec<u8>, Vec<BigUint>)> =
        Vec::with_capacity(request.labeled_messages.len());
    for (label, value) in &request.labeled_messages {
        labeled_messages.push((
            label.as_bytes().to_vec(),
            int_or_big_int_to_big_uint_1(value)?,
        ));
        labels.push(label);
    }
    let cts = actions::encrypt(&request.uid, &labeled_messages, &***kms_client)?;
    let mut encoded_cts: EncryptResponse = HashMap::with_capacity(cts.len());
    for (idx, ct) in cts.iter().enumerate() {
        let mut encoded_ct: Vec<String> = Vec::with_capacity(ct.len());
        for c in ct {
            encoded_ct.push(hex::encode(c.to_bytes_be()))
        }
        encoded_cts.insert(labels[idx].to_string(), encoded_ct);
    }
    Ok(Json(encoded_cts))
}

// -----------------------
// LWE Decrypt
// -----------------------

#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct LabeledCipherTexts {
    label: String,
    // n clients x m length
    cipher_texts: Vec<Vec<String>>,
}

#[derive(Apiv2Schema, Serialize, Deserialize, Debug, Clone)]
pub struct DecryptRequest {
    functional_key_uid: String,
    // l entries of n cipher texts of length m
    labeled_cipher_texts: HashMap<String, Vec<Vec<String>>>,
    // n clients x m vector length
    vectors: Vec<Vec<IntOrBigInt>>,
}

// l messages of length m
pub type DecryptResponse = HashMap<String, String>;

/// `POST /mcfe/lwe/decrypt/`
/// Decrypt the provided cipher texts
/// using a MCFE Functional Key
#[api_v2_operation]
pub async fn decrypt(
    request: Json<DecryptRequest>,
    kms_client: Data<Box<dyn cosmian_kms_client::Client>>,
) -> ActixResult<Json<DecryptResponse>> {
    let mut labels: Vec<&String> = Vec::with_capacity(request.labeled_cipher_texts.len());
    let mut labeled_cipher_texts: Vec<(Vec<u8>, Vec<Vec<BigUint>>)> =
        Vec::with_capacity(request.labeled_cipher_texts.len());
    for (label, cts) in &request.labeled_cipher_texts {
        labeled_cipher_texts.push((label.as_bytes().to_vec(), hex_to_big_uint_2(cts)?));
        labels.push(label);
    }
    let messages: Vec<BigUint> = actions::decrypt(
        &request.functional_key_uid,
        &labeled_cipher_texts,
        &int_or_big_int_to_big_uint_2(&request.vectors)?,
        &***kms_client,
    )?;
    let mut result: DecryptResponse = HashMap::with_capacity(messages.len());
    for (idx, message) in messages.iter().enumerate() {
        result.insert(labels[idx].clone(), message.to_str_radix(10));
    }
    Ok(Json(result))
}

// -----------------------
// Create FKS Secret Keys
// TODO Replace with an MPC protocol
// -----------------------

type FksSecretKeysResponse = Vec<Vec<Vec<String>>>;

/// `POST:/mcfe/lwe/fks_secret_keys/create`
/// Create a set of secret keys used by clients to encrypt the functional key
/// shares. These keys sum to zero in ℤq. This utility will be replaced by an
/// MPC protocol.
#[api_v2_operation]
pub async fn create_fks_secret_keys(
    setup: Json<Setup>,
) -> ActixResult<Json<FksSecretKeysResponse>> {
    let lwe_setup = lwe::Setup::try_from(&(*setup))?;
    let keys = actions::fks_secret_keys(&lwe_setup)?;
    let mut response: FksSecretKeysResponse = Vec::with_capacity(keys.len());
    for k in &keys {
        response.push(big_uint_to_hex_2(&k.0))
    }
    Ok(Json(response))
}

// -----------------------
// Conversion Utilities
// -----------------------

fn int_or_big_int_to_big_uint_1(input: &[IntOrBigInt]) -> CResult<Vec<BigUint>> {
    let mut vector: Vec<BigUint> = Vec::with_capacity(input.len());
    for v in input {
        vector.push(BigUint::try_from(v)?);
    }
    Ok(vector)
}

fn int_or_big_int_to_big_uint_2(input: &[Vec<IntOrBigInt>]) -> CResult<Vec<Vec<BigUint>>> {
    let mut result: Vec<Vec<BigUint>> = Vec::with_capacity(input.len());
    for v_i in input {
        result.push(int_or_big_int_to_big_uint_1(v_i)?);
    }
    Ok(result)
}

fn hex_to_big_uint_1(input: &[String]) -> CResult<Vec<BigUint>> {
    let mut vector: Vec<BigUint> = Vec::with_capacity(input.len());
    for s in input {
        let bytes = hex::decode(s)
            .context("Invalid big int hex data")
            .coded(StatusCode::BAD_REQUEST)?;
        vector.push(BigUint::from_bytes_be(&bytes));
    }
    Ok(vector)
}

fn hex_to_big_uint_2(input: &[Vec<String>]) -> CResult<Vec<Vec<BigUint>>> {
    let mut result: Vec<Vec<BigUint>> = Vec::with_capacity(input.len());
    for v_i in input {
        result.push(hex_to_big_uint_1(v_i)?);
    }
    Ok(result)
}

fn big_uint_to_hex_2(input: &[Vec<BigUint>]) -> Vec<Vec<String>> {
    input.iter().map(|v| big_uint_to_hex_1(v)).collect()
}

fn big_uint_to_hex_1(input: &[BigUint]) -> Vec<String> {
    input.iter().map(|v| hex::encode(v.to_bytes_be())).collect()
}
