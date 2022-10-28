use actix_web::web;
use cosmian_crypto_base::{
    abe::{
        bilinear_map::bls12_381::Bls12_381,
        policy::{AccessPolicy, Policy},
        wrapper::{self, generate_user_decryption_key},
        Engine,
    },
    hybrid_crypto::header::UID_LENGTH,
};
use paperclip::actix::{api_v2_operation, web::Json, Apiv2Schema};
use serde::{Deserialize, Serialize};

use crate::prelude::*;

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// GENERATE MASTER KEY ////////////////////////
///////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// /
///
//
// Declare shared structures between ABE endpoints
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKey {
    nb_revocation: usize,
    complete_policy: Policy,
}

impl paperclip::v2::schema::Apiv2Schema for MasterKey {
    const DESCRIPTION: &'static str = "MasterKey Apiv2Schema";
    const NAME: Option<&'static str> = None;
    const REQUIRED: bool = true;
}
#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct MasterKeyResponse {
    master_private_key: String,
    public_key: String,
    policy: String,
}

pub fn _generate_master_key(req: &MasterKey) -> anyhow::Result<MasterKeyResponse> {
    debug!(
        "POST /abe/stateless/generate_master_key. Request: {:?}",
        serde_json::to_string(&req)?
    );
    let req = req.clone();
    let engine = Engine::<Gpsw<Bls12_381>>::new(&req.complete_policy);
    let mk = engine.generate_master_key()?;

    let response = MasterKeyResponse {
        master_private_key: mk.0.to_string(),
        public_key: mk.1.to_string(),
        policy: engine.pg.to_string(),
    };
    debug!(
        "POST /abe/stateless/generate_master_key. Response: {:?}",
        serde_json::to_string(&response)?
    );
    Ok(response)
}

/// `POST /abe/stateless/generate_master_key`
/// Generate ABE master private key
#[api_v2_operation]
pub async fn generate_master_key(
    req: web::Json<MasterKey>,
) -> ActixResult<Json<MasterKeyResponse>> {
    Ok(Json(
        _generate_master_key(&req.into_inner()).expect("failed generating master key"),
    ))
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// GENERATE USER DECRYPTION KEY ///////////////
///////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// /
#[derive(Serialize, Deserialize, Debug)]
pub struct UserKey {
    master_private_key: String,
    master_public_key: String,
    policy_group: String,
    access_policy: AccessPolicy,
}

impl paperclip::v2::schema::Apiv2Schema for UserKey {
    const DESCRIPTION: &'static str = "UserKey Apiv2Schema";
    const NAME: Option<&'static str> = None;
    const REQUIRED: bool = true;
}
#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct UserKeyResponse {
    user_decryption_key: String,
}

fn _generate_decryption_key(req: UserKey) -> anyhow::Result<UserKeyResponse> {
    debug!(
        "POST /abe/stateless/generate_decryption_key. Request: {:?}",
        serde_json::to_string(&req)?
    );
    let private_key = hex::decode(req.master_private_key).context("failed building private key")?;
    let _public_key = hex::decode(&req.master_public_key).context("failed building public key")?;
    let policy_group = hex::decode(req.policy_group).context("failed building policy group")?;
    let pg: Policy =
        serde_json::from_slice(&policy_group).context("failed deserializing json policy group")?;

    let decryption_key = generate_user_decryption_key(&private_key[..], &req.access_policy, &pg)
        .context("failed generating key pair")?;

    let key_pair = req.master_public_key + &decryption_key;
    let response = UserKeyResponse {
        user_decryption_key: key_pair,
    };
    debug!(
        "POST /abe/stateless/generate_decryption_key. Response: {:?}",
        serde_json::to_string(&response)?
    );
    Ok(response)
}

/// `POST /abe/stateless/generate_decryption_key`
/// Generate user decryption key
#[api_v2_operation]
pub async fn generate_decryption_key(req: Json<UserKey>) -> ActixResult<Json<UserKeyResponse>> {
    Ok(Json(
        _generate_decryption_key(req.into_inner()).expect("failed generate user key"),
    ))
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// GENERATE SYMMETRIC KEY //////////////////////
///////////////////////////////////////////////////////////////////////////////
////////////////////////////////// /
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptSymmetricKey {
    uid: String,
    public_key: String,
    access_policy: AccessPolicy,
    policy_group: String,
}

impl paperclip::v2::schema::Apiv2Schema for EncryptSymmetricKey {
    const DESCRIPTION: &'static str = "EncryptSymmetricKey Apiv2Schema";
    const NAME: Option<&'static str> = None;
    const REQUIRED: bool = true;
}

#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct EncryptSymmetricKeyResponse {
    symmetric_key: String,
    encrypted_header: String,
}

fn _encrypt_symmetric_key(req: EncryptSymmetricKey) -> anyhow::Result<EncryptSymmetricKeyResponse> {
    debug!(
        "POST /abe/stateless/encrypt_symmetric_key. Request: {:?}",
        serde_json::to_string(&req)?
    );
    let public_key = hex::decode(req.public_key).context("failed decoding public key")?;
    let uid = hex::decode(req.uid).context("failed decoding uid")?;
    let policy_group = hex::decode(req.policy_group).context("failed decoding policy group")?;

    let mut new_uid = [0_u8; UID_LENGTH];
    new_uid.copy_from_slice(&uid[..UID_LENGTH]);
    let (symmetric_key, encrypted_header) = wrapper::generate_symmetric_key(
        &new_uid,
        &public_key[..],
        &req.access_policy.attributes(),
        &policy_group,
    )
    .context("failed generating and encrypting symmetric key")?;

    let response = EncryptSymmetricKeyResponse {
        symmetric_key: hex::encode(symmetric_key),
        encrypted_header: hex::encode(encrypted_header),
    };
    debug!(
        "POST /abe/stateless/encrypt_symmetric_key. Response: {:?}",
        serde_json::to_string(&response)?
    );
    Ok(response)
}

/// `POST /abe/stateless/init_encrypt`
/// Generate and encrypt symmetric key using ABE with given attributes
/// Start symmetric encryption on `plaintext`
#[api_v2_operation]
pub async fn encrypt_symmetric_key(
    req: Json<EncryptSymmetricKey>,
) -> ActixResult<Json<EncryptSymmetricKeyResponse>> {
    Ok(Json(
        _encrypt_symmetric_key(req.into_inner()).expect("failed encrypt symmetric key"),
    ))
}
////////////////////////////////////////////////////////////////////////////////
////////////// GENERATE SYMMETRIC KEY and START ENCRYPTING//////////////////////
///////////////////////////////////////////////////////////////////////////////
////////////// /
#[derive(Serialize, Deserialize, Debug)]
pub struct InitEncrypt {
    uid: String,
    public_key: String,
    access_policy: AccessPolicy,
    policy_group: String,
    plaintext: String,
}

impl paperclip::v2::schema::Apiv2Schema for InitEncrypt {
    const DESCRIPTION: &'static str = "InitEncrypt Apiv2Schema";
    const NAME: Option<&'static str> = None;
    const REQUIRED: bool = true;
}

#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct InitEncryptResponse {
    symmetric_key: String,
    encrypted_header: String,
    ciphertext: String,
    block_number: usize,
}

fn _init_encrypt(req: InitEncrypt) -> anyhow::Result<InitEncryptResponse> {
    debug!(
        "POST /abe/stateless/init_encrypt. Request: {:?}",
        serde_json::to_string(&req)?
    );
    let public_key = hex::decode(req.public_key).context("failed decoding public key")?;
    let uid = hex::decode(req.uid).context("failed decoding uid")?;
    let plaintext = hex::decode(req.plaintext).context("failed decoding plaintext")?;
    let policy_group = hex::decode(req.policy_group).context("failed decoding policy group")?;

    let mut new_uid = [0_u8; UID_LENGTH];
    new_uid.copy_from_slice(&uid[..UID_LENGTH]);
    let (symmetric_key, encrypted_header, _header_obj) = wrapper::generate_symmetric_key(
        &new_uid,
        &public_key[..],
        &req.access_policy,
        &policy_group,
    )
    .context("failed generating and encrypting symmetric key")?;

    let (ciphertext, block_number) = wrapper::encrypt(&symmetric_key, &new_uid, &plaintext[..], 0)?;

    let response = InitEncryptResponse {
        symmetric_key: hex::encode(symmetric_key),
        encrypted_header: hex::encode(encrypted_header),
        ciphertext: hex::encode(ciphertext),
        block_number,
    };
    debug!(
        "POST /abe/stateless/init_encrypt. Response: {:?}",
        serde_json::to_string(&response)?
    );
    Ok(response)
}

/// `POST /abe/stateless/init_encrypt`
/// Generate and encrypt symmetric key using ABE with given attributes
/// Start symmetric encryption on `plaintext`
#[api_v2_operation]
pub async fn init_encrypt(req: Json<InitEncrypt>) -> ActixResult<Json<InitEncryptResponse>> {
    Ok(Json(
        _init_encrypt(req.into_inner()).expect("failed init encryption"),
    ))
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// ENCRYPT ///////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// /
#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct Encrypt {
    uid: String,
    symmetric_key: String,
    plaintext: String,
    block_number: usize,
}
#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct EncryptResponse {
    ciphertext: String,
    block_number: usize,
}

fn _encrypt(req: Encrypt) -> anyhow::Result<EncryptResponse> {
    debug!(
        "POST /abe/stateless/encrypt. Request: {:?}",
        serde_json::to_string(&req)?
    );
    let symmetric_key =
        hex::decode(req.symmetric_key).context("failed decoding hex-symmetric-key")?;
    let plaintext = hex::decode(req.plaintext).context("failed decoding hex-plaintext")?;
    let uid = hex::decode(req.uid).context("failed decoding hex-uid")?;

    let output = wrapper::encrypt(
        &symmetric_key[..],
        &uid[..],
        &plaintext[..],
        req.block_number,
    )
    .context("failed encrypting data")?;

    let response = EncryptResponse {
        ciphertext: hex::encode(output.0),
        block_number: output.1,
    };
    debug!(
        "POST /abe/stateless/encrypt. Response: {:?}",
        serde_json::to_string(&response)?
    );
    Ok(response)
}

/// `POST /abe/stateless/encrypt`
/// Encrypt plain text data
/// Return hex encoded representation of encrypted bytes (ABE header followed by
/// data)
#[api_v2_operation]
pub async fn encrypt(req: Json<Encrypt>) -> ActixResult<Json<EncryptResponse>> {
    Ok(Json(_encrypt(req.into_inner()).expect("failed encryption")))
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////// DECRYPT SYMMETRIC KEY ///////////////////////////
///////////////////////////////////////////////////////////////////////////////
////////////////////////////// /
#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct DecryptSymmetricKey {
    user_decryption_key: String,
    encrypted_header: String,
}
#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct DecryptSymmetricKeyResponse {
    clear_symmetric_key: String,
}

fn _decrypt_symmetric_key(req: DecryptSymmetricKey) -> anyhow::Result<DecryptSymmetricKeyResponse> {
    debug!(
        "POST /abe/stateless/decrypt_symmetric_key. Request: {:?}",
        serde_json::to_string(&req)?
    );
    let user_decryption_key =
        hex::decode(req.user_decryption_key).context("failed decoding hex-user_decryption_key")?;
    let encrypted_header =
        hex::decode(req.encrypted_header).context("failed decoding hex-encrypted_header")?;

    let output = wrapper::decrypt_header(&user_decryption_key[..], &encrypted_header[..])
        .context("failed decrypting ABE")?;

    let response = DecryptSymmetricKeyResponse {
        clear_symmetric_key: hex::encode(output.symmetric_key.0),
    };
    debug!(
        "POST /abe/stateless/decrypt_symmetric_key. Response {:?}",
        serde_json::to_string(&response)?
    );
    Ok(response)
}

/// `POST /abe/stateless/decrypt`
/// Decrypt ciphertext data
#[api_v2_operation]
pub async fn decrypt_symmetric_key(
    req: Json<DecryptSymmetricKey>,
) -> ActixResult<Json<DecryptSymmetricKeyResponse>> {
    Ok(Json(
        _decrypt_symmetric_key(req.into_inner()).expect("failed decrypt symmetric key"),
    ))
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////// DECRYPT /////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
////////////////////////////// /
#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct Decrypt {
    user_decryption_key: String,
    encrypted_header: String,
    block_number: usize,
    ciphertext: String,
}
#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct DecryptResponse {
    cleartext: String,
}

fn _decrypt(req: Decrypt) -> anyhow::Result<DecryptResponse> {
    debug!(
        "POST /abe/stateless/decrypt. Request: {:?}",
        serde_json::to_string(&req)?
    );
    let user_decryption_key =
        hex::decode(req.user_decryption_key).context("failed decoding hex-user_decryption_key")?;
    let encrypted_header =
        hex::decode(req.encrypted_header).context("failed decoding hex-encrypted_header")?;
    let ciphertext = hex::decode(req.ciphertext).context("failed decoding hex-ciphertext")?;

    let output = wrapper::decrypt(
        &user_decryption_key[..],
        &encrypted_header[..],
        &ciphertext[..],
        req.block_number,
    )
    .context("failed decrypting ABE")?;

    let response = DecryptResponse {
        cleartext: hex::encode(output),
    };
    debug!(
        "POST /abe/stateless/decrypt. Response: {:?}",
        serde_json::to_string(&response)?
    );
    Ok(response)
}

/// `POST /abe/stateless/decrypt`
/// Decrypt ciphertext data
#[api_v2_operation]
pub async fn decrypt(req: Json<Decrypt>) -> ActixResult<Json<DecryptResponse>> {
    Ok(Json(_decrypt(req.into_inner()).expect("failed decryption")))
}

// policy access
#[cfg(test)]
mod tests {
    use common::prelude::*;
    use cosmian_crypto_base::{
        abe::{
            bilinear_map::bls12_381::Bls12_381,
            policy::{ap, Policy},
            Engine,
        },
        entropy::new_uid,
        hybrid_crypto::Block,
        symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
    };

    use super::_generate_master_key;
    use crate::rest::abe::no_kmip::{
        Decrypt, DecryptSymmetricKey, Encrypt, EncryptSymmetricKey, InitEncrypt, MasterKey,
        MasterKeyResponse, UserKey, _decrypt, _decrypt_symmetric_key, _encrypt,
        _encrypt_symmetric_key, _generate_decryption_key, _init_encrypt,
    };

    type Bl = Block<Aes256GcmCrypto>;
    const CLEAR_TEXT_SIZE: usize = Bl::MAX_CLEAR_TEXT_LENGTH;

    #[test]
    fn master_key_response() -> anyhow::Result<()> {
        let engine = Engine::<Gpsw<Bls12_381>>::new(
            &Policy::new(10)
                .add_axis("Countries", &["FR", "EN"], false)?
                .add_axis("Levels", &["Sec_Level_1"], true)?,
        );
        let mk = engine.generate_master_key()?;

        let response = MasterKeyResponse {
            master_private_key: mk.0.to_string(),
            public_key: mk.1.to_string(),
            policy: engine.pg.to_string(),
        };

        debug!("ABE Master key creation: {:?}", response);
        Ok(())
    }

    #[test]
    fn stateless_functional_tests() -> anyhow::Result<()> {
        test_utils::log_init("cosmian_server=info");
        let plaintext_1 = vec![0; CLEAR_TEXT_SIZE];
        let plaintext_2 = vec![1; CLEAR_TEXT_SIZE];
        let uid = new_uid();
        let mk = _generate_master_key(&MasterKey {
            nb_revocation: 10,
            complete_policy: Policy::new(10)
                .add_axis("Countries", &["FR", "EN"], false)?
                .add_axis("Levels", &["Sec_Level_1"], true)?,
        })?;
        let uk = _generate_decryption_key(UserKey {
            master_private_key: mk.master_private_key,
            master_public_key: mk.public_key.clone(),
            policy_group: mk.policy.clone(),
            access_policy: ap("Levels", "Sec_Level_1") & ap("Countries", "FR"),
        })?;
        let ciphertext_1 = _init_encrypt(InitEncrypt {
            uid: hex::encode(uid),
            public_key: mk.public_key.clone(),
            access_policy: ap("Levels", "Sec_Level_1") & ap("Countries", "FR"),
            policy_group: mk.policy.clone(),
            plaintext: hex::encode(&plaintext_1),
        })?;
        let ciphertext_2 = _encrypt(Encrypt {
            block_number: 1,
            uid: hex::encode(uid),
            symmetric_key: ciphertext_1.symmetric_key,
            plaintext: hex::encode(&plaintext_2),
        })?;
        let mut big_ciphertext = hex::decode(ciphertext_1.ciphertext)?;
        big_ciphertext.extend_from_slice(&hex::decode(ciphertext_2.ciphertext)?);

        let cleartext = _decrypt(Decrypt {
            user_decryption_key: uk.user_decryption_key.clone(),
            encrypted_header: ciphertext_1.encrypted_header,
            block_number: 0,
            ciphertext: hex::encode(big_ciphertext),
        })?;

        assert_eq!(
            hex::encode(plaintext_1) + &hex::encode(plaintext_2),
            cleartext.cleartext
        );

        let encrypted_sk = _encrypt_symmetric_key(EncryptSymmetricKey {
            uid: hex::encode(uid),
            public_key: mk.public_key,
            access_policy: ap("Levels", "Sec_Level_1") & ap("Countries", "FR"),
            policy_group: mk.policy,
        })?;

        let dsk = _decrypt_symmetric_key(DecryptSymmetricKey {
            user_decryption_key: uk.user_decryption_key,
            encrypted_header: encrypted_sk.encrypted_header,
        })?;

        assert_eq!(dsk.clear_symmetric_key, encrypted_sk.symmetric_key);

        Ok(())
    }
}
