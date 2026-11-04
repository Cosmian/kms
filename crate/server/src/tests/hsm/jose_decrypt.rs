//! JOSE flow A: an RSA key pair provisioned in the HSM decrypts a client-built JWE.
//!
//! 1. the public key is fetched from `GET /.well-known/jwks.json` and selected by `kid`;
//! 2. the client builds a JWE (`RSA-OAEP-256` + `A256GCM`) with OpenSSL only;
//! 3. `POST /v1/crypto/decrypt` unwraps the CEK with the HSM private key (`sensitive=true`,
//!    so the software path cannot work) and caches it in memory — never in the DB;
//! 4. the plaintext is re-encrypted with `POST /v1/crypto/encrypt` (`dir`) under a KMS AES key.

use actix_web::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use cosmian_kms_interfaces::as_hsm_uid;
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    KmipOperation,
    extra::tagging::VENDOR_ID_COSMIAN,
    kmip_operations::{Get, Operation},
    kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
    requests::{create_rsa_key_pair_request, symmetric_key_create_request},
};
use openssl::{
    bn::BigNum,
    encrypt::Encrypter,
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    symm::{Cipher, decrypt_aead, encrypt_aead},
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    core::ObjectHandle,
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    routes::jose::cek_cache,
    tests::{
        hsm::{EMPTY_TAGS, delete_key, hsm_clap_config, revoke_key, send_message},
        test_utils::{
            self, get_json_with_uri, get_tmp_sqlite_path, post_json_raw, post_json_with_uri,
        },
    },
};

const OWNER: &str = "admin";
const PLAINTEXT: &[u8] = b"JOSE + HSM end-to-end plaintext";

fn str_field<'a>(v: &'a Value, field: &str) -> KResult<&'a str> {
    v[field]
        .as_str()
        .ok_or_else(|| KmsError::Default(format!("missing string field '{field}' in {v}")))
}

fn b64_field(v: &Value, field: &str) -> KResult<Vec<u8>> {
    B64.decode(str_field(v, field)?)
        .map_err(|e| KmsError::Default(format!("bad base64url in '{field}': {e}")))
}

pub(super) async fn test_jose_hsm_decryption() -> KResult<()> {
    // Unauthenticated in-process requests run as the default user ("admin"), and JWKS only
    // lists keys owned by it.
    let mut clap_config = hsm_clap_config(OWNER, None)?;
    clap_config.db.sqlite_path = get_tmp_sqlite_path();
    clap_config.google_cse_config.google_cse_enable = false;
    let slot = clap_config.hsm.hsm_slot[0];
    let kms = Box::pin(test_utils::test_kms_with_google_cse(clap_config)).await;
    let app = test_utils::test_app_with_kms(kms.clone(), None).await;

    // ── Provision a sensitive RSA pair in the HSM, tagged for JWKS publication ──
    let sk = as_hsm_uid!(slot, Uuid::new_v4());
    let pk = format!("{sk}_pk");
    let create = create_rsa_key_pair_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(sk.clone())),
        ["jwks"],
        2048,
        true,
        None,
    )?;
    send_message(
        kms.clone(),
        OWNER,
        vec![Operation::CreateKeyPair(Box::new(create))],
    )
    .await?;

    // ── JWKS: the HSM public key is published without `use` / `alg` ──
    let jwks: Value = get_json_with_uri(&app, "/.well-known/jwks.json").await?;
    let jwk = jwks["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|k| k["kid"] == pk.as_str()))
        .ok_or_else(|| KmsError::Default(format!("HSM public key {pk} not in JWKS: {jwks}")))?;
    assert_eq!(jwk["kty"], "RSA");
    assert!(jwk.get("use").is_none(), "unexpected `use` in {jwk}");
    assert!(jwk.get("alg").is_none(), "unexpected `alg` in {jwk}");
    let public_key = PKey::from_rsa(Rsa::from_public_components(
        BigNum::from_slice(&b64_field(jwk, "n")?)?,
        BigNum::from_slice(&b64_field(jwk, "e")?)?,
    )?)?;

    // ── Client side: build the JWE with OpenSSL only ──
    let mut cek = vec![0_u8; 32];
    kms.rng
        .fill_bytes(&mut cek)
        .map_err(|e| KmsError::Default(e.to_string()))?;
    let mut iv = vec![0_u8; 12];
    kms.rng
        .fill_bytes(&mut iv)
        .map_err(|e| KmsError::Default(e.to_string()))?;
    let protected = B64.encode(format!(
        r#"{{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"{pk}"}}"#
    ));
    let mut oaep_wrapper = Encrypter::new(&public_key)?;
    oaep_wrapper.set_rsa_padding(Padding::PKCS1_OAEP)?;
    oaep_wrapper.set_rsa_oaep_md(MessageDigest::sha256())?;
    oaep_wrapper.set_rsa_mgf1_md(MessageDigest::sha256())?;
    let mut encrypted_key = vec![0_u8; oaep_wrapper.encrypt_len(&cek)?];
    let len = oaep_wrapper.encrypt(&cek, &mut encrypted_key)?;
    encrypted_key.truncate(len);
    let mut tag = vec![0_u8; 16];
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        &cek,
        Some(&iv),
        protected.as_bytes(),
        PLAINTEXT,
        &mut tag,
    )?;
    let jwe = |tag: &[u8]| {
        json!({
            "protected": protected,
            "encrypted_key": B64.encode(&encrypted_key),
            "iv": B64.encode(&iv),
            "ciphertext": B64.encode(&ciphertext),
            "tag": B64.encode(tag),
        })
    };

    // ── 1. Cache miss: the HSM oracle unwraps the CEK ──
    let resp: Value = post_json_with_uri(&app, jwe(&tag), "/v1/crypto/decrypt").await?;
    assert_eq!(str_field(&resp, "kid")?, pk);
    assert_eq!(b64_field(&resp, "data")?, PLAINTEXT);

    // ── 2. The CEK is cached in memory and never persisted ──
    let owm = crate::core::retrieve_object_utils::retrieve_object_for_operation(
        ObjectHandle::from(sk.as_str()),
        KmipOperation::Decrypt,
        &kms,
        &UserId::from(OWNER),
    )
    .await?;
    let cached = cek_cache::peek_cek(&kms, &sk, &encrypted_key, owm.object()).await;
    assert_eq!(cached.as_deref().map(Vec::as_slice), Some(cek.as_slice()));
    assert!(
        kms.database
            .retrieve_object(&cek_cache::cek_cache_uid(&sk, &encrypted_key))
            .await?
            .is_none(),
        "the CEK must not be written to the database"
    );

    // ── 3. Cache hit ──
    let resp: Value = post_json_with_uri(&app, jwe(&tag), "/v1/crypto/decrypt").await?;
    assert_eq!(b64_field(&resp, "data")?, PLAINTEXT);

    // ── 4. Tampered tag is rejected ──
    let mut bad_tag = tag.clone();
    if let Some(b) = bad_tag.first_mut() {
        *b ^= 0x01;
    }
    let (status, body) = post_json_raw(&app, jwe(&bad_tag), "/v1/crypto/decrypt").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // ── Re-encrypt the plaintext under a KMS AES key (`dir`) ──
    let aes_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let responses = send_message(kms.clone(), OWNER, vec![Operation::Create(aes_request)]).await?;
    let Some(Operation::CreateResponse(created)) = responses.first() else {
        return Err(KmsError::Default("invalid Create response".to_owned()));
    };
    let aes_kid = created.unique_identifier.to_string();

    let jwe_out: Value = post_json_with_uri(
        &app,
        json!({
            "kid": aes_kid,
            "alg": "dir",
            "enc": "A256GCM",
            "data": B64.encode(PLAINTEXT),
        }),
        "/v1/crypto/encrypt",
    )
    .await?;
    let out_protected = str_field(&jwe_out, "protected")?;
    let out_header = B64
        .decode(out_protected)
        .map_err(|e| KmsError::Default(e.to_string()))?;
    assert_eq!(
        String::from_utf8_lossy(&out_header),
        format!(r#"{{"alg":"dir","enc":"A256GCM","kid":"{aes_kid}"}}"#)
    );
    let aes_object = kms
        .get(
            Get::new(
                UniqueIdentifier::TextString(aes_kid.clone()),
                false,
                None,
                None,
            ),
            &UserId::from(OWNER),
        )
        .await?
        .object;
    let aes_bytes = aes_object.key_block()?.key_bytes()?;
    let recovered = decrypt_aead(
        Cipher::aes_256_gcm(),
        &aes_bytes,
        Some(&b64_field(&jwe_out, "iv")?),
        out_protected.as_bytes(),
        &b64_field(&jwe_out, "ciphertext")?,
        &b64_field(&jwe_out, "tag")?,
    )?;
    assert_eq!(recovered, PLAINTEXT);

    // ── Cleanup ──
    delete_key(&sk, OWNER, &kms).await?;
    delete_key(&pk, OWNER, &kms).await?;
    revoke_key(&aes_kid, OWNER, &kms).await?;
    delete_key(&aes_kid, OWNER, &kms).await?;
    Ok(())
}
