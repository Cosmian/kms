//! JOSE flow B: import an external RSA public key, then one `POST /v1/crypto/encrypt`
//! call builds a complete JWE whose CEK is a KMS-held AES key (`cek_kid`).

use actix_web::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use cosmian_kms_access::access::Access;
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    KmipOperation,
    kmip_operations::{Get, GetResponse},
    kmip_types::UniqueIdentifier,
};
use openssl::{
    encrypt::Decrypter,
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    symm::{Cipher, decrypt_aead},
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    routes::jose::{CryptoApiError, JoseEncAlgorithm, encrypt::cek_from_kms_key},
    tests::test_utils::{
        self, https_clap_config, post_2_1, post_json_raw, post_json_with_uri,
        test_kms_with_google_cse,
    },
};

const DATA: &[u8] = b"flow B plaintext";

fn field_bytes(v: &Value, field: &str) -> KResult<Vec<u8>> {
    let s = v[field]
        .as_str()
        .ok_or_else(|| KmsError::Default(format!("missing '{field}' in {v}")))?;
    B64.decode(s)
        .map_err(|e| KmsError::Default(format!("bad base64url in '{field}': {e}")))
}

/// `{"kty":"RSA","kid":…,"n":…,"e":…,"key_ops":…}` for the public half of `rsa`.
fn public_jwk(rsa: &Rsa<openssl::pkey::Private>, kid: &str, key_ops: &Value) -> Value {
    json!({
        "kty": "RSA",
        "kid": kid,
        "n": B64.encode(rsa.n().to_vec()),
        "e": B64.encode(rsa.e().to_vec()),
        "key_ops": key_ops,
    })
}

async fn create_aes_key<S, B>(app: &S, alg: &str) -> KResult<String>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let resp: Value =
        post_json_with_uri(app, json!({"kty": "oct", "alg": alg}), "/v1/crypto/keys").await?;
    Ok(resp["kid"]
        .as_str()
        .ok_or_else(|| KmsError::Default(format!("missing kid in {resp}")))?
        .to_owned())
}

#[tokio::test]
async fn test_jose_public_import_and_cek_kid_encryption() -> KResult<()> {
    let app = test_utils::test_app(None).await;

    // The recipient holds the private key outside the KMS.
    let recipient = Rsa::generate(2048)?;
    let recipient_kid = format!("recipient-kpub-{}", Uuid::new_v4());

    // Import the recipient's public key under its own kid.
    let imported: Value = post_json_with_uri(
        &app,
        public_jwk(&recipient, &recipient_kid, &json!(["encrypt"])),
        "/v1/crypto/keys",
    )
    .await?;
    assert_eq!(imported["kid"], recipient_kid.as_str());
    assert_eq!(imported["kty"], "RSA");
    assert_eq!(imported["key_ops"], json!(["encrypt"]));
    assert!(imported.get("kid_public").is_none(), "{imported}");

    // KMS-held CEK.
    let cek_key = create_aes_key(&app, "A256GCM").await?;
    let got: GetResponse = post_2_1(
        &app,
        Get::new(
            UniqueIdentifier::TextString(cek_key.clone()),
            false,
            None,
            None,
        ),
    )
    .await?;
    let cek = got.object.key_block()?.key_bytes()?;

    // One call produces the complete JWE.
    let jwe: Value = post_json_with_uri(
        &app,
        json!({
            "kid": recipient_kid,
            "alg": "RSA-OAEP-256",
            "enc": "A256GCM",
            "data": B64.encode(DATA),
            "cek_kid": cek_key,
        }),
        "/v1/crypto/encrypt",
    )
    .await?;
    let protected = jwe["protected"]
        .as_str()
        .ok_or_else(|| KmsError::Default(format!("missing protected in {jwe}")))?;
    assert_eq!(
        String::from_utf8_lossy(&field_bytes(&jwe, "protected")?),
        format!(r#"{{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"{recipient_kid}"}}"#)
    );

    // The recipient unwraps the CEK with its private key: it is exactly the KMS key.
    let private_key = PKey::from_rsa(recipient)?;
    let mut decrypter = Decrypter::new(&private_key)?;
    decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    decrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
    decrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;
    let encrypted_key = field_bytes(&jwe, "encrypted_key")?;
    let mut unwrapped = vec![0_u8; decrypter.decrypt_len(&encrypted_key)?];
    let len = decrypter.decrypt(&encrypted_key, &mut unwrapped)?;
    unwrapped.truncate(len);
    assert_eq!(unwrapped.as_slice(), cek.as_slice());

    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &unwrapped,
        Some(&field_bytes(&jwe, "iv")?),
        protected.as_bytes(),
        &field_bytes(&jwe, "ciphertext")?,
        &field_bytes(&jwe, "tag")?,
    )?;
    assert_eq!(plaintext, DATA);
    Ok(())
}

#[tokio::test]
async fn test_jose_public_import_and_cek_kid_errors() -> KResult<()> {
    let mut clap_config = https_clap_config();
    clap_config.google_cse_config.google_cse_enable = false;
    let kms = Box::pin(test_kms_with_google_cse(clap_config)).await;
    let app = test_utils::test_app_with_kms(kms.clone(), None).await;

    let recipient = Rsa::generate(2048)?;
    let recipient_kid = format!("recipient-kpub-{}", Uuid::new_v4());
    let import = public_jwk(&recipient, &recipient_kid, &json!(["encrypt"]));
    drop(post_json_with_uri::<_, _, Value, _>(&app, import.clone(), "/v1/crypto/keys").await?);

    let cek_key = create_aes_key(&app, "A256GCM").await?;
    let cek_key_128 = create_aes_key(&app, "A128GCM").await?;
    let encrypt = |alg: &str, cek_kid: &str| {
        json!({
            "kid": recipient_kid,
            "alg": alg,
            "enc": "A256GCM",
            "data": B64.encode(DATA),
            "cek_kid": cek_kid,
        })
    };

    // `cek_kid` only makes sense with RSA-OAEP key wrapping.
    let aes_kid = create_aes_key(&app, "A256GCM").await?;
    let mut dir = encrypt("dir", &cek_key);
    dir["kid"] = json!(aes_kid);
    let (status, body) = post_json_raw(&app, dir, "/v1/crypto/encrypt").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // A 128-bit key cannot be the CEK of A256GCM.
    let (status, body) = post_json_raw(
        &app,
        encrypt("RSA-OAEP-256", &cek_key_128),
        "/v1/crypto/encrypt",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // The same kid cannot be imported twice.
    let (status, body) = post_json_raw(&app, import, "/v1/crypto/keys").await;
    assert_ne!(status, StatusCode::OK, "{body}");

    // `kid` is import-only.
    let (status, body) = post_json_raw(
        &app,
        json!({"kty": "RSA", "bits": 2048, "kid": "x"}),
        "/v1/crypto/keys",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Sign is not a valid usage for an imported public encryption key.
    let other = Rsa::generate(2048)?;
    let (status, body) = post_json_raw(
        &app,
        public_jwk(&other, &Uuid::new_v4().to_string(), &json!(["sign"])),
        "/v1/crypto/keys",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // `n` alone is not an import: it is still a generation request.
    let generated: Value = post_json_with_uri(
        &app,
        json!({"kty": "RSA", "n": B64.encode(other.n().to_vec())}),
        "/v1/crypto/keys",
    )
    .await?;
    assert!(generated["kid_public"].is_string(), "{generated}");

    // A user holding only `Encrypt` on the CEK key cannot export it as a CEK.
    kms.grant_access(
        &Access {
            unique_identifier: Some(UniqueIdentifier::TextString(cek_key.clone())),
            user_id: "other".to_owned(),
            operation_types: vec![KmipOperation::Encrypt],
        },
        &UserId::from("admin"),
    )
    .await?;
    let res = Box::pin(cek_from_kms_key(
        &kms,
        &UserId::from("other"),
        &cek_key,
        JoseEncAlgorithm::A256GCM,
    ))
    .await;
    assert!(
        matches!(
            res,
            Err(CryptoApiError::Forbidden(_) | CryptoApiError::NotFound(_))
        ),
        "an Encrypt-only user must not obtain the CEK bytes"
    );
    Ok(())
}
