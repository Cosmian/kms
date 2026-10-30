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

    // Import the recipient's public key under its own kid; `cek_kid` needs `wrapKey`.
    let imported: Value = post_json_with_uri(
        &app,
        public_jwk(&recipient, &recipient_kid, &json!(["encrypt", "wrapKey"])),
        "/v1/crypto/keys",
    )
    .await?;
    assert_eq!(imported["kid"], recipient_kid.as_str());
    assert_eq!(imported["kty"], "RSA");
    assert_eq!(imported["key_ops"], json!(["encrypt", "wrapKey"]));
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
    let import = public_jwk(&recipient, &recipient_kid, &json!(["encrypt", "wrapKey"]));
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

/// An imported public-only key has no private key the KMS could decrypt with: the CEK must not
/// be parked in the cache for it. Also: an oversized public exponent is refused at import.
#[tokio::test]
async fn test_public_only_import_caches_no_cek_and_bounds_exponent() -> KResult<()> {
    use crate::routes::jose::cek_cache::{insert_cek, peek_cek};

    let mut clap_config = https_clap_config();
    clap_config.google_cse_config.google_cse_enable = false;
    let kms = Box::pin(test_kms_with_google_cse(clap_config)).await;
    let app = test_utils::test_app_with_kms(kms.clone(), None).await;

    let recipient = Rsa::generate(2048)?;
    let recipient_kid = format!("recipient-kpub-{}", Uuid::new_v4());
    drop(
        post_json_with_uri::<_, _, Value, _>(
            &app,
            public_jwk(&recipient, &recipient_kid, &json!(["encrypt", "wrapKey"])),
            "/v1/crypto/keys",
        )
        .await?,
    );
    let cek_key = create_aes_key(&app, "A256GCM").await?;
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
    let encrypted_key = field_bytes(&jwe, "encrypted_key")?;

    let public: GetResponse = post_2_1(
        &app,
        Get::new(
            UniqueIdentifier::TextString(recipient_kid.clone()),
            false,
            None,
            None,
        ),
    )
    .await?;
    assert!(
        peek_cek(&kms, &recipient_kid, &encrypted_key, &public.object)
            .await
            .is_none(),
        "no CEK may be cached for a key without a linked private key"
    );
    // Control: the same lookup does find an entry that was actually inserted.
    insert_cek(&kms, &recipient_kid, b"other", &public.object, &[1_u8; 32]).await;
    assert!(
        peek_cek(&kms, &recipient_kid, b"other", &public.object)
            .await
            .is_some()
    );

    // e = 2^300 + 1 is odd and large: refused at import, not later as a 500 in /encrypt.
    let mut huge_e = vec![0_u8; 38];
    huge_e[0] = 0x10;
    huge_e[37] = 0x01;
    let mut import = public_jwk(&recipient, &Uuid::new_v4().to_string(), &json!(["encrypt"]));
    import["e"] = json!(B64.encode(huge_e));
    let (status, body) = post_json_raw(&app, import, "/v1/crypto/keys").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    Ok(())
}

/// A CEK cached under one RSA key must never be served for another key, even when both keys
/// have the same fingerprint object (HSM sensitive keys are metadata stubs with no identity).
#[tokio::test]
async fn test_cek_cache_is_bound_to_the_key_uid() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attributes, kmip_types::CryptographicAlgorithm,
        requests::create_symmetric_key_kmip_object,
    };

    use crate::routes::jose::cek_cache::{insert_cek, peek_cek};

    let mut clap_config = https_clap_config();
    clap_config.google_cse_config.google_cse_enable = false;
    let kms = Box::pin(test_kms_with_google_cse(clap_config)).await;

    // Same object for both keys: stands in for two same-size sensitive HSM key stubs.
    let stub = create_symmetric_key_kmip_object(
        "cosmian",
        &[0_u8; 32],
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            ..Attributes::default()
        },
    )?;
    let encrypted_key = [7_u8; 256];
    let cek = [9_u8; 32];

    insert_cek(&kms, "key-a", &encrypted_key, &stub, &cek).await;

    let hit = peek_cek(&kms, "key-a", &encrypted_key, &stub).await;
    assert_eq!(hit.as_deref().map(Vec::as_slice), Some(cek.as_slice()));
    assert!(
        peek_cek(&kms, "key-b", &encrypted_key, &stub)
            .await
            .is_none(),
        "a CEK cached under key-a must not be returned for key-b"
    );
    Ok(())
}

/// Importing a private key as `x` also creates `x_pk`: when that uid is taken the import is
/// refused up front and no orphan private key `x` is left behind.
#[tokio::test]
async fn test_private_import_refused_when_derived_public_uid_exists() -> KResult<()> {
    let app = test_utils::test_app(None).await;
    let rsa = Rsa::generate(2048)?;
    let kid = format!("x-{}", Uuid::new_v4());

    drop(
        post_json_with_uri::<_, _, Value, _>(
            &app,
            public_jwk(&rsa, &format!("{kid}_pk"), &json!(["encrypt"])),
            "/v1/crypto/keys",
        )
        .await?,
    );

    let mut private = public_jwk(&rsa, &kid, &json!(["sign"]));
    for (name, value) in [
        ("d", rsa.d()),
        (
            "p",
            rsa.p()
                .ok_or_else(|| KmsError::Default("no p".to_owned()))?,
        ),
        (
            "q",
            rsa.q()
                .ok_or_else(|| KmsError::Default("no q".to_owned()))?,
        ),
        (
            "dp",
            rsa.dmp1()
                .ok_or_else(|| KmsError::Default("no dp".to_owned()))?,
        ),
        (
            "dq",
            rsa.dmq1()
                .ok_or_else(|| KmsError::Default("no dq".to_owned()))?,
        ),
        (
            "qi",
            rsa.iqmp()
                .ok_or_else(|| KmsError::Default("no qi".to_owned()))?,
        ),
    ] {
        private[name] = json!(B64.encode(value.to_vec()));
    }
    private["key_ops"] = Value::Null;

    let (status, body) = post_json_raw(&app, private.clone(), "/v1/crypto/keys").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // No orphan: the uid `kid` is still free, a symmetric import under it succeeds.
    let imported: Value = post_json_with_uri(
        &app,
        json!({"kty": "oct", "alg": "A256GCM", "kid": kid, "k": B64.encode([1_u8; 32])}),
        "/v1/crypto/keys",
    )
    .await?;
    assert_eq!(imported["kid"], kid.as_str());
    Ok(())
}

/// Regression (gate #2 F3): a `cek_kid` export follows the rules of the equivalent wrapped KMIP
/// Export: the recipient key must allow `WrapKey`, and the RSA-OAEP hashes must pass the
/// algorithm policy (DEFAULT excludes SHA-1, so `RSA-OAEP` is refused, `RSA-OAEP-256` is not).
#[tokio::test]
async fn test_cek_kid_enforces_wrap_usage_and_algorithm_policy() -> KResult<()> {
    let mut clap_config = https_clap_config();
    clap_config.google_cse_config.google_cse_enable = false;
    clap_config.kmip_policy.policy_id = Some("DEFAULT".to_owned());
    let kms = Box::pin(test_kms_with_google_cse(clap_config)).await;
    let app = test_utils::test_app_with_kms(kms, None).await;

    let recipient = Rsa::generate(3072)?;
    let import = |key_ops: Value| {
        let kid = format!("recipient-kpub-{}", Uuid::new_v4());
        (public_jwk(&recipient, &kid, &key_ops), kid)
    };
    let (wrap_jwk, wrap_kid) = import(json!(["encrypt", "wrapKey"]));
    let (encrypt_only_jwk, encrypt_only_kid) = import(json!(["encrypt"]));
    for jwk in [wrap_jwk, encrypt_only_jwk] {
        drop(post_json_with_uri::<_, _, Value, _>(&app, jwk, "/v1/crypto/keys").await?);
    }
    let cek_key = create_aes_key(&app, "A256GCM").await?;
    let encrypt = |kid: &str, alg: &str| {
        json!({
            "kid": kid,
            "alg": alg,
            "enc": "A256GCM",
            "data": B64.encode(DATA),
            "cek_kid": cek_key,
        })
    };

    // Recipient without WrapKey: refused.
    let (status, body) = post_json_raw(
        &app,
        encrypt(&encrypt_only_kid, "RSA-OAEP-256"),
        "/v1/crypto/encrypt",
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        body["description"].to_string().contains("WrapKey"),
        "{body}"
    );

    // RSA-OAEP (SHA-1 / MGF1-SHA-1) is outside the DEFAULT policy: refused.
    let (status, body) =
        post_json_raw(&app, encrypt(&wrap_kid, "RSA-OAEP"), "/v1/crypto/encrypt").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        body["description"].to_string().contains("Deprecated hash"),
        "{body}"
    );

    // Allowed: WrapKey usage and RSA-OAEP-256.
    let jwe: Value = post_json_with_uri(
        &app,
        encrypt(&wrap_kid, "RSA-OAEP-256"),
        "/v1/crypto/encrypt",
    )
    .await?;
    assert!(!field_bytes(&jwe, "encrypted_key")?.is_empty(), "{jwe}");
    Ok(())
}
