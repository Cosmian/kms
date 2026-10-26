//! Algorithm and wrapped-key branches of the Google CSE endpoints.
//!
//! These run on the default test app (token validation disabled, so the tokens are never
//! checked): with validation disabled, `wrap` stores arbitrary bytes under the `google_cse`
//! key with no additional authenticated data, which is exactly what `privatekeysign` and
//! `privatekeydecrypt` expect to unwrap.

use actix_http::{Request, body::MessageBody};
use actix_web::{
    ResponseError,
    dev::{Service, ServiceResponse},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose};
use openssl::{
    hash::{MessageDigest, hash},
    md::{Md, MdRef},
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
    sign::RsaPssSaltlen,
};
use serde_json::Value;

use super::{DUMMY_TOKEN, import_google_cse_symmetric_key_with_access};
use crate::{
    error::KmsError,
    routes::google_cse::operations::{
        PrivateKeyDecryptRequest, PrivateKeySignRequest, PrivilegedPrivateKeyDecryptRequest,
        PrivilegedUnwrapRequest, PrivilegedWrapRequest, UnwrapRequest, WrapRequest,
    },
    tests::test_utils::{self, post_json_raw},
};

const DEK: [u8; 32] = [7; 32];

async fn app()
-> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error> {
    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned())).await;
    import_google_cse_symmetric_key_with_access(&app)
        .await
        .unwrap();
    app
}

fn b64(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(bytes)
}

fn field(body: &Value, name: &str) -> String {
    body.get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no string field `{name}` in {body}"))
        .to_owned()
}

fn invalid_request() -> StatusCode {
    KmsError::InvalidRequest(String::new()).status_code()
}

/// Assert a failed reply (any non-200 status) whose `details` contain `details_contain`.
fn assert_failed(reply: &(StatusCode, Value), details_contain: &str) {
    let (status, body) = reply;
    assert_ne!(*status, StatusCode::OK, "unexpected success: {body}");
    let details = body
        .get("details")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        details.contains(details_contain),
        "`{details}` does not contain `{details_contain}`"
    );
}

/// Wrap `bytes` with the `google_cse` key (through `/google_cse/wrap`), return the wrapped key.
async fn wrap_bytes<B, S>(app: &S, bytes: &[u8]) -> String
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let (status, body) = post_json_raw(
        app,
        WrapRequest {
            authentication: DUMMY_TOKEN.to_owned(),
            authorization: DUMMY_TOKEN.to_owned(),
            key: b64(bytes),
            reason: String::new(),
        },
        "/google_cse/wrap",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    field(&body, "wrapped_key")
}

/// The same RSA key as PKCS#1 DER and as PKCS#8 DER.
fn der_encodings(rsa: &Rsa<Private>) -> [(&'static str, Vec<u8>); 2] {
    [
        ("PKCS#1", rsa.private_key_to_der().unwrap()),
        (
            "PKCS#8",
            PKey::from_rsa(rsa.clone())
                .unwrap()
                .private_key_to_pkcs8()
                .unwrap(),
        ),
    ]
}

struct SignCase {
    algorithm: &'static str,
    padding: Padding,
    md: &'static MdRef,
    message_digest: MessageDigest,
}

/// The algorithms the FIPS provider accepts: SHA-2 with PKCS#1 v1.5 or RSASSA-PSS.
fn fips_sign_cases() -> Vec<SignCase> {
    [
        (
            "SHA256withRSA",
            Padding::PKCS1,
            Md::sha256(),
            MessageDigest::sha256(),
        ),
        (
            "SHA512withRSA",
            Padding::PKCS1,
            Md::sha512(),
            MessageDigest::sha512(),
        ),
        (
            "SHA256withRSA/PSS",
            Padding::PKCS1_PSS,
            Md::sha256(),
            MessageDigest::sha256(),
        ),
        (
            "SHA512withRSA/PSS",
            Padding::PKCS1_PSS,
            Md::sha512(),
            MessageDigest::sha512(),
        ),
    ]
    .into_iter()
    .map(|(algorithm, padding, md, message_digest)| SignCase {
        algorithm,
        padding,
        md,
        message_digest,
    })
    .collect()
}

/// Every algorithm the endpoint handles. The FIPS provider refuses SHA-1 signatures, so the
/// SHA-1 cases are only exercised in non-FIPS builds.
#[cfg(feature = "non-fips")]
fn sign_cases() -> Vec<SignCase> {
    let mut cases = fips_sign_cases();
    cases.extend(
        [
            (
                "SHA1withRSA",
                Padding::PKCS1,
                Md::sha1(),
                MessageDigest::sha1(),
            ),
            (
                "SHA1withRSA/PSS",
                Padding::PKCS1_PSS,
                Md::sha1(),
                MessageDigest::sha1(),
            ),
        ]
        .map(|(algorithm, padding, md, message_digest)| SignCase {
            algorithm,
            padding,
            md,
            message_digest,
        }),
    );
    cases
}

/// Every algorithm the endpoint handles that the FIPS provider allows.
#[cfg(not(feature = "non-fips"))]
fn sign_cases() -> Vec<SignCase> {
    fips_sign_cases()
}

fn sign_request(
    algorithm: &str,
    digest: &[u8],
    wrapped_private_key: String,
) -> PrivateKeySignRequest {
    PrivateKeySignRequest {
        authentication: DUMMY_TOKEN.to_owned(),
        authorization: DUMMY_TOKEN.to_owned(),
        algorithm: algorithm.to_owned(),
        digest: b64(digest),
        rsa_pss_salt_length: None,
        reason: String::new(),
        wrapped_private_key,
    }
}

#[tokio::test]
async fn private_key_sign_all_algorithms() {
    let app = app().await;
    let rsa = Rsa::generate(2048).unwrap();
    let public_key = PKey::from_rsa(rsa.clone()).unwrap();

    for (encoding, der) in der_encodings(&rsa) {
        let wrapped_private_key = wrap_bytes(&app, &der).await;
        for case in sign_cases() {
            let digest = hash(case.message_digest, b"message").unwrap();
            let (status, body) = post_json_raw(
                &app,
                sign_request(case.algorithm, &digest, wrapped_private_key.clone()),
                "/google_cse/privatekeysign",
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{} {encoding}: {body}",
                case.algorithm
            );
            let signature = general_purpose::STANDARD
                .decode(field(&body, "signature"))
                .unwrap();

            let mut ctx = PkeyCtx::new(&public_key).unwrap();
            ctx.verify_init().unwrap();
            ctx.set_signature_md(case.md).unwrap();
            ctx.set_rsa_padding(case.padding).unwrap();
            if case.padding == Padding::PKCS1_PSS {
                // Google verifies RSASSA-PSS with MGF1 digest == message digest.
                ctx.set_rsa_mgf1_md(case.md).unwrap();
                ctx.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                    .unwrap();
            }
            assert!(
                ctx.verify(&digest, &signature).unwrap(),
                "{} {encoding}: signature does not verify",
                case.algorithm
            );
        }
    }
}

/// `rsa_pss_salt_length` is honored: the signature verifies with that salt length only.
#[tokio::test]
async fn private_key_sign_pss_honors_salt_length() {
    let app = app().await;
    let rsa = Rsa::generate(2048).unwrap();
    let public_key = PKey::from_rsa(rsa.clone()).unwrap();
    let wrapped = wrap_bytes(&app, &rsa.private_key_to_der().unwrap()).await;
    let digest = hash(MessageDigest::sha256(), b"message").unwrap();

    let mut request = sign_request("SHA256withRSA/PSS", &digest, wrapped);
    request.rsa_pss_salt_length = Some(20);
    let (status, body) = post_json_raw(&app, request, "/google_cse/privatekeysign").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let signature = general_purpose::STANDARD
        .decode(field(&body, "signature"))
        .unwrap();

    let verify = |salt: RsaPssSaltlen| {
        let mut ctx = PkeyCtx::new(&public_key).unwrap();
        ctx.verify_init().unwrap();
        ctx.set_signature_md(Md::sha256()).unwrap();
        ctx.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        ctx.set_rsa_mgf1_md(Md::sha256()).unwrap();
        ctx.set_rsa_pss_saltlen(salt).unwrap();
        ctx.verify(&digest, &signature).unwrap_or(false)
    };
    assert!(verify(RsaPssSaltlen::custom(20)));
    assert!(!verify(RsaPssSaltlen::DIGEST_LENGTH));
}

#[tokio::test]
async fn private_key_sign_unknown_algorithm() {
    let app = app().await;
    let rsa = Rsa::generate(2048).unwrap();
    let wrapped = wrap_bytes(&app, &rsa.private_key_to_der().unwrap()).await;
    let digest = hash(MessageDigest::sha256(), b"message").unwrap();

    let reply = post_json_raw(
        &app,
        sign_request("MD5withRSA", &digest, wrapped),
        "/google_cse/privatekeysign",
    )
    .await;
    assert_failed(&reply, "Padding algorithm not handled.");
}

#[tokio::test]
async fn private_key_sign_bad_digest_base64() {
    let app = app().await;
    let rsa = Rsa::generate(2048).unwrap();
    let wrapped = wrap_bytes(&app, &rsa.private_key_to_der().unwrap()).await;

    let mut request = sign_request("SHA256withRSA", b"", wrapped);
    "%%%".clone_into(&mut request.digest);
    let reply = post_json_raw(&app, request, "/google_cse/privatekeysign").await;
    assert_failed(&reply, "");
}

struct DecryptCase {
    algorithm: &'static str,
    padding: Padding,
    md: Option<&'static MdRef>,
}

fn decrypt_cases() -> [DecryptCase; 4] {
    [
        ("RSA/ECB/PKCS1Padding", Padding::PKCS1, None),
        (
            "RSA/ECB/OAEPwithSHA-1andMGF1Padding",
            Padding::PKCS1_OAEP,
            Some(Md::sha1()),
        ),
        (
            "RSA/ECB/OAEPwithSHA-256andMGF1Padding",
            Padding::PKCS1_OAEP,
            Some(Md::sha256()),
        ),
        (
            "RSA/ECB/OAEPwithSHA-512andMGF1Padding",
            Padding::PKCS1_OAEP,
            Some(Md::sha512()),
        ),
    ]
    .map(|(algorithm, padding, md)| DecryptCase {
        algorithm,
        padding,
        md,
    })
}

/// Encrypt `DEK` with the public part of `rsa`, the way a Google client does.
fn encrypt_dek(rsa: &Rsa<Private>, case: &DecryptCase, label: Option<&[u8]>) -> Vec<u8> {
    let key = PKey::from_rsa(rsa.clone()).unwrap();
    let mut ctx = PkeyCtx::new(&key).unwrap();
    ctx.encrypt_init().unwrap();
    ctx.set_rsa_padding(case.padding).unwrap();
    if let Some(md) = case.md {
        ctx.set_rsa_oaep_md(md).unwrap();
        ctx.set_rsa_mgf1_md(md).unwrap();
    }
    if let Some(label) = label {
        ctx.set_rsa_oaep_label(label).unwrap();
    }
    let mut encrypted = Vec::new();
    ctx.encrypt_to_vec(&DEK, &mut encrypted).unwrap();
    encrypted
}

fn decrypt_request(
    algorithm: &str,
    encrypted_data_encryption_key: String,
    wrapped_private_key: String,
) -> PrivateKeyDecryptRequest {
    PrivateKeyDecryptRequest {
        authentication: DUMMY_TOKEN.to_owned(),
        authorization: DUMMY_TOKEN.to_owned(),
        algorithm: algorithm.to_owned(),
        encrypted_data_encryption_key,
        rsa_oaep_label: None,
        reason: String::new(),
        wrapped_private_key,
    }
}

#[tokio::test]
async fn private_key_decrypt_all_algorithms() {
    let app = app().await;
    let rsa = Rsa::generate(2048).unwrap();

    for (encoding, der) in der_encodings(&rsa) {
        let wrapped_private_key = wrap_bytes(&app, &der).await;
        for case in decrypt_cases() {
            let (status, body) = post_json_raw(
                &app,
                decrypt_request(
                    case.algorithm,
                    b64(&encrypt_dek(&rsa, &case, None)),
                    wrapped_private_key.clone(),
                ),
                "/google_cse/privatekeydecrypt",
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{} {encoding}: {body}",
                case.algorithm
            );
            assert_eq!(field(&body, "data_encryption_key"), b64(&DEK));
        }
    }
}

/// `reason` and `perimeter_id` are optional in Google's requests: they may be omitted.
#[tokio::test]
async fn requests_without_optional_fields() {
    let app = app().await;
    let (status, body) = post_json_raw(
        &app,
        serde_json::json!({
            "authentication": DUMMY_TOKEN,
            "authorization": DUMMY_TOKEN,
            "key": b64(&DEK),
        }),
        "/google_cse/wrap",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let wrapped_key = field(&body, "wrapped_key");
    let (status, body) = post_json_raw(
        &app,
        serde_json::json!({
            "authentication": DUMMY_TOKEN,
            "authorization": DUMMY_TOKEN,
            "wrapped_key": wrapped_key,
        }),
        "/google_cse/unwrap",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(field(&body, "key"), b64(&DEK));

    let (status, body) = post_json_raw(
        &app,
        serde_json::json!({
            "authentication": DUMMY_TOKEN,
            "key": b64(&DEK),
            "resource_name": "resource-1",
        }),
        "/google_cse/privilegedwrap",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn private_key_decrypt_oaep_label() {
    let app = app().await;
    let rsa = Rsa::generate(2048).unwrap();
    let wrapped = wrap_bytes(&app, &rsa.private_key_to_der().unwrap()).await;
    let algorithm = "RSA/ECB/OAEPwithSHA-256andMGF1Padding";
    let case = DecryptCase {
        algorithm,
        padding: Padding::PKCS1_OAEP,
        md: Some(Md::sha256()),
    };
    let encrypted = b64(&encrypt_dek(&rsa, &case, Some(b"label")));

    let mut request = decrypt_request(algorithm, encrypted.clone(), wrapped.clone());
    request.rsa_oaep_label = Some(b64(b"label"));
    let (status, body) = post_json_raw(&app, request, "/google_cse/privatekeydecrypt").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(field(&body, "data_encryption_key"), b64(&DEK));

    // without the label the OAEP decryption fails
    let reply = post_json_raw(
        &app,
        decrypt_request(algorithm, encrypted, wrapped),
        "/google_cse/privatekeydecrypt",
    )
    .await;
    assert_failed(&reply, "");
}

#[tokio::test]
async fn private_key_decrypt_unknown_algorithm() {
    let app = app().await;
    let rsa = Rsa::generate(2048).unwrap();
    let wrapped = wrap_bytes(&app, &rsa.private_key_to_der().unwrap()).await;

    let (status, body) = post_json_raw(
        &app,
        decrypt_request("RSA/ECB/OAEPwithMD5", b64(&[1_u8; 256]), wrapped),
        "/google_cse/privatekeydecrypt",
    )
    .await;
    assert_eq!(status, invalid_request(), "{body}");
    assert_failed(&(status, body), "Decryption algorithm not handled.");
}

// OAEP, not PKCS#1 v1.5: OpenSSL's implicit rejection makes a bad PKCS#1 v1.5 ciphertext
// "decrypt" to random bytes instead of failing.
#[tokio::test]
async fn private_key_decrypt_bad_ciphertext() {
    let app = app().await;
    let rsa = Rsa::generate(2048).unwrap();
    let wrapped = wrap_bytes(&app, &rsa.private_key_to_der().unwrap()).await;

    let reply = post_json_raw(
        &app,
        decrypt_request(
            "RSA/ECB/OAEPwithSHA-256andMGF1Padding",
            b64(&[0x5a_u8; 256]),
            wrapped,
        ),
        "/google_cse/privatekeydecrypt",
    )
    .await;
    assert_failed(&reply, "");
}

#[tokio::test]
async fn private_key_decrypt_bad_base64() {
    let app = app().await;
    let rsa = Rsa::generate(2048).unwrap();
    let wrapped = wrap_bytes(&app, &rsa.private_key_to_der().unwrap()).await;

    let reply = post_json_raw(
        &app,
        decrypt_request("RSA/ECB/PKCS1Padding", "%%%".to_owned(), wrapped),
        "/google_cse/privatekeydecrypt",
    )
    .await;
    assert_failed(&reply, "");
}

fn spki_hash(rsa: &Rsa<Private>) -> String {
    let der = PKey::from_rsa(rsa.clone())
        .unwrap()
        .public_key_to_der()
        .unwrap();
    b64(&hash(MessageDigest::sha256(), &der).unwrap())
}

fn privileged_decrypt_request(
    algorithm: &str,
    encrypted_data_encryption_key: String,
    wrapped_private_key: String,
    spki_hash: String,
) -> PrivilegedPrivateKeyDecryptRequest {
    PrivilegedPrivateKeyDecryptRequest {
        authentication: DUMMY_TOKEN.to_owned(),
        algorithm: algorithm.to_owned(),
        encrypted_data_encryption_key,
        rsa_oaep_label: None,
        reason: String::new(),
        wrapped_private_key,
        spki_hash,
        spki_hash_algorithm: "SHA-256".to_owned(),
    }
}

// `privilegedprivatekeydecrypt` only loads PKCS#1 DER private keys (`Rsa::private_key_from_der`),
// unlike `privatekeydecrypt`, which also accepts PKCS#8.
#[tokio::test]
async fn privileged_private_key_decrypt_all_algorithms() {
    let app = app().await;
    let rsa = Rsa::generate(2048).unwrap();
    let wrapped = wrap_bytes(&app, &rsa.private_key_to_der().unwrap()).await;

    for case in decrypt_cases() {
        let (status, body) = post_json_raw(
            &app,
            privileged_decrypt_request(
                case.algorithm,
                b64(&encrypt_dek(&rsa, &case, None)),
                wrapped.clone(),
                spki_hash(&rsa),
            ),
            "/google_cse/privilegedprivatekeydecrypt",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}: {body}", case.algorithm);
        assert_eq!(field(&body, "data_encryption_key"), b64(&DEK));
    }
}

#[tokio::test]
async fn privileged_private_key_decrypt_spki_mismatch() {
    let app = app().await;
    let rsa = Rsa::generate(2048).unwrap();
    let other = Rsa::generate(2048).unwrap();
    let wrapped = wrap_bytes(&app, &rsa.private_key_to_der().unwrap()).await;
    let case = &decrypt_cases()[0];

    let reply = post_json_raw(
        &app,
        privileged_decrypt_request(
            case.algorithm,
            b64(&encrypt_dek(&rsa, case, None)),
            wrapped,
            spki_hash(&other),
        ),
        "/google_cse/privilegedprivatekeydecrypt",
    )
    .await;
    assert_failed(
        &reply,
        "spki_hash does not match with the associated private key.",
    );
}

#[tokio::test]
async fn privileged_private_key_decrypt_bad_spki_algorithm() {
    let app = app().await;
    let rsa = Rsa::generate(2048).unwrap();
    let wrapped = wrap_bytes(&app, &rsa.private_key_to_der().unwrap()).await;
    let case = &decrypt_cases()[0];

    let mut request = privileged_decrypt_request(
        case.algorithm,
        b64(&encrypt_dek(&rsa, case, None)),
        wrapped,
        spki_hash(&rsa),
    );
    "sha-999".clone_into(&mut request.spki_hash_algorithm);
    let (status, body) =
        post_json_raw(&app, request, "/google_cse/privilegedprivatekeydecrypt").await;
    assert_eq!(status, invalid_request(), "{body}");
    assert_failed(&(status, body), "Invalid spki hash algorithm");
}

fn unwrap_request(wrapped_key: String) -> UnwrapRequest {
    UnwrapRequest {
        authentication: DUMMY_TOKEN.to_owned(),
        authorization: DUMMY_TOKEN.to_owned(),
        wrapped_key,
        reason: String::new(),
    }
}

#[tokio::test]
async fn wrapped_key_too_short() {
    let app = app().await;

    // nonce (12) + tag (16) = 28 bytes minimum
    let (status, body) =
        post_json_raw(&app, unwrap_request(b64(&[0_u8; 27])), "/google_cse/unwrap").await;
    assert_eq!(status, invalid_request(), "{body}");
    assert_failed(
        &(status, body),
        "Invalid wrapped key - insufficient length.",
    );
}

#[tokio::test]
async fn wrapped_key_tampered_tag() {
    let app = app().await;
    let wrapped = wrap_bytes(&app, &DEK).await;

    // sanity: the untouched wrapped key unwraps
    let (status, body) =
        post_json_raw(&app, unwrap_request(wrapped.clone()), "/google_cse/unwrap").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(field(&body, "key"), b64(&DEK));

    let mut bytes = general_purpose::STANDARD.decode(wrapped).unwrap();
    let last = bytes.last_mut().unwrap();
    *last ^= 0x01;
    let reply = post_json_raw(&app, unwrap_request(b64(&bytes)), "/google_cse/unwrap").await;
    assert_failed(&reply, "");
}

#[tokio::test]
async fn wrapped_key_bad_base64() {
    let app = app().await;

    let reply = post_json_raw(&app, unwrap_request("%%%".to_owned()), "/google_cse/unwrap").await;
    assert_failed(&reply, "");
}

#[tokio::test]
async fn wrap_bad_base64_key() {
    let app = app().await;

    let reply = post_json_raw(
        &app,
        WrapRequest {
            authentication: DUMMY_TOKEN.to_owned(),
            authorization: DUMMY_TOKEN.to_owned(),
            key: "%%%".to_owned(),
            reason: String::new(),
        },
        "/google_cse/wrap",
    )
    .await;
    assert_failed(&reply, "");
}

#[tokio::test]
async fn privileged_unwrap_wrong_resource_name() {
    let app = app().await;

    let (status, body) = post_json_raw(
        &app,
        PrivilegedWrapRequest {
            authentication: DUMMY_TOKEN.to_owned(),
            key: b64(&DEK),
            perimeter_id: String::new(),
            resource_name: "res-a".to_owned(),
            reason: String::new(),
        },
        "/google_cse/privilegedwrap",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let wrapped_key = field(&body, "wrapped_key");

    let unwrap = |resource_name: &str| PrivilegedUnwrapRequest {
        authentication: DUMMY_TOKEN.to_owned(),
        reason: String::new(),
        resource_name: resource_name.to_owned(),
        wrapped_key: wrapped_key.clone(),
    };
    let (status, body) = post_json_raw(&app, unwrap("res-a"), "/google_cse/privilegedunwrap").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(field(&body, "key"), b64(&DEK));

    let reply = post_json_raw(&app, unwrap("res-b"), "/google_cse/privilegedunwrap").await;
    assert_failed(&reply, "");
}
