#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::panic_in_result_fn,
    clippy::unwrap_in_result,
    clippy::expect_used
)]

use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose};
use cosmian_logger::{debug, log_init, reexport::tracing};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
    sign::Signer,
};
use serde::{Deserialize, Serialize};
use test_kms_server::{TestsContext, start_default_test_kms_server_with_utimaco_hsm};

use crate::{
    actions::kms::{
        shared::ImportSecretDataOrKeyAction, symmetric::keys::create_key::CreateKeyAction,
    },
    error::{KmsCliError, result::KmsCliResult},
};

pub(crate) async fn generate_google_jwt() -> KmsCliResult<String> {
    #[derive(Deserialize)]
    struct RefreshToken {
        pub id_token: String,
    }

    let client_id = std::env::var("TEST_GOOGLE_OAUTH_CLIENT_ID").map_err(|e| {
        KmsCliError::ServerError(format!("Failed to get TEST_GOOGLE_OAUTH_CLIENT_ID: {e}"))
    })?;
    let client_secret = std::env::var("TEST_GOOGLE_OAUTH_CLIENT_SECRET").map_err(|e| {
        KmsCliError::ServerError(format!(
            "Failed to get TEST_GOOGLE_OAUTH_CLIENT_SECRET: {e}"
        ))
    })?;
    let refresh_token = std::env::var("TEST_GOOGLE_OAUTH_REFRESH_TOKEN").map_err(|e| {
        KmsCliError::ServerError(format!(
            "Failed to get TEST_GOOGLE_OAUTH_REFRESH_TOKEN: {e}"
        ))
    })?;

    assert!(!client_id.is_empty());
    assert!(!client_secret.is_empty());
    assert!(!refresh_token.is_empty());

    let res = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await
        .unwrap();

    let id_token = res.json::<RefreshToken>().await.unwrap().id_token;

    tracing::debug!("ID token: {id_token:?}");

    Ok(id_token)
}

// For digest test: local HMAC-SHA256 compute mirroring server logic
fn local_resource_key_hash(resource_name: &str, perimeter_id: &str, dek: &[u8]) -> String {
    // Server side uses: HMAC-SHA256(key=unwrapped_dek, data="ResourceKeyDigest:{resource_name}:{perimeter_id}")
    let data = format!("ResourceKeyDigest:{resource_name}:{perimeter_id}");
    let key = PKey::hmac(dek).expect("hmac pkey");
    let mut signer = Signer::new(MessageDigest::sha256(), &key).expect("signer");
    signer.update(data.as_bytes()).expect("update");
    general_purpose::STANDARD.encode(signer.sign_to_vec().expect("sign"))
}

// ----------------------------- Helpers -----------------------------

async fn import_google_cse_demo_key_and_grant(ctx: &TestsContext) -> KmsCliResult<()> {
    // Import the Google CSE symmetric key from documentation as JSON TTLV
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    // Create the Google CSE key in the HSM (prefix hsm::0::)
    let wrapping_key_id = CreateKeyAction {
        key_id: Some(format!("hsm::0::another_google_cse_{ts}")),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let _cse_key_id = ImportSecretDataOrKeyAction {
        key_file: PathBuf::from(
            "../../documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.json",
        ),
        replace_existing: true,
        unwrap: true,
        wrapping_key_id: Some(wrapping_key_id.to_string()),
        key_id: Some("google_cse".to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct PrivateKeySignReq<'a> {
    authentication: &'a str,
    authorization: &'a str,
    algorithm: &'a str,
    digest: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rsa_pss_salt_length: Option<i32>,
    reason: &'a str,
    wrapped_private_key: &'a str,
}

#[derive(Deserialize, Serialize)]
struct PrivateKeySignResp {
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct PrivateKeyDecryptReq<'a> {
    authentication: &'a str,
    authorization: &'a str,
    algorithm: &'a str,
    #[serde(rename = "encrypted_data_encryption_key")]
    encrypted_dek: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rsa_oaep_label: Option<String>,
    reason: &'a str,
    wrapped_private_key: &'a str,
}

#[derive(Deserialize, Serialize)]
struct PrivateKeyDecryptResp {
    #[serde(rename = "data_encryption_key")]
    dek: String,
}

#[derive(Serialize, Deserialize)]
struct WrapRequest<'a> {
    authentication: &'a str,
    authorization: &'a str,
    key: &'a str,
    reason: &'a str,
}

#[derive(Deserialize, Serialize)]
struct WrapResponse {
    wrapped_key: String,
}

#[derive(Serialize, Deserialize)]
struct UnwrapRequest<'a> {
    authentication: &'a str,
    authorization: &'a str,
    wrapped_key: &'a str,
    reason: &'a str,
}

#[derive(Deserialize, Serialize)]
struct UnwrapResponse {
    key: String,
}

#[derive(Serialize, Deserialize)]
struct PrivilegedWrapRequest<'a> {
    authentication: &'a str,
    key: &'a str,
    perimeter_id: &'a str,
    resource_name: &'a str,
    reason: &'a str,
}

#[derive(Deserialize, Serialize)]
struct PrivilegedWrapResponse {
    wrapped_key: String,
}

#[derive(Serialize, Deserialize)]
struct PrivilegedUnwrapRequest<'a> {
    authentication: &'a str,
    resource_name: &'a str,
    wrapped_key: &'a str,
    reason: &'a str,
}

#[derive(Deserialize, Serialize)]
struct PrivilegedUnwrapResponse {
    key: String,
}

#[derive(Serialize, Deserialize)]
struct PrivilegedPrivateKeyDecryptRequest<'a> {
    authentication: &'a str,
    algorithm: &'a str,
    #[serde(rename = "encrypted_data_encryption_key")]
    encrypted_dek: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rsa_oaep_label: Option<String>,
    reason: &'a str,
    wrapped_private_key: &'a str,
    spki_hash: &'a str,
    spki_hash_algorithm: &'a str,
}

#[derive(Deserialize, Serialize)]
struct PrivilegedPrivateKeyDecryptResponse {
    #[serde(rename = "data_encryption_key")]
    dek: String,
}

#[derive(Serialize, Deserialize)]
struct DigestRequest<'a> {
    authorization: &'a str,
    wrapped_key: &'a str,
    reason: &'a str,
}

#[derive(Deserialize, Serialize)]
struct DigestResponse {
    #[serde(rename = "resource_key_hash")]
    hash: String,
}

// ----------------------------- Tests -----------------------------
#[tokio::test]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints and an Utimaco HSM"]
async fn hsm_test_google_cse_status() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;
    let status = ctx.get_owner_client().google_cse_status().await?;
    // In the client API, StatusResponse only exposes `kacls_url`
    assert!(!status.kacls_url.is_empty());
    assert!(status.kacls_url.contains("http"));
    Ok(())
}

#[tokio::test]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints and an Utimaco HSM"]
async fn hsm_test_google_cse_private_key_sign() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;
    let owner = ctx.get_owner_client();

    // Import google_cse key matching the wrapped private key used below
    import_google_cse_demo_key_and_grant(ctx).await?;

    let wrapped_private_key: &str =
        include_str!("../../../../../../documentation/docs/google_cse/test_wrapped_private_key");
    let digest = "gXIjp2D7tR4WvHJBXaINWLekf5k5AeKRw4zkySYDDYs="; // base64

    let req = PrivateKeySignReq {
        authentication: "test",
        authorization: "test",
        algorithm: "SHA256withRSA",
        digest,
        rsa_pss_salt_length: None,
        reason: "Gmail",
        wrapped_private_key,
    };

    debug!("private key sign request post");
    let resp: PrivateKeySignResp = owner
        .post_no_ttlv("/google_cse/privatekeysign", Some(&req))
        .await?;
    debug!("private key sign response: {:?}", resp.signature);

    // Verify signature with test public key
    let user_public_key_pem_pkcs1 =
        include_bytes!("../../../../../../test_data/certificates/gmail_cse/test_public_key");
    let rsa_public_key = Rsa::public_key_from_pem_pkcs1(user_public_key_pem_pkcs1)
        .map_err(|e| KmsCliError::Default(e.to_string()))?;
    let public_key =
        PKey::from_rsa(rsa_public_key).map_err(|e| KmsCliError::Default(e.to_string()))?;

    let mut pk = PkeyCtx::new(&public_key).map_err(|e| KmsCliError::Default(e.to_string()))?;
    pk.verify_init()
        .map_err(|e| KmsCliError::Default(e.to_string()))?;
    pk.verify(
        &general_purpose::STANDARD.decode(digest)?,
        &general_purpose::STANDARD.decode(resp.signature)?,
    )
    .map_err(|e| KmsCliError::Default(e.to_string()))?;

    Ok(())
}

#[tokio::test]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints and an Utimaco HSM"]
async fn hsm_test_google_cse_encrypt_and_private_key_decrypt() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;
    let owner = ctx.get_owner_client();

    import_google_cse_demo_key_and_grant(ctx).await?;

    // Encrypt a DEK with the test public key (PKCS1)
    let dek = vec![1_u8; 32];
    let pub_key_pem =
        include_bytes!("../../../../../../test_data/certificates/gmail_cse/test_public_key");
    let rsa_public_key = Rsa::public_key_from_pem_pkcs1(pub_key_pem)
        .map_err(|e| KmsCliError::Default(e.to_string()))?;
    let public_key =
        PKey::from_rsa(rsa_public_key).map_err(|e| KmsCliError::Default(e.to_string()))?;
    let mut pk_ctx = PkeyCtx::new(&public_key).map_err(|e| KmsCliError::Default(e.to_string()))?;
    pk_ctx.encrypt_init().unwrap();
    pk_ctx.set_rsa_padding(Padding::PKCS1).unwrap();
    let sz = pk_ctx.encrypt(&dek, None).unwrap();
    let mut encrypted_dek = vec![0_u8; sz];
    pk_ctx.encrypt(&dek, Some(&mut encrypted_dek)).unwrap();
    let encrypted_dek_b64 = general_purpose::STANDARD.encode(encrypted_dek);

    let wrapped_private_key: &str =
        include_str!("../../../../../../documentation/docs/google_cse/test_wrapped_private_key");

    let req = PrivateKeyDecryptReq {
        authentication: "test",
        authorization: "test",
        algorithm: "RSA/ECB/PKCS1Padding",
        encrypted_dek: &encrypted_dek_b64,
        rsa_oaep_label: None,
        reason: "Gmail",
        wrapped_private_key,
    };

    let resp: PrivateKeyDecryptResp = owner
        .post_no_ttlv("/google_cse/privatekeydecrypt", Some(&req))
        .await?;

    assert_eq!(general_purpose::STANDARD.encode(dek), resp.dek);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints and an Utimaco HSM"]
async fn hsm_test_google_cse_wrap_unwrap_key() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;
    let owner = ctx.get_owner_client();

    // Create or import the google_cse key — use import to ensure expected UID
    import_google_cse_demo_key_and_grant(ctx).await?;

    let dek_b64 = "wHrlNOTI9mU6PBdqiq7EQA=="; // arbitrary base64 key

    let wrap_req = WrapRequest {
        authentication: "test",
        authorization: "test",
        key: dek_b64,
        reason: "",
    };
    let wrap_resp: WrapResponse = owner
        .post_no_ttlv("/google_cse/wrap", Some(&wrap_req))
        .await?;

    let unwrap_req = UnwrapRequest {
        authentication: "test",
        authorization: "test",
        wrapped_key: &wrap_resp.wrapped_key,
        reason: "",
    };
    let unwrap_resp: UnwrapResponse = owner
        .post_no_ttlv("/google_cse/unwrap", Some(&unwrap_req))
        .await?;

    assert_eq!(dek_b64, unwrap_resp.key);
    Ok(())
}

#[tokio::test]
async fn test_google_cse_resource_key_hash() -> KmsCliResult<()> {
    // This ports server-side test_google_cse_resource_key_hash without hitting the server
    // Use same two examples as documentation and server test, comparing hex digests
    let dek_hex = "6a68079290123ed8f23c845cc8bda91cd961c0246b79446662919e336920cbef";
    let dek_bytes = hex::decode(dek_hex)?;
    let resource_name = "//googleapis.com/testcase/hJB0PzRI7nl79LC18qaV8WMDCBALBSs9BREcq79MfVw";
    let h_b64 = local_resource_key_hash(resource_name, "", &dek_bytes);
    let h_hex = hex::encode(general_purpose::STANDARD.decode(h_b64)?);
    assert_eq!(
        h_hex,
        "4d9aafeb06cd0e812d0f3c10f18573a5aee4c86300a104fad9b258f0b71bd813"
    );

    let dek_hex2 = "05b62b91cb66f19e27789fb69eb680fac113a70a120178d6cfa6b1b4cb11bb95";
    let dek_bytes2 = hex::decode(dek_hex2)?;
    let resource_name2 = "//googleapis.com/testcase/od8yfZiS5ZF2RN27X4ClalsV6LobL2FwKRk4qOJxWdE";
    let h2_b64 = local_resource_key_hash(resource_name2, "perimeter1", &dek_bytes2);
    let h2_hex = hex::encode(general_purpose::STANDARD.decode(h2_b64)?);
    assert_eq!(
        h2_hex,
        "1b6231a171bc10ef99dd3b08f0742620811a59191570284d32b674c531cc2da5"
    );

    Ok(())
}

// #[tokio::test]
// #[ignore = "Requires Google OAuth credentials and access to Google CSE privileged endpoints and an Utimaco HSM"]
// async fn hsm_test_google_cse_privileged_wrap_unwrap_key() -> KmsCliResult<()> {
//     log_init(None);
//     let ctx = start_default_test_kms_server_with_utimaco_hsm().await;
//     let owner = ctx.get_owner_client();
//     import_google_cse_demo_key_and_grant(ctx).await?;

//     let dek_b64 = "wHrlNOTI9mU6PBdqiq7EQA==";
//     let resource_name = "resource_name_test";
//     let token: String = generate_google_jwt()
//         .await
//         .expect("Error on token generation");

//     let p_wrap = PrivilegedWrapRequest {
//         authentication: &token,
//         key: dek_b64,
//         perimeter_id: "",
//         resource_name,
//         reason: "",
//     };
//     let w: PrivilegedWrapResponse = owner
//         .post_no_ttlv("/google_cse/privilegedwrap", Some(&p_wrap))
//         .await?;

//     let p_unwrap = PrivilegedUnwrapRequest {
//         authentication: "test",
//         resource_name,
//         wrapped_key: &w.wrapped_key,
//         reason: "",
//     };
//     let u: PrivilegedUnwrapResponse = owner
//         .post_no_ttlv("/google_cse/privilegedunwrap", Some(&p_unwrap))
//         .await?;

//     assert_eq!(dek_b64, u.key);
//     Ok(())
// }

// #[tokio::test]
// #[ignore = "Requires Google OAuth credentials and access to Google CSE privileged endpoints and an Utimaco HSM"]
// async fn hsm_test_google_cse_privileged_private_key_decrypt() -> KmsCliResult<()> {
//     log_init(None);
//     let ctx = start_default_test_kms_server_with_utimaco_hsm().await;
//     let owner = ctx.get_owner_client();
//     import_google_cse_demo_key_and_grant(ctx).await?;

//     // Load user's public key (PKCS1) and compute SPKI hash
//     let user_public_key_pem_pkcs1 =
//         include_bytes!("../../../../../../test_data/certificates/gmail_cse/test_public_key");
//     let rsa_public_key = Rsa::public_key_from_pem_pkcs1(user_public_key_pem_pkcs1)
//         .map_err(|e| KmsCliError::Default(e.to_string()))?;
//     let public_key =
//         PKey::from_rsa(rsa_public_key).map_err(|e| KmsCliError::Default(e.to_string()))?;
//     let spki_hash = openssl::hash::hash(
//         MessageDigest::sha256(),
//         &public_key
//             .public_key_to_der()
//             .map_err(|e| KmsCliError::Default(e.to_string()))?,
//     )
//     .map_err(|e| KmsCliError::Default(e.to_string()))?;
//     let spki_hash_b64 = general_purpose::STANDARD.encode(spki_hash);

//     // Encrypt a 32-byte DEK with the public key (PKCS1 padding)
//     let dek = vec![1_u8; 32];
//     let mut pk_ctx = PkeyCtx::new(&public_key).map_err(|e| KmsCliError::Default(e.to_string()))?;
//     pk_ctx.encrypt_init()
//         .map_err(|e| KmsCliError::Default(e.to_string()))?;
//     pk_ctx.set_rsa_padding(Padding::PKCS1)
//         .map_err(|e| KmsCliError::Default(e.to_string()))?;
//     let sz = pk_ctx
//         .encrypt(&dek, None)
//         .map_err(|e| KmsCliError::Default(e.to_string()))?;
//     let mut encrypted_dek = vec![0u8; sz];
//     pk_ctx.encrypt(&dek, Some(&mut encrypted_dek))
//         .map_err(|e| KmsCliError::Default(e.to_string()))?;
//     let encrypted_dek_b64 = general_purpose::STANDARD.encode(encrypted_dek);

//     let wrapped_private_key: &str =
//         include_str!("../../../../../../documentation/docs/google_cse/test_wrapped_private_key");
//     let token: String = generate_google_jwt()
//         .await
//         .expect("Error on token generation");

//     let req = PrivilegedPrivateKeyDecryptRequest {
//         authentication: &token,
//         algorithm: "RSA/ECB/PKCS1Padding",
//         encrypted_dek: &encrypted_dek_b64,
//         rsa_oaep_label: None,
//         reason: "Gmail",
//         wrapped_private_key,
//         spki_hash: &spki_hash_b64,
//         spki_hash_algorithm: "SHA-256",
//     };

//     let resp: PrivilegedPrivateKeyDecryptResponse = owner
//         .post_no_ttlv("/google_cse/privilegedprivatekeydecrypt", Some(&req))
//         .await?;

//     assert_eq!(general_purpose::STANDARD.encode(dek), resp.dek);
//     Ok(())
// }

// NOTE: The original server-side test `test_google_cse_custom_jwt` validates a custom JWT
// against the server's JWKS and uses internal helpers. Replicating it here would require
// additional crypto and config wiring. If needed, we can add it later using jsonwebtoken
// with a local RS256 key and fetch `/google_cse/certs` to validate. For now, it is omitted.
