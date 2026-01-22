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
use cosmian_kmip::kmip_2_1::KmipOperation;
use cosmian_logger::{
    debug, info, log_init,
    reexport::tracing::{self, trace},
};
use openssl::{
    hash::MessageDigest,
    md::Md,
    pkey::PKey,
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
    sign::Signer,
};
use serde::Deserialize;
use serial_test::serial;
use test_kms_server::{
    TestsContext,
    reexport::cosmian_kms_server::routes::google_cse::operations::{
        PrivateKeyDecryptRequest, PrivateKeyDecryptResponse, PrivateKeySignRequest,
        PrivateKeySignResponse, PrivilegedPrivateKeyDecryptRequest,
        PrivilegedPrivateKeyDecryptResponse, PrivilegedUnwrapRequest, PrivilegedUnwrapResponse,
        PrivilegedWrapRequest, PrivilegedWrapResponse, UnwrapRequest, UnwrapResponse, WrapRequest,
        WrapResponse,
    },
    start_default_test_kms_server_with_utimaco_and_kek,
    start_default_test_kms_server_with_utimaco_hsm,
};

use crate::{
    actions::kms::{
        access::GrantAccess, google::key_pairs::create::CreateKeyPairsAction,
        shared::ImportSecretDataOrKeyAction, symmetric::keys::create_key::CreateKeyAction,
    },
    error::{KmsCliError, result::KmsCliResult},
    tests::kms::certificates::certify::import_root_and_intermediate,
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
    let _cse_key_id = ImportSecretDataOrKeyAction {
        key_file: PathBuf::from(
            "../../documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.json",
        ),
        replace_existing: true,
        unwrap: true,
        key_id: Some("google_cse".to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    GrantAccess {
        user: "*".to_string(),
        object_uid: Some("google_cse".to_string()),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_owner_client())
    .await?;

    Ok(())
}

// ----------------------------- Tests -----------------------------
#[tokio::test]
#[serial]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints and an Utimaco HSM"]
async fn hsm_google_cse_status() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server_with_utimaco_and_kek().await;
    let status = ctx.get_owner_client().google_cse_status().await?;
    // In the client API, StatusResponse only exposes `kacls_url`
    assert!(!status.kacls_url.is_empty());
    assert!(status.kacls_url.contains("http"));
    Ok(())
}

#[tokio::test]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints and an Utimaco HSM"]
#[serial]
async fn hsm_google_cse_private_key_sign() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;
    let owner = ctx.get_owner_client();

    // Import google_cse key matching the wrapped private key used below
    import_google_cse_demo_key_and_grant(ctx).await?;

    let wrapped_private_key: &str =
        include_str!("../../../../../../documentation/docs/google_cse/test_wrapped_private_key");
    let digest = "gXIjp2D7tR4WvHJBXaINWLekf5k5AeKRw4zkySYDDYs="; // base64

    let req = PrivateKeySignRequest {
        authentication: "test".to_string(),
        authorization: "test".to_string(),
        algorithm: "SHA256withRSA".to_string(),
        digest: digest.to_string(),
        rsa_pss_salt_length: None,
        reason: "Gmail".to_string(),
        wrapped_private_key: wrapped_private_key.to_string(),
    };

    debug!("private key sign request post");
    let resp: PrivateKeySignResponse = owner
        .post_no_ttlv("/google_cse/privatekeysign", Some(&req))
        .await?;
    debug!("private key sign response: {:?}", resp.signature);

    // Verify signature with test public key
    let user_public_key_pem_pkcs1 =
        include_bytes!("../../../../../../test_data/certificates/gmail_cse/test_public_key");
    let rsa_public_key = Rsa::public_key_from_pem_pkcs1(user_public_key_pem_pkcs1)?;
    let public_key = PKey::from_rsa(rsa_public_key)?;

    let mut pk = PkeyCtx::new(&public_key)?;
    pk.verify_init()?;
    // The server signs a *pre-hashed* SHA-256 digest using PKCS#1 v1.5 padding.
    // Be explicit here to avoid relying on OpenSSL/provider defaults.
    pk.set_rsa_padding(Padding::PKCS1)?;
    pk.set_signature_md(Md::sha256())?;
    pk.verify(
        &general_purpose::STANDARD.decode(digest)?,
        &general_purpose::STANDARD.decode(resp.signature)?,
    )?;

    Ok(())
}

#[tokio::test]
#[serial]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints and an Utimaco HSM"]
async fn hsm_google_cse_encrypt_and_private_key_decrypt() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;
    let owner = ctx.get_owner_client();

    import_google_cse_demo_key_and_grant(ctx).await?;

    // Encrypt a DEK with the test public key (PKCS1)
    let dek = vec![1_u8; 32];
    let pub_key_pem =
        include_bytes!("../../../../../../test_data/certificates/gmail_cse/test_public_key");
    let rsa_public_key = Rsa::public_key_from_pem_pkcs1(pub_key_pem)?;
    let public_key = PKey::from_rsa(rsa_public_key)?;
    let mut pk_ctx = PkeyCtx::new(&public_key)?;
    pk_ctx.encrypt_init().unwrap();
    pk_ctx.set_rsa_padding(Padding::PKCS1).unwrap();
    let sz = pk_ctx.encrypt(&dek, None).unwrap();
    let mut encrypted_dek = vec![0_u8; sz];
    pk_ctx.encrypt(&dek, Some(&mut encrypted_dek)).unwrap();
    let encrypted_dek_b64 = general_purpose::STANDARD.encode(encrypted_dek);

    let wrapped_private_key: &str =
        include_str!("../../../../../../documentation/docs/google_cse/test_wrapped_private_key");

    let req = PrivateKeyDecryptRequest {
        authentication: "test".to_string(),
        authorization: "test".to_string(),
        algorithm: "RSA/ECB/PKCS1Padding".to_string(),
        encrypted_data_encryption_key: encrypted_dek_b64,
        rsa_oaep_label: None,
        reason: "Gmail".to_string(),
        wrapped_private_key: wrapped_private_key.to_string(),
    };

    let resp: PrivateKeyDecryptResponse = owner
        .post_no_ttlv("/google_cse/privatekeydecrypt", Some(&req))
        .await?;

    assert_eq!(
        general_purpose::STANDARD.encode(dek),
        resp.data_encryption_key
    );
    Ok(())
}

#[tokio::test]
#[serial]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints and an Utimaco HSM"]
async fn hsm_google_cse_wrap_unwrap_key() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;
    let owner = ctx.get_owner_client();

    // Create or import the google_cse key — use import to ensure expected UID
    import_google_cse_demo_key_and_grant(ctx).await?;

    let dek_b64 = "wHrlNOTI9mU6PBdqiq7EQA=="; // arbitrary base64 key

    let wrap_req = WrapRequest {
        authentication: "test".to_string(),
        authorization: "test".to_string(),
        key: dek_b64.to_string(),
        reason: String::new(),
    };
    let wrap_resp: WrapResponse = owner
        .post_no_ttlv("/google_cse/wrap", Some(&wrap_req))
        .await?;

    let unwrap_req = UnwrapRequest {
        authentication: "test".to_string(),
        authorization: "test".to_string(),
        wrapped_key: wrap_resp.wrapped_key,
        reason: String::new(),
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

#[ignore = "Requires an Utimaco HSM setup"]
#[serial]
#[tokio::test]
async fn hsm_google_cse_create_key_pair() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    // Create the Google CSE key in the HSM (prefix hsm::0::)
    let cse_key_id = CreateKeyAction {
        key_id: Some(format!("hsm::0::google_cse_{ts}")),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // import signers
    let (_root_id, _intermediate_id, issuer_private_key_id) =
        Box::pin(import_root_and_intermediate(ctx)).await.unwrap();

    // Create key pair without certificate extensions (must fail)
    let action = CreateKeyPairsAction {
        user_id: "john.doe@acme.com".to_owned(),
        cse_key_id: cse_key_id.to_string(),
        issuer_private_key_id: None,
        subject_name: "CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US".to_owned(),
        rsa_private_key_id: None,
        sensitive: false,
        wrapping_key_id: None,
        leaf_certificate_extensions: None,
        leaf_certificate_id: None,
        leaf_certificate_pkcs12_file: None,
        leaf_certificate_pkcs12_password: None,
        number_of_days: 365,
        dry_run: true,
    };
    action.run(ctx.get_owner_client()).await.unwrap_err();

    // Create key pair with certificate extensions (must succeed)
    let action = CreateKeyPairsAction {
        issuer_private_key_id: Some(issuer_private_key_id.clone()),
        leaf_certificate_extensions: Some(PathBuf::from(
            "../../test_data/certificates/openssl/ext_leaf.cnf",
        )),
        ..action
    };
    let certificate_1 = action.run(ctx.get_owner_client()).await.unwrap();

    // Create key pair with certificate id (must succeed)
    let action = CreateKeyPairsAction {
        issuer_private_key_id: None,
        leaf_certificate_extensions: None,
        leaf_certificate_id: Some(certificate_1.to_string()),
        ..action
    };
    let _certificate_2 = action.run(ctx.get_owner_client()).await.unwrap();

    // Create key pair using a certificate file (must succeed)
    let action = CreateKeyPairsAction {
        user_id: "john.barry@acme.com".to_owned(),
        leaf_certificate_id: None,
        issuer_private_key_id: None,
        leaf_certificate_extensions: None,
        leaf_certificate_pkcs12_file: Some(PathBuf::from(
            "../../test_data/certificates/csr/leaf.p12",
        )),
        leaf_certificate_pkcs12_password: Some("secret".to_owned()),
        ..action
    };
    let _certificate_3 = action.run(ctx.get_owner_client()).await.unwrap();

    Ok(())
}

#[ignore = "Requires Google OAuth credentials and an Utimaco HSM"]
#[serial]
#[tokio::test]
async fn hsm_google_cse_create_key_pair_using_imported_google_cse() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_and_kek().await;

    let cse_key_id = ImportSecretDataOrKeyAction {
        key_file: PathBuf::from(
            "../../documentation/docs/google_cse/original_kms_cse_key.demo.key.json",
        ),
        replace_existing: true,
        unwrap: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // import signers
    let (_root_id, _intermediate_id, issuer_private_key_id) =
        Box::pin(import_root_and_intermediate(ctx)).await.unwrap();
    info!("Root and intermediate CA created");

    // create key pair without certificate extensions (must succeed)
    let action = CreateKeyPairsAction {
        user_id: "john.doe@acme.com".to_owned(),
        cse_key_id: cse_key_id.to_string(),
        issuer_private_key_id: Some(issuer_private_key_id.clone()),
        leaf_certificate_extensions: Some(PathBuf::from(
            "../../test_data/certificates/openssl/ext_leaf.cnf",
        )),
        subject_name: "CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US".to_owned(),
        rsa_private_key_id: None,
        sensitive: false,
        wrapping_key_id: None,
        leaf_certificate_id: None,
        leaf_certificate_pkcs12_file: None,
        leaf_certificate_pkcs12_password: None,
        number_of_days: 365,
        dry_run: true,
    };
    action.run(ctx.get_owner_client()).await.unwrap();

    Ok(())
}

#[tokio::test]
#[serial]
#[ignore = "Requires Google OAuth credentials and an Utimaco HSM"]
async fn hsm_google_cse_privileged_wrap_unwrap_key() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_and_kek().await;
    import_google_cse_demo_key_and_grant(ctx).await?;

    let dek_b64 = "wHrlNOTI9mU6PBdqiq7EQA==";
    let resource_name = "resource_name_test";
    let token: String = generate_google_jwt()
        .await
        .expect("Error on token generation");

    let p_wrap = PrivilegedWrapRequest {
        authentication: token.clone(),
        key: dek_b64.to_string(),
        perimeter_id: String::new(),
        resource_name: resource_name.to_string(),
        reason: String::new(),
    };
    let w: PrivilegedWrapResponse = ctx
        .get_owner_client()
        .post_no_ttlv("/google_cse/privilegedwrap", Some(&p_wrap))
        .await?;

    trace!("Wrapped key: {:?}", w.wrapped_key);

    let p_unwrap = PrivilegedUnwrapRequest {
        authentication: token,
        resource_name: resource_name.to_string(),
        wrapped_key: w.wrapped_key,
        reason: String::new(),
    };
    let u: PrivilegedUnwrapResponse = ctx
        .get_owner_client()
        .post_no_ttlv("/google_cse/privilegedunwrap", Some(&p_unwrap))
        .await?;

    assert_eq!(dek_b64, u.key);
    Ok(())
}

#[tokio::test]
#[serial]
#[ignore = "Requires Google OAuth credentials and access to Google CSE privileged endpoints and an Utimaco HSM"]
async fn hsm_google_cse_privileged_private_key_decrypt() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_and_kek().await;
    import_google_cse_demo_key_and_grant(ctx).await?;

    // Load user's public key (PKCS1) and compute SPKI hash
    let user_public_key_pem_pkcs1 =
        include_bytes!("../../../../../../test_data/certificates/gmail_cse/test_public_key");
    let rsa_public_key = Rsa::public_key_from_pem_pkcs1(user_public_key_pem_pkcs1)?;
    let public_key = PKey::from_rsa(rsa_public_key)?;
    let spki_hash = openssl::hash::hash(MessageDigest::sha256(), &public_key.public_key_to_der()?)?;
    let spki_hash_b64 = general_purpose::STANDARD.encode(spki_hash);

    // Encrypt a 32-byte DEK with the public key (PKCS1 padding)
    let dek = vec![1_u8; 32];
    let mut pk_ctx = PkeyCtx::new(&public_key)?;
    pk_ctx.encrypt_init()?;
    pk_ctx.set_rsa_padding(Padding::PKCS1)?;
    let sz = pk_ctx.encrypt(&dek, None)?;
    let mut encrypted_dek = vec![0_u8; sz];
    pk_ctx.encrypt(&dek, Some(&mut encrypted_dek))?;
    let encrypted_dek_b64 = general_purpose::STANDARD.encode(encrypted_dek);

    let wrapped_private_key: &str =
        include_str!("../../../../../../documentation/docs/google_cse/test_wrapped_private_key");
    let token: String = generate_google_jwt()
        .await
        .expect("Error on token generation");

    let req = PrivilegedPrivateKeyDecryptRequest {
        authentication: token,
        algorithm: "RSA/ECB/PKCS1Padding".to_string(),
        encrypted_data_encryption_key: encrypted_dek_b64,
        rsa_oaep_label: None,
        reason: "Gmail".to_string(),
        wrapped_private_key: wrapped_private_key.to_string(),
        spki_hash: spki_hash_b64,
        spki_hash_algorithm: "SHA-256".to_string(),
    };

    let resp: PrivilegedPrivateKeyDecryptResponse = ctx
        .get_owner_client()
        .post_no_ttlv("/google_cse/privilegedprivatekeydecrypt", Some(&req))
        .await?;

    assert_eq!(
        general_purpose::STANDARD.encode(dek),
        resp.data_encryption_key
    );
    Ok(())
}

// NOTE: The original server-side test `test_google_cse_custom_jwt` validates a custom JWT
// against the server's JWKS and uses internal helpers. Replicating it here would require
// additional crypto and config wiring. If needed, we can add it later using jsonwebtoken
// with a local RS256 key and fetch `/google_cse/certs` to validate. For now, it is omitted.
