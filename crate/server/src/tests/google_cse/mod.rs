use std::path::PathBuf;

use base64::{engine::general_purpose, Engine};
use cosmian_kmip::kmip::{kmip_operations::Import, kmip_types::UniqueIdentifier};
use cosmian_kms_cli::actions::shared::utils::{
    read_bytes_from_file, read_object_from_json_ttlv_bytes,
};

use crate::{
    result::KResult,
    routes::google_cse::operations::{PrivateKeySignRequest, PrivateKeySignResponse},
    tests::{google_cse::utils::generate_google_jwt, test_utils},
};

pub mod utils;

fn import_google_cse_symkey() -> Import {
    let symmetric_key = read_bytes_from_file(&PathBuf::from(
        "../../documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.json",
    ))
    .unwrap();

    let object = read_object_from_json_ttlv_bytes(&symmetric_key).unwrap();

    let request = Import {
        unique_identifier: UniqueIdentifier::TextString("google_cse".to_string()),
        object_type: object.object_type(),
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes: object.attributes().cloned().unwrap_or_default(),
        object,
    };

    tracing::debug!("request: {request:?}");
    request
}

// fn private_key_sign_single_test() {}

#[tokio::test]
async fn test_cse_private_key_sign() -> KResult<()> {
    cosmian_logger::log_utils::log_init("debug,cosmian_kms_server=debug");

    let jwt = generate_google_jwt().await;

    let app = test_utils::test_app(Some("http://127.0.0.1/google_cse/".to_string())).await;

    let import_request = import_google_cse_symkey();
    test_utils::post(&app, import_request).await?;

    tracing::debug!("private key sign request");
    let pksr = PrivateKeySignRequest {
        authentication: jwt.clone(),
        authorization: jwt,
        algorithm: "RSA_SHA256".to_string(),
        digest: "toto".to_string(),
        rsa_pss_salt_length: None,
        reason: "Gmail".to_string(),
        wrapped_private_key: general_purpose::STANDARD.encode("secret"),
    };

    tracing::debug!("private key sign request post");
    let _pksr_response: PrivateKeySignResponse =
        test_utils::post_with_uri(&app, pksr, "/google_cse/privatekeysign").await?;

    Ok(())
}
