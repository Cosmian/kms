use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose, Engine};
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Import, ImportResponse},
    kmip_types::UniqueIdentifier,
    ttlv::{deserializer::from_ttlv, TTLV},
};
use cosmian_kms_client::access::{Access, ObjectOperationType, SuccessResponse};
use openssl::{pkey_ctx::PkeyCtx, rsa::Padding, x509::X509};

use crate::{
    result::{KResult, KResultHelper},
    routes::google_cse::operations::{
        PrivateKeyDecryptRequest, PrivateKeyDecryptResponse, PrivateKeySignRequest,
        PrivateKeySignResponse,
    },
    tests::{google_cse::utils::generate_google_jwt, test_utils},
};

pub mod utils;

// Default JWT issuer URI
#[cfg(test)]
const JWT_ISSUER_URI: &str = "https://accounts.google.com";

// Default JWT Set URI
#[cfg(test)]
const JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Read all bytes from a file
pub fn read_bytes_from_file(file: &impl AsRef<Path>) -> KResult<Vec<u8>> {
    let mut buffer = Vec::new();
    File::open(file)
        .with_context(|| format!("could not open the file {}", file.as_ref().display()))?
        .read_to_end(&mut buffer)
        .with_context(|| format!("could not read the file {}", file.as_ref().display()))?;

    Ok(buffer)
}

/// Read an object from KMIP JSON TTLV bytes slice
pub fn read_object_from_json_ttlv_bytes(bytes: &[u8]) -> KResult<Object> {
    // Read the object from the file
    let ttlv = serde_json::from_slice::<TTLV>(bytes)
        .with_context(|| "failed parsing the object from the json file".to_owned())?;
    // Deserialize the object
    let object: Object = from_ttlv(&ttlv)?;
    Ok(object)
}

fn import_google_cse_symmetric_key() -> Import {
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

// #[tokio::test]
// async fn test_ossl_sign_verify() -> KResult<()> {
//     cosmian_logger::log_utils::log_init("debug,cosmian_kms_server=trace");

//     //-------------------------------------------------------------------------
//     // The RSA blue public key
//     //-------------------------------------------------------------------------
//     let blue_public_key = read_bytes_from_file(&PathBuf::from(
//         "src/routes/google_cse/python/openssl/blue.pem",
//     ))
//     .unwrap();
//     let rsa_public_key = X509::from_pem(&blue_public_key)?;
//     let public_key = rsa_public_key.public_key()?;

//     // PAYLOAD
//     let digest =
//         general_purpose::STANDARD.decode("MSKaRPMiIFwZoWGYjA/MV8mLNNYGW3GpODrEjdbbQqE=")?;
//     let signature =
//         general_purpose::STANDARD.decode("O3VF4GC/ohpXtA9bofQfKAtJ5ieDF0jDE2dslC7HVIVo49sDAIqlmosybRaTLgy4L6x5dXiGkefBxySiNxShdMBoe0QK+Z63+R84+S/dAC40rvMhkuTOpm4CphrpdeJpMpAH3Ge8P98+mCqw33VlWTQ82wRGT1wRzNhI9iI67tFw0mn7bH92XR4FfXoJZfpuuQ3VJxENJw6+kBBa4zQV1pudG84afRe8BkayfzjwWPl0btoF3A9rnKHv9sQohGgLM0NWlETJFWeDtUr4OJKPv+GyoFN8vJfHCFwIRtFg/CbLqZqHJa+lIUpGxirglCVAYJl7Ir6FKyVP1KsRjDmSOGPg+ZrtrZY9aibwnMwx0C0sbInlSLInvddFlMBoLKBbKWu8VUPh4toA7o7Pf/cum+tUk6BbCftMrQUsW4J/78KCIFx6dDFijM9WyFfbYrgEkbA7ClPBTfuJDaxf1nwqTc00BW9HcjVy8noyRPDctCFCZdLOoB+L5a0+Oz7O5niPAXa0Eku/Q261bgV+2Oj0YzUprkmGiwTbnaQLSvzgPpkw5DO9nAmOfR2KI5lBvMt/879JrcZtK0Sm5p5307Tzy28DPRFnHR3p11ANnFLK8lLA0Z+3RYv38h3n8yt6UfX0w8Rbc4++fnbVAfVC04W8PP2FmlKxHAb+p8wBQgTzs/U=")?;

//     // Verify the signature
//     let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)?;
//     verifier.update(&digest)?;

//     assert!(verifier.verify(&signature)?);

//     //-------------------------------------------------------------------------
//     // Signature again
//     //-------------------------------------------------------------------------
//     let digest =
//         general_purpose::STANDARD.decode("9lb4w0UM8hTxaEWSRKbu1sMVxE4KD2Y4m7n7DvFlHW4=")?;
//     // The RSA blue private key
//     let blue_private_key = read_bytes_from_file(&PathBuf::from(
//         "src/routes/google_cse/python/openssl/blue.key",
//     ))
//     .unwrap();

//     let rsa_private_key = Rsa::<Private>::private_key_from_pem(&blue_private_key)?;
//     let private_key = PKey::from_rsa(rsa_private_key)?;
//     let mut signer = Signer::new(MessageDigest::sha256(), &private_key)?;

//     tracing::debug!("padding method: {:?}", signer.rsa_padding());

//     signer.update(&digest)?;
//     let signature = signer.sign_to_vec()?;

//     tracing::debug!(
//         "signature: {}",
//         general_purpose::STANDARD.encode(signature.clone())
//     );

//     //-------------------------------------------------------------------------
//     // Verify
//     //-------------------------------------------------------------------------
//     // Verify the signature
//     let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)?;
//     verifier.update(&digest)?;

//     assert!(verifier.verify(&signature)?);

//     Ok(())
// }

#[tokio::test]
async fn test_cse_private_key_sign() -> KResult<()> {
    std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", JWKS_URI);
    std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", JWT_ISSUER_URI);
    cosmian_logger::log_utils::log_init("debug,cosmian_kms_server=trace");

    let jwt = generate_google_jwt().await;

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_string())).await;

    let import_request = import_google_cse_symmetric_key();
    tracing::debug!("import_request created");

    let response: ImportResponse = test_utils::post(&app, import_request).await?;
    tracing::debug!("import response: {response:?}");

    tracing::debug!("grant post");
    let access = Access {
        unique_identifier: Some(UniqueIdentifier::TextString("google_cse".to_string())),
        user_id: "*".to_string(),
        operation_types: vec![
            ObjectOperationType::Create,
            ObjectOperationType::Destroy,
            ObjectOperationType::Get,
            ObjectOperationType::Encrypt,
            ObjectOperationType::Decrypt,
        ],
    };

    let access_response: SuccessResponse =
        test_utils::post_with_uri(&app, access, "/access/grant").await?;
    tracing::debug!("grant response post: {access_response:?}");

    // The RSA blue private key has been AES256 wrapped with `demo.key.json`
    let wrapped_private_key =
        include_str!("../../../../../documentation/docs/google_cse/blue_wrapped_private_key");
    let digest = "MSKaRPMiIFwZoWGYjA/MV8mLNNYGW3GpODrEjdbbQqE=";

    let pksr = PrivateKeySignRequest {
        authentication: jwt.clone(),
        authorization: jwt,
        algorithm: "SHA256withRSA".to_string(),
        digest: digest.to_string(),
        e_key: Some("e_key".to_string()),
        rsa_pss_salt_length: None,
        reason: "Gmail".to_string(),
        wrapped_private_key: wrapped_private_key.to_string(),
    };

    tracing::debug!("private key sign request post");
    let pksr_response: PrivateKeySignResponse =
        test_utils::post_with_uri(&app, pksr, "/google_cse/privatekeysign").await?;
    tracing::debug!("private key sign response post: {pksr_response:?}");

    // The RSA blue private key has been AES256 wrapped with `demo.key.json`
    let blue_public_key = read_bytes_from_file(&PathBuf::from(
        "src/routes/google_cse/python/openssl/blue.pem",
    ))
    .unwrap();

    let rsa_public_key = X509::from_pem(&blue_public_key)?;
    let public_key = rsa_public_key.public_key()?;

    let mut pkey_context = PkeyCtx::new(&public_key)?;
    pkey_context.verify_init()?;
    pkey_context.verify(
        &general_purpose::STANDARD.decode(digest)?,
        &general_purpose::STANDARD.decode(pksr_response.signature)?,
    )?;

    Ok(())
}

#[tokio::test]
async fn test_cse_private_key_decrypt() -> KResult<()> {
    std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", JWKS_URI);
    std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", JWT_ISSUER_URI);

    cosmian_logger::log_utils::log_init("info,cosmian_kms_server=trace");

    let jwt = generate_google_jwt().await;

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_string())).await;

    let path = std::env::current_dir()?;
    println!("The current directory is {}", path.display());

    // The RSA blue private key has been AES256 wrapped with `demo.key.json`
    let blue_public_key = read_bytes_from_file(&PathBuf::from(
        "src/routes/google_cse/python/openssl/blue.pem",
    ))
    .unwrap();

    let rsa_public_key = X509::from_pem(&blue_public_key)?;

    let public_key = rsa_public_key.public_key()?;

    // Perform RSA PKCS1 decryption.
    let mut ctx = PkeyCtx::new(&public_key)?;
    ctx.encrypt_init()?;
    ctx.set_rsa_padding(Padding::PKCS1)?;

    let dek = vec![1_u8; 32];
    let encrypt_size = ctx.encrypt(&dek, None)?;

    let mut encrypted_data_encryption_key = vec![0_u8; encrypt_size];
    ctx.encrypt(&dek, Some(&mut *encrypted_data_encryption_key))?;

    tracing::debug!("rsa pkcs1: dek={dek:?}\nencrypted_dek={encrypted_data_encryption_key:?}");

    let import_request = import_google_cse_symmetric_key();
    tracing::debug!("import_request created");

    let response: ImportResponse = test_utils::post(&app, import_request).await?;
    tracing::debug!("import response: {response:?}");

    tracing::debug!("grant post");
    let access = Access {
        unique_identifier: Some(UniqueIdentifier::TextString("google_cse".to_string())),
        user_id: "*".to_string(),
        operation_types: vec![
            ObjectOperationType::Create,
            ObjectOperationType::Destroy,
            ObjectOperationType::Get,
            ObjectOperationType::Encrypt,
            ObjectOperationType::Decrypt,
        ],
    };

    let access_response: SuccessResponse =
        test_utils::post_with_uri(&app, access, "/access/grant").await?;
    tracing::debug!("grant response post: {access_response:?}");

    // The RSA blue private key has been AES256 wrapped with `demo.key.json`
    let wrapped_private_key =
        include_str!("../../../../../documentation/docs/google_cse/blue_wrapped_private_key");

    let request = PrivateKeyDecryptRequest {
        authentication: jwt.clone(),
        authorization: jwt,
        algorithm: "SHA256withRSA".to_string(),
        encrypted_data_encryption_key: general_purpose::STANDARD
            .encode(encrypted_data_encryption_key),
        rsa_oaep_label: None,
        reason: "Gmail".to_string(),
        wrapped_private_key: wrapped_private_key.to_string(),
    };

    tracing::debug!("private key decrypt request post");
    let response: PrivateKeyDecryptResponse =
        test_utils::post_with_uri(&app, request, "/google_cse/privatekeydecrypt").await?;
    tracing::debug!("private key decrypt response post: {response:?}"); //TODO: remove it

    assert_eq!(
        general_purpose::STANDARD.encode(dek),
        response.data_encryption_key
    );

    Ok(())
}
