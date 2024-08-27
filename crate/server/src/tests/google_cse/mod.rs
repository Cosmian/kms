#![allow(clippy::unwrap_used, clippy::print_stdout, clippy::panic_in_result_fn)]

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
use cosmian_logger::log_utils::log_init;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
    sign::{Signer, Verifier},
    x509::X509,
};
use tracing::warn;

use crate::{
    error::KmsError,
    result::{KResult, KResultHelper},
    routes::google_cse::operations::{
        PrivateKeyDecryptRequest, PrivateKeyDecryptResponse, PrivateKeySignRequest,
        PrivateKeySignResponse, PrivilegedPrivateKeyDecryptRequest,
        PrivilegedPrivateKeyDecryptResponse, PrivilegedUnwrapRequest, PrivilegedUnwrapResponse,
        PrivilegedWrapRequest, PrivilegedWrapResponse, StatusResponse, UnwrapRequest,
        UnwrapResponse, WrapRequest, WrapResponse,
    },
    tests::test_utils,
};

pub(crate) mod utils;

// Default JWT issuer URI for Gmail endpoint
#[cfg(test)]
const GMAIL_JWT_ISSUER_URI: &str = "gsuitecse-tokenissuer-gmail@system.gserviceaccount.com";

// Default JWT Set URI for Gmail endpoint
#[cfg(test)]
const GMAIL_JWKS_URI: &str = "https://www.googleapis.com/service_accounts/v1/jwk/gsuitecse-tokenissuer-gmail@system.gserviceaccount.com";

// Default JWT issuer URI for Drive endpoint
#[cfg(test)]
const DRIVE_JWT_ISSUER_URI: &str = "https://accounts.google.com";

// Default JWT Set URI for Drive endpoint
#[cfg(test)]
const DRIVE_JWKS_URI: &str = "https://www.googleapis.com/service_accounts/v1/jwk/gsuitecse-tokenissuer-drive@system.gserviceaccount.com";

// Default JWT Set URI for Drive endpoint
#[cfg(test)]
const AUTHENTICATION_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImE0OTM5MWJmNTJiNThjMWQ1NjAyNTVjMmYyYTA0ZTU5ZTIyYTdiNjUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5OTY3Mzk1MTAzNzQtYXU5ZmRiZ3A3MmRhY3JzYWcyNjdja2czMmpmM2QzZTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5OTY3Mzk1MTAzNzQtYXU5ZmRiZ3A3MmRhY3JzYWcyNjdja2czMmpmM2QzZTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDI5NjU4MTQxNjkwOTQzMDMxMTIiLCJoZCI6ImNvc21pYW4uY29tIiwiZW1haWwiOiJibHVlQGNvc21pYW4uY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5vbmNlIjoiTWFJdHdqQ3VUTVVtYVo1VmFiQmlmdzpodHRwczovL2NsaWVudC1zaWRlLWVuY3J5cHRpb24uZ29vZ2xlLmNvbSIsIm5iZiI6MTcyNDc0NjU5NSwiaWF0IjoxNzI0NzQ2ODk1LCJleHAiOjE3MjQ3NTA0OTUsImp0aSI6IjU4NTg5OGZmZWViNGFkNTQ0M2I1YjA4ODMyODc2ODg3MWRhNzE1NjQifQ.ZZNpMNUsmMG4X3Or8xYyOv8I6QjFOKw_x805EuKVbokyN3bXyhZHB7Jb52yeY4laS55wgg0w5S9RR1WeZCUXZyUp5rhLUBVcli3SkK7TTJ49yV0mVHUzcdr8X3R__v1TjSOf8unrRVPKtEe7ERMusphP6i0KFCvt8f-h0qZjg1H6n97ANHLRAvgU2vBpk3kWunhBjTM9uuUBlzuGRiTTJQJGxHfj51bKbWokGv7kUC8iDdDX5u72bfCMqCHZ3WdcETnJjRdi7qIK4I1cf2iRw3a1XdU1GlATag9tutADl0rjafdJCUCy9VHDt-bfUzdHlO63eby7NnUyD1CTWW9_HQ";

/// Read all bytes from a file
pub(crate) fn read_bytes_from_file(file: &impl AsRef<Path>) -> KResult<Vec<u8>> {
    let mut buffer = Vec::new();
    File::open(file)
        .with_context(|| format!("could not open the file {}", file.as_ref().display()))?
        .read_to_end(&mut buffer)
        .with_context(|| format!("could not read the file {}", file.as_ref().display()))?;

    Ok(buffer)
}

/// Read an object from KMIP JSON TTLV bytes slice
pub(crate) fn read_object_from_json_ttlv_bytes(bytes: &[u8]) -> KResult<Object> {
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
        unique_identifier: UniqueIdentifier::TextString("google_cse".to_owned()),
        object_type: object.object_type(),
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes: object.attributes().cloned().unwrap_or_default(),
        object,
    };

    tracing::debug!("request: {request:?}");
    request
}

#[test]
fn test_ossl_sign_verify() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    //-------------------------------------------------------------------------
    // Signature
    //-------------------------------------------------------------------------
    let digest =
        general_purpose::STANDARD.decode("9lb4w0UM8hTxaEWSRKbu1sMVxE4KD2Y4m7n7DvFlHW4=")?;
    // The RSA blue private key
    let blue_private_key = read_bytes_from_file(&PathBuf::from(
        "src/routes/google_cse/python/openssl/blue.key",
    ))?;

    let rsa_private_key = Rsa::<Private>::private_key_from_pem(&blue_private_key)?;
    let private_key = PKey::from_rsa(rsa_private_key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &private_key)?;

    tracing::debug!("padding method: {:?}", signer.rsa_padding());

    signer.update(&digest)?;
    let signature = signer.sign_to_vec()?;

    tracing::debug!(
        "signature: {}",
        general_purpose::STANDARD.encode(signature.clone())
    );

    //-------------------------------------------------------------------------
    // Verify
    //-------------------------------------------------------------------------
    // The RSA blue public key
    let blue_public_key = read_bytes_from_file(&PathBuf::from(
        "src/routes/google_cse/python/openssl/blue.pem",
    ))?;
    let rsa_public_key = X509::from_pem(&blue_public_key)?;
    let public_key = rsa_public_key.public_key()?;
    // Verify the signature
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)?;
    verifier.update(&digest)?;

    assert!(verifier.verify(&signature)?);

    Ok(())
}

#[tokio::test]
async fn test_cse_status() -> KResult<()> {
    cosmian_logger::log_utils::log_init(Some("debug,cosmian_kms_server=trace"));

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_string())).await;

    let response: StatusResponse = test_utils::get_with_uri(&app, "/google_cse/status").await?;
    tracing::debug!("status_request sent");

    assert_eq!(response.server_type, "KACLS");
    assert_eq!(response.vendor_id, "Cosmian");

    Ok(())
}

#[tokio::test]
async fn test_cse_private_key_sign() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", GMAIL_JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", GMAIL_JWT_ISSUER_URI);
    }
    cosmian_logger::log_utils::log_init(Some("debug,cosmian_kms_server=trace"));

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned())).await;

    let import_request = import_google_cse_symmetric_key();
    tracing::debug!("import_request created");

    let response: ImportResponse = test_utils::post(&app, import_request).await?;
    tracing::debug!("import response: {response:?}");

    tracing::debug!("grant post");
    let access = Access {
        unique_identifier: Some(UniqueIdentifier::TextString("google_cse".to_owned())),
        user_id: "*".to_owned(),
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
        authentication: AUTHENTICATION_TOKEN.to_owned(),
        authorization: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImEzYzUyYTU5MTQ5MjI4ZGQ0YjBiZGFkMjNkOGQ0M2JjMWE1MTViYzEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJnc3VpdGVjc2UtdG9rZW5pc3N1ZXItZ21haWxAc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJhdWQiOiJjc2UtYXV0aG9yaXphdGlvbiIsImVtYWlsIjoiYmx1ZUBjb3NtaWFuLmNvbSIsInJlc291cmNlX25hbWUiOiIvL2dtYWlsLmdvb2dsZWFwaXMuY29tL2dtYWlsL3VzZXJzL2JsdWUlNDBjb3NtaWFuLmNvbS9zZXR0aW5ncy9jc2Uva2V5cGFpcnMvQU5lMUJtaVFINlh3T0lsdEhGNjUtb2xSY2FWbUxzTjJ6TEVQalQ3aHliOFNFdWp6ZEFKejlST3YybXpEaXdGeTE3ZnB4akhnWmprRUdDalZPZXVkTGdGcWhSeTI0USIsInJvbGUiOiJzaWduZXIiLCJrYWNsc191cmwiOiJodHRwczovL2NzZS5jb3NtaWFuLmNvbS9nb29nbGVfY3NlIiwicGVyaW1ldGVyX2lkIjoiIiwiaWF0IjoxNzI0NzQ3NjU2LCJleHAiOjE3MjQ3NTEyNTYsIm1lc3NhZ2VfaWQiOiJcdTAwM2NDQVA4RDdwMTBvRnUzR2JkT0JWRnhwQkhOWFdMTlduZnNHQndzWU9jem43X3JrZUJjU0FAbWFpbC5nbWFpbC5jb21cdTAwM2UiLCJzcGtpX2hhc2giOiJodUhTSjM5S0MrNThKcTgwY2l1VW1tNEpvZ1Ntd0c1QmUySU5PaGpRRTg0XHUwMDNkIiwic3BraV9oYXNoX2FsZ29yaXRobSI6IlNIQS0yNTYifQ.B0Z2KjpTpIzXqcgQvxoDY5Gns6AGP6W96hXHq6M2mVbvfvRVmca-tVhUCgZy7qgt44ltRv766kcNwCLXvSF5z11wR13HscLdAO7AWKrikBg4EPPAg44jojKk_a1QCfjq8NWEy_QfUWOEoHNzxV1DrAYd2K0TSlK7RaQY42Jx9xGvsxPIANFtjBfm8OlwqecsOCYcrZLO2b92A4FK2wLV57Gl88MDXlL2rJHkmFVkIGFh_bo4Eo9iWI9okEwdVvHkYQ83WWf5zi2uhH366bf5RM2wZLBIo_JrPNPrsFoVrKxryxNpyTDQ2iCbNR5eCZSUkuIf6EXsj2_CEXOpHJDgLw".to_owned(),
        algorithm: "SHA256withRSA".to_owned(),
        digest: digest.to_owned(),
        rsa_pss_salt_length: None,
        reason: "Gmail".to_owned(),
        wrapped_private_key: wrapped_private_key.to_owned(),
    };

    tracing::debug!("private key sign request post");
    let pksr_response: PrivateKeySignResponse =
        test_utils::post_with_uri(&app, pksr, "/google_cse/privatekeysign").await?;
    tracing::debug!("private key sign response post: {pksr_response:?}");

    // The RSA blue private key has been AES256 wrapped with `demo.key.json`
    let blue_public_key = read_bytes_from_file(&PathBuf::from(
        "src/routes/google_cse/python/openssl/blue.pem",
    ))?;

    let rsa_public_key = X509::from_pem(&blue_public_key)?;
    let public_key = rsa_public_key.public_key()?;

    let mut ctx = PkeyCtx::new(&public_key)?;
    ctx.verify_init()?;
    ctx.verify(
        &general_purpose::STANDARD.decode(digest)?,
        &general_purpose::STANDARD.decode(pksr_response.signature)?,
    )?;

    Ok(())
}

#[tokio::test]
async fn test_cse_private_key_decrypt() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", GMAIL_JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", GMAIL_JWT_ISSUER_URI);
    }

    cosmian_logger::log_utils::log_init(Some("info,cosmian_kms_server=trace"));

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned())).await;

    let path = std::env::current_dir()?;
    println!("The current directory is {}", path.display());

    // The RSA blue private key has been AES256 wrapped with `demo.key.json`
    let blue_public_key = read_bytes_from_file(&PathBuf::from(
        "src/routes/google_cse/python/openssl/blue.pem",
    ))?;

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
        unique_identifier: Some(UniqueIdentifier::TextString("google_cse".to_owned())),
        user_id: "*".to_owned(),
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
        authentication: AUTHENTICATION_TOKEN.to_owned(),
        authorization: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImEzYzUyYTU5MTQ5MjI4ZGQ0YjBiZGFkMjNkOGQ0M2JjMWE1MTViYzEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJnc3VpdGVjc2UtdG9rZW5pc3N1ZXItZ21haWxAc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJhdWQiOiJjc2UtYXV0aG9yaXphdGlvbiIsImVtYWlsIjoiYmx1ZUBjb3NtaWFuLmNvbSIsInJlc291cmNlX25hbWUiOiIvL2dtYWlsLmdvb2dsZWFwaXMuY29tL2dtYWlsL3VzZXJzL2JsdWUlNDBjb3NtaWFuLmNvbS9zZXR0aW5ncy9jc2Uva2V5cGFpcnMvQU5lMUJtaVFINlh3T0lsdEhGNjUtb2xSY2FWbUxzTjJ6TEVQalQ3aHliOFNFdWp6ZEFKejlST3YybXpEaXdGeTE3ZnB4akhnWmprRUdDalZPZXVkTGdGcWhSeTI0USIsInJvbGUiOiJkZWNyeXB0ZXIiLCJrYWNsc191cmwiOiJodHRwczovL2NzZS5jb3NtaWFuLmNvbS9nb29nbGVfY3NlIiwicGVyaW1ldGVyX2lkIjoiIiwiaWF0IjoxNzI0NzQ3NzE5LCJleHAiOjE3MjQ3NTEzMTksIm1lc3NhZ2VfaWQiOiJcdTAwM2NDQUZMMFFxbnluUTZNaVJmOENPeHZpeWZpTDJ3QnIwQ1I2bkhjSDktT0VkdGpDd3E0WXdAbWFpbC5nbWFpbC5jb21cdTAwM2UiLCJzcGtpX2hhc2giOiJodUhTSjM5S0MrNThKcTgwY2l1VW1tNEpvZ1Ntd0c1QmUySU5PaGpRRTg0XHUwMDNkIiwic3BraV9oYXNoX2FsZ29yaXRobSI6IlNIQS0yNTYifQ.iNZhH_MlMOUiM2ANYamHwxZcYdHlXYrPa_1JNJclxC2JT663_QAplzbDsi_mqHK0ZzgJC8xXsMRtBnhyufB-EKMEpHfS4BYjMszOAynvqinMrzkp-W4Y-WQ3RPvVdH-_QwAwU6elstkDCI-kjsQ1s3-cbVho0v3FeKPAISV-B2lDoX1NcSG_Ct8z1G6KNk6G3pWp-gILu4izm-uzsHVnumX_iB3Rji_YP5wveR9mINdYVsXJg0FC6htT4m16R24GX-YYnUNwUJNHUXO1YKdKvX_h8KBJAJl0nrITRTNX5Ae0kxWrMg1tpKqhUwQo77ARklEFY09sL3xTdx7tfkJH9A".to_owned(),
        algorithm: "RSA/ECB/PKCS1Padding".to_owned(),
        encrypted_data_encryption_key: general_purpose::STANDARD
            .encode(encrypted_data_encryption_key),
        rsa_oaep_label: None,
        reason: "Gmail".to_owned(),
        wrapped_private_key: wrapped_private_key.to_owned(),
    };

    tracing::debug!("private key decrypt request post");
    let response: PrivateKeyDecryptResponse =
        test_utils::post_with_uri(&app, request, "/google_cse/privatekeydecrypt").await?;
    tracing::debug!("private key decrypt response post: {response:?}");

    assert_eq!(
        general_purpose::STANDARD.encode(dek),
        response.data_encryption_key
    );

    Ok(())
}

#[tokio::test]
async fn test_cse_wrap_unwrap_key() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", DRIVE_JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", DRIVE_JWT_ISSUER_URI);
    }

    cosmian_logger::log_utils::log_init(Some("info,cosmian_kms_server=trace"));

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

    let dek = "wHrlNOTI9mU6PBdqiq7EQA==";

    let writer_authz_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhhZjdiNDdmOWI3OGMzMTNiYzgxZjQwMDIwYzJhMDI1YzNjYWU1ZjMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJnc3VpdGVjc2UtdG9rZW5pc3N1ZXItZHJpdmVAc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJhdWQiOiJjc2UtYXV0aG9yaXphdGlvbiIsImVtYWlsIjoiYmx1ZUBjb3NtaWFuLmNvbSIsInJlc291cmNlX25hbWUiOiIvL2dvb2dsZWFwaXMuY29tL2RyaXZlL2ZpbGVzLzEyeXNxck5WUHdTUnhtanJGVGJVYjhRVUhYQ1Bfa29hNiIsInJvbGUiOiJ3cml0ZXIiLCJrYWNsc191cmwiOiJodHRwczovL2NzZS5jb3NtaWFuLmNvbS9nb29nbGVfY3NlIiwicGVyaW1ldGVyX2lkIjoiIiwiaWF0IjoxNzI0NzUwMDQ4LCJleHAiOjE3MjQ3NTM2NDgsImVtYWlsX3R5cGUiOiJnb29nbGUifQ.JpSd2fzzoWAWcNyETeh33x3U82z885tGeZK669KP51L9TRyMfGR2mfCVckYZayCRXafVJTsq3Zu24zRYktn65cVXoiMjIInW3CQkanb44AnafpTKRmzXMlrPiYgi39YqSHz2nB36HoUQOEt1IYh70lEx4rx_vr6w4AeSijHnvkiCDKjJGyd3eUBR0Hya1l_dOTa4vN6Bqa0AhG8tFWC_HBHR90ne0jc7B5Tc_U3lRLac1l8R_E9jfwqqrkY1FYbVogE82DmSmRJGcV0XKOHIqrynV3JapY8nEGjEJAggahUlf3255p2O3FiBP4q7-AkPRkv9vpK7r_oSkzG2Q8ytAg";

    let reader_authz_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhhZjdiNDdmOWI3OGMzMTNiYzgxZjQwMDIwYzJhMDI1YzNjYWU1ZjMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJnc3VpdGVjc2UtdG9rZW5pc3N1ZXItZHJpdmVAc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJhdWQiOiJjc2UtYXV0aG9yaXphdGlvbiIsImVtYWlsIjoiYmx1ZUBjb3NtaWFuLmNvbSIsInJlc291cmNlX25hbWUiOiIvL2dvb2dsZWFwaXMuY29tL2RyaXZlL2ZpbGVzLzEyeXNxck5WUHdTUnhtanJGVGJVYjhRVUhYQ1Bfa29hNiIsInJvbGUiOiJyZWFkZXIiLCJrYWNsc191cmwiOiJodHRwczovL2NzZS5jb3NtaWFuLmNvbS9nb29nbGVfY3NlIiwicGVyaW1ldGVyX2lkIjoiIiwiaWF0IjoxNzI0NzYxNTk2LCJleHAiOjE3MjQ3NjUxOTYsImVtYWlsX3R5cGUiOiJnb29nbGUifQ.GM9qfct33Z1fvoiy_RwQxGS-Q04msrhp78fL_RXMnNStr-cqp8-ZBKFrKwRHsK49locYUA-j9Ugk6o7p4Z0nuHDK18SMbLbflBJMFLsC23H6taktHBrMi8_eic7ETzk7by4pM0pi3IkBctwXPvmY1o0-dr8Y6EPkHbBs_rt4xbv_FX1zuUW2_ecD0oyQ7bRsd7O8JoF8VG9xBlvhkrriTmkx-SsCjazvk7Vqvcllvy21DBOKizRkZyiFdFYPI9qk0SDEtEfQqXdTUlaWimW4-lRPori9Y97ULgZ5CIXEgZ2UcXEuM-ZYXZi4tJ2Sx9pF7jXBS6ZuKR4nljqYwpn4VQ";

    let wrong_resource_name_authz_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhhZjdiNDdmOWI3OGMzMTNiYzgxZjQwMDIwYzJhMDI1YzNjYWU1ZjMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJnc3VpdGVjc2UtdG9rZW5pc3N1ZXItZHJpdmVAc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJhdWQiOiJjc2UtYXV0aG9yaXphdGlvbiIsImVtYWlsIjoiYmx1ZUBjb3NtaWFuLmNvbSIsInJlc291cmNlX25hbWUiOiIvL2dvb2dsZWFwaXMuY29tL2RyaXZlL2ZpbGVzLzFKS1NmZmJ1dXBTNkdvUDBXRHhSdzI5S3dIN25UYWJNNyIsInJvbGUiOiJyZWFkZXIiLCJrYWNsc191cmwiOiJodHRwczovL2NzZS5jb3NtaWFuLmNvbS9nb29nbGVfY3NlIiwicGVyaW1ldGVyX2lkIjoiIiwiaWF0IjoxNzI0NzU5OTkzLCJleHAiOjE3MjQ3NjM1OTMsImVtYWlsX3R5cGUiOiJnb29nbGUifQ.CMiya9xB1GuQkSpn_ME-ofB8kPS4qYyr1jM2ONQPLhu82a-bffci5sIGt0cpQh3iMWku4Wx-YV3RyqL5GUVz0sCgY9lVh5YZyZNUAqOlUHEHTAk-aPqwMoRS_gUnrIWUc8W7MiiuS1gY4FuZ_sNz-iafh14XmRp9Rc165wJjUOex8NTuZs2J505jaZhcrqvPBMKTmq5vnXmLUq_6DhgBigBkfwVMQ7wZ8Pf1kcah5z0iYi2cywLNCSxd3eGhtTtsqVb9z2dlC2H2dtu60CGw2eszdYoew71WBOfhort7fG3440fPJ6zeskc5owwSuvMaEPJZhzxu2hj_1tXP0plqrg";

    let wrong_role_wrap_request = WrapRequest {
        authentication: AUTHENTICATION_TOKEN.to_string(),
        authorization: reader_authz_token.to_string(),
        key: dek.to_string(),
        reason: String::new(),
    };

    tracing::debug!("wrapping key request post with wrong role");
    let response: Result<WrapRequest, KmsError> =
        test_utils::post_with_uri(&app, wrong_role_wrap_request, "/google_cse/wrap").await;

    assert!(response.is_err());
    if let Err(e) = response {
        assert!(
            e.to_string().contains(
                "Access denied: Authorization token should contain a role of writer upgrader"
            ),
            "Should raise an error if"
        );
    }

    let wrap_request = WrapRequest {
        authentication: AUTHENTICATION_TOKEN.to_string(),
        authorization: writer_authz_token.to_string(),
        key: dek.to_string(),
        reason: String::new(),
    };

    tracing::debug!("wrapping key request post");
    let response: WrapResponse =
        test_utils::post_with_uri(&app, wrap_request, "/google_cse/wrap").await?;
    tracing::debug!("wrapping key response post: {response:?}");

    let wrapped_key = response.wrapped_key;

    let wrong_resource_unwrap_request = UnwrapRequest {
        authentication: AUTHENTICATION_TOKEN.to_string(),
        authorization: wrong_resource_name_authz_token.to_string(),
        wrapped_key: wrapped_key.clone(),
        reason: String::new(),
    };

    tracing::debug!("unwrapping key request post with wrong resource_name");
    let response: Result<UnwrapResponse, KmsError> =
        test_utils::post_with_uri(&app, wrong_resource_unwrap_request, "/google_cse/unwrap").await;

    assert!(response.is_err());

    let unwrap_request: UnwrapRequest = UnwrapRequest {
        authentication: AUTHENTICATION_TOKEN.to_string(),
        authorization: reader_authz_token.to_string(),
        wrapped_key,
        reason: String::new(),
    };

    tracing::debug!("unwrapping key request post");
    let response: UnwrapResponse =
        test_utils::post_with_uri(&app, unwrap_request, "/google_cse/unwrap").await?;
    tracing::debug!("unwrapping key response post: {response:?}");

    assert_eq!(dek, response.key);

    Ok(())
}

#[tokio::test]
async fn test_cse_privileged_wrap_unwrap_key() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", DRIVE_JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", DRIVE_JWT_ISSUER_URI);
    }

    cosmian_logger::log_utils::log_init(Some("info,cosmian_kms_server=trace"));

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

    let dek = "wHrlNOTI9mU6PBdqiq7EQA==";

    let wrap_request = PrivilegedWrapRequest {
        authentication: AUTHENTICATION_TOKEN.to_string(),
        key: dek.to_string(),
        perimeter_id: String::new(),
        resource_name: "resource_name_test".to_string(),
        reason: String::new(),
    };

    tracing::debug!("privileged wrapping key request post");
    let response: PrivilegedWrapResponse =
        test_utils::post_with_uri(&app, wrap_request, "/google_cse/privilegedwrap").await?;
    tracing::debug!("privileged wrapping key response post: {response:?}");

    let wrapped_key = response.wrapped_key;

    let wrong_resource_unwrap_request = PrivilegedUnwrapRequest {
        authentication: AUTHENTICATION_TOKEN.to_string(),
        resource_name: "wrong_resource_name_test".to_string(),
        wrapped_key: wrapped_key.clone(),
        reason: String::new(),
    };

    tracing::debug!("privileged unwrapping key request post with wrong resource_name");
    let response: Result<PrivilegedUnwrapResponse, KmsError> = test_utils::post_with_uri(
        &app,
        wrong_resource_unwrap_request,
        "/google_cse/privilegedunwrap",
    )
    .await;

    assert!(response.is_err());

    let unwrap_request = PrivilegedUnwrapRequest {
        authentication: AUTHENTICATION_TOKEN.to_string(),
        resource_name: "resource_name_test".to_string(),
        wrapped_key,
        reason: String::new(),
    };

    tracing::debug!("privileged unwrapping key request post");
    let response: PrivilegedUnwrapResponse =
        test_utils::post_with_uri(&app, unwrap_request, "/google_cse/privilegedunwrap").await?;

    assert_eq!(dek, response.key);

    Ok(())
}

#[tokio::test]
async fn test_cse_privileged_private_key_decrypt() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", GMAIL_JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", GMAIL_JWT_ISSUER_URI);
    }

    cosmian_logger::log_utils::log_init(Some("info,cosmian_kms_server=trace"));

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
    let blue_spki_hash =
        openssl::hash::hash(MessageDigest::sha256(), &public_key.public_key_to_der()?)?;

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

    let request = PrivilegedPrivateKeyDecryptRequest {
        authentication: AUTHENTICATION_TOKEN.to_string(),
        algorithm: "RSA/ECB/PKCS1Padding".to_string(),
        encrypted_data_encryption_key: general_purpose::STANDARD
            .encode(encrypted_data_encryption_key),
        rsa_oaep_label: None,
        reason: "Gmail".to_string(),
        wrapped_private_key: wrapped_private_key.to_string(),
        spki_hash: general_purpose::STANDARD.encode(blue_spki_hash),
        spki_hash_algorithm: "SHA-256".to_string(),
    };

    tracing::debug!("privileged private key decrypt request post");
    let response: PrivilegedPrivateKeyDecryptResponse =
        test_utils::post_with_uri(&app, request, "/google_cse/privilegedprivatekeydecrypt").await?;
    tracing::debug!("privileged private key decrypt response post: {response:?}");

    assert_eq!(
        general_purpose::STANDARD.encode(dek),
        response.data_encryption_key
    );

    Ok(())
}
