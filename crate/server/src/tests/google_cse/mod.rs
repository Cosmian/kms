#![allow(clippy::unwrap_used, clippy::print_stdout, clippy::panic_in_result_fn)]
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use actix_http::{body::MessageBody, Request};
use actix_service::Service;
use actix_web::dev::ServiceResponse;
use base64::{engine::general_purpose, Engine};
use cosmian_kmip::{
    crypto::{certificates::EXTENSION_CONFIG, rsa::kmip_requests::create_rsa_key_pair_request},
    kmip::{
        extra::{VENDOR_ATTR_X509_EXTENSION, VENDOR_ID_COSMIAN},
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingSpecification},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Certify, Get, Import, ImportResponse},
        kmip_types::{
            Attributes, BlockCipherMode, CertificateAttributes, CryptographicParameters,
            EncodingOption, EncryptionKeyInformation, KeyFormatType, Link, LinkType,
            LinkedObjectIdentifier, UniqueIdentifier, VendorAttribute, WrappingMethod,
        },
        ttlv::{deserializer::from_ttlv, TTLV},
    },
};
use cosmian_kms_client::access::{Access, ObjectOperationType, SuccessResponse};
use cosmian_logger::log_utils::log_init;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
    sign::{Signer, Verifier},
    x509::X509,
};
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::{
    config::ServerParams,
    result::{KResult, KResultHelper},
    routes::google_cse::operations::{
        DigestRequest, DigestResponse, PrivateKeyDecryptRequest, PrivateKeyDecryptResponse,
        PrivateKeySignRequest, PrivateKeySignResponse, PrivilegedPrivateKeyDecryptRequest,
        PrivilegedPrivateKeyDecryptResponse, PrivilegedUnwrapRequest, PrivilegedUnwrapResponse,
        PrivilegedWrapRequest, PrivilegedWrapResponse, RewrapRequest, RewrapResponse,
        StatusResponse, UnwrapRequest, UnwrapResponse, WrapRequest, WrapResponse, GOOGLE_CSE_ID,
    },
    tests::{
        google_cse::utils::generate_google_jwt,
        test_utils::{self, https_clap_config},
    },
    KMSServer,
};

pub(crate) mod utils;

// Default JWT issuer URI for Gmail endpoint
#[cfg(test)]
const JWT_ISSUER_URI: &str = "https://accounts.google.com";

// Default JWT Set URI for Gmail endpoint
#[cfg(test)]
const JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";

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

async fn import_google_cse_symmetric_key_with_access<B, S>(app: &S) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let symmetric_key = read_bytes_from_file(&PathBuf::from(
        "../../documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.json",
    ))
    .unwrap();

    let object = read_object_from_json_ttlv_bytes(&symmetric_key).unwrap();

    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        object_type: object.object_type(),
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes: object.attributes().cloned().unwrap_or_default(),
        object,
    };

    tracing::debug!("import request: {import_request}");
    let response: ImportResponse = test_utils::post(app, import_request).await?;
    tracing::debug!("import response: {response:?}");

    let access = Access {
        unique_identifier: Some(UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned())),
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
        test_utils::post_with_uri(app, access, "/access/grant").await?;
    tracing::debug!("grant response post: {access_response:?}");

    Ok(())
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
    log_init(Some("debug,cosmian_kms_server=trace"));

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned())).await;

    let response: StatusResponse = test_utils::get_with_uri(&app, "/google_cse/status").await?;
    tracing::debug!("status_request sent");

    assert_eq!(response.server_type, "KACLS");
    assert_eq!(response.vendor_id, "Cosmian");

    Ok(())
}

#[tokio::test]
async fn test_cse_private_key_sign() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", JWT_ISSUER_URI);
    }
    log_init(Some("debug,cosmian_kms_server=trace"));

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned())).await;

    // Import google CSE key
    import_google_cse_symmetric_key_with_access(&app).await?;

    let wrapped_private_key =
        include_str!("../../../../../documentation/docs/google_cse/test_wrapped_private_key");
    let digest = "gXIjp2D7tR4WvHJBXaINWLekf5k5AeKRw4zkySYDDYs=";

    let token: String = generate_google_jwt()
        .await
        .expect("Error on token generation");

    let pksr = PrivateKeySignRequest {
        authentication: token.clone(),
        authorization: token.clone(),
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

    let user_public_key_pem_pkcs1 = read_bytes_from_file(&PathBuf::from(
        "src/routes/google_cse/python/openssl/test_public_key",
    ))
    .unwrap();

    // Load the public key from bytes
    let rsa_public_key = Rsa::public_key_from_pem_pkcs1(&user_public_key_pem_pkcs1)?;

    // Convert the RSA public key into a PKey<Public>
    let public_key = PKey::from_rsa(rsa_public_key)?;

    let mut ctx = PkeyCtx::new(&public_key)?;
    ctx.verify_init()?;
    ctx.verify(
        &general_purpose::STANDARD.decode(digest)?,
        &general_purpose::STANDARD.decode(pksr_response.signature)?,
    )?;

    Ok(())
}

// RSA PKCS1 encryption
fn rsa_encrypt(rsa_public_key: Rsa<Public>, dek: &[u8]) -> KResult<String> {
    // Convert the RSA public key into a PKey<Public>
    let public_key = PKey::from_rsa(rsa_public_key)?;

    // Perform RSA PKCS1 encryption.
    let mut ctx = PkeyCtx::new(&public_key)?;
    ctx.encrypt_init()?;
    ctx.set_rsa_padding(Padding::PKCS1)?;

    let encrypt_size = ctx.encrypt(dek, None)?;

    let mut encrypted_data_encryption_key = vec![0_u8; encrypt_size];
    ctx.encrypt(dek, Some(&mut *encrypted_data_encryption_key))?;

    tracing::debug!("rsa pkcs1: dek={dek:?}\nencrypted_dek={encrypted_data_encryption_key:?}");
    Ok(general_purpose::STANDARD.encode(encrypted_data_encryption_key))
}

pub(crate) fn build_private_key_from_der_bytes(
    key_format_type: KeyFormatType,
    bytes: Zeroizing<Vec<u8>>,
) -> Object {
    Object::PrivateKey {
        key_block: KeyBlock {
            key_format_type,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(bytes),
                attributes: Some(Box::default()),
            },
            // According to the KMIP spec, the cryptographic algorithm is not required
            // as long as it can be recovered from the Key Format Type or the Key Value.
            // Also it should not be specified if the cryptographic length is not specified.
            cryptographic_algorithm: None,
            // See comment above
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    }
}

#[tokio::test]
async fn test_create_pair_encrypt_decrypt() -> KResult<()> {
    log_init(None);

    let clap_config = https_clap_config();
    let kms = Arc::new(KMSServer::instantiate(ServerParams::try_from(clap_config)?).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // Create google_cse key
    let google_cse_object =
        read_object_from_json_ttlv_bytes(&read_bytes_from_file(&PathBuf::from(
            "../../documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.\
             json",
        ))?)?;
    let google_cse_key = kms
        .import(
            Import {
                unique_identifier: UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
                object_type: google_cse_object.object_type(),
                replace_existing: Some(false),
                key_wrap_type: None,
                attributes: google_cse_object.attributes().cloned().unwrap_or_default(),
                object: google_cse_object,
            },
            owner,
            None,
        )
        .await?;

    // Create RSA key pair for Google GMail
    let created_key_pair = kms
        .create_key_pair(
            create_rsa_key_pair_request(None, Vec::<String>::new(), 4096)?,
            owner,
            None,
        )
        .await?;

    // Wrap the created private key with the google_cse key
    let wrapped_key_bytes = kms
        .get(
            Get::new(
                created_key_pair.private_key_unique_identifier.clone(),
                false,
                Some(KeyWrappingSpecification {
                    wrapping_method: WrappingMethod::Encrypt,
                    encryption_key_information: Some(EncryptionKeyInformation {
                        unique_identifier: google_cse_key.unique_identifier,
                        cryptographic_parameters: Some(Box::new(CryptographicParameters {
                            block_cipher_mode: Some(BlockCipherMode::GCM),
                            ..CryptographicParameters::default()
                        })),
                    }),
                    attribute_name: None,
                    encoding_option: Some(EncodingOption::NoEncoding),
                    ..KeyWrappingSpecification::default()
                }),
                None,
            ),
            owner,
            None,
        )
        .await?
        .object
        .key_block()?
        .key_bytes()?;
    debug!(
        "wrapped_key_bytes: {}",
        general_purpose::STANDARD.encode(&wrapped_key_bytes)
    );

    // Import the intermediate certificate as PKCS12 file
    let private_key = build_private_key_from_der_bytes(
        KeyFormatType::PKCS12,
        Zeroizing::from(read_bytes_from_file(
            &"src/routes/google_cse/python/openssl/int.p12".to_owned(),
        )?),
    );

    let mut attributes = private_key.attributes().cloned().unwrap_or_default();
    attributes.set_link(
        LinkType::PKCS12PasswordLink,
        LinkedObjectIdentifier::TextString("secret".to_owned()),
    );

    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString("intermediate_cse_cert".to_owned()),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes,
        object: private_key,
    };
    let intermediate_cert = kms.import(import_request, owner, None).await?;

    // Certify the public key: sign created public key with issuer private key
    let attributes = Attributes {
        object_type: Some(ObjectType::Certificate),
        certificate_attributes: Some(Box::new(CertificateAttributes::parse_subject_line(
            "CN=Google CSE Gmail",
        )?)),
        link: Some(vec![Link {
            link_type: LinkType::PrivateKeyLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                intermediate_cert.unique_identifier.to_string(),
            ),
        }]),
        vendor_attributes: Some(vec![VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_X509_EXTENSION.to_owned(),
            attribute_value: EXTENSION_CONFIG.to_vec(),
        }]),
        ..Attributes::default()
    };

    let certify_request = Certify {
        unique_identifier: Some(created_key_pair.public_key_unique_identifier.clone()),
        attributes: Some(attributes),
        ..Certify::default()
    };

    let certificate_unique_identifier = kms
        .certify(certify_request, owner, None)
        .await?
        .unique_identifier;

    // Export the certificate and chain in PKCS7 format (just checking that it works)
    let pkcs7 = kms
        .get(
            Get::new(
                certificate_unique_identifier.clone(),
                false,
                None,
                Some(KeyFormatType::PKCS7),
            ),
            owner,
            None,
        )
        .await?;

    if let Object::Certificate {
        certificate_value, ..
    } = &pkcs7.object
    {
        trace!(
            "pkcs7_format: {:?}",
            general_purpose::STANDARD.encode(certificate_value)
        );
    }

    // Encrypt with RSA public key
    let rsa_public_key = kms
        .get(
            Get::new(
                created_key_pair.public_key_unique_identifier.clone(),
                false,
                None,
                None,
            ),
            owner,
            None,
        )
        .await?;

    // The dek in clear
    let dek = vec![1_u8; 16];

    // Encrypt with the RSA public key
    let rsa_public_key =
        Rsa::public_key_from_der_pkcs1(&rsa_public_key.object.key_block()?.key_bytes()?)?;

    let encrypted_data_encryption_key = rsa_encrypt(rsa_public_key, &dek)?;
    debug!(
        "encrypted_data_encryption_key: {:?}",
        encrypted_data_encryption_key
    );

    let data_encryption_key = test_cse_private_key_decrypt(
        &encrypted_data_encryption_key,
        &general_purpose::STANDARD.encode(wrapped_key_bytes),
    )
    .await?;

    assert_eq!(general_purpose::STANDARD.encode(dek), data_encryption_key);
    Ok(())
}

async fn test_cse_private_key_decrypt(
    encrypted_data_encryption_key: &str,
    wrapped_private_key: &str,
) -> KResult<String> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", JWT_ISSUER_URI);
    }

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned())).await;
    // Import google CSE key
    import_google_cse_symmetric_key_with_access(&app).await?;

    let token: String = generate_google_jwt()
        .await
        .expect("Error on token generation");

    let request = PrivateKeyDecryptRequest {
        authentication: token.clone(),
        authorization: token.clone(),
        algorithm: "RSA/ECB/PKCS1Padding".to_owned(),
        encrypted_data_encryption_key: encrypted_data_encryption_key.to_owned(),
        rsa_oaep_label: None,
        reason: "Gmail".to_owned(),
        wrapped_private_key: wrapped_private_key.to_owned(),
    };

    tracing::debug!("private key decrypt request post");
    let response: PrivateKeyDecryptResponse =
        test_utils::post_with_uri(&app, request, "/google_cse/privatekeydecrypt").await?;
    tracing::debug!("private key decrypt response post: {response:?}");

    Ok(response.data_encryption_key)
}

#[tokio::test]
async fn test_encrypt_and_private_key_decrypt() -> KResult<()> {
    log_init(None);
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", JWT_ISSUER_URI);
    }

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned())).await;
    // Import google CSE key
    import_google_cse_symmetric_key_with_access(&app).await?;

    let dek = vec![1_u8; 32];

    let pub_key_pem = read_bytes_from_file(&PathBuf::from(
        "src/routes/google_cse/python/openssl/test_public_key",
    ))?;
    let rsa_public_key = Rsa::public_key_from_pem_pkcs1(&pub_key_pem)?;
    let encrypted_data_encryption_key = rsa_encrypt(rsa_public_key, &dek)?;

    let wrapped_private_key =
        include_str!("../../../../../documentation/docs/google_cse/test_wrapped_private_key");

    let data_encryption_key =
        test_cse_private_key_decrypt(&encrypted_data_encryption_key, wrapped_private_key).await?;

    assert_eq!(general_purpose::STANDARD.encode(dek), data_encryption_key);

    Ok(())
}

#[tokio::test]
async fn test_cse_wrap_unwrap_key() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWT_ISSUER", JWT_ISSUER_URI);
    }

    log_init(Some("info,cosmian_kms_server=trace"));

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned())).await;

    // Import google CSE key
    import_google_cse_symmetric_key_with_access(&app).await?;

    let dek = "wHrlNOTI9mU6PBdqiq7EQA==";

    let token: String = generate_google_jwt()
        .await
        .expect("Error on token generation");

    let wrap_request = WrapRequest {
        authentication: token.clone(),
        authorization: token.clone(),
        key: dek.to_owned(),
        reason: String::new(),
    };

    tracing::debug!("wrapping key request post");
    let wrap_response: WrapResponse =
        test_utils::post_with_uri(&app, wrap_request, "/google_cse/wrap").await?;
    tracing::debug!("wrapping key response post: {wrap_response:?}");

    let wrapped_key = wrap_response.wrapped_key;

    let unwrap_request: UnwrapRequest = UnwrapRequest {
        authentication: token.clone(),
        authorization: token.clone(),
        wrapped_key,
        reason: String::new(),
    };

    tracing::debug!("unwrapping key request post");
    let unwrap_response: UnwrapResponse =
        test_utils::post_with_uri(&app, unwrap_request, "/google_cse/unwrap").await?;
    tracing::debug!("unwrapping key response post: {unwrap_response:?}");

    assert_eq!(dek, unwrap_response.key);

    Ok(())
}

#[tokio::test]
async fn test_cse_privileged_wrap_unwrap_key() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", JWT_ISSUER_URI);
    }

    log_init(Some("info,cosmian_kms_server=trace"));

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned())).await;

    // Import google CSE key
    import_google_cse_symmetric_key_with_access(&app).await?;

    let dek = "wHrlNOTI9mU6PBdqiq7EQA==";

    let token: String = generate_google_jwt()
        .await
        .expect("Error on token generation");

    let wrap_request = PrivilegedWrapRequest {
        authentication: token.clone(),
        key: dek.to_owned(),
        perimeter_id: String::new(),
        resource_name: "resource_name_test".to_owned(),
        reason: String::new(),
    };

    tracing::debug!("privileged wrapping key request post");
    let wrap_response: PrivilegedWrapResponse =
        test_utils::post_with_uri(&app, wrap_request, "/google_cse/privilegedwrap").await?;
    tracing::debug!("privileged wrapping key response post: {wrap_response:?}");

    let wrapped_key = wrap_response.wrapped_key;

    let unwrap_request = PrivilegedUnwrapRequest {
        authentication: token.clone(),
        resource_name: "resource_name_test".to_owned(),
        wrapped_key,
        reason: String::new(),
    };

    tracing::debug!("privileged unwrapping key request post");
    let unwrap_response: PrivilegedUnwrapResponse =
        test_utils::post_with_uri(&app, unwrap_request, "/google_cse/privilegedunwrap").await?;

    assert_eq!(dek, unwrap_response.key);

    Ok(())
}

#[tokio::test]
async fn test_cse_privileged_private_key_decrypt() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", JWT_ISSUER_URI);
    }

    log_init(Some("info,cosmian_kms_server=trace"));

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned())).await;

    let path = std::env::current_dir()?;
    println!("The current directory is {}", path.display());

    let user_public_key_pem_pkcs1 = read_bytes_from_file(&PathBuf::from(
        "src/routes/google_cse/python/openssl/test_public_key",
    ))
    .unwrap();

    // Load the public key from bytes
    let rsa_public_key = Rsa::public_key_from_pem_pkcs1(&user_public_key_pem_pkcs1)?;

    // Convert the RSA public key into a PKey<Public>
    let public_key = PKey::from_rsa(rsa_public_key)?;
    let user_spki_hash =
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

    // Import google CSE key
    import_google_cse_symmetric_key_with_access(&app).await?;

    let wrapped_private_key =
        include_str!("../../../../../documentation/docs/google_cse/test_wrapped_private_key");

    let token: String = generate_google_jwt()
        .await
        .expect("Error on token generation");

    let private_key_decrypt_request = PrivilegedPrivateKeyDecryptRequest {
        authentication: token.clone(),
        algorithm: "RSA/ECB/PKCS1Padding".to_owned(),
        encrypted_data_encryption_key: general_purpose::STANDARD
            .encode(encrypted_data_encryption_key),
        rsa_oaep_label: None,
        reason: "Gmail".to_owned(),
        wrapped_private_key: wrapped_private_key.to_owned(),
        spki_hash: general_purpose::STANDARD.encode(user_spki_hash),
        spki_hash_algorithm: "SHA-256".to_owned(),
    };

    tracing::debug!("privileged private key decrypt request post");
    let private_key_decrypt_response: PrivilegedPrivateKeyDecryptResponse =
        test_utils::post_with_uri(
            &app,
            private_key_decrypt_request,
            "/google_cse/privilegedprivatekeydecrypt",
        )
        .await?;
    tracing::debug!(
        "privileged private key decrypt response post: {private_key_decrypt_response:?}"
    );

    assert_eq!(
        general_purpose::STANDARD.encode(dek),
        private_key_decrypt_response.data_encryption_key
    );

    Ok(())
}

#[tokio::test]
async fn test_cse_rewrap_key() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWT_ISSUER", JWT_ISSUER_URI);
    }

    log_init(Some("info,cosmian_kms_server=trace"));

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned())).await;

    // Import google_cse key
    import_google_cse_symmetric_key_with_access(&app).await?;

    // Import original_kms google_cse key
    let original_symmetric_key = read_bytes_from_file(&PathBuf::from(
        "../../documentation/docs/google_cse/original_kms_cse_key.demo.key.json",
    ))
    .unwrap();

    let object = read_object_from_json_ttlv_bytes(&original_symmetric_key).unwrap();

    // We defined that original kms imported key must be importing under the original_kacls_url as ID
    let import_original_key_request = Import {
        unique_identifier: UniqueIdentifier::TextString("original_kacls_url_test".to_owned()),
        object_type: object.object_type(),
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes: object.attributes().cloned().unwrap_or_default(),
        object,
    };

    let response_original_key_import: ImportResponse =
        test_utils::post(&app, import_original_key_request).await?;
    tracing::debug!(
        "import original kms google_cse key response: {response_original_key_import:?}"
    );

    let access_original_key_request = Access {
        unique_identifier: Some(UniqueIdentifier::TextString(
            "original_kacls_url_test".to_owned(),
        )),
        user_id: "*".to_owned(),
        operation_types: vec![
            ObjectOperationType::Create,
            ObjectOperationType::Destroy,
            ObjectOperationType::Get,
            ObjectOperationType::Encrypt,
            ObjectOperationType::Decrypt,
        ],
    };

    let access_original_key_response: SuccessResponse =
        test_utils::post_with_uri(&app, access_original_key_request, "/access/grant").await?;
    tracing::debug!("grant response post: {access_original_key_response:?}");

    // Original DEK and Wrapped DEK with original kms google_cse key
    let dek: &str = "wHrlNOTI9mU6PBdqiq7EQA==";
    let wrapped_dek = "k+rlNR98tECJk8ZXhYOYUgCQFh14E2U24UkBslqZhcipcUQ6Kj9OuIIhnAc=";

    // Rewrap DEK with current KMS
    let token: String = generate_google_jwt()
        .await
        .expect("Error on token generation");
    let rewrap_request = RewrapRequest {
        authorization: token.clone(),
        original_kacls_url: "original_kacls_url_test".to_owned(),
        wrapped_key: wrapped_dek.to_owned(),
        reason: String::new(),
    };

    let rewrap_response: RewrapResponse =
        test_utils::post_with_uri(&app, rewrap_request, "/google_cse/rewrap").await?;
    tracing::debug!("rewrapping key response post: {rewrap_response:?}");

    // Unwrap DEK and compare it to the initial DEK
    let rewrapped_key = rewrap_response.wrapped_key;

    let unwrap_request = PrivilegedUnwrapRequest {
        authentication: token.clone(),
        resource_name: String::new(),
        wrapped_key: rewrapped_key.clone(),
        reason: String::new(),
    };

    let unwrap_response: PrivilegedUnwrapResponse =
        test_utils::post_with_uri(&app, unwrap_request, "/google_cse/privilegedunwrap").await?;

    assert_eq!(dek, unwrap_response.key);

    // Compare the generated resource_key_hash to the one computed on the digest endpoint
    let digest_request = DigestRequest {
        authorization: token.clone(),
        wrapped_key: rewrapped_key,
        reason: String::new(),
    };
    tracing::debug!("digest key request post");
    let digest_response: DigestResponse =
        test_utils::post_with_uri(&app, digest_request, "/google_cse/digest").await?;

    assert_eq!(
        digest_response.resource_key_hash,
        rewrap_response.resource_key_hash
    );

    Ok(())
}
