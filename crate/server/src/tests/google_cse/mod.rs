#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::panic_in_result_fn,
    clippy::unwrap_in_result
)]

// Base imports used by all tests
// Imports for Google CSE tests
use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use actix_http::{Request, body::MessageBody};
use actix_web::dev::{Service, ServiceResponse};
use alcoholic_jwt::JWKS;
use base64::{Engine, engine::general_purpose};
use cosmian_kms_access::access::{Access, SuccessResponse};
use cosmian_kms_client_utils::reexport::cosmian_kmip::time_normalize;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{BlockCipherMode, KeyWrapType},
        kmip_2_1::{
            KmipOperation,
            extra::{VENDOR_ATTR_X509_EXTENSION, VENDOR_ID_COSMIAN},
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingSpecification},
            kmip_objects::{Certificate, Object, ObjectType, PrivateKey},
            kmip_operations::{Certify, Get, GetResponse, Import, ImportResponse},
            kmip_types::{
                CertificateAttributes, CryptographicParameters, EncodingOption,
                EncryptionKeyInformation, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
                UniqueIdentifier, VendorAttribute, VendorAttributeValue, WrappingMethod,
            },
            requests::create_rsa_key_pair_request,
        },
        ttlv::{TTLV, from_ttlv},
    },
    cosmian_kms_crypto::crypto::certificates::EXTENSION_CONFIG,
};
use cosmian_logger::{debug, log_init, trace};
use hex::{FromHex, ToHex};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
    sign::{Signer, Verifier},
    x509::X509,
};
use zeroize::Zeroizing;

#[cfg(feature = "non-fips")]
use crate::routes::google_cse::operations::StatusResponse;
use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    middlewares::{JwksManager, JwtConfig},
    result::{KResult, KResultHelper},
    routes::google_cse::{
        GoogleCseConfig,
        operations::{
            GOOGLE_CSE_ID, PrivateKeyDecryptRequest, PrivateKeyDecryptResponse,
            PrivateKeySignRequest, PrivateKeySignResponse, PrivilegedPrivateKeyDecryptRequest,
            PrivilegedPrivateKeyDecryptResponse, PrivilegedUnwrapRequest, PrivilegedUnwrapResponse,
            PrivilegedWrapRequest, PrivilegedWrapResponse, UnwrapRequest, UnwrapResponse,
            WrapRequest, WrapResponse, compute_resource_key_hash, create_jwt,
        },
        validate_cse_authentication_token,
    },
    tests::{
        google_cse::utils::generate_google_jwt,
        test_utils::{self, https_clap_config, post_2_1},
    },
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
    let object: Object = from_ttlv(ttlv)?;
    Ok(object)
}

async fn import_google_cse_symmetric_key_with_access<B, S>(app: &S) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let symmetric_key = read_bytes_from_file(&PathBuf::from(
        "../../documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.json",
    ))?;

    let object = read_object_from_json_ttlv_bytes(&symmetric_key)?;

    // Set activation_date to current time to ensure key is immediately active
    let mut attributes = object.attributes().cloned().unwrap_or_default();
    attributes.activation_date = Some(time_normalize()?);

    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
        object_type: object.object_type(),
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes,
        object,
    };

    debug!("import request: {import_request}");
    let response: ImportResponse = test_utils::post_2_1(app, import_request).await?;
    debug!("import response: {}", response);

    let access = Access {
        unique_identifier: Some(UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned())),
        user_id: "*".to_owned(),
        operation_types: vec![
            KmipOperation::Create,
            KmipOperation::Destroy,
            KmipOperation::Get,
            KmipOperation::Encrypt,
            KmipOperation::Decrypt,
        ],
    };

    let access_response: SuccessResponse =
        test_utils::post_json_with_uri(app, access, "/access/grant").await?;
    debug!("grant response post: {:?}", access_response);

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
        "../../test_data/certificates/gmail_cse/blue.key",
    ))?;

    let rsa_private_key = Rsa::<Private>::private_key_from_pem(&blue_private_key)?;
    let private_key = PKey::from_rsa(rsa_private_key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &private_key)?;

    debug!("padding method: {:?}", signer.rsa_padding());

    signer.update(&digest)?;
    let signature = signer.sign_to_vec()?;

    debug!(
        "signature: {}",
        general_purpose::STANDARD.encode(signature.clone())
    );

    //-------------------------------------------------------------------------
    // Verify
    //-------------------------------------------------------------------------
    // The RSA blue public key
    let blue_public_key = read_bytes_from_file(&PathBuf::from(
        "../../test_data/certificates/gmail_cse/blue.pem",
    ))?;
    let rsa_public_key = X509::from_pem(&blue_public_key)?;
    let public_key = rsa_public_key.public_key()?;
    // Verify the signature
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)?;
    verifier.update(&digest)?;

    assert!(verifier.verify(&signature)?);

    Ok(())
}

/// Test resource key hash computing, from Google official documentation examples
/// Run OpenSSL in command line to verify the results:
/// echo -n "<ResourceKeyDigest://googleapis.com/testcase/hJB0PzRI7nl79LC18qaV8WMDCBALBSs9BREcq79MfVw>:" | openssl sha256 -mac HMAC -macopt hexkey:6a68079290123ed8f23c845cc8bda91cd961c0246b79446662919e336920cbef -binary | xxd -p -c 256
/// echo -n "<ResourceKeyDigest://googleapis.com/testcase/od8yfZiS5ZF2RN27X4ClalsV6LobL2FwKRk4qOJxWdE:perimeter1>" | openssl sha256 -mac HMAC -macopt hexkey:05b62b91cb66f19e27789fb69eb680fac113a70a120178d6cfa6b1b4cb11bb95 -binary | xxd -p -c 256
#[tokio::test]
async fn test_google_cse_resource_key_hash() -> KResult<()> {
    let dek = "6a68079290123ed8f23c845cc8bda91cd961c0246b79446662919e336920cbef";
    let dek_data = Vec::from_hex(dek).unwrap();

    let resource_name: String =
        "//googleapis.com/testcase/hJB0PzRI7nl79LC18qaV8WMDCBALBSs9BREcq79MfVw".to_owned();

    let base64_digest = compute_resource_key_hash(&resource_name, "", &dek_data.into()).unwrap();
    let bytes = general_purpose::STANDARD.decode(base64_digest).unwrap();
    let hex_digest = bytes.encode_hex::<String>();

    let expected_digest = "4d9aafeb06cd0e812d0f3c10f18573a5aee4c86300a104fad9b258f0b71bd813";

    assert_eq!(hex_digest, expected_digest);

    let dek_bis = "05b62b91cb66f19e27789fb69eb680fac113a70a120178d6cfa6b1b4cb11bb95";

    let dek_data_bis = Vec::from_hex(dek_bis).unwrap();

    let resource_name_bis: String =
        "//googleapis.com/testcase/od8yfZiS5ZF2RN27X4ClalsV6LobL2FwKRk4qOJxWdE".to_owned();

    let perimeter = "perimeter1";

    let base64_digest_bis =
        compute_resource_key_hash(&resource_name_bis, perimeter, &dek_data_bis.into()).unwrap();
    let bytes_bis = general_purpose::STANDARD.decode(base64_digest_bis).unwrap();
    let hex_digest_bis = bytes_bis.encode_hex::<String>();

    let expected_digest_bis = "1b6231a171bc10ef99dd3b08f0742620811a59191570284d32b674c531cc2da5";

    assert_eq!(hex_digest_bis, expected_digest_bis);

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_google_cse_status() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned()), None).await;

    let response: StatusResponse =
        test_utils::get_json_with_uri(&app, "/google_cse/status").await?;
    debug!("status_request sent");

    assert_eq!(response.server_type, "KACLS");
    assert_eq!(response.vendor_id, "Cosmian");

    Ok(())
}

#[tokio::test]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints"]
async fn test_google_cse_private_key_sign() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", JWT_ISSUER_URI);
    };
    log_init(None);

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned()), None).await;

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

    debug!("private key sign request post");
    let pksr_response: PrivateKeySignResponse =
        test_utils::post_json_with_uri(&app, pksr, "/google_cse/privatekeysign").await?;
    debug!("private key sign response post: {pksr_response:?}");

    let user_public_key_pem_pkcs1 = read_bytes_from_file(&PathBuf::from(
        "../../test_data/certificates/gmail_cse/test_public_key",
    ))?;

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

    debug!("rsa pkcs1: dek={dek:?}\nencrypted_dek={encrypted_data_encryption_key:?}");
    Ok(general_purpose::STANDARD.encode(encrypted_data_encryption_key))
}

pub(crate) fn build_private_key_from_der_bytes(
    key_format_type: KeyFormatType,
    bytes: Zeroizing<Vec<u8>>,
) -> Object {
    Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            key_format_type,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(bytes),
                attributes: Some(Attributes::default()),
            }),
            // According to the KMIP spec, the cryptographic algorithm is not required
            // as long as it can be recovered from the Key Format Type or the Key Value.
            // Also it should not be specified if the cryptographic length is not specified.
            cryptographic_algorithm: None,
            // See comment above
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    })
}

#[tokio::test]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints"]
async fn test_google_cse_create_pair_encrypt_decrypt() -> KResult<()> {
    log_init(Some("debug"));

    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // Create google_cse key
    let google_cse_object =
        read_object_from_json_ttlv_bytes(&read_bytes_from_file(&PathBuf::from(
            "../../documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.\
             json",
        ))?)?;

    // Set activation_date to current time to ensure key is immediately active
    // Note: Import operation truncates now to remove milliseconds, so we do the same
    let activation_time = time_normalize()?;
    let mut google_cse_attributes = google_cse_object.attributes().cloned().unwrap_or_default();
    google_cse_attributes.activation_date = Some(activation_time);

    let google_cse_key = kms
        .import(
            Import {
                unique_identifier: UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned()),
                object_type: google_cse_object.object_type(),
                replace_existing: Some(false),
                key_wrap_type: None,
                attributes: google_cse_attributes,
                object: google_cse_object,
            },
            owner,
            None,
        )
        .await?;

    // Create RSA key pair for Google GMail
    let created_key_pair = kms
        .create_key_pair(
            create_rsa_key_pair_request(None, Vec::<String>::new(), 4096, false, None)?,
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
                        cryptographic_parameters: Some(CryptographicParameters {
                            block_cipher_mode: Some(BlockCipherMode::GCM),
                            ..CryptographicParameters::default()
                        }),
                    }),
                    attribute_name: None,
                    encoding_option: Some(EncodingOption::NoEncoding),
                    ..KeyWrappingSpecification::default()
                }),
                None,
            ),
            owner,
        )
        .await?
        .object
        .key_block()?
        .wrapped_key_bytes()?;
    debug!(
        "wrapped_key_bytes: {}",
        general_purpose::STANDARD.encode(&wrapped_key_bytes)
    );

    // Import the intermediate certificate as PKCS12 file
    let private_key = build_private_key_from_der_bytes(
        KeyFormatType::PKCS12,
        Zeroizing::from(read_bytes_from_file(
            &"../../test_data/certificates/gmail_cse/int.p12".to_owned(),
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
        certificate_attributes: Some(CertificateAttributes::parse_subject_line(
            "CN=Google CSE Gmail",
        )?),
        link: Some(vec![Link {
            link_type: LinkType::PrivateKeyLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                intermediate_cert.unique_identifier.to_string(),
            ),
        }]),
        vendor_attributes: Some(vec![VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_X509_EXTENSION.to_owned(),
            attribute_value: VendorAttributeValue::ByteString(EXTENSION_CONFIG.to_vec()),
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
        )
        .await?;

    if let Object::Certificate(Certificate {
        certificate_value, ..
    }) = &pkcs7.object
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
        )
        .await?;

    // The dek in clear
    let dek = vec![1_u8; 16];

    // Encrypt with the RSA public key
    let rsa_public_key =
        Rsa::public_key_from_der_pkcs1(&rsa_public_key.object.key_block()?.pkcs_der_bytes()?)?;

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
    };

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned()), None).await;
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

    debug!("===> private key decrypt request post");
    let response: PrivateKeyDecryptResponse =
        test_utils::post_json_with_uri(&app, request, "/google_cse/privatekeydecrypt").await?;
    debug!("===> private key decrypt response post: {response:?}");

    Ok(response.data_encryption_key)
}

#[tokio::test]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints"]
async fn test_google_cse_encrypt_and_private_key_decrypt() -> KResult<()> {
    log_init(None);
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", JWT_ISSUER_URI);
    };

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned()), None).await;
    // Import google CSE key
    import_google_cse_symmetric_key_with_access(&app).await?;

    let dek = vec![1_u8; 32];

    let pub_key_pem = read_bytes_from_file(&PathBuf::from(
        "../../test_data/certificates/gmail_cse/test_public_key",
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
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints"]
async fn test_google_cse_wrap_unwrap_key() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWT_ISSUER", JWT_ISSUER_URI);
    };

    log_init(None);

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned()), None).await;

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

    debug!("wrapping key request post");
    let wrap_response: WrapResponse =
        test_utils::post_json_with_uri(&app, wrap_request, "/google_cse/wrap").await?;
    debug!("wrapping key response post: {wrap_response:?}");

    let wrapped_key = wrap_response.wrapped_key;

    let unwrap_request: UnwrapRequest = UnwrapRequest {
        authentication: token.clone(),
        authorization: token.clone(),
        wrapped_key,
        reason: String::new(),
    };

    debug!("unwrapping key request post");
    let unwrap_response: UnwrapResponse =
        test_utils::post_json_with_uri(&app, unwrap_request, "/google_cse/unwrap").await?;
    debug!("unwrapping key response post: {unwrap_response:?}");

    assert_eq!(dek, unwrap_response.key);

    Ok(())
}

#[tokio::test]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints"]
async fn test_google_cse_privileged_wrap_unwrap_key() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", JWT_ISSUER_URI);
    };

    log_init(None);

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned()), None).await;

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

    debug!("privileged wrapping key request post");
    let wrap_response: PrivilegedWrapResponse =
        test_utils::post_json_with_uri(&app, wrap_request, "/google_cse/privilegedwrap").await?;
    debug!("privileged wrapping key response post: {wrap_response:?}");

    let wrapped_key = wrap_response.wrapped_key;

    let unwrap_request = PrivilegedUnwrapRequest {
        authentication: token.clone(),
        resource_name: "resource_name_test".to_owned(),
        wrapped_key,
        reason: String::new(),
    };

    debug!("privileged unwrapping key request post");
    let unwrap_response: PrivilegedUnwrapResponse =
        test_utils::post_json_with_uri(&app, unwrap_request, "/google_cse/privilegedunwrap")
            .await?;

    assert_eq!(dek, unwrap_response.key);

    Ok(())
}

#[tokio::test]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints"]
async fn test_google_cse_privileged_private_key_decrypt() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_GMAIL_JWT_ISSUER", JWT_ISSUER_URI);
    };

    log_init(None);

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_owned()), None).await;

    let path = std::env::current_dir()?;
    println!("The current directory is {}", path.display());

    let user_public_key_pem_pkcs1 = read_bytes_from_file(&PathBuf::from(
        "../../test_data/certificates/gmail_cse/test_public_key",
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

    debug!("rsa pkcs1: dek={dek:?}\nencrypted_dek={encrypted_data_encryption_key:?}");

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

    debug!("privileged private key decrypt request post");
    let private_key_decrypt_response: PrivilegedPrivateKeyDecryptResponse =
        test_utils::post_json_with_uri(
            &app,
            private_key_decrypt_request,
            "/google_cse/privilegedprivatekeydecrypt",
        )
        .await?;
    debug!("privileged private key decrypt response post: {private_key_decrypt_response:?}");

    assert_eq!(
        general_purpose::STANDARD.encode(dek),
        private_key_decrypt_response.data_encryption_key
    );

    Ok(())
}

#[tokio::test]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints"]
async fn test_google_cse_custom_jwt() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWT_ISSUER", JWT_ISSUER_URI);
    };

    log_init(None);

    let app = test_utils::test_app(Some("https://127.0.0.1:9998".to_owned()), None).await;

    let resource_name = "resource_name_test".to_owned();
    let kacls_url = "https://127.0.0.1:9998/google_cse";

    // --- Retrieve RSA Private Key from KMS ---
    let get_request = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(format!("{GOOGLE_CSE_ID}_rsa"))),
        key_format_type: Some(KeyFormatType::PKCS1),
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        key_compression_type: None,
        key_wrapping_specification: None,
    };

    let response: GetResponse = post_2_1(&app, get_request).await?;

    let private_key_bytes = match response.object_type {
        ObjectType::PrivateKey => match &response.object.key_block()?.key_value {
            Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(bytes),
                ..
            }) => bytes,
            _ => {
                return Err(KmsError::InvalidRequest(
                    "Expected ByteString key material for RSA private key.".to_owned(),
                ));
            }
        },
        _ => {
            return Err(KmsError::InvalidRequest(
                "Provided ID is not an RSA private key.".to_owned(),
            ));
        }
    };

    // Generate custom JWT
    let jwt_token = create_jwt(private_key_bytes, kacls_url, kacls_url, &resource_name)
        .expect("Failed to create JWT");
    assert!(!jwt_token.is_empty(), "JWT should not be empty");

    // Retrieve JWKS inner exposed
    let jwks: JWKS = test_utils::get_json_with_uri(&app, "/google_cse/certs")
        .await
        .expect("Failed to fetch JWKS from server");

    // Prepare JWKS Manager
    let mut jwks_map = HashMap::new();
    jwks_map.insert(kacls_url.to_owned(), jwks);

    let jwks_manager = JwksManager {
        uris: vec![kacls_url.to_owned()],
        jwks: RwLock::new(jwks_map),
        last_update: RwLock::new(None),
        proxy_params: None,
    };

    let cse_config = GoogleCseConfig {
        authentication: Arc::new(vec![JwtConfig {
            jwt_issuer_uri: kacls_url.to_owned(),
            jwt_audience: Some(vec!["kacls-migration".to_owned()]),
            jwks: Arc::new(jwks_manager),
        }]),
        authorization: HashMap::new(),
    };

    // Validate custom JWT
    let result = validate_cse_authentication_token(
        &jwt_token,
        &Some(cse_config),
        kacls_url,
        "admin",
        Some(resource_name),
    )
    .await;

    assert!(
        result.is_ok(),
        "Expected JWT validation to succeed, but got error: {:?}",
        result.err()
    );

    Ok(())
}

#[tokio::test]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints"]
async fn test_google_cse_custom_jwt_multi_audience_match() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWT_ISSUER", JWT_ISSUER_URI);
    };

    log_init(None);

    let app = test_utils::test_app(Some("https://127.0.0.1:9998".to_owned()), None).await;

    let resource_name = "resource_name_test".to_owned();
    let kacls_url = "https://127.0.0.1:9998/google_cse";

    // Retrieve RSA Private Key
    let get_request = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(format!("{GOOGLE_CSE_ID}_rsa"))),
        key_format_type: Some(KeyFormatType::PKCS1),
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        key_compression_type: None,
        key_wrapping_specification: None,
    };
    let response: GetResponse = post_2_1(&app, get_request).await?;
    let private_key_bytes = match response.object_type {
        ObjectType::PrivateKey => match &response.object.key_block()?.key_value {
            Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(bytes),
                ..
            }) => bytes,
            _ => {
                return Err(KmsError::InvalidRequest(
                    "Expected ByteString key material for RSA private key.".to_owned(),
                ));
            }
        },
        _ => {
            return Err(KmsError::InvalidRequest(
                "Provided ID is not an RSA private key.".to_owned(),
            ));
        }
    };

    // Generate JWT with aud = "kacls-migration"
    let jwt_token = create_jwt(private_key_bytes, kacls_url, kacls_url, &resource_name)
        .expect("Failed to create JWT");

    // Retrieve JWKS inner exposed
    let jwks: JWKS = test_utils::get_json_with_uri(&app, "/google_cse/certs").await?;

    // Prepare JWKS Manager
    let mut jwks_map = HashMap::new();
    jwks_map.insert(kacls_url.to_owned(), jwks);
    let jwks_manager = JwksManager {
        uris: vec![kacls_url.to_owned()],
        jwks: RwLock::new(jwks_map),
        last_update: RwLock::new(None),
        proxy_params: None,
    };

    // Configure multiple allowed audiences, including the correct one
    let cse_config = GoogleCseConfig {
        authentication: Arc::new(vec![JwtConfig {
            jwt_issuer_uri: kacls_url.to_owned(),
            jwt_audience: Some(vec!["wrong-aud".to_owned(), "kacls-migration".to_owned()]),
            jwks: Arc::new(jwks_manager),
        }]),
        authorization: HashMap::new(),
    };

    // Validate custom JWT
    let result = validate_cse_authentication_token(
        &jwt_token,
        &Some(cse_config),
        kacls_url,
        "admin",
        Some(resource_name),
    )
    .await;

    assert!(
        result.is_ok(),
        "Expected JWT validation to succeed with any-of audience match"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "Requires Google OAuth credentials and access to Google CSE endpoints"]
async fn test_google_cse_custom_jwt_multi_audience_nomatch() -> KResult<()> {
    unsafe {
        std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWKS_URI", JWKS_URI);
        std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWT_ISSUER", JWT_ISSUER_URI);
    };

    log_init(None);

    let app = test_utils::test_app(Some("https://127.0.0.1:9998".to_owned()), None).await;
    let resource_name = "resource_name_test".to_owned();
    let kacls_url = "https://127.0.0.1:9998/google_cse";

    // Retrieve RSA Private Key
    let get_request = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(format!("{GOOGLE_CSE_ID}_rsa"))),
        key_format_type: Some(KeyFormatType::PKCS1),
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        key_compression_type: None,
        key_wrapping_specification: None,
    };
    let response: GetResponse = post_2_1(&app, get_request).await?;
    let private_key_bytes = match response.object_type {
        ObjectType::PrivateKey => match &response.object.key_block()?.key_value {
            Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(bytes),
                ..
            }) => bytes,
            _ => {
                return Err(KmsError::InvalidRequest(
                    "Expected ByteString key material for RSA private key.".to_owned(),
                ));
            }
        },
        _ => {
            return Err(KmsError::InvalidRequest(
                "Provided ID is not an RSA private key.".to_owned(),
            ));
        }
    };

    // Generate JWT with aud = "kacls-migration"
    let jwt_token = create_jwt(private_key_bytes, kacls_url, kacls_url, &resource_name)
        .expect("Failed to create JWT");

    // Retrieve JWKS inner exposed
    let jwks: JWKS = test_utils::get_json_with_uri(&app, "/google_cse/certs").await?;

    // Prepare JWKS Manager
    let mut jwks_map = HashMap::new();
    jwks_map.insert(kacls_url.to_owned(), jwks);
    let jwks_manager = JwksManager {
        uris: vec![kacls_url.to_owned()],
        jwks: RwLock::new(jwks_map),
        last_update: RwLock::new(None),
        proxy_params: None,
    };

    // Configure multiple allowed audiences, none matching token aud
    let cse_config = GoogleCseConfig {
        authentication: Arc::new(vec![JwtConfig {
            jwt_issuer_uri: kacls_url.to_owned(),
            jwt_audience: Some(vec!["wrong1".to_owned(), "wrong2".to_owned()]),
            jwks: Arc::new(jwks_manager),
        }]),
        authorization: HashMap::new(),
    };

    // Validate custom JWT should fail
    let result = validate_cse_authentication_token(
        &jwt_token,
        &Some(cse_config),
        kacls_url,
        "admin",
        Some(resource_name),
    )
    .await;

    assert!(
        result.is_err(),
        "Expected JWT validation to fail without audience match"
    );
    Ok(())
}
