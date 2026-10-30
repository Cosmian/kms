//! Gmail CSE key-pair certification with a PKCS#12 intermediate certificate.
//!
//! Non-FIPS only: the PKCS12KDF MAC of the PKCS#12 file is not available in the FIPS provider.

use std::path::PathBuf;

use base64::{Engine, engine::general_purpose};
use cosmian_kms_client_utils::reexport::cosmian_kmip::time_normalize;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::BlockCipherMode,
        kmip_2_1::{
            extra::{VENDOR_ATTR_X509_EXTENSION, tagging::VENDOR_ID_COSMIAN},
            kmip_attributes::Attributes,
            kmip_data_structures::KeyWrappingSpecification,
            kmip_objects::{Certificate, Object, ObjectType},
            kmip_operations::{Certify, Get, Import},
            kmip_types::{
                CertificateAttributes, CryptographicParameters, EncodingOption,
                EncryptionKeyInformation, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
                UniqueIdentifier, VendorAttribute, VendorAttributeValue, WrappingMethod,
            },
            requests::create_rsa_key_pair_request,
        },
    },
    cosmian_kms_crypto::crypto::certificates::EXTENSION_CONFIG,
};
use cosmian_logger::{debug, log_init, trace};
use openssl::rsa::Rsa;
use zeroize::Zeroizing;

use super::{
    build_private_key_from_der_bytes, read_bytes_from_file, read_object_from_json_ttlv_bytes,
    rsa_encrypt, test_cse_private_key_decrypt,
};
use crate::{
    middlewares::UserId, result::KResult, routes::google_cse::operations::GOOGLE_CSE_ID,
    tests::test_utils::test_kms,
};

#[tokio::test]
async fn test_google_cse_create_pair_encrypt_decrypt() -> KResult<()> {
    log_init(Some("debug"));

    let kms = test_kms().await?;
    let owner = UserId::from("eyJhbGciOiJSUzI1Ni");

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
            &owner,
        )
        .await?;

    // Create RSA key pair for Google GMail
    let created_key_pair = kms
        .create_key_pair(
            create_rsa_key_pair_request(
                VENDOR_ID_COSMIAN,
                None,
                Vec::<String>::new(),
                4096,
                false,
                None,
            )?,
            &owner,
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
            &owner,
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
    // only Active keys may sign certificates
    attributes.activation_date = Some(time_normalize()?);
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
    let intermediate_cert = kms.import(import_request, &owner).await?;

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
        .certify(certify_request, &owner)
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
            &owner,
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
            &owner,
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
