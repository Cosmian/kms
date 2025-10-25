use std::path::PathBuf;

use base64::Engine;
use cosmian_kmip::{
    kmip_0::kmip_types::BlockCipherMode,
    kmip_2_1::kmip_types::{CryptographicAlgorithm, CryptographicParameters},
};
use cosmian_kms_client::{ExportObjectParams, export_object};
use cosmian_logger::{info, log_init};
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{
        google::keypairs::create::CreateKeyPairsAction,
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
    tests::kms::certificates::certify::import_root_and_intermediate,
};

#[tokio::test]
async fn create_google_key_pair() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Create the Google CSE key
    let cse_key_id = CreateKeyAction::default()
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

#[derive(serde::Serialize)]
struct PrivateKeySignReq<'a> {
    authentication: &'a str,
    authorization: &'a str,
    algorithm: &'a str,
    digest: &'a str,
    rsa_pss_salt_length: Option<i32>,
    reason: &'a str,
    wrapped_private_key: &'a str,
}

#[tokio::test]
async fn create_google_key_pair_and_sign_with_private_key() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Create the Google CSE key
    let cse_key_id = CreateKeyAction {
        key_id: Some("google_cse".to_owned()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // import signers
    let (_root_id, _intermediate_id, issuer_private_key_id) =
        Box::pin(import_root_and_intermediate(ctx)).await.unwrap();

    // Create key pair without certificate extensions (must fail)
    let action = CreateKeyPairsAction {
        user_id: "marta.doe@acme.com".to_owned(),
        cse_key_id: cse_key_id.to_string(),
        issuer_private_key_id: Some(issuer_private_key_id.to_string()),
        subject_name: "CN=Marta Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US".to_owned(),
        rsa_private_key_id: None,
        sensitive: false,
        wrapping_key_id: None,
        leaf_certificate_extensions: Some(PathBuf::from(
            "../../test_data/certificates/openssl/ext_leaf.cnf",
        )),
        leaf_certificate_id: None,
        leaf_certificate_pkcs12_file: None,
        leaf_certificate_pkcs12_password: None,
        dry_run: true,
    };
    let cert_id = action.run(ctx.get_owner_client()).await?;
    info!("Created certificate ID: {cert_id}");

    // Here comes a double check on RSA private key
    // Resolve the private key id from the certificate via GetAttributes
    let owner_client = ctx.get_owner_client();
    let attrs = owner_client
        .get_attributes(cosmian_kmip::kmip_2_1::kmip_operations::GetAttributes {
            unique_identifier: Some(
                cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                    cert_id.to_string(),
                ),
            ),
            attribute_reference: None,
        })
        .await?
        .attributes;
    let private_key_id = attrs
        .get_link(cosmian_kmip::kmip_2_1::kmip_types::LinkType::PrivateKeyLink)
        .expect("Certificate should be linked to a private key")
        .to_string();
    info!("Resolved private key ID: {private_key_id}");

    let (_, wrapped_private_key, _attributes) = export_object(
        &ctx.get_owner_client(),
        &private_key_id,
        ExportObjectParams {
            wrapping_key_id: Some(&cse_key_id.to_string()),
            wrapping_cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::GCM),
                ..CryptographicParameters::default()
            }),
            // When wrapping, the server requires the default key format (unspecified)
            key_format_type: None,
            ..ExportObjectParams::default()
        },
    )
    .await?;

    let pkcs1_b64 = base64::engine::general_purpose::STANDARD.encode(
        wrapped_private_key
            .key_block()
            .unwrap()
            .wrapped_key_bytes()
            .unwrap(),
    );
    info!(
        "Exported private key in PKCS#8 DER (base64): {}",
        &pkcs1_b64
    );

    // Provide a valid SHA-256 digest (base64, padded). Here we use SHA-256("")
    // which equals 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
    let digest_b64 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".to_owned();
    // In tests, token validation is disabled (see server test utils), so any non-empty strings will do
    let req = PrivateKeySignReq {
        authentication: "test",
        authorization: "test",
        algorithm: "SHA256withRSA",
        digest: &digest_b64,
        rsa_pss_salt_length: None,
        reason: "CLI test",
        wrapped_private_key: &pkcs1_b64,
    };

    // Use raw post_no_ttlv to send JSON to /google_cse/privatekeysign and expect an error
    owner_client
        .post_no_ttlv::<_, serde_json::Value>("/google_cse/privatekeysign", Some(&req))
        .await?;

    Ok(())
}
