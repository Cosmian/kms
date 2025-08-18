use std::path::PathBuf;

use cosmian_logger::log_init;
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
        user_id: "john.doe@acme.com".to_string(),
        cse_key_id: cse_key_id.to_string(),
        issuer_private_key_id,
        subject_name: "CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US".to_string(),
        rsa_private_key_id: None,
        sensitive: false,
        wrapping_key_id: None,
        leaf_certificate_extensions: None,
        leaf_certificate_id: None,
        leaf_certificate_pkcs12_file: None,
        leaf_certificate_pkcs12_password: None,
        dry_run: true,
    };
    assert!(action.run(ctx.get_owner_client()).await.is_err());

    // Create key pair with certificate extensions (must succeed)
    let action = CreateKeyPairsAction {
        leaf_certificate_extensions: Some(PathBuf::from(
            "../../test_data/certificates/openssl/ext_leaf.cnf",
        )),
        ..action
    };
    let certificate_1 = action.run(ctx.get_owner_client()).await.unwrap();

    // Create key pair with certificate id (must succeed)
    let action = CreateKeyPairsAction {
        leaf_certificate_extensions: None,
        leaf_certificate_id: Some(certificate_1.to_string()),
        ..action
    };
    let _certificate_2 = action.run(ctx.get_owner_client()).await.unwrap();

    // Create key pair using a certificate file (must succeed)
    let action = CreateKeyPairsAction {
        user_id: "john.barry@acme.com".to_string(),
        leaf_certificate_id: None,
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
