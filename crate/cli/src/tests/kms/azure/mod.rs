use std::fs;

use cosmian_kmip::kmip_2_1::{kmip_objects::ObjectType, kmip_types::KeyFormatType};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{
        azure::byok::{ExportByokAction, ImportKekAction},
        rsa::keys::create_key_pair::CreateKeyPairAction,
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::{KmsCliError, result::KmsCliResult},
};

#[tokio::test]
async fn test_azure_byok_import_kek_then_export_byok() -> KmsCliResult<()> {
    // 1. Instantiate a default KMS server
    let ctx = start_default_test_kms_server().await;
    let kms_client = ctx.get_owner_client();

    // 2. Generate an RSA key pair, export the public key as PEM, then import it as Azure KEK
    let (_private_key_id, public_key_id) = CreateKeyPairAction {
        key_size: 2048,
        tags: vec!["test".to_owned()],
        ..CreateKeyPairAction::default()
    }
    .run(kms_client.clone())
    .await?;

    let tmp_dir = TempDir::new()?;
    let kek_pem_path = tmp_dir.path().join("kek_pub.pem");

    // Export the public key material as PKCS#8 DER and convert to PEM.
    let (_id, kek_pub_object, _attributes) = cosmian_kms_client::export_object(
        &kms_client,
        &public_key_id.to_string(),
        cosmian_kms_client::ExportObjectParams {
            unwrap: true,
            wrapping_key_id: None,
            allow_revoked: false,
            key_format_type: Some(cosmian_kmip::kmip_2_1::kmip_types::KeyFormatType::PKCS8),
            encode_to_ttlv: false,
            wrapping_cryptographic_parameters: None,
            authenticated_encryption_additional_data: None,
        },
    )
    .await
    .map_err(|e| KmsCliError::Default(format!("Failed to export RSA public key: {e}")))?;

    let key_block = kek_pub_object
        .key_block()
        .map_err(|e| KmsCliError::Default(format!("Invalid exported key block: {e}")))?;
    let der: Vec<u8> = match key_block.key_value.as_ref() {
        Some(cosmian_kmip::kmip_2_1::kmip_data_structures::KeyValue::ByteString(v)) => v.to_vec(),
        Some(cosmian_kmip::kmip_2_1::kmip_data_structures::KeyValue::Structure {
            key_material,
            ..
        }) => match key_material {
            cosmian_kmip::kmip_2_1::kmip_data_structures::KeyMaterial::ByteString(v) => v.to_vec(),
            x => {
                return Err(KmsCliError::Default(format!(
                    "Unsupported exported public key material: {x:?}"
                )));
            }
        },
        None => {
            return Err(KmsCliError::Default(
                "Exported public key has no key value".into(),
            ));
        }
    };

    let pem = cosmian_kms_client_utils::export_utils::der_to_pem(
        der.as_slice(),
        KeyFormatType::PKCS8,
        ObjectType::PublicKey,
    )
    .map_err(|e| KmsCliError::Default(format!("DER to PEM conversion failed: {e}")))?;

    fs::write(&kek_pem_path, pem.as_slice())?;

    let kid = "https://unit.test/keys/KEK/00000000000000000000000000000000".to_owned();
    ImportKekAction {
        kek_file: kek_pem_path,
        kid: kid.clone(),
        key_id: None,
    }
    .run(kms_client.clone())
    .await?;

    // The import action writes to stdout and does not return the imported id; locate it via tag.
    // Tag is `kid:<kid>`.
    let locate_request = cosmian_kms_client_utils::locate_utils::build_locate_request(
        Some(vec![format!("kid:{kid}")]),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .map_err(|e| KmsCliError::Default(format!("Failed to build Locate request: {e}")))?;

    let locate_response = kms_client
        .locate(locate_request)
        .await
        .map_err(|e| KmsCliError::Default(format!("Failed to locate imported KEK: {e}")))?;

    let imported_kek_id = locate_response
        .unique_identifier
        .unwrap_or_default()
        .into_iter()
        .next()
        .ok_or_else(|| KmsCliError::Default("Failed to locate imported Azure KEK".to_owned()))?
        .to_string();

    // 3. Generate a symmetric key and run ExportByokAction using it as wrapped_key_id
    let sym_key_id = CreateKeyAction {
        number_of_bits: Some(256),
        tags: vec!["test".to_owned()],
        ..CreateKeyAction::default()
    }
    .run(kms_client.clone())
    .await?
    .to_string();

    let byok_file = tmp_dir.path().join("out.byok");

    ExportByokAction {
        wrapped_key_id: sym_key_id,
        kek_id: imported_kek_id,
        byok_file: Some(byok_file.clone()),
    }
    .run(kms_client)
    .await?;

    // Assert byok file written
    let contents = std::fs::read_to_string(&byok_file)?;
    assert!(contents.contains("\"ciphertext\""));
    assert!(contents.contains("\"kid\""));

    Ok(())
}
