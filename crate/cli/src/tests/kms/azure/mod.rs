use crate::{
    actions::kms::{
        azure::byok::{ExportByokAction, ImportKekAction},
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::{KmsCliError, result::KmsCliResult},
    tests::kms::shared::openssl_utils::{generate_rsa_keypair, rsa_aes_key_wrap_sha1_unwrap},
};
use base64::Engine;
use cosmian_kms_client::{ExportObjectParams, export_object};
use std::fs;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

#[tokio::test]
async fn test_azure_byok_import_kek_then_export_byok() -> KmsCliResult<()> {
    // 1. Instantiate a default KMS server
    let ctx = start_default_test_kms_server().await;
    let kms_client = ctx.get_owner_client();

    let tmp_dir = TempDir::new()?;
    let kek_pem_path = tmp_dir.path().join("kek_pub.pem");

    // 2. Generate an RSA key pair locally, write the public key in PKCS#8 PEM, then import it as Azure KEK
    let (private_key, public_key) = generate_rsa_keypair()?;
    let public_key_pem = public_key
        .public_key_to_pem()
        .map_err(|e| KmsCliError::Default(format!("Failed to serialize public key PEM: {e}")))?;
    fs::write(&kek_pem_path, &public_key_pem)?;

    let kid = "https://unit.test/keys/KEK/00000000000000000000000000000000".to_owned();
    let imported_kek_id = ImportKekAction {
        kek_file: kek_pem_path,
        kid: kid.clone(),
        key_id: None,
    }
    .run(kms_client.clone())
    .await?;

    // The import action writes to stdout and does not return the imported id; locate it via tag.
    // Tag is `kid:<kid>`.

    // 3. Generate a symmetric key and run ExportByokAction using it as wrapped_key_id
    let sym_key_id = CreateKeyAction {
        number_of_bits: Some(256),
        tags: vec!["test".to_owned()],
        ..CreateKeyAction::default()
    }
    .run(kms_client.clone())
    .await?
    .to_string();
    // for later verification
    let (_, cosmian_key_material, _) =
        export_object(&kms_client, &sym_key_id, ExportObjectParams::default()).await?;
    let original_key_bytes = cosmian_key_material.key_block()?.key_bytes()?;

    let byok_file = tmp_dir.path().join("out.byok");

    ExportByokAction {
        wrapped_key_id: sym_key_id,
        kek_id: imported_kek_id.to_string(),
        byok_file: Some(byok_file.clone()),
    }
    .run(kms_client)
    .await?;

    // 4. Post-export verifications

    // Assert byok file written
    let byok_contents = std::fs::read_to_string(&byok_file)?;
    assert!(byok_contents.contains("\"ciphertext\""));
    assert!(byok_contents.contains("\"kid\""));

    // Unwrap and verify the key matches original (via helper function)
    let json: serde_json::Value = serde_json::from_str(&byok_contents)?;
    let ciphertext_b64url = json["ciphertext"]
        .as_str()
        .ok_or("Missing 'ciphertext' field in BYOK JSON")
        .unwrap();

    // Decode BASE64URL first
    let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(ciphertext_b64url)
        .map_err(|e| KmsCliError::Default(format!("Failed to decode BASE64URL: {e}")))?;

    // now unwrap
    let unwrapped_key_bytes = rsa_aes_key_wrap_sha1_unwrap(&ciphertext, &private_key).unwrap();

    assert_eq!(
        unwrapped_key_bytes,
        original_key_bytes.to_vec(),
        "Unwrapped key should match original"
    );

    Ok(())
}
