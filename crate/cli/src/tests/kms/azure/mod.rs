use std::fs;

use openssl::{
    pkey::{PKey, Private, Public},
    rsa::Rsa,
};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{
        azure::byok::{ExportByokAction, ImportKekAction},
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::{KmsCliError, result::KmsCliResult},
};

/// Generate RSA keypair using OpenSSL (random size from 2048, 3072, or 4096 bits).
///
/// This mirrors AWS KMS "get-parameters-for-import" wrapping key specs and keeps
/// the test independent from KMS RSA key generation/export actions.
fn generate_rsa_keypair() -> KmsCliResult<(PKey<Private>, PKey<Public>)> {
    let key_sizes = [2048_u32, 3072_u32, 4096_u32];
    // Avoid introducing new RNG deps in the CLI crate's dev-deps.
    let bits = key_sizes[std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| {
            let len_u32 = u32::try_from(key_sizes.len()).unwrap_or(1);
            let idx_u32 = d.subsec_nanos() % len_u32;
            usize::try_from(idx_u32).unwrap_or(0)
        })
        .unwrap_or(0)];

    let rsa = Rsa::generate(bits)
        .map_err(|e| KmsCliError::Default(format!("Failed to generate RSA key: {e}")))?;
    let private_key = PKey::from_rsa(rsa.clone())
        .map_err(|e| KmsCliError::Default(format!("Failed to build private key: {e}")))?;
    let public_key = PKey::from_rsa(
        Rsa::from_public_components(
            rsa.n()
                .to_owned()
                .map_err(|e| KmsCliError::Default(format!("Failed to clone modulus: {e}")))?,
            rsa.e()
                .to_owned()
                .map_err(|e| KmsCliError::Default(format!("Failed to clone exponent: {e}")))?,
        )
        .map_err(|e| KmsCliError::Default(format!("Failed to build public RSA key: {e}")))?,
    )
    .map_err(|e| KmsCliError::Default(format!("Failed to build public key: {e}")))?;

    Ok((private_key, public_key))
}

#[tokio::test]
async fn test_azure_byok_import_kek_then_export_byok() -> KmsCliResult<()> {
    // 1. Instantiate a default KMS server
    let ctx = start_default_test_kms_server().await;
    let kms_client = ctx.get_owner_client();

    let tmp_dir = TempDir::new()?;
    let kek_pem_path = tmp_dir.path().join("kek_pub.pem");

    // 2. Generate an RSA key pair locally, write the public key in PKCS#8 PEM, then import it as Azure KEK
    let (_private_key, public_key) = generate_rsa_keypair()?;
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

    let byok_file = tmp_dir.path().join("out.byok");

    ExportByokAction {
        wrapped_key_id: sym_key_id,
        kek_id: imported_kek_id.to_string(),
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
