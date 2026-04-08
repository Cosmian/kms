use std::fs;

use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::fpe::{
        DecryptAction, EncryptAction, FpeArgs, FpeDataType, keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
async fn test_fpe_text_roundtrip() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    let tmp_dir = TempDir::new()?;
    let input_file = tmp_dir.path().join("card.txt");
    let encrypted_file = tmp_dir.path().join("card.enc");
    let decrypted_file = tmp_dir.path().join("card.dec");
    let plaintext = "1234-5678-9012-3456";
    fs::write(&input_file, plaintext)?;

    EncryptAction {
        args: FpeArgs {
            key_id: Some(key_id.to_string()),
            tags: None,
            data_type: FpeDataType::Text,
            alphabet: Some("numeric".to_owned()),
            tweak: Some("aabbccdd".to_owned()),
            input_file: Some(input_file.clone()),
            output_file: Some(encrypted_file.clone()),
        },
    }
    .run(ctx.get_owner_client())
    .await?;

    let ciphertext = fs::read_to_string(&encrypted_file)?;
    assert_ne!(ciphertext, plaintext);
    assert_eq!(
        ciphertext.matches('-').count(),
        plaintext.matches('-').count()
    );

    DecryptAction {
        args: FpeArgs {
            key_id: Some(key_id.to_string()),
            tags: None,
            data_type: FpeDataType::Text,
            alphabet: Some("numeric".to_owned()),
            tweak: Some("aabbccdd".to_owned()),
            input_file: Some(encrypted_file),
            output_file: Some(decrypted_file.clone()),
        },
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(fs::read_to_string(&decrypted_file)?, plaintext);
    Ok(())
}

#[tokio::test]
async fn test_fpe_integer_roundtrip() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    let tmp_dir = TempDir::new()?;
    let input_file = tmp_dir.path().join("integer.txt");
    let encrypted_file = tmp_dir.path().join("integer.enc");
    let decrypted_file = tmp_dir.path().join("integer.dec");
    let plaintext = "123456789012";
    fs::write(&input_file, plaintext)?;

    EncryptAction {
        args: FpeArgs {
            key_id: Some(key_id.to_string()),
            tags: None,
            data_type: FpeDataType::Integer,
            alphabet: Some("numeric".to_owned()),
            tweak: Some("01020304".to_owned()),
            input_file: Some(input_file.clone()),
            output_file: Some(encrypted_file.clone()),
        },
    }
    .run(ctx.get_owner_client())
    .await?;

    let ciphertext = fs::read_to_string(&encrypted_file)?;
    assert_ne!(ciphertext, plaintext);
    assert_eq!(ciphertext.len(), plaintext.len());

    DecryptAction {
        args: FpeArgs {
            key_id: Some(key_id.to_string()),
            tags: None,
            data_type: FpeDataType::Integer,
            alphabet: Some("numeric".to_owned()),
            tweak: Some("01020304".to_owned()),
            input_file: Some(encrypted_file),
            output_file: Some(decrypted_file.clone()),
        },
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(fs::read_to_string(&decrypted_file)?, plaintext);
    Ok(())
}

#[tokio::test]
async fn test_fpe_float_roundtrip() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    let tmp_dir = TempDir::new()?;
    let input_file = tmp_dir.path().join("float.txt");
    let encrypted_file = tmp_dir.path().join("float.enc");
    let decrypted_file = tmp_dir.path().join("float.dec");
    let plaintext = "123456.789";
    fs::write(&input_file, plaintext)?;

    EncryptAction {
        args: FpeArgs {
            key_id: Some(key_id.to_string()),
            tags: None,
            data_type: FpeDataType::Float,
            alphabet: None,
            tweak: Some("cafebabe".to_owned()),
            input_file: Some(input_file.clone()),
            output_file: Some(encrypted_file.clone()),
        },
    }
    .run(ctx.get_owner_client())
    .await?;

    let ciphertext = fs::read_to_string(&encrypted_file)?;
    assert_ne!(ciphertext, plaintext);

    DecryptAction {
        args: FpeArgs {
            key_id: Some(key_id.to_string()),
            tags: None,
            data_type: FpeDataType::Float,
            alphabet: None,
            tweak: Some("cafebabe".to_owned()),
            input_file: Some(encrypted_file),
            output_file: Some(decrypted_file.clone()),
        },
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(fs::read_to_string(&decrypted_file)?, plaintext);
    Ok(())
}
