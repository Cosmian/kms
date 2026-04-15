use cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm;
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::{
        symmetric::keys::create_key::CreateKeyAction,
        tokenize::{TokenizeDecryptAction, TokenizeEncryptAction},
    },
    error::result::KmsCliResult,
};

/// Create a 256-bit AES symmetric key and return its unique identifier as a `String`.
async fn create_aes_256_key(ctx: &test_kms_server::TestsContext) -> KmsCliResult<String> {
    let key_id = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Aes,
        number_of_bits: Some(256),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    Ok(key_id.to_string())
}

#[tokio::test]
async fn test_tokenize_roundtrip_alphanumeric() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let key_id = create_aes_256_key(ctx).await?;

    let plaintext = "Hello2026XYZ";

    let ciphertext = TokenizeEncryptAction {
        key_id: key_id.clone(),
        plaintext: plaintext.to_owned(),
        alphabet: "alpha_numeric".to_owned(),
        tweak: String::new(),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(
        ciphertext.len(),
        plaintext.len(),
        "FPE must preserve length"
    );
    assert_ne!(
        ciphertext, plaintext,
        "ciphertext must differ from plaintext"
    );

    let recovered = TokenizeDecryptAction {
        key_id,
        ciphertext,
        alphabet: "alpha_numeric".to_owned(),
        tweak: String::new(),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(recovered, plaintext);
    Ok(())
}

#[tokio::test]
async fn test_tokenize_roundtrip_numeric() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let key_id = create_aes_256_key(ctx).await?;

    let plaintext = "4111111111111111";

    let ciphertext = TokenizeEncryptAction {
        key_id: key_id.clone(),
        plaintext: plaintext.to_owned(),
        alphabet: "numeric".to_owned(),
        tweak: String::new(),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(ciphertext.len(), plaintext.len());
    assert!(
        ciphertext.chars().all(|c| c.is_ascii_digit()),
        "all ciphertext characters must be digits"
    );

    let recovered = TokenizeDecryptAction {
        key_id,
        ciphertext,
        alphabet: "numeric".to_owned(),
        tweak: String::new(),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(recovered, plaintext);
    Ok(())
}

/// Verify that the tweak is incorporated into the output: the same plaintext encrypted
/// with two different tweaks must produce different ciphertexts.
#[tokio::test]
async fn test_tokenize_tweak_binding() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let key_id = create_aes_256_key(ctx).await?;

    let plaintext = "Hello2026XYZ";

    let ct1 = TokenizeEncryptAction {
        key_id: key_id.clone(),
        plaintext: plaintext.to_owned(),
        alphabet: "alpha_numeric".to_owned(),
        tweak: "domain-A".to_owned(),
    }
    .run(ctx.get_owner_client())
    .await?;

    let ct2 = TokenizeEncryptAction {
        key_id: key_id.clone(),
        plaintext: plaintext.to_owned(),
        alphabet: "alpha_numeric".to_owned(),
        tweak: "domain-B".to_owned(),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_ne!(
        ct1, ct2,
        "different tweaks must produce different ciphertexts"
    );

    // Each ciphertext must round-trip with its own tweak
    let recovered1 = TokenizeDecryptAction {
        key_id: key_id.clone(),
        ciphertext: ct1,
        alphabet: "alpha_numeric".to_owned(),
        tweak: "domain-A".to_owned(),
    }
    .run(ctx.get_owner_client())
    .await?;

    let recovered2 = TokenizeDecryptAction {
        key_id,
        ciphertext: ct2,
        alphabet: "alpha_numeric".to_owned(),
        tweak: "domain-B".to_owned(),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(recovered1, plaintext);
    assert_eq!(recovered2, plaintext);
    Ok(())
}

/// Every character in the ciphertext must belong to the chosen alphabet.
#[tokio::test]
async fn test_tokenize_format_preserving() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let key_id = create_aes_256_key(ctx).await?;

    let plaintext = "deadbeefcafe1234";

    let ciphertext = TokenizeEncryptAction {
        key_id,
        plaintext: plaintext.to_owned(),
        alphabet: "hexadecimal".to_owned(),
        tweak: String::new(),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(ciphertext.len(), plaintext.len());
    assert!(
        ciphertext
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "all ciphertext characters must be lowercase hex digits (0-9a-f)"
    );
    Ok(())
}

/// A 128-bit AES key (16 bytes) must be rejected: the route requires exactly 32 bytes.
#[tokio::test]
async fn test_tokenize_invalid_key_size() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let key_id = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Aes,
        number_of_bits: Some(128),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let result = TokenizeEncryptAction {
        key_id: key_id.to_string(),
        plaintext: "Hello2026XYZ".to_owned(),
        alphabet: "alpha_numeric".to_owned(),
        tweak: String::new(),
    }
    .run(ctx.get_owner_client())
    .await;

    assert!(
        result.is_err(),
        "encrypting with a 128-bit key must fail: FPE requires 32 bytes"
    );
    Ok(())
}

/// Passing an RSA private key ID must be rejected because it is not a symmetric key.
#[tokio::test]
async fn test_tokenize_wrong_key_type() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let (private_key_id, _public_key_id) =
        crate::actions::rsa::keys::create_key_pair::CreateKeyPairAction::default()
            .run(ctx.get_owner_client())
            .await?;

    let result = TokenizeEncryptAction {
        key_id: private_key_id.to_string(),
        plaintext: "Hello2026XYZ".to_owned(),
        alphabet: "alpha_numeric".to_owned(),
        tweak: String::new(),
    }
    .run(ctx.get_owner_client())
    .await;

    assert!(
        result.is_err(),
        "encrypting with an RSA key must fail: FPE requires an AES-256 symmetric key"
    );
    Ok(())
}

/// An alphabet string with only one unique character fails the `< 2` unique chars check
/// in `Alphabet::try_from` inside `parse_alphabet`. Sending `"a"` as the alphabet value
/// exercises the path through `from_preset_or_custom` → `TryFrom<&str>` → `FPEError::AlphabetError`.
#[tokio::test]
async fn test_tokenize_invalid_alphabet() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let key_id = create_aes_256_key(ctx).await?;

    let result = TokenizeEncryptAction {
        key_id,
        plaintext: "Hello2026XYZ".to_owned(),
        // Single-character string: not a known preset and has only 1 unique char → error
        alphabet: "a".to_owned(),
        tweak: String::new(),
    }
    .run(ctx.get_owner_client())
    .await;

    assert!(
        result.is_err(),
        "an alphabet with only one unique character must be rejected"
    );
    Ok(())
}
