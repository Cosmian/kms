//! Since AWS KMS is a managed service where private keys never leave the HSM,
//! we simulate the `ImportKeyMaterial` step by unwrapping with OpenSSL.
//!
//! ## Test Matrix
//!
//! | Test Function                          | Wrapping Algorithm        | Key Type           | Key Source         | KEK Import | Export Mode |
//! |----------------------------------------|---------------------------|--------------------|--------------------|------------|-------------|
//! | `aws_byok_with_rsa_aes_key_wrap_sha256`| `RSA_AES_KEY_WRAP_SHA_256`| ECC (private key)  | KMS (generated)    | Base64     | File (bin)  |
//! | `aws_byok_with_rsaes_oaep_sha256`      | `RSAES_OAEP_SHA_256`      | AES-256            | Test file (imported) | Base64     | Base64      |
//! | `aws_byok_with_rsaes_oaep_sha1`        | `RSAES_OAEP_SHA_1`        | HMAC               | KMS (generated)    | File (DER) | Base64      |
//! | `aws_byok_with_rsa_aes_key_wrap_sha1`  | `RSA_AES_KEY_WRA_SHA_1`   | RSA (private key)  | KMS (generated)    | File (DER) | File (bin)  |
//!
//! [AWS KMS Docs](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-encrypt-key-material.html)

use base64::Engine;
use cosmian_kms_client::reexport::cosmian_kms_client_utils::{
    create_utils::SymmetricAlgorithm, import_utils::ImportKeyFormat,
};
use cosmian_kms_client::{ExportObjectParams, export_object};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::CsRng;
use cosmian_logger::log_init;
use sha2::digest::crypto_common::rand_core::{RngCore, SeedableRng};
use test_kms_server::start_default_test_kms_server;
use uuid::Uuid;

use crate::actions::kms::{
    aws::byok::{
        export_key_material::ExportByokAction, import_kek::ImportKekAction,
        wrapping_algorithms::AwsKmsWrappingAlgorithm,
    },
    elliptic_curves::keys::create_key_pair::CreateKeyPairAction as CreateEccKeyPairAction,
    rsa::keys::create_key_pair::CreateKeyPairAction as CreateRsaKeyPairAction,
    shared::ImportSecretDataOrKeyAction,
    symmetric::keys::create_key::CreateKeyAction,
};
use crate::error::result::KmsCliResult;
use crate::tests::kms::shared::openssl_utils::{
    generate_rsa_keypair, rsa_aes_key_wrap_sha1_unwrap, rsa_aes_key_wrap_sha256_unwrap,
    rsaes_oaep_sha1_unwrap, rsaes_oaep_sha256_unwrap,
};

// Test constants from AWS KMS GetParametersForImport response
const TEST_KEY_ARN: &str =
    "arn:aws:kms:eu-west-3:447182645454:key/e8518bca-e1d0-4519-a915-d80da8e8f38a";

const TEST_PUBLIC_KEY_BASE64: &str = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEApujv1m1gfctmaIaWD4ns9b5MWrr2JwYJYo82Ri3AoQZkOq0BQKkBazO61Scn/+buRE57x5tYTfUTZdnwUe4OuGgTRmH/2SPbcILbpulLP31YnqEP5IxLnn7Z9NR6VODn0QiUyv/uaHE/uBD7mt1+KHKEOBn+rL53/ht3yrboGgqxKj84FITNPaiOZ7yTccB0yCqvlKWYpcrIPeTBdGlpXni10GyBxRqGfkmKuX9/rxwDlBbzdAXn9nHOmhhZlzBUHDzidXZvYrfWEqxfnYAuTbb0Dwj/7eTiFUKseV7NXU/KpAyIG3OghDjNF7PnKT7Zlf7CvSYE+9DOqadBzjQjbOu10lLdoo2nWfCtkvE5XrZkqJHHk+9DUBnkQX3I6MdCWlfTp8QWHiwbo8rFLC4ZSLCB/QqhTh8XnHwdVkmrDKhpYQH6m1pJcsG4sIICDwIkdMSkw/CHOk+bl76TIsVqCu/7QyvFLtsvIDG3Ia0qwshYpUuIoKxXfgwUuZiwSN2RAgMBAAE=";

// Generate the key material locally, then import it to the kms using ImportSecretDataOrKeyAction
// The key material of this test will be a symmetric encryption key (32 bytes)
// Import kek as base64 string
// Export the key material wrapped with the kek as base64 string
#[tokio::test]
async fn aws_byok_with_rsaes_oaep_sha256() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Test initialization steps :
    // Generate a local RSA keypair for wrapping  (simulating AWS KMS GetParametersForImport)
    let (private_key, public_key) = generate_rsa_keypair().expect("Failed to generate RSA keypair");

    let public_key_base64 = base64::engine::general_purpose::STANDARD.encode(
        public_key
            .public_key_to_der()
            .expect("Failed to export public key to DER"),
    );

    let temp_dir = std::env::temp_dir();

    // Generate a random symmetric key to be wrapped (simulating the key material to be imported)
    let cosmian_key_id = "test-symmetric-key";
    let mut cosmian_key_bytes = [0_u8; 32];
    let mut rng = CsRng::from_entropy();
    rng.fill_bytes(&mut cosmian_key_bytes);

    let cosmian_key_file = temp_dir.join(format!("cosmian_key_test_{}.bin", uuid::Uuid::new_v4()));
    std::fs::write(&cosmian_key_file, cosmian_key_bytes).expect("Failed to write public key file");

    let import_key_action = ImportSecretDataOrKeyAction {
        key_file: cosmian_key_file.clone(),
        key_id: Some(cosmian_key_id.to_owned()),
        key_format: ImportKeyFormat::Aes, // Indicates this is an AES symmetric key
        ..Default::default()
    };

    import_key_action.run(ctx.get_owner_client()).await?;

    // We now have all necessary elements to start the test
    // Step 1: Import the Kek
    let import_action = ImportKekAction {
        // TODO: check why the compiler complains abt an optional fields (the kek id)
        kek_base64: Some(public_key_base64),
        kek_file: None,
        key_arn: Some(TEST_KEY_ARN.to_owned()),
        wrapping_algorithm: AwsKmsWrappingAlgorithm::RsaesOaepSha256,
        key_id: None,
    };

    let kek_id = import_action.run(ctx.get_owner_client()).await?;

    // Step 2: export the wrapped key
    let export_action = ExportByokAction {
        key_id: cosmian_key_id.to_string(),
        kek_id: kek_id.to_string(),
        token_file_path: None,
        output_file_path: None,
    };

    let wrapped_key_b64 = export_action.run(ctx.get_owner_client()).await?;

    let wrapped_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&wrapped_key_b64)
        .expect("Failed to decode base64 wrapped key");

    // Step 3: (simulating AWS KMS ImportKeyMaterial) Unwrap the key locally with the private key
    let unwrapped_key_bytes =
        rsaes_oaep_sha256_unwrap(&wrapped_key_bytes, &private_key).expect("Failed to unwrap key");

    // Finally: Verify the unwrapped key matches the original key material
    assert_eq!(
        unwrapped_key_bytes, cosmian_key_bytes,
        "Unwrapped key should match the original key material"
    );

    std::fs::remove_file(&cosmian_key_file)?;
    Ok(())
}

// Generate the key material with the KMS, then export it using ExportObjectParams for later verification
// The key material of this test will be a HMAC keys
// Import kek as a file blob
// Export the key material wrapped with the kek as a file blob
#[tokio::test]
async fn aws_byok_with_rsaes_oaep_sha1() -> KmsCliResult<()> {
    log_init(None);

    let ctx = start_default_test_kms_server().await;
    // Test initialization steps :
    // Generate a local RSA keypair for wrapping  (simulating AWS KMS GetParametersForImport).
    let (aws_private_key_mock, aws_public_key_mock) =
        generate_rsa_keypair().expect("Failed to generate RSA keypair");

    let temp_dir = std::env::temp_dir();

    // Write the public key to a file (DER format) to import it later.
    let kek_file_path = temp_dir.join(format!("kek_test_{}.der", uuid::Uuid::new_v4()));
    std::fs::write(
        &kek_file_path,
        aws_public_key_mock
            .public_key_to_der()
            .expect("Failed to export public key to DER"),
    )
    .expect("Failed to write KEK file");

    let key_sizes = [224, 256, 384, 512];
    let mut rng = CsRng::from_entropy();
    let bits = key_sizes[(rng.next_u32() as usize) % key_sizes.len()];

    // Generate a random symmetric key in the kms.
    let cosmian_key_id = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Sha3,
        number_of_bits: Some(bits),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let (_, cosmian_key_material, _attributes) = export_object(
        &ctx.get_owner_client(),
        &cosmian_key_id.to_string(),
        ExportObjectParams::default(),
    )
    .await?;

    // Keep this here for the final verification.
    let cosmian_key_bytes = cosmian_key_material.key_block()?.key_bytes()?;

    // We now have all necessary elements to start the test
    // Step 1: Import the KEK from file
    let import_action = ImportKekAction {
        kek_base64: None,
        kek_file: Some(kek_file_path.clone()),
        key_arn: Some(TEST_KEY_ARN.to_owned()),
        wrapping_algorithm: AwsKmsWrappingAlgorithm::RsaesOaepSha1,
        key_id: None,
    };

    let kek_id = import_action.run(ctx.get_owner_client()).await?;

    // Step 2: Export the wrapped key
    let export_action = ExportByokAction {
        key_id: cosmian_key_id.to_string(),
        kek_id: kek_id.to_string(),
        token_file_path: None,
        output_file_path: None,
    };

    let wrapped_key_b64 = export_action.run(ctx.get_owner_client()).await?;

    let wrapped_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&wrapped_key_b64)
        .expect("Failed to decode base64 wrapped key");

    // Verification step: (simulating AWS KMS ImportKeyMaterial) Unwrap the key locally with the private key
    let unwrapped_key_bytes = rsaes_oaep_sha1_unwrap(&wrapped_key_bytes, &aws_private_key_mock)
        .expect("Failed to unwrap key");

    // Finally: Verify the unwrapped key matches the original key material
    assert_eq!(
        unwrapped_key_bytes,
        cosmian_key_bytes.to_vec(),
        "Unwrapped key should match the original key material"
    );

    // Cleanup temp files
    std::fs::remove_file(&kek_file_path)?;

    Ok(())
}

// Generate the key material with the KMS, then export it using ExportObjectParams for later verification
// The key material of this test will be an RSA private key
// Import kek as a file blob
// Export the key material wrapped with the kek as a file blob
#[tokio::test]
async fn aws_byok_with_rsa_aes_key_wrap_sha1() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (aws_private_key_mock, aws_public_key_mock) =
        generate_rsa_keypair().expect("Failed to generate RSA keypair");

    let temp_dir = std::env::temp_dir();

    // Write the public key to a file (DER format) to import it later
    let kek_file_path = temp_dir.join(format!("kek_test_{}.der", Uuid::new_v4()));
    std::fs::write(
        &kek_file_path,
        aws_public_key_mock
            .public_key_to_der()
            .expect("Failed to export public key to DER"),
    )
    .expect("Failed to write KEK file");

    // Generate an RSA keypair in the KMS (the key material to wrap will be the private key)
    let key_sizes = [2048, 3072, 4096];
    let mut rng = CsRng::from_entropy();
    let bits = key_sizes[(rng.next_u32() as usize) % key_sizes.len()];

    let create_keypair_action = CreateRsaKeyPairAction {
        key_size: bits,
        ..Default::default()
    };

    // we will discard the public key for the test - real world users will simply export it in plaintext
    let (private_key_id, _public_key_id) =
        create_keypair_action.run(ctx.get_owner_client()).await?;

    // Export the private key unwrapped and keep its plaintext bytes for later verification
    let (_, cosmian_key_material, _) = export_object(
        &ctx.get_owner_client(),
        &private_key_id.to_string(),
        ExportObjectParams::default(),
    )
    .await?;
    let cosmian_key_bytes = cosmian_key_material.key_block()?.key_bytes()?;

    // We now have all necessary elements to start the test
    // Step 1: Import the KEK from file
    let import_action = ImportKekAction {
        kek_file: Some(kek_file_path.clone()),
        kek_base64: None,
        key_arn: Some(TEST_KEY_ARN.to_owned()),
        wrapping_algorithm: AwsKmsWrappingAlgorithm::RsaAesKeyWrapSha1,
        key_id: None,
    };

    let kek_id = import_action.run(ctx.get_owner_client()).await?;
    let output_file_path = temp_dir.join(format!("wrapped_key_test_{private_key_id}.bin"));

    // Step 2: Export the wrapped key
    let export_action = ExportByokAction {
        key_id: private_key_id.to_string(),
        kek_id: kek_id.to_string(),
        token_file_path: None,
        output_file_path: Some(output_file_path.clone()),
    };

    export_action.run(ctx.get_owner_client()).await?;

    // Verification step: Read the file and unwrap the key locally with the private key
    let wrapped_key_bytes = std::fs::read(&output_file_path).expect("Failed to read KEK file");

    let mut unwrapped_key_bytes =
        rsa_aes_key_wrap_sha1_unwrap(&wrapped_key_bytes, &aws_private_key_mock)
            .expect("Failed to unwrap key");

    // IMPORTANT: Asymmetric key material must be BER-encoded or DER-encoded in Public-Key Cryptography Standards (PKCS) #8 format that complies with RFC 5208.
    let pkey = openssl::pkey::PKey::private_key_from_pkcs8(&unwrapped_key_bytes)
        .expect("Failed to parse PKCS#8 key");
    let rsa = pkey.rsa().expect("Key should be RSA");
    unwrapped_key_bytes = rsa
        .private_key_to_der()
        .expect("Failed to convert to PKCS#1");

    // Finally: Verify the unwrapped key matches the original key material
    assert_eq!(
        unwrapped_key_bytes,
        cosmian_key_bytes.to_vec(),
        "Unwrapped key should match the original key material"
    );

    // Cleanup temp files
    std::fs::remove_file(&kek_file_path)?;
    std::fs::remove_file(&output_file_path)?;

    Ok(())
}

// Generate the key material with the KMS, then export it using ExportObjectParams for later verification
// Import kek as base64 string
// Export the key material wrapped with the kek as a file blob
// /!\ It's not possible to export cleartext ECC private keys from the KMS, so we skip the plaintext verification step
#[tokio::test]
async fn aws_byok_with_rsa_aes_key_wrap_sha256() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (aws_private_key_mock, aws_public_key_mock) =
        generate_rsa_keypair().expect("Failed to generate RSA keypair");

    let public_key_base64 = base64::engine::general_purpose::STANDARD.encode(
        aws_public_key_mock
            .public_key_to_der()
            .expect("Failed to export public key to DER"),
    );

    let temp_dir = std::env::temp_dir();

    // Generate an ECC keypair in the KMS (the key material to wrap will be the private key)
    let create_keypair_action = CreateEccKeyPairAction {
        sensitive: false,
        ..Default::default()
    };

    let (private_key_id, _public_key_id) =
        create_keypair_action.run(ctx.get_owner_client()).await?;

    let import_action = ImportKekAction {
        kek_base64: Some(public_key_base64),
        kek_file: None,
        key_arn: Some(TEST_KEY_ARN.to_owned()),
        wrapping_algorithm: AwsKmsWrappingAlgorithm::RsaAesKeyWrapSha256,
        key_id: None,
    };

    let kek_id = import_action.run(ctx.get_owner_client()).await?;

    let output_file_path = temp_dir.join(format!("wrapped_key_test_{private_key_id}.bin"));

    let export_action = ExportByokAction {
        key_id: private_key_id.to_string(),
        kek_id: kek_id.to_string(),
        token_file_path: None,
        output_file_path: Some(output_file_path.clone()),
    };

    export_action.run(ctx.get_owner_client()).await?;

    // Verification step: Read the file and unwrap the key locally with the private key
    let wrapped_key_bytes =
        std::fs::read(&output_file_path).expect("Failed to read wrapped key file");

    let unwrapped_key_bytes =
        rsa_aes_key_wrap_sha256_unwrap(&wrapped_key_bytes, &aws_private_key_mock)
            .expect("Failed to unwrap key");

    // Parse the unwrapped key as PKCS#8
    let pkey = openssl::pkey::PKey::private_key_from_pkcs8(&unwrapped_key_bytes)
        .expect("Failed to parse PKCS#8 key");

    // Extract the ECC key (and check it's valid)
    let _ec_key = pkey.ec_key().expect("Key should be ECC");

    std::fs::remove_file(&output_file_path)?;

    Ok(())
}

// #[cfg(feature = "non-fips")]
// pub(crate) fn sm2pke_unwrap(
//     ciphertext: &[u8],
//     private_key: &PKey<Private>,
// ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
//     // Verify the key is an SM2 key

//     use openssl::pkey_ctx::PkeyCtx;
//     if private_key.id() != openssl::pkey::Id::SM2 {
//         return Err("Private key is not an SM2 key".into());
//     }

//     // Create decryption context
//     let mut ctx = PkeyCtx::new(private_key)?;
//     ctx.decrypt_init()?;

//     // Calculate buffer size for decryption
//     let buffer_len = ctx.decrypt(ciphertext, None)?;
//     let mut plaintext = vec![0_u8; buffer_len];

//     // Perform decryption
//     let plaintext_len = ctx.decrypt(ciphertext, Some(&mut plaintext))?;
//     plaintext.truncate(plaintext_len);

//     Ok(plaintext)
// }
