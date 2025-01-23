//! These tests  require a connection to a working HSM and are gated behind the `utimaco` feature.
//! To run a test, cd into the crate directory and run (replace `XXX` with the actual password):
//! ```
//! HSM_USER_PASSWORD=XXX cargo test --target x86_64-unknown-linux-gnu --features utimaco -- tests::test_all
//! ```

use std::{
    collections::HashMap,
    ptr,
    sync::{Arc, Once},
    thread,
};

use cosmian_kms_interfaces::{HsmObjectFilter, KeyMaterial, KeyType};
use libloading::Library;
use pkcs11_sys::{CKF_OS_LOCKING_OK, CKR_OK, CK_C_INITIALIZE_ARGS, CK_RV, CK_VOID_PTR};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use uuid::Uuid;

use crate::{
    AesKeySize, PError, PResult, RsaKeySize, SlotManager, Utimaco, UtimacoEncryptionAlgorithm,
};

static TRACING_INIT: Once = Once::new();
fn initialize_logging() {
    TRACING_INIT.call_once(|| {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::INFO) // Adjust the level as needed
            .with_writer(std::io::stdout)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Setting default subscriber failed");
    });
}

fn get_hsm_password() -> PResult<String> {
    let user_password = option_env!("HSM_USER_PASSWORD")
        .ok_or_else(|| {
            PError::Default(
                "The user password for the HSM is not set. Please set the HSM_USER_PASSWORD \
                 environment variable"
                    .to_string(),
            )
        })?
        .to_string();
    Ok(user_password)
}

fn get_slot() -> PResult<Arc<SlotManager>> {
    let user_password = get_hsm_password()?;
    let passwords = HashMap::from([(0x04, Some(user_password.clone()))]);
    let hsm = Utimaco::instantiate("/lib/libnethsm64.so", passwords)?;
    let manager = hsm.get_slot(0x04)?;
    Ok(manager)
}

#[test]
fn test_all() -> PResult<()> {
    test_hsm_get_info()?;
    test_destroy_all()?;
    test_generate_aes_key()?;
    test_generate_rsa_keypair()?;
    test_rsa_key_wrap()?;
    test_rsa_pkcs_encrypt()?;
    test_rsa_oaep_encrypt()?;
    test_aes_gcm_encrypt()?;
    multi_threaded_rsa_encrypt_decrypt_test()?;
    test_get_key_metadata()?;
    test_list_objects()?;
    test_destroy_all()?;
    Ok(())
}

#[test]
fn low_level_test() -> PResult<()> {
    let path = "/lib/libcs_pkcs11_R3.so";
    let library = unsafe { Library::new(path) }?;
    let init = unsafe { library.get::<fn(pInitArgs: CK_VOID_PTR) -> CK_RV>(b"C_Initialize") }?;

    let mut pInitArgs = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK,
        pReserved: ptr::null_mut(),
    };
    let rv = init(&mut pInitArgs as *const CK_C_INITIALIZE_ARGS as CK_VOID_PTR);
    assert_eq!(rv, CKR_OK);

    Ok(())
}

#[test]
fn test_hsm_get_info() -> PResult<()> {
    initialize_logging();
    let hsm = Utimaco::instantiate("/lib/libcs_pkcs11_R3.so", HashMap::new())?;
    let info = hsm.get_info()?;
    info!("Connected to the HSM: {info}");
    Ok(())
}

#[test]
fn test_generate_aes_key() -> PResult<()> {
    initialize_logging();
    let key_id = Uuid::new_v4().to_string();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let key_handle = session.generate_aes_key(key_id.as_bytes(), AesKeySize::Aes256, false)?;
    info!("Generated exportable AES key: {}", key_id);
    // assert the key handles are identical
    assert_eq!(key_handle, session.get_object_handle(key_id.as_bytes())?);
    // re-export the key
    let key = session
        .export_key(key_handle)?
        .expect("Failed to find the key");
    let key_bytes = match key.key_material() {
        KeyMaterial::AesKey(v) => v,
        KeyMaterial::RsaPrivateKey(_) | KeyMaterial::RsaPublicKey(_) => {
            panic!("Expected an AES key");
        }
    };
    assert_eq!(key_bytes.len() * 8, 256);
    assert_eq!(key.id(), key_id.as_str());
    match key.key_material() {
        KeyMaterial::AesKey(v) => {
            assert_eq!(v.len(), 32);
        }
        KeyMaterial::RsaPrivateKey(_) | KeyMaterial::RsaPublicKey(_) => {
            panic!("Expected an AES key");
        }
    }

    // Generate a sensitive AES key
    let key_id = Uuid::new_v4().to_string();
    let key_handle = session.generate_aes_key(key_id.as_bytes(), AesKeySize::Aes256, true)?;
    info!("Generated sensitive AES key: {}", key_id);
    // assert the key handles are identical
    assert_eq!(key_handle, session.get_object_handle(key_id.as_bytes())?);
    // it should not be exportable
    assert!(session.export_key(key_handle).is_err());
    Ok(())
}

#[test]
fn test_generate_rsa_keypair() -> PResult<()> {
    initialize_logging();
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk ";
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let (sk_handle, pk_handle) = session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa2048,
        false,
    )?;
    info!("Generated exportable RSA key: sk: {sk_id}, pk: {pk_id}");
    // export the private key
    assert_eq!(sk_handle, session.get_object_handle(sk_id.as_bytes())?);
    let key = session
        .export_key(sk_handle)?
        .expect("Failed to find the private key");
    assert_eq!(key.id(), sk_id.as_str());
    match key.key_material() {
        KeyMaterial::RsaPrivateKey(v) => {
            assert_eq!(v.modulus.len() * 8, 2048);
        }
        KeyMaterial::RsaPublicKey(_) | KeyMaterial::AesKey(_) => {
            panic!("Expected an RSA private key");
        }
    }
    // export the public key
    assert_eq!(pk_handle, session.get_object_handle(pk_id.as_bytes())?);
    let key = session
        .export_key(pk_handle)?
        .expect("Failed to find the public key");
    assert_eq!(key.id(), pk_id.as_str());
    match key.key_material() {
        KeyMaterial::RsaPublicKey(v) => {
            assert_eq!(v.modulus.len() * 8, 2048);
        }
        KeyMaterial::RsaPrivateKey(_) | KeyMaterial::AesKey(_) => {
            panic!("Expected an RSA public key");
        }
    }
    // Generate a sensitive AES key
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk ";
    session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa2048,
        true,
    )?;
    info!("Generated sensitive RSA key: sk: {sk_id}, pk: {pk_id}");
    // the private key should not be exportable
    let sk_handle = session.get_object_handle(sk_id.as_bytes())?;
    assert!(session.export_key(sk_handle).is_err());
    // the public key should be exportable
    let pk_handle = session.get_object_handle(pk_id.as_bytes())?;
    let _key = session.export_key(pk_handle)?;
    Ok(())
}

#[test]
fn test_rsa_key_wrap() -> PResult<()> {
    initialize_logging();
    let key_id = Uuid::new_v4().to_string();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let symmetric_key = session.generate_aes_key(key_id.as_bytes(), AesKeySize::Aes256, true)?;
    info!("Symmetric key handle: {symmetric_key}");
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk ";
    let (sk, pk) = session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa2048,
        true,
    )?;
    info!("RSA handles sk: {sk}, pl: {pk}");
    let encrypted_key = session.wrap_aes_key_with_rsa_oaep(pk, symmetric_key)?;
    assert_eq!(encrypted_key.len(), 2048 / 8);
    let decrypted_key =
        session.unwrap_aes_key_with_rsa_oaep(sk, &encrypted_key, "another_label")?;
    info!("Unwrapped symmetric key handle: {}", decrypted_key);
    Ok(())
}

#[test]
fn test_rsa_pkcs_encrypt() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let data = b"Hello, World!";
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk ";
    let (sk, pk) = session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa2048,
        true,
    )?;
    info!("RSA handles sk: {sk}, pl: {pk}");
    let enc = session.encrypt(pk, UtimacoEncryptionAlgorithm::RsaPkcsV15, data)?;
    assert_eq!(enc.ciphertext.len(), 2048 / 8);
    let plaintext = session.decrypt(sk, UtimacoEncryptionAlgorithm::RsaPkcsV15, &enc.ciphertext)?;
    assert_eq!(plaintext.as_slice(), data);
    Ok(())
}

#[test]
fn test_rsa_oaep_encrypt() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let data = b"Hello, World!";
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk ";
    let (sk, pk) = session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa2048,
        true,
    )?;
    info!("RSA handles sk: {sk}, pl: {pk}");
    let enc = session.encrypt(pk, UtimacoEncryptionAlgorithm::RsaOaep, data)?;
    assert_eq!(enc.ciphertext.len(), 2048 / 8);
    let plaintext = session.decrypt(sk, UtimacoEncryptionAlgorithm::RsaOaep, &enc.ciphertext)?;
    assert_eq!(plaintext.as_slice(), data);
    Ok(())
}

#[test]
fn test_aes_gcm_encrypt() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let data = b"Hello, World!";
    let key_id = Uuid::new_v4().to_string();
    let sk = session.generate_aes_key(key_id.as_bytes(), AesKeySize::Aes256, true)?;
    info!("AES key handle: {sk}");
    let enc = session.encrypt(sk, UtimacoEncryptionAlgorithm::AesGcm, data)?;
    assert_eq!(enc.ciphertext.len(), data.len());
    assert_eq!(enc.tag.clone().unwrap_or_default().len(), 16);
    assert_eq!(enc.iv.clone().unwrap_or_default().len(), 12);
    let plaintext = session.decrypt(
        sk,
        UtimacoEncryptionAlgorithm::AesGcm,
        [
            enc.iv.unwrap_or_default(),
            enc.ciphertext,
            enc.tag.unwrap_or_default(),
        ]
        .concat()
        .as_slice(),
    )?;
    assert_eq!(plaintext.as_slice(), data);
    Ok(())
}

#[test]
fn multi_threaded_rsa_encrypt_decrypt_test() -> PResult<()> {
    initialize_logging();

    // Initialize the HSM once and share it across threads
    let slot = get_slot()?;

    let mut handles = vec![];
    for _ in 0..4 {
        let slot = slot.clone();
        let handle = thread::spawn(move || {
            let session = slot.open_session(true)?;
            let data = b"Hello, World!";
            let sk_id = Uuid::new_v4().to_string();
            let pk_id = sk_id.clone() + "_pk ";
            let (sk, pk) = session.generate_rsa_key_pair(
                sk_id.as_bytes(),
                pk_id.as_bytes(),
                RsaKeySize::Rsa2048,
                true,
            )?;
            info!("RSA handles sk: {sk}, pk: {pk}");
            let encrypted_content =
                session.encrypt(pk, UtimacoEncryptionAlgorithm::RsaOaep, data)?;
            assert_eq!(encrypted_content.ciphertext.len(), 2048 / 8);
            let plaintext = session.decrypt(
                sk,
                UtimacoEncryptionAlgorithm::RsaOaep,
                &encrypted_content.ciphertext,
            )?;
            assert_eq!(plaintext.as_slice(), data);
            Ok::<(), PError>(())
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked")?;
    }

    Ok(())
}

#[test]
fn test_list_objects() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    for object in objects.iter() {
        session.destroy_object(*object)?;
    }
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    assert_eq!(objects.len(), 0);
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk ";
    let (_sk, _pk) = session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa2048,
        false,
    )?;
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    assert_eq!(objects.len(), 2);
    let objects = session.list_objects(HsmObjectFilter::RsaKey)?;
    assert_eq!(objects.len(), 2);
    let objects = session.list_objects(HsmObjectFilter::RsaPublicKey)?;
    assert_eq!(objects.len(), 1);
    let objects = session.list_objects(HsmObjectFilter::RsaPrivateKey)?;
    assert_eq!(objects.len(), 1);
    let objects = session.list_objects(HsmObjectFilter::AesKey)?;
    assert_eq!(objects.len(), 0);
    // add another keypair
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk ";
    let (_sk, _pk) = session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa3072,
        false,
    )?;
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    assert_eq!(objects.len(), 4);
    let objects = session.list_objects(HsmObjectFilter::RsaKey)?;
    assert_eq!(objects.len(), 4);
    let objects = session.list_objects(HsmObjectFilter::RsaPublicKey)?;
    assert_eq!(objects.len(), 2);
    let objects = session.list_objects(HsmObjectFilter::RsaPrivateKey)?;
    assert_eq!(objects.len(), 2);
    let objects = session.list_objects(HsmObjectFilter::AesKey)?;
    assert_eq!(objects.len(), 0);
    // add an AES key
    let key_id = Uuid::new_v4().to_string();
    let _key = session.generate_aes_key(key_id.as_bytes(), AesKeySize::Aes256, false)?;
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    assert_eq!(objects.len(), 5);
    let objects = session.list_objects(HsmObjectFilter::AesKey)?;
    assert_eq!(objects.len(), 1);
    Ok(())
}

#[test]
fn test_get_key_metadata() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;

    // generate an AES key
    let key_id = Uuid::new_v4().to_string();
    let key_handle = session.generate_aes_key(key_id.as_bytes(), AesKeySize::Aes256, true)?;
    // get the key basics
    let key_type = session
        .get_key_type(key_handle)?
        .ok_or_else(|| PError::Default("Key not found".to_string()))?;
    assert_eq!(key_type, KeyType::AesKey);
    // get the metadata
    let metadata = session
        .get_key_metadata(key_handle)?
        .ok_or_else(|| PError::Default("Key not found".to_string()))?;
    assert_eq!(metadata.key_type, KeyType::AesKey);
    assert!(metadata.sensitive);
    assert_eq!(metadata.key_length_in_bits, 256);
    assert_eq!(metadata.id.as_str(), key_id.as_str());

    // generate an RSA keypair
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk ";
    let (sk, pk) = session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa2048,
        true,
    )?;

    // get the private key basics
    let key_type = session
        .get_key_type(sk)?
        .ok_or_else(|| PError::Default("Key not found".to_string()))?;
    assert_eq!(key_type, KeyType::RsaPrivateKey);

    // get the private key metadata
    let metadata = session
        .get_key_metadata(sk)?
        .ok_or_else(|| PError::Default("Key not found".to_string()))?;
    assert_eq!(metadata.key_type, KeyType::RsaPrivateKey);
    assert_eq!(metadata.key_length_in_bits, 2048);
    assert_eq!(metadata.id.as_str(), sk_id.as_str());
    assert!(metadata.sensitive);

    // get the public key basics
    let key_type = session
        .get_key_type(pk)?
        .ok_or_else(|| PError::Default("Key not found".to_string()))?;
    assert_eq!(key_type, KeyType::RsaPublicKey);

    // get the public key metadata
    let metadata = session
        .get_key_metadata(pk)?
        .ok_or_else(|| PError::Default("Key not found".to_string()))?;
    assert_eq!(metadata.key_type, KeyType::RsaPublicKey);
    // assert!(metadata.sensitive);
    assert_eq!(metadata.key_length_in_bits, 2048);
    assert_eq!(metadata.id.as_str(), pk_id.as_str());
    Ok(())
}

#[test]
fn test_destroy_all() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    for object in objects.iter() {
        session.destroy_object(*object)?;
    }
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    assert_eq!(objects.len(), 0);
    Ok(())
}
