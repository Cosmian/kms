//! These tests  require a connection to a working HSM and are gated behind the `softhsm2` feature.
//! To run a test, cd into the crate directory and run (replace `XXX` with the actual password):
//! ```
//! HSM_USER_PASSWORD=12345678 cargo test --target x86_64-unknown-linux-gnu --features softhsm2 -- tests::test_hsm_softhsm2_all
//! ```
use std::{collections::HashMap, ptr, sync::Arc, thread};

use cosmian_kms_base_hsm::{
    AesKeySize, HError, HResult, HsmEncryptionAlgorithm, RsaKeySize, RsaOaepDigest, SlotManager,
    test_helpers::{get_hsm_password, get_hsm_slot_id},
};
use cosmian_kms_interfaces::{HsmObjectFilter, KeyMaterial, KeyType};
use cosmian_logger::{info, log_init};
use libloading::Library;
use pkcs11_sys::{
    CK_C_INITIALIZE_ARGS, CK_RV, CK_VOID_PTR, CKF_OS_LOCKING_OK, CKM_AES_CBC, CKM_RSA_PKCS_OAEP,
    CKR_OK,
};
use rand::{TryRngCore, rngs::OsRng};
use uuid::Uuid;

use crate::{SOFTHSM2_PKCS11_LIB, Softhsm2};

const LIB_PATH: &str = SOFTHSM2_PKCS11_LIB;

fn generate_random_data<const T: usize>() -> HResult<[u8; T]> {
    let mut bytes = [0_u8; T];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| HError::Default(format!("Error generating random data: {e}")))?;
    Ok(bytes)
}

fn get_slot() -> HResult<Arc<SlotManager>> {
    let user_password = get_hsm_password()?;
    let slot = get_hsm_slot_id()?;
    let passwords = HashMap::from([(slot, Some(user_password))]);
    let hsm = Softhsm2::instantiate(LIB_PATH, passwords)?;
    let slots = hsm.get_available_slot_list()?;
    assert_eq!(slots.len(), 1);
    assert_eq!(slots.first(), Some(&slot));
    let manager = hsm.get_slot(slot)?;
    Ok(manager)
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_all() -> HResult<()> {
    test_hsm_softhsm2_get_info()?;
    test_hsm_softhsm2_get_mechanisms()?;
    test_hsm_softhsm2_get_supported_algorithms()?;
    test_hsm_softhsm2_destroy_all()?;
    test_hsm_softhsm2_generate_aes_key()?;
    test_hsm_softhsm2_generate_rsa_keypair()?;
    test_hsm_softhsm2_rsa_key_wrap()?;
    test_hsm_softhsm2_rsa_pkcs_encrypt()?;
    test_hsm_softhsm2_rsa_oaep_encrypt()?;
    test_hsm_softhsm2_aes_gcm_encrypt()?;
    test_hsm_softhsm2_aes_cbc_encrypt()?;
    test_hsm_softhsm2_aes_cbc_multi_round_encrypt()?;
    test_hsm_softhsm2_multi_threaded_rsa_encrypt_decrypt_test()?;
    test_hsm_softhsm2_get_key_metadata()?;
    test_hsm_softhsm2_list_objects()?;
    test_hsm_softhsm2_destroy_all()?;
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_low_level_test() -> HResult<()> {
    let path = LIB_PATH;
    let library = unsafe { Library::new(path) }?;
    let init = unsafe { library.get::<fn(p_init_args: CK_VOID_PTR) -> CK_RV>(b"C_Initialize") }?;

    let mut p_init_args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK,
        pReserved: ptr::null_mut(),
    };
    let rv = init(&raw mut p_init_args as CK_VOID_PTR);
    assert_eq!(rv, CKR_OK);

    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_get_info() -> HResult<()> {
    log_init(None);
    let hsm = Softhsm2::instantiate(LIB_PATH, HashMap::new())?;
    let info = hsm.get_info()?;
    info!("Connected to the HSM: {info}");
    let slots = hsm.get_available_slot_list()?;
    assert_eq!(slots.len(), 0);
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_get_mechanisms() -> HResult<()> {
    log_init(None);
    let slot = get_slot()?;
    let mut mechanisms = slot.get_supported_mechanisms()?;
    mechanisms.sort_unstable();
    info!("Supported mechanisms: {:?}", mechanisms);
    let pkcs_oaep_mechanism_info = slot.get_mechanism_info(CKM_RSA_PKCS_OAEP);
    info!("CKM_RSA_PKCS_OAEP info: {:?}", pkcs_oaep_mechanism_info);
    let cbc_mechanism_info = slot.get_mechanism_info(CKM_AES_CBC);
    info!("CKM_AES_CBC info: {:?}", cbc_mechanism_info);
    let session = slot.open_session(true)?;
    let supported_hash = session.get_supported_oaep_hash();
    info!("{:?}", supported_hash);
    session.close()?;
    let session_2 = slot.open_session(true)?;
    let supported_hash_2 = session_2.get_supported_oaep_hash();
    info!("{:?}", supported_hash_2);
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_get_supported_algorithms() -> HResult<()> {
    let user_password = get_hsm_password()?;
    let slot = get_hsm_slot_id()?;
    let passwords = HashMap::from([(slot, Some(user_password))]);
    let hsm = Softhsm2::instantiate(LIB_PATH, passwords)?;
    let supported_algorithms = hsm.get_algorithms(slot)?;
    info!("{:?}", supported_algorithms);

    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_generate_aes_key() -> HResult<()> {
    log_init(None);
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
    session.export_key(key_handle).unwrap_err();
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_generate_rsa_keypair() -> HResult<()> {
    log_init(Some("debug"));
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
    session.export_key(sk_handle).unwrap_err();
    // the public key should be exportable
    let pk_handle = session.get_object_handle(pk_id.as_bytes())?;
    let _key = session.export_key(pk_handle)?;
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_rsa_key_wrap() -> HResult<()> {
    log_init(None);
    let key_id = Uuid::new_v4().to_string();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let symmetric_key = session.generate_aes_key(key_id.as_bytes(), AesKeySize::Aes256, true)?;
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk ";
    let (sk, pk) = session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa2048,
        true,
    )?;
    let encrypted_key =
        session.wrap_aes_key_with_rsa_oaep(pk, symmetric_key, RsaOaepDigest::SHA1)?;
    assert_eq!(encrypted_key.len(), 2048 / 8);
    let decrypted_key = session.unwrap_aes_key_with_rsa_oaep(
        sk,
        &encrypted_key,
        "another_label",
        RsaOaepDigest::SHA1,
    )?;
    info!("Unwrapped symmetric key with handle: {}", decrypted_key);
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_rsa_pkcs_encrypt() -> HResult<()> {
    log_init(None);
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
    let enc = session.encrypt(pk, HsmEncryptionAlgorithm::RsaPkcsV15, data)?;
    assert_eq!(enc.ciphertext.len(), 2048 / 8);
    let plaintext = session.decrypt(sk, HsmEncryptionAlgorithm::RsaPkcsV15, &enc.ciphertext)?;
    assert_eq!(plaintext.as_slice(), data);
    info!("Successfully encrypted/decrypted with RSA PKCS");
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_rsa_oaep_encrypt() -> HResult<()> {
    log_init(None);
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
    let enc = session.encrypt(pk, HsmEncryptionAlgorithm::RsaOaepSha1, data)?;
    assert_eq!(enc.ciphertext.len(), 2048 / 8);
    let plaintext = session.decrypt(sk, HsmEncryptionAlgorithm::RsaOaepSha1, &enc.ciphertext)?;
    assert_eq!(plaintext.as_slice(), data);
    let data_2 = generate_random_data::<128>()?;
    let enc_2 = session.encrypt(pk, HsmEncryptionAlgorithm::RsaOaepSha1, &data_2)?;
    assert_eq!(enc_2.ciphertext.len(), 2048 / 8);
    let plaintext_2 =
        session.decrypt(sk, HsmEncryptionAlgorithm::RsaOaepSha1, &enc_2.ciphertext)?;
    assert_eq!(plaintext_2.as_slice(), data_2);
    info!("Successfully encrypted/decrypted with RSA OAEP");
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_aes_gcm_encrypt() -> HResult<()> {
    log_init(None);
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let data = b"Hello, World!";
    let key_id = Uuid::new_v4().to_string();
    let sk = session.generate_aes_key(key_id.as_bytes(), AesKeySize::Aes256, true)?;
    info!("AES key handle: {sk}");
    let enc = session.encrypt(sk, HsmEncryptionAlgorithm::AesGcm, data)?;
    assert_eq!(enc.ciphertext.len(), data.len());
    assert_eq!(enc.tag.clone().unwrap_or_default().len(), 16);
    assert_eq!(enc.iv.clone().unwrap_or_default().len(), 12);
    let plaintext = session.decrypt(
        sk,
        HsmEncryptionAlgorithm::AesGcm,
        [
            enc.iv.unwrap_or_default(),
            enc.ciphertext,
            enc.tag.unwrap_or_default(),
        ]
        .concat()
        .as_slice(),
    )?;
    assert_eq!(plaintext.as_slice(), data);
    info!("Successfully encrypted/decrypted with AES GCM");
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_aes_cbc_encrypt() -> HResult<()> {
    log_init(None);
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let data = b"Hello, World!";
    let key_id = Uuid::new_v4().to_string();
    let sk = session.generate_aes_key(key_id.as_bytes(), AesKeySize::Aes256, true)?;
    info!("AES key handle: {sk}");
    let enc = session.encrypt(sk, HsmEncryptionAlgorithm::AesCbc, data)?;
    assert_eq!(enc.ciphertext.len(), 16);
    assert_eq!(enc.tag.clone().unwrap_or_default().len(), 0);
    assert_eq!(enc.iv.clone().unwrap_or_default().len(), 16);
    let plaintext = session.decrypt(
        sk,
        HsmEncryptionAlgorithm::AesCbc,
        [
            enc.iv.unwrap_or_default(),
            enc.ciphertext,
            enc.tag.unwrap_or_default(),
        ]
        .concat()
        .as_slice(),
    )?;
    assert_eq!(plaintext.as_slice(), data);
    info!("Successfully encrypted/decrypted with AES CBC");
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_aes_cbc_multi_round_encrypt() -> HResult<()> {
    log_init(None);
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let key_id = Uuid::new_v4().to_string();
    let sk = session.generate_aes_key(key_id.as_bytes(), AesKeySize::Aes256, true)?;
    info!("AES key handle: {sk}");
    let data_1k = generate_random_data::<1024>()?;
    let data_8k = generate_random_data::<8192>()?;

    let enc_1k_single = session.encrypt(sk, HsmEncryptionAlgorithm::AesCbc, &data_1k)?;

    assert_eq!(enc_1k_single.ciphertext.len(), 1040);
    assert_eq!(enc_1k_single.tag.clone().unwrap_or_default().len(), 0);
    assert_eq!(enc_1k_single.iv.clone().unwrap_or_default().len(), 16);

    let mut iv: [u8; 16] = enc_1k_single
        .iv
        .clone()
        .unwrap_or_default()
        .try_into()
        .map_err(|_| HError::Default("IV must be exactly 16 bytes long".to_owned()))?;
    let enc_1k_multi = session.encrypt_aes_cbc_multi_round(sk, iv, &data_1k, 16)?;
    assert_eq!(enc_1k_multi.ciphertext, enc_1k_single.ciphertext);
    assert_eq!(enc_1k_multi.tag, enc_1k_single.tag);
    assert_eq!(enc_1k_multi.iv, enc_1k_single.iv);

    let plaintext_1k_single_single = session.decrypt(
        sk,
        HsmEncryptionAlgorithm::AesCbc,
        [
            enc_1k_single.iv.clone().unwrap_or_default(),
            enc_1k_single.ciphertext.clone(),
            enc_1k_single.tag.clone().unwrap_or_default(),
        ]
        .concat()
        .as_slice(),
    )?;
    let plaintext_1k_single_multi = session.decrypt_aes_cbc_multi_round(
        sk,
        &enc_1k_single.iv.clone().unwrap_or_default(),
        &enc_1k_single.ciphertext,
        16,
    )?;
    let plaintext_1k_multi_single = session.decrypt(
        sk,
        HsmEncryptionAlgorithm::AesCbc,
        [
            enc_1k_multi.iv.clone().unwrap_or_default(),
            enc_1k_multi.ciphertext.clone(),
            enc_1k_multi.tag.unwrap_or_default(),
        ]
        .concat()
        .as_slice(),
    )?;
    let plaintext_1k_multi_multi = session.decrypt_aes_cbc_multi_round(
        sk,
        &enc_1k_multi.iv.unwrap_or_default(),
        &enc_1k_multi.ciphertext,
        16,
    )?;

    assert_eq!(plaintext_1k_single_single.as_slice(), data_1k);
    assert_eq!(plaintext_1k_single_multi.as_slice(), data_1k);
    assert_eq!(plaintext_1k_multi_single.as_slice(), data_1k);
    assert_eq!(plaintext_1k_multi_multi.as_slice(), data_1k);

    let enc_8k_single = session.encrypt(sk, HsmEncryptionAlgorithm::AesCbc, &data_8k)?;

    assert_eq!(enc_8k_single.ciphertext.len(), 8208);
    assert_eq!(enc_8k_single.tag.clone().unwrap_or_default().len(), 0);
    assert_eq!(enc_8k_single.iv.clone().unwrap_or_default().len(), 16);

    iv = enc_8k_single
        .iv
        .clone()
        .unwrap_or_default()
        .try_into()
        .map_err(|_| HError::Default("IV must be exactly 16 bytes long".to_owned()))?;
    let enc_8k_multi = session.encrypt_aes_cbc_multi_round(sk, iv, &data_8k, 128)?;
    assert_eq!(enc_8k_multi.ciphertext, enc_8k_single.ciphertext);
    assert_eq!(enc_8k_multi.tag, enc_8k_single.tag);
    assert_eq!(enc_8k_multi.iv, enc_8k_single.iv);

    let plaintext_8k_single_single = session.decrypt(
        sk,
        HsmEncryptionAlgorithm::AesCbc,
        [
            enc_8k_single.iv.clone().unwrap_or_default(),
            enc_8k_single.ciphertext.clone(),
            enc_8k_single.tag.clone().unwrap_or_default(),
        ]
        .concat()
        .as_slice(),
    )?;
    let plaintext_8k_single_multi = session.decrypt_aes_cbc_multi_round(
        sk,
        &enc_8k_single.iv.clone().unwrap_or_default(),
        &enc_8k_single.ciphertext,
        128,
    )?;
    let plaintext_8k_multi_single = session.decrypt(
        sk,
        HsmEncryptionAlgorithm::AesCbc,
        [
            enc_8k_multi.iv.clone().unwrap_or_default(),
            enc_8k_multi.ciphertext.clone(),
            enc_8k_multi.tag.unwrap_or_default(),
        ]
        .concat()
        .as_slice(),
    )?;
    let plaintext_8k_multi_multi = session.decrypt_aes_cbc_multi_round(
        sk,
        &enc_8k_multi.iv.unwrap_or_default(),
        &enc_8k_multi.ciphertext,
        128,
    )?;

    assert_eq!(plaintext_8k_single_single.as_slice(), data_8k);
    assert_eq!(plaintext_8k_single_multi.as_slice(), data_8k);
    assert_eq!(plaintext_8k_multi_single.as_slice(), data_8k);
    assert_eq!(plaintext_8k_multi_multi.as_slice(), data_8k);

    info!("Successfully multi round encrypted/decrypted with AES CBC");
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_multi_threaded_rsa_encrypt_decrypt_test() -> HResult<()> {
    log_init(None);

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
                session.encrypt(pk, HsmEncryptionAlgorithm::RsaOaepSha1, data)?;
            assert_eq!(encrypted_content.ciphertext.len(), 2048 / 8);
            let plaintext = session.decrypt(
                sk,
                HsmEncryptionAlgorithm::RsaOaepSha1,
                &encrypted_content.ciphertext,
            )?;
            assert_eq!(plaintext.as_slice(), data);
            Ok::<(), HError>(())
        });
        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .map_err(|e| HError::Default(format!("Thread panicked: {e:?}")))??;
    }
    info!("Successfully encrypted/decrypted with RSA OAEP in multiple threads");
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_list_objects() -> HResult<()> {
    log_init(None);
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    session.clear_object_handles()?;
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    for object in &objects {
        session.destroy_object(*object)?;
    }
    session.clear_object_handles()?;
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
    session.clear_object_handles()?;
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
    session.clear_object_handles()?;
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
    session.clear_object_handles()?;
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    assert_eq!(objects.len(), 5);
    let objects = session.list_objects(HsmObjectFilter::AesKey)?;
    assert_eq!(objects.len(), 1);
    info!("Listed all objects");
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_get_key_metadata() -> HResult<()> {
    log_init(None);
    let slot = get_slot()?;
    let session = slot.open_session(true)?;

    // generate an AES key
    let key_id = Uuid::new_v4().to_string();
    let key_handle = session.generate_aes_key(key_id.as_bytes(), AesKeySize::Aes256, true)?;
    // get the key basics
    let key_type = session
        .get_key_type(key_handle)?
        .ok_or_else(|| HError::Default("Key not found".to_owned()))?;
    assert_eq!(key_type, KeyType::AesKey);
    // get the metadata
    let metadata = session
        .get_key_metadata(key_handle)?
        .ok_or_else(|| HError::Default("Key not found".to_owned()))?;
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
        .ok_or_else(|| HError::Default("Key not found".to_owned()))?;
    assert_eq!(key_type, KeyType::RsaPrivateKey);

    // get the private key metadata
    let metadata = session
        .get_key_metadata(sk)?
        .ok_or_else(|| HError::Default("Key not found".to_owned()))?;
    assert_eq!(metadata.key_type, KeyType::RsaPrivateKey);
    assert_eq!(metadata.key_length_in_bits, 2048);
    assert_eq!(metadata.id.as_str(), sk_id.as_str());
    assert!(metadata.sensitive);

    // get the public key basics
    let key_type = session
        .get_key_type(pk)?
        .ok_or_else(|| HError::Default("Key not found".to_owned()))?;
    assert_eq!(key_type, KeyType::RsaPublicKey);

    // get the public key metadata
    let metadata = session
        .get_key_metadata(pk)?
        .ok_or_else(|| HError::Default("Key not found".to_owned()))?;
    assert_eq!(metadata.key_type, KeyType::RsaPublicKey);
    // assert!(metadata.sensitive);
    assert_eq!(metadata.key_length_in_bits, 2048);
    assert_eq!(metadata.id.as_str(), pk_id.as_str());
    info!("Got key metadata");
    Ok(())
}

#[test]
#[ignore = "Requires Linux, SoftHSM2 library, and HSM environment"]
fn test_hsm_softhsm2_destroy_all() -> HResult<()> {
    log_init(None);
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    for object in &objects {
        session.destroy_object(*object)?;
    }
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    assert_eq!(objects.len(), 0);
    info!("Destroyed all objects");
    Ok(())
}
