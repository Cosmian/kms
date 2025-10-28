//! Shared HSM test suite used by vendor crates to avoid duplication.
//! Each vendor crate provides a small config and delegates to these helpers.
#![allow(clippy::panic_in_result_fn)]
#![allow(clippy::missing_panics_doc)]

use std::{collections::HashMap, ptr, sync::Arc, thread};

use cosmian_kms_interfaces::{HSM, HsmObjectFilter, KeyMaterial, KeyType};
use cosmian_logger::{debug, info, log_init};
use futures::executor::block_on;
use libloading::Library;
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_C_INITIALIZE_ARGS, CK_FALSE, CK_KEY_TYPE, CK_MECHANISM,
    CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_RV, CK_TRUE, CK_ULONG, CK_VOID_PTR, CKA_DECRYPT,
    CKA_ECDSA_PARAMS, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL, CKA_PRIVATE,
    CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN, CKA_UNWRAP, CKA_VERIFY, CKA_WRAP, CKF_OS_LOCKING_OK,
    CKK_EC, CKM_AES_CBC, CKM_EC_KEY_PAIR_GEN, CKM_RSA_PKCS_OAEP, CKR_OK,
};
use rand::{TryRngCore, rngs::OsRng};
use uuid::Uuid;

use crate::{
    AesKeySize, BaseHsm, HError, HResult, HsmEncryptionAlgorithm, RsaKeySize, RsaOaepDigest,
    Session, SlotManager, hsm_call,
};

/// Per-HSM configuration for shared tests
#[derive(Debug)]
pub struct HsmTestConfig<'a> {
    pub lib_path: &'a str,
    pub slot_ids_and_passwords: HashMap<usize, Option<String>>, // for BaseHsm::instantiate
    pub slot_id_for_tests: usize,                               // slot to use
    pub rsa_oaep_digest: Option<RsaOaepDigest>,                 // Some if supported, None if not
    pub threads: usize,                                         // number of threads for MT test
    pub supports_rsa_wrap: bool, // whether RSA OAEP wrap/unwrap is supported
}

fn generate_random_data<const T: usize>() -> HResult<[u8; T]> {
    let mut bytes = [0_u8; T];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| HError::Default(format!("Error generating random data: {e}")))?;
    Ok(bytes)
}

#[allow(unsafe_code)]
pub fn low_level_init_test(cfg: &HsmTestConfig) -> HResult<()> {
    let path = cfg.lib_path;
    let library = unsafe { Library::new(path) }?;
    let init = unsafe { library.get::<fn(p_init_args: CK_VOID_PTR) -> CK_RV>(b"C_Initialize") }?;

    let p_init_args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK,
        pReserved: ptr::null_mut(),
    };
    let rv = init(
        ptr::from_ref(&p_init_args)
            .cast::<std::ffi::c_void>()
            .cast_mut(),
    );

    assert_eq!(rv, CKR_OK);

    Ok(())
}

pub fn instantiate<P>(cfg: &HsmTestConfig) -> HResult<BaseHsm<P>>
where
    P: crate::hsm_capabilities::HsmProvider,
    BaseHsm<P>: Sized,
{
    info!("instantiating hsm");
    BaseHsm::<P>::instantiate(cfg.lib_path, cfg.slot_ids_and_passwords.clone())
}

pub fn get_slot<P>(hsm: &BaseHsm<P>, cfg: &HsmTestConfig) -> HResult<Arc<SlotManager>>
where
    P: crate::hsm_capabilities::HsmProvider,
    BaseHsm<P>: Sized,
{
    debug!("Getting available slot list");
    let slots = hsm.get_available_slot_list()?;
    info!("Available slots: {:?}", slots);
    if !slots.contains(&cfg.slot_id_for_tests) {
        return Err(HError::Default(format!(
            "Configured slot {} is not available in {:?}",
            cfg.slot_id_for_tests, slots
        )));
    }
    debug!("HSM Test configuration: {cfg:#?}");
    hsm.get_slot(cfg.slot_id_for_tests)
}

/// Instantiate the HSM and return a slot manager for the configured slot id.
pub fn instantiate_and_get_slot<P>(cfg: &HsmTestConfig) -> HResult<Arc<SlotManager>>
where
    P: crate::hsm_capabilities::HsmProvider,
    BaseHsm<P>: Sized,
{
    let hsm: BaseHsm<P> = instantiate(cfg)?;
    get_slot(&hsm, cfg)
}

pub fn get_info<P>(cfg: &HsmTestConfig) -> HResult<()>
where
    P: crate::hsm_capabilities::HsmProvider,
    BaseHsm<P>: Sized,
{
    log_init(None);
    let hsm = BaseHsm::<P>::instantiate(cfg.lib_path, HashMap::new())?;
    let info = hsm.get_info()?;
    info!("Connected to the HSM: {info}");
    Ok(())
}

pub fn get_mechanisms_and_hashes(slot: &Arc<SlotManager>) -> HResult<()> {
    log_init(None);
    info!("Getting mechanisms");
    let mut mechanisms = slot.get_supported_mechanisms()?;
    mechanisms.sort_unstable();
    info!("Supported mechanisms: {:?}", mechanisms);
    let pkcs_oaep_mechanism_info = slot.get_mechanism_info(CKM_RSA_PKCS_OAEP);
    info!("CKM_RSA_PKCS_OAEP info: {:?}", pkcs_oaep_mechanism_info);
    let cbc_mechanism_info = slot.get_mechanism_info(CKM_AES_CBC);
    info!("CKM_AES_CBC info: {:?}", cbc_mechanism_info);
    let session = slot.open_session(true)?;
    let supported_hash = session.get_supported_oaep_hash();
    info!("Supported OAEP Hash (1) {:?}", supported_hash);
    session.close()?;
    let session_2 = slot.open_session(true)?;
    let supported_hash_2 = session_2.get_supported_oaep_hash();
    info!("Supported OAEP Hash (2) {:?}", supported_hash_2);
    Ok(())
}

pub fn get_supported_algorithms<P>(cfg: &HsmTestConfig) -> HResult<()>
where
    P: crate::hsm_capabilities::HsmProvider,
    BaseHsm<P>: Sized,
{
    log_init(None);
    info!("Config: {cfg:#?}");
    let hsm = BaseHsm::<P>::instantiate(cfg.lib_path, cfg.slot_ids_and_passwords.clone())?;
    let supported_algorithms = hsm.get_algorithms(cfg.slot_id_for_tests)?;
    info!("{:?}", supported_algorithms);
    Ok(())
}

pub fn destroy_all(slot: &Arc<SlotManager>) -> HResult<()> {
    log_init(None);
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

#[allow(clippy::panic, clippy::unwrap_used)]
pub fn generate_aes_key(slot: &Arc<SlotManager>) -> HResult<()> {
    log_init(None);
    let key_id = Uuid::new_v4().to_string();
    let session = slot.open_session(true)?;
    let key_handle = session.generate_aes_key(key_id.as_bytes(), AesKeySize::Aes256, false)?;
    info!("Generated exportable AES key: {}", key_id);
    // assert the key handles are identical
    assert_eq!(key_handle, session.get_object_handle(key_id.as_bytes())?);
    // try export if allowed
    if let Ok(Some(key)) = session.export_key(key_handle) {
        let KeyMaterial::AesKey(key_bytes) = key.key_material() else {
            panic!("Expected an AES key")
        };
        assert_eq!(key_bytes.len() * 8, 256);
        assert_eq!(key.id(), key_id.as_str());
        if let KeyMaterial::AesKey(v) = key.key_material() {
            assert_eq!(v.len(), 32);
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

#[allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
pub fn generate_rsa_keypair(slot: &Arc<SlotManager>) -> HResult<()> {
    log_init(None);
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk";
    let session = slot.open_session(true)?;
    let (sk_handle, pk_handle) = session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa2048,
        false,
    )?;
    info!("Generated exportable RSA key: sk: {sk_id}, pk: {pk_id}");
    // exportability differs per HSM; verify handles and metadata
    assert_eq!(sk_handle, session.get_object_handle(sk_id.as_bytes())?);
    assert_eq!(pk_handle, session.get_object_handle(pk_id.as_bytes())?);
    // public key should be exportable
    let key = session
        .export_key(pk_handle)?
        .expect("Failed to find the public key");
    assert_eq!(key.id(), pk_id.as_str());
    match key.key_material() {
        KeyMaterial::RsaPublicKey(v) => assert_eq!(v.modulus.len() * 8, 2048),
        _ => panic!("Expected an RSA public key"),
    }

    // sensitive keypair
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk";
    session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa2048,
        true,
    )?;
    info!("Generated sensitive RSA key: sk: {sk_id}, pk: {pk_id}");
    let sk_handle = session.get_object_handle(sk_id.as_bytes())?;
    session.export_key(sk_handle).unwrap_err();
    let pk_handle = session.get_object_handle(pk_id.as_bytes())?;
    let _unused = session.export_key(pk_handle)?;
    Ok(())
}

pub fn rsa_key_wrap(slot: &Arc<SlotManager>, digest: RsaOaepDigest) -> HResult<()> {
    log_init(None);
    let key_id = Uuid::new_v4().to_string();
    let session = slot.open_session(true)?;
    let symmetric_key = session.generate_aes_key(key_id.as_bytes(), AesKeySize::Aes256, true)?;
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk";
    let (sk, pk) = session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa2048,
        true,
    )?;
    let encrypted_key = session.wrap_aes_key_with_rsa_oaep(pk, symmetric_key, digest)?;
    assert_eq!(encrypted_key.len(), 2048 / 8);
    let decrypted_key =
        session.unwrap_aes_key_with_rsa_oaep(sk, &encrypted_key, "another_label", digest)?;
    info!("Unwrapped symmetric key with handle: {}", decrypted_key);
    Ok(())
}

pub fn rsa_pkcs_encrypt(slot: &Arc<SlotManager>) -> HResult<()> {
    log_init(None);
    let session = slot.open_session(true)?;
    let data = b"Hello, World!";
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk";
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

pub fn rsa_oaep_encrypt(slot: &Arc<SlotManager>, digest: RsaOaepDigest) -> HResult<()> {
    log_init(None);
    let session = slot.open_session(true)?;
    let data = b"Hello, World!";
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk";
    let (sk, pk) = session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa2048,
        true,
    )?;
    let enc = match digest {
        RsaOaepDigest::SHA1 => session.encrypt(pk, HsmEncryptionAlgorithm::RsaOaepSha1, data)?,
        RsaOaepDigest::SHA256 => {
            session.encrypt(pk, HsmEncryptionAlgorithm::RsaOaepSha256, data)?
        }
    };
    assert_eq!(enc.ciphertext.len(), 2048 / 8);
    let plaintext = match digest {
        RsaOaepDigest::SHA1 => {
            session.decrypt(sk, HsmEncryptionAlgorithm::RsaOaepSha1, &enc.ciphertext)?
        }
        RsaOaepDigest::SHA256 => {
            session.decrypt(sk, HsmEncryptionAlgorithm::RsaOaepSha256, &enc.ciphertext)?
        }
    };
    assert_eq!(plaintext.as_slice(), data);
    let data_2 = generate_random_data::<128>()?;
    let enc_2 = match digest {
        RsaOaepDigest::SHA1 => session.encrypt(pk, HsmEncryptionAlgorithm::RsaOaepSha1, &data_2)?,
        RsaOaepDigest::SHA256 => {
            session.encrypt(pk, HsmEncryptionAlgorithm::RsaOaepSha256, &data_2)?
        }
    };
    assert_eq!(enc_2.ciphertext.len(), 2048 / 8);
    let plaintext_2 = match digest {
        RsaOaepDigest::SHA1 => {
            session.decrypt(sk, HsmEncryptionAlgorithm::RsaOaepSha1, &enc_2.ciphertext)?
        }
        RsaOaepDigest::SHA256 => {
            session.decrypt(sk, HsmEncryptionAlgorithm::RsaOaepSha256, &enc_2.ciphertext)?
        }
    };
    assert_eq!(plaintext_2.as_slice(), data_2);
    info!("Successfully encrypted/decrypted with RSA OAEP");
    Ok(())
}

pub fn aes_gcm_encrypt(slot: &Arc<SlotManager>) -> HResult<()> {
    log_init(None);
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

pub fn aes_cbc_encrypt(slot: &Arc<SlotManager>) -> HResult<()> {
    log_init(None);
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

pub fn aes_cbc_multi_round(slot: &Arc<SlotManager>) -> HResult<()> {
    log_init(None);
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
        .map_err(|e| HError::Default(format!("IV must be exactly 16 bytes long: {e:?}")))?;
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
        .map_err(|e| HError::Default(format!("IV must be exactly 16 bytes long: {e:?}")))?;
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

pub fn multi_threaded_rsa(
    slot: &Arc<SlotManager>,
    digest: RsaOaepDigest,
    threads: usize,
) -> HResult<()> {
    log_init(None);

    let mut handles = vec![];
    for _ in 0..threads {
        let slot = slot.clone();
        let handle = thread::spawn(move || {
            let session = slot.open_session(true)?;
            let data = b"Hello, World!";
            let sk_id = Uuid::new_v4().to_string();
            let pk_id = sk_id.clone() + "_pk";
            let (sk, pk) = session.generate_rsa_key_pair(
                sk_id.as_bytes(),
                pk_id.as_bytes(),
                RsaKeySize::Rsa2048,
                true,
            )?;
            info!("RSA handles sk: {sk}, pk: {pk}");
            let enc_alg = match digest {
                RsaOaepDigest::SHA1 => HsmEncryptionAlgorithm::RsaOaepSha1,
                RsaOaepDigest::SHA256 => HsmEncryptionAlgorithm::RsaOaepSha256,
            };
            let encrypted_content = session.encrypt(pk, enc_alg, data)?;
            assert_eq!(encrypted_content.ciphertext.len(), 2048 / 8);
            let plaintext = session.decrypt(sk, enc_alg, &encrypted_content.ciphertext)?;
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

pub fn list_objects(slot: &Arc<SlotManager>) -> HResult<()> {
    log_init(None);
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
    let pk_id = sk_id.clone() + "_pk";
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
    let pk_id = sk_id.clone() + "_pk";
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

pub fn get_key_metadata(slot: &Arc<SlotManager>) -> HResult<()> {
    log_init(None);
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
    let pk_id = sk_id.clone() + "_pk";
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
    assert_eq!(metadata.key_length_in_bits, 2048);
    assert_eq!(metadata.id.as_str(), pk_id.as_str());
    info!("Got key metadata");
    Ok(())
}

#[allow(clippy::panic, clippy::unwrap_used)]
pub fn search_incompatible_key<P>(hsm: &BaseHsm<P>, cfg: &HsmTestConfig) -> HResult<()>
where
    P: crate::hsm_capabilities::HsmProvider,
    BaseHsm<P>: Sized,
{
    log_init(None);
    let valid_key_id_0 = Uuid::new_v4().to_string();
    let valid_key_id_1 = Uuid::new_v4().to_string();
    let valid_key_id_2 = Uuid::new_v4().to_string();
    let valid_key_id_3 = Uuid::new_v4().to_string();
    let slot = get_slot(hsm, cfg)?;
    let session = slot.open_session(true)?;

    let object_list_start = session.list_objects(HsmObjectFilter::Any)?;
    let object_find_start =
        block_on(hsm.find(cfg.slot_id_for_tests, HsmObjectFilter::Any)).unwrap_or(vec![]);

    let valid_key_handle_0 =
        session.generate_aes_key(valid_key_id_0.as_bytes(), AesKeySize::Aes128, false)?;
    let valid_key_handle_1 =
        session.generate_aes_key(valid_key_id_1.as_bytes(), AesKeySize::Aes128, false)?;
    let Ok((sk, pk)) = generate_incompatible_key_pair(&session) else {
        info!("Failed to generate incompatible key. Skipping invalid object search test");
        return Ok(());
    };
    let valid_key_handle_2 =
        session.generate_aes_key(valid_key_id_2.as_bytes(), AesKeySize::Aes128, false)?;
    let valid_key_handle_3 =
        session.generate_aes_key(valid_key_id_3.as_bytes(), AesKeySize::Aes128, false)?;

    let object_list_test = session.list_objects(HsmObjectFilter::Any)?;
    let object_find_test =
        block_on(hsm.find(cfg.slot_id_for_tests, HsmObjectFilter::Any)).unwrap_or(vec![]);
    assert_eq!(object_list_start.len() + 6, object_list_test.len());
    assert_eq!(object_find_start.len() + 4, object_find_test.len());

    session.destroy_object(valid_key_handle_0)?;
    session.destroy_object(valid_key_handle_1)?;
    session.destroy_object(sk)?;
    session.destroy_object(pk)?;
    session.destroy_object(valid_key_handle_2)?;
    session.destroy_object(valid_key_handle_3)?;

    let object_list_end = session.list_objects(HsmObjectFilter::Any)?;
    let object_find_end =
        block_on(hsm.find(cfg.slot_id_for_tests, HsmObjectFilter::Any)).unwrap_or(vec![]);
    assert_eq!(object_list_start.len(), object_list_end.len());
    assert_eq!(object_find_start.len(), object_find_end.len());
    info!("Tested invalid object search");
    Ok(())
}

fn generate_incompatible_key_pair(
    session: &Session,
) -> HResult<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    let ec_params: [u8; 11] = [
        0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03,
    ]; // brainpoolP192r1
    let sk_id = Uuid::new_v4().to_string();
    let pk_id = sk_id.clone() + "_pk";
    let mut pub_key_handle = CK_OBJECT_HANDLE::default();
    let mut priv_key_handle = CK_OBJECT_HANDLE::default();
    let mut pub_key_template = vec![
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: std::ptr::from_ref(&CKK_EC)
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN,
            pValue: std::ptr::from_ref(&CK_TRUE)
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT,
            pValue: std::ptr::from_ref(&CK_TRUE)
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_ECDSA_PARAMS,
            pValue: ec_params.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
            ulValueLen: CK_ULONG::try_from(ec_params.len())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: pk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
            ulValueLen: CK_ULONG::try_from(pk_id.len())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_WRAP,
            pValue: std::ptr::from_ref(&CK_TRUE)
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY,
            pValue: std::ptr::from_ref(&CK_TRUE)
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
        },
    ];

    let mut priv_key_template = vec![
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: std::ptr::from_ref(&CKK_EC)
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN,
            pValue: std::ptr::from_ref(&CK_TRUE)
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE,
            pValue: std::ptr::from_ref(&CK_TRUE)
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT,
            pValue: std::ptr::from_ref(&CK_TRUE)
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: sk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
            ulValueLen: CK_ULONG::try_from(sk_id.len())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_UNWRAP,
            pValue: std::ptr::from_ref(&CK_TRUE)
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN,
            pValue: std::ptr::from_ref(&CK_TRUE)
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE,
            pValue: std::ptr::from_ref(&CK_FALSE)
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE,
            pValue: std::ptr::from_ref(&CK_TRUE)
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
        },
    ];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let p_mechanism: CK_MECHANISM_PTR = &raw mut mechanism;
    hsm_call!(
        session.hsm(),
        "Failed generating EC key pair",
        C_GenerateKeyPair,
        session.session_handle(),
        p_mechanism,
        pub_key_template.as_mut_ptr(),
        CK_ULONG::try_from(pub_key_template.len())?,
        priv_key_template.as_mut_ptr(),
        CK_ULONG::try_from(priv_key_template.len())?,
        &raw mut pub_key_handle,
        &raw mut priv_key_handle
    );

    Ok((priv_key_handle, pub_key_handle))
}
