//! Characterization tests for `cosmian_pkcs11_module::sessions` behavior.

use std::{ptr, sync::Arc};

use pkcs11_sys::{CK_INVALID_HANDLE, CK_ULONG, CKF_SERIAL_SESSION, CKO_DATA};
use serial_test::serial;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ModuleError, ModuleResult,
    core::{
        attribute::{Attribute, Attributes},
        object::Object,
    },
    objects_store::OBJECTS_STORE,
    pkcs11::{C_Finalize, C_Initialize, C_OpenSession},
    sessions::{self, Session},
    traits::{
        Backend, Certificate, DataObject, DecryptContext, EncryptContext, EncryptionAlgorithm,
        KeyAlgorithm, MessageEncryptionOutput, PrivateKey, PublicKey, SearchOptions, SignContext,
        SignOperation, SignatureAlgorithm, SymmetricKey, Version, register_backend,
    },
    utils::{test_decrypt, test_encrypt, test_generate_key},
};

struct CharTestBackend;

impl Backend for CharTestBackend {
    fn token_label(&self) -> [u8; 32] {
        *b"Cosmian Char Test Token         "
    }

    fn token_manufacturer_id(&self) -> [u8; 32] {
        *b"Cosmian                         "
    }

    fn token_model(&self) -> [u8; 16] {
        *b"char-model      "
    }

    fn token_serial_number(&self) -> [u8; 16] {
        *b"char-serial     "
    }

    fn library_description(&self) -> [u8; 32] {
        *b"Cosmian PKCS11 Char Test        "
    }

    fn library_version(&self) -> Version {
        Version { major: 1, minor: 0 }
    }

    fn find_certificate(
        &self,
        _query: SearchOptions,
    ) -> ModuleResult<Option<Arc<dyn Certificate>>> {
        Ok(None)
    }

    fn find_all_certificates(&self) -> ModuleResult<Vec<Arc<dyn Certificate>>> {
        Ok(vec![])
    }

    fn find_private_key(&self, _query: SearchOptions) -> ModuleResult<Arc<dyn PrivateKey>> {
        Err(ModuleError::FunctionNotSupported)
    }

    fn find_all_private_keys(&self) -> ModuleResult<Vec<Arc<dyn PrivateKey>>> {
        Ok(vec![])
    }

    fn find_public_key(&self, _query: SearchOptions) -> ModuleResult<Arc<dyn PublicKey>> {
        Err(ModuleError::FunctionNotSupported)
    }

    fn find_all_public_keys(&self) -> ModuleResult<Vec<Arc<dyn PublicKey>>> {
        Ok(vec![])
    }

    fn find_symmetric_key(&self, _query: SearchOptions) -> ModuleResult<Arc<dyn SymmetricKey>> {
        Err(ModuleError::FunctionNotSupported)
    }

    fn find_all_symmetric_keys(&self) -> ModuleResult<Vec<Arc<dyn SymmetricKey>>> {
        Ok(vec![])
    }

    fn generate_key(
        &self,
        _algorithm: KeyAlgorithm,
        _key_length: usize,
        _sensitive: bool,
        _label: Option<&str>,
    ) -> ModuleResult<Arc<dyn SymmetricKey>> {
        Ok(Arc::new(CharSymKey))
    }

    fn create_object(&self, label: &str, data: &[u8]) -> ModuleResult<Arc<dyn DataObject>> {
        Ok(Arc::new(CharDataObject {
            remote_id: label.to_owned(),
            value: Zeroizing::new(data.to_vec()),
        }))
    }

    fn revoke_object(&self, _remote_id: &str) -> ModuleResult<()> {
        Ok(())
    }

    fn destroy_object(&self, _remote_id: &str) -> ModuleResult<()> {
        Ok(())
    }

    fn encrypt(&self, _ctx: &EncryptContext, cleartext: Vec<u8>) -> ModuleResult<Vec<u8>> {
        let mut ct = cleartext;
        ct.extend_from_slice(b"_enc");
        Ok(ct)
    }

    fn decrypt(
        &self,
        _ctx: &DecryptContext,
        ciphertext: Vec<u8>,
    ) -> ModuleResult<Zeroizing<Vec<u8>>> {
        if ciphertext.ends_with(b"_enc") {
            let len = ciphertext.len().saturating_sub(4);
            let mut pt = Vec::new();
            let slice = ciphertext.get(..len).unwrap();
            pt.extend_from_slice(slice);
            Ok(Zeroizing::new(pt))
        } else {
            Ok(Zeroizing::new(ciphertext))
        }
    }

    fn encrypt_message(
        &self,
        _ctx: &EncryptContext,
        _cleartext: Vec<u8>,
    ) -> ModuleResult<MessageEncryptionOutput> {
        Err(ModuleError::FunctionNotSupported)
    }

    fn remote_sign(
        &self,
        _remote_id: &str,
        _algorithm: &SignatureAlgorithm,
        _data: &[u8],
        _key_algorithm: KeyAlgorithm,
    ) -> ModuleResult<Vec<u8>> {
        Ok(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
    }

    fn remote_verify(
        &self,
        _remote_id: &str,
        _algorithm: &SignatureAlgorithm,
        _data: &[u8],
        _signature: &[u8],
        _key_algorithm: KeyAlgorithm,
    ) -> ModuleResult<()> {
        Ok(())
    }

    fn generate_random(&self, buf: &mut [u8]) -> ModuleResult<()> {
        buf.fill(0xAA);
        Ok(())
    }

    fn find_all_objects(&self) -> ModuleResult<Vec<Arc<Object>>> {
        Ok(vec![Arc::new(Object::DataObject(Arc::new(
            CharDataObject {
                remote_id: "char-data-unique-1".to_owned(),
                value: Zeroizing::new(b"data-val-1".to_vec()),
            },
        )))])
    }

    fn find_all_data_objects(&self) -> ModuleResult<Vec<Arc<dyn DataObject>>> {
        Ok(vec![Arc::new(CharDataObject {
            remote_id: "char-data-unique-1".to_owned(),
            value: Zeroizing::new(b"data-val-1".to_vec()),
        })])
    }

    fn find_data_object(&self, query: SearchOptions) -> ModuleResult<Option<Arc<dyn DataObject>>> {
        match query {
            SearchOptions::Id(id) if id == "char-data-unique-1" => {
                Ok(Some(Arc::new(CharDataObject {
                    remote_id: "char-data-unique-1".to_owned(),
                    value: Zeroizing::new(b"refreshed-val-1".to_vec()),
                })))
            }
            _ => Ok(None),
        }
    }
}

struct CharSymKey;

impl SymmetricKey for CharSymKey {
    fn remote_id(&self) -> &'static str {
        "char_sym_key"
    }

    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Aes256
    }

    fn key_size(&self) -> usize {
        32
    }

    fn raw_bytes(&self) -> ModuleResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(vec![0x42; 32]))
    }
}

struct CharEcdsaPrivateKey;

impl PrivateKey for CharEcdsaPrivateKey {
    fn remote_id(&self) -> &'static str {
        "char_ecdsa_priv_key"
    }

    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::EccP256
    }

    fn key_size(&self) -> usize {
        32
    }

    fn sign(&self, _algorithm: &SignatureAlgorithm, _data: &[u8]) -> ModuleResult<Vec<u8>> {
        Ok(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
    }

    fn pkcs8_der_bytes(&self) -> ModuleResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(vec![0x30; 32]))
    }

    fn rsa_public_exponent(&self) -> ModuleResult<Vec<u8>> {
        Err(ModuleError::FunctionNotSupported)
    }
}

struct CharDataObject {
    remote_id: String,
    value: Zeroizing<Vec<u8>>,
}

impl Zeroize for CharDataObject {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl DataObject for CharDataObject {
    fn remote_id(&self) -> &str {
        &self.remote_id
    }

    fn value(&self) -> Zeroizing<Vec<u8>> {
        self.value.clone()
    }

    fn application(&self) -> Vec<u8> {
        b"CharApp".to_vec()
    }

    fn data_hash(&self) -> Vec<u8> {
        vec![0_u8; 32]
    }
}

fn init_char_test_backend() {
    register_backend(Box::new(CharTestBackend));
}

#[test]
#[serial]
fn characterization_sessions_empty_find_all_objects_loop() {
    init_char_test_backend();
    let mut session = Session::default();
    let empty_attrs = Attributes::from(vec![]);
    session.load_find_context(&empty_attrs).unwrap();
    let store_count = session.find_objects_ctx.len();
    assert_eq!(store_count, 1);
}

#[test]
#[serial]
fn characterization_sessions_cko_data_find_refresh_loop() {
    init_char_test_backend();
    let mut session = Session::default();
    let dummy_data = Arc::new(Object::DataObject(Arc::new(CharDataObject {
        remote_id: "char-data-unique-1".to_owned(),
        value: Zeroizing::new(b"initial".to_vec()),
    })));
    {
        let mut store = OBJECTS_STORE.write().unwrap();
        store.upsert(dummy_data);
    }
    let attrs = Attributes::from(vec![
        Attribute::Class(CKO_DATA),
        Attribute::Label("char-data-unique-1".to_owned()),
    ]);
    session.load_find_context(&attrs).unwrap();
    let ctx_len = session.find_objects_ctx.len();
    assert_eq!(ctx_len, 2);
}
#[test]
#[serial]
fn characterization_sessions_search_all_cko_certificate_ensure_x509() {
    init_char_test_backend();
    let mut session = Session::default();
    // 1. Valid X509 certificate type passes ensure_X509_or_none
    let valid_attrs = Attributes::from(vec![
        Attribute::Class(pkcs11_sys::CKO_CERTIFICATE),
        Attribute::CertificateType(pkcs11_sys::CKC_X_509),
    ]);
    session.load_find_context(&valid_attrs).unwrap();

    // 2. Unsupported certificate type returns error from ensure_X509_or_none
    let invalid_attrs = Attributes::from(vec![
        Attribute::Class(pkcs11_sys::CKO_CERTIFICATE),
        Attribute::CertificateType(999),
    ]);
    let err = session.load_find_context(&invalid_attrs).unwrap_err();
    assert_eq!(
        err.to_string(),
        "ensure_X509_or_none: support for certificate type: 999 is not implemented".to_owned()
    );
}

#[test]
#[serial]
fn characterization_sessions_sign_buffer_size_negotiation_and_too_small() {
    init_char_test_backend();
    let mut session = Session::default();
    session.sign_ctx = Some(SignContext {
        algorithm: SignatureAlgorithm::Ecdsa,
        private_key: Arc::new(CharEcdsaPrivateKey),
        operation: SignOperation::Classic,
        payload: None,
        pending_signature: None,
    });

    let data = b"characterization-sign-payload";
    let mut sig_len: CK_ULONG = 0;
    // 1. Buffer size query with NULL pointer: returns exact expected length
    unsafe {
        session
            .sign(Some(data), ptr::null_mut(), &raw mut sig_len)
            .unwrap();
    }
    assert_eq!(sig_len, 8);

    // 2. Buffer too small error path (length set to 4)
    let mut short_buf = [0_u8; 4];
    let mut short_len: CK_ULONG = 4;
    let err = unsafe {
        session
            .sign(Some(data), short_buf.as_mut_ptr(), &raw mut short_len)
            .unwrap_err()
    };
    assert_eq!(err.to_string(), "buffer too small".to_owned());
    // Required length is updated in the out pointer
    assert_eq!(short_len, 8);

    // 3. Successful signature into sized buffer
    let mut out_buf = [0_u8; 8];
    let mut valid_len: CK_ULONG = 8;
    unsafe {
        session
            .sign(Some(data), out_buf.as_mut_ptr(), &raw mut valid_len)
            .unwrap();
    }
    assert_eq!(valid_len, 8);
    const EXPECTED_SIG: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    assert_eq!(out_buf, EXPECTED_SIG);
}

#[test]
#[serial]
fn characterization_sessions_decrypt_buffer_size_negotiation_and_too_small() {
    init_char_test_backend();
    let mut session = Session::default();
    session.decrypt_ctx = Some(DecryptContext {
        remote_object_id: "char_sym_key".to_owned(),
        algorithm: EncryptionAlgorithm::AesCbcPad,
        iv: Some(vec![0; 16]),
        aad: None,
    });

    let ciphertext = b"plaintext_enc".to_vec();
    let mut out_len: CK_ULONG = 0;

    // 1. Buffer size query with NULL pointer
    session
        .decrypt(ciphertext.clone(), ptr::null_mut(), &raw mut out_len)
        .unwrap();
    assert_eq!(out_len, 9);

    // 2. Buffer too small
    let mut short_buf = [0_u8; 4];
    let mut short_len: CK_ULONG = 4;
    let err = session
        .decrypt(
            ciphertext.clone(),
            short_buf.as_mut_ptr(),
            &raw mut short_len,
        )
        .unwrap_err();
    assert_eq!(err.to_string(), "buffer too small".to_owned());

    // 3. Full decrypt
    let mut full_buf = [0_u8; 9];
    let mut full_len: CK_ULONG = 9;
    session
        .decrypt(ciphertext, full_buf.as_mut_ptr(), &raw mut full_len)
        .unwrap();
    assert_eq!(full_len, 9);
    assert_eq!(full_buf.as_slice(), b"plaintext");
}

#[test]
fn characterization_sessions_create_incremental_handle() {
    let handle1 = sessions::create(CKF_SERIAL_SESSION);
    let handle2 = sessions::create(CKF_SERIAL_SESSION);
    assert_ne!(handle1, 0);
    assert_ne!(handle2, 0);
    assert_ne!(handle1, handle2);
    let exists1 = sessions::exists(handle1).unwrap();
    let exists2 = sessions::exists(handle2).unwrap();
    assert!(exists1);
    assert!(exists2);
}

#[test]
#[serial]
fn characterization_utils_helpers_encrypt_decrypt_cycle() {
    init_char_test_backend();
    C_Initialize(ptr::null_mut());
    let mut session_h = CK_INVALID_HANDLE;
    unsafe {
        C_OpenSession(
            1,
            CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &raw mut session_h,
        );
    }
    assert_ne!(session_h, CK_INVALID_HANDLE);

    let key_h = test_generate_key(session_h);
    assert_ne!(key_h, CK_INVALID_HANDLE);

    let plaintext = b"characterization-utils-pt".to_vec();
    let ct = test_encrypt(session_h, key_h, plaintext.clone());
    let pt = test_decrypt(session_h, key_h, ct);
    let slice = pt.get(..plaintext.len()).unwrap();
    assert_eq!(slice, plaintext.as_slice());

    C_Finalize(ptr::null_mut());
}
