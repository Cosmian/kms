/// CNG KSP DLL verification — exercises the NCrypt function table via FFI.
///
/// This module implements the `ckms cng verify` command. It loads the DLL,
/// obtains the function-pointer table, and calls each entry point to validate
/// that the KSP works correctly against a live KMS server.
#[cfg(windows)]
#[allow(
    unsafe_code,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::doc_markdown,
    clippy::indexing_slicing,
    clippy::missing_asserts_for_indexing,
    clippy::print_stdout
)]
pub(crate) mod win {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, path::Path, ptr};

    use windows_sys::Win32::{
        Foundation::HMODULE,
        Security::Cryptography::{
            BCRYPT_ECCKEY_BLOB, BCRYPT_RSAKEY_BLOB, NCRYPT_KEY_STORAGE_FUNCTION_TABLE,
        },
        System::LibraryLoader::{GetProcAddress, LoadLibraryW},
    };

    use crate::error::{KmsCliError, result::KmsCliResult};

    // Per-curve ECDSA public-key blob magic constants.
    const BCRYPT_ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3136_5345;
    const KSP_RSAPUBLIC_MAGIC: u32 = 0x3153_4152;

    const ERROR_SUCCESS: i32 = 0;
    #[allow(clippy::cast_possible_wrap)]
    const NTE_NO_KEY: i32 = 0x8009_0008_u32 as i32;
    #[allow(clippy::cast_possible_wrap)]
    const NTE_NOT_SUPPORTED: i32 = 0x8009_0029_u32 as i32;

    const BCRYPT_PAD_PKCS1: u32 = 0x0000_0002;
    const BCRYPT_PAD_OAEP: u32 = 0x0000_0004;
    const BCRYPT_PAD_PSS: u32 = 0x0000_0008;

    #[repr(C)]
    struct BcryptPkcs1PaddingInfo {
        psz_alg_id: *const u16,
    }

    #[repr(C)]
    struct BcryptPssPaddingInfo {
        psz_alg_id: *const u16,
        cb_salt: u32,
    }

    #[repr(C)]
    struct BcryptOaepPaddingInfo {
        psz_alg_id: *const u16,
        pb_label: *const u8,
        cb_label: u32,
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn sha256_wide() -> Vec<u16> {
        to_wide("SHA256")
    }
    fn rsa_wide() -> Vec<u16> {
        to_wide("RSA")
    }
    fn ecdsa_p256_wide() -> Vec<u16> {
        to_wide("ECDSA_P256")
    }
    fn ecdsa_p384_wide() -> Vec<u16> {
        to_wide("ECDSA_P384")
    }
    fn ecdsa_p521_wide() -> Vec<u16> {
        to_wide("ECDSA_P521")
    }
    fn ncrypt_length_property() -> Vec<u16> {
        to_wide("Length")
    }

    // ── DLL loader ───────────────────────────────────────────────────────

    struct KspDll {
        // Keep the handle alive so Windows doesn't unload the DLL.
        // We intentionally never call FreeLibrary — see below.
        _handle: HMODULE,
        table: &'static NCRYPT_KEY_STORAGE_FUNCTION_TABLE,
    }

    impl KspDll {
        fn load(dll_path: &str) -> Result<Self, String> {
            type GetKeyStorageInterfaceFn = unsafe extern "system" fn(
                *const u16,
                *mut *const NCRYPT_KEY_STORAGE_FUNCTION_TABLE,
                u32,
            ) -> i32;

            let wide_path = to_wide(dll_path);
            let handle = unsafe { LoadLibraryW(wide_path.as_ptr()) };
            if handle.is_null() {
                return Err(format!(
                    "LoadLibraryW failed for {dll_path} (error {})",
                    unsafe { windows_sys::Win32::Foundation::GetLastError() }
                ));
            }

            let proc_name = b"GetKeyStorageInterface\0";
            let proc = unsafe { GetProcAddress(handle, proc_name.as_ptr()) };
            let proc = proc.ok_or_else(|| {
                format!("GetProcAddress(GetKeyStorageInterface) failed for {dll_path}")
            })?;

            let get_interface: GetKeyStorageInterfaceFn = unsafe { std::mem::transmute(proc) };

            let mut table_ptr: *const NCRYPT_KEY_STORAGE_FUNCTION_TABLE = ptr::null();
            let provider_name = to_wide("Cosmian KMS Key Storage Provider");
            let status = unsafe { get_interface(provider_name.as_ptr(), &raw mut table_ptr, 0) };
            if status != ERROR_SUCCESS || table_ptr.is_null() {
                return Err(format!("GetKeyStorageInterface returned 0x{status:08X}"));
            }

            let table = unsafe { &*table_ptr };
            Ok(Self {
                _handle: handle,
                table,
            })
        }
    }

    // We intentionally do NOT implement Drop for KspDll.
    //
    // The CNG KSP DLL spawns a tokio runtime with background threads.
    // Calling `FreeLibrary` while those threads are still alive causes an
    // `ACCESS_VIOLATION` / `STATUS_STACK_BUFFER_OVERRUN` on Windows.
    // The DLL stays loaded until process exit, which is safe and expected
    // for a diagnostic verification tool.

    // ── NCrypt helper wrappers ───────────────────────────────────────────

    fn open_provider(dll: &KspDll) -> Result<usize, String> {
        let open_fn = dll.table.OpenProvider.ok_or("OpenProvider not in table")?;
        let provider_name = to_wide("Cosmian KMS Key Storage Provider");
        let mut h_provider: usize = 0;
        let status = unsafe { open_fn(&raw mut h_provider, provider_name.as_ptr(), 0) };
        if status != ERROR_SUCCESS {
            return Err(format!("OpenProvider: 0x{status:08X}"));
        }
        Ok(h_provider)
    }

    fn free_provider(dll: &KspDll, h_provider: usize) {
        if let Some(f) = dll.table.FreeProvider {
            unsafe { f(h_provider) };
        }
    }

    fn create_persisted_key(
        dll: &KspDll,
        h_provider: usize,
        alg: &[u16],
        name: &str,
    ) -> Result<usize, String> {
        let create_fn = dll
            .table
            .CreatePersistedKey
            .ok_or("CreatePersistedKey not in table")?;
        let wide_name = to_wide(name);
        let mut h_key: usize = 0;
        let status = unsafe {
            create_fn(
                h_provider,
                &raw mut h_key,
                alg.as_ptr(),
                wide_name.as_ptr(),
                0,
                0,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("CreatePersistedKey({name}): 0x{status:08X}"));
        }
        Ok(h_key)
    }

    fn set_key_property_dword(
        dll: &KspDll,
        h_provider: usize,
        h_key: usize,
        prop_name: &[u16],
        value: u32,
    ) -> Result<(), String> {
        let set_fn = dll
            .table
            .SetKeyProperty
            .ok_or("SetKeyProperty not in table")?;
        let bytes = value.to_le_bytes();
        let status = unsafe { set_fn(h_provider, h_key, prop_name.as_ptr(), bytes.as_ptr(), 4, 0) };
        if status != ERROR_SUCCESS {
            return Err(format!("SetKeyProperty: 0x{status:08X}"));
        }
        Ok(())
    }

    fn finalize_key(dll: &KspDll, h_provider: usize, h_key: usize) -> Result<(), String> {
        let finalize_fn = dll.table.FinalizeKey.ok_or("FinalizeKey not in table")?;
        let status = unsafe { finalize_fn(h_provider, h_key, 0) };
        if status != ERROR_SUCCESS {
            return Err(format!("FinalizeKey: 0x{status:08X}"));
        }
        Ok(())
    }

    fn export_key(
        dll: &KspDll,
        h_provider: usize,
        h_key: usize,
        blob_type: &str,
    ) -> Result<Vec<u8>, String> {
        let export_fn = dll.table.ExportKey.ok_or("ExportKey not in table")?;
        let blob_type_w = to_wide(blob_type);

        let mut cb_result: u32 = 0;
        let status = unsafe {
            export_fn(
                h_provider,
                h_key,
                0,
                blob_type_w.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                0,
                &raw mut cb_result,
                0,
            )
        };
        if status != ERROR_SUCCESS || cb_result == 0 {
            return Err(format!("ExportKey (size query): 0x{status:08X}"));
        }

        let mut buf = vec![0_u8; cb_result as usize];
        let status = unsafe {
            export_fn(
                h_provider,
                h_key,
                0,
                blob_type_w.as_ptr(),
                ptr::null(),
                buf.as_mut_ptr(),
                cb_result,
                &raw mut cb_result,
                0,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("ExportKey (data): 0x{status:08X}"));
        }
        buf.truncate(cb_result as usize);
        Ok(buf)
    }

    fn sign_hash_pkcs1(
        dll: &KspDll,
        h_provider: usize,
        h_key: usize,
        hash: &[u8],
    ) -> Result<Vec<u8>, String> {
        let sign_fn = dll.table.SignHash.ok_or("SignHash not in table")?;
        let sha256 = sha256_wide();
        let padding_info = BcryptPkcs1PaddingInfo {
            psz_alg_id: sha256.as_ptr(),
        };

        let mut cb_sig: u32 = 0;
        let status = unsafe {
            sign_fn(
                h_provider,
                h_key,
                (&raw const padding_info).cast(),
                hash.as_ptr(),
                hash.len() as u32,
                ptr::null_mut(),
                0,
                &raw mut cb_sig,
                BCRYPT_PAD_PKCS1,
            )
        };
        if status != ERROR_SUCCESS || cb_sig == 0 {
            return Err(format!("SignHash PKCS1 (size): 0x{status:08X}"));
        }

        let mut sig = vec![0_u8; cb_sig as usize];
        let status = unsafe {
            sign_fn(
                h_provider,
                h_key,
                (&raw const padding_info).cast(),
                hash.as_ptr(),
                hash.len() as u32,
                sig.as_mut_ptr(),
                cb_sig,
                &raw mut cb_sig,
                BCRYPT_PAD_PKCS1,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("SignHash PKCS1 (sign): 0x{status:08X}"));
        }
        sig.truncate(cb_sig as usize);
        Ok(sig)
    }

    fn sign_hash_pss(
        dll: &KspDll,
        h_provider: usize,
        h_key: usize,
        hash: &[u8],
        salt_len: u32,
    ) -> Result<Vec<u8>, String> {
        let sign_fn = dll.table.SignHash.ok_or("SignHash not in table")?;
        let sha256 = sha256_wide();
        let padding_info = BcryptPssPaddingInfo {
            psz_alg_id: sha256.as_ptr(),
            cb_salt: salt_len,
        };

        let mut cb_sig: u32 = 0;
        let status = unsafe {
            sign_fn(
                h_provider,
                h_key,
                (&raw const padding_info).cast(),
                hash.as_ptr(),
                hash.len() as u32,
                ptr::null_mut(),
                0,
                &raw mut cb_sig,
                BCRYPT_PAD_PSS,
            )
        };
        if status != ERROR_SUCCESS || cb_sig == 0 {
            return Err(format!("SignHash PSS (size): 0x{status:08X}"));
        }

        let mut sig = vec![0_u8; cb_sig as usize];
        let status = unsafe {
            sign_fn(
                h_provider,
                h_key,
                (&raw const padding_info).cast(),
                hash.as_ptr(),
                hash.len() as u32,
                sig.as_mut_ptr(),
                cb_sig,
                &raw mut cb_sig,
                BCRYPT_PAD_PSS,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("SignHash PSS (sign): 0x{status:08X}"));
        }
        sig.truncate(cb_sig as usize);
        Ok(sig)
    }

    fn sign_hash_ecdsa(
        dll: &KspDll,
        h_provider: usize,
        h_key: usize,
        hash: &[u8],
    ) -> Result<Vec<u8>, String> {
        let sign_fn = dll.table.SignHash.ok_or("SignHash not in table")?;

        let mut cb_sig: u32 = 0;
        let status = unsafe {
            sign_fn(
                h_provider,
                h_key,
                ptr::null(),
                hash.as_ptr(),
                hash.len() as u32,
                ptr::null_mut(),
                0,
                &raw mut cb_sig,
                0,
            )
        };
        if status != ERROR_SUCCESS || cb_sig == 0 {
            return Err(format!("SignHash ECDSA (size): 0x{status:08X}"));
        }

        let buf_size = cb_sig + 16;
        let mut sig = vec![0_u8; buf_size as usize];
        let status = unsafe {
            sign_fn(
                h_provider,
                h_key,
                ptr::null(),
                hash.as_ptr(),
                hash.len() as u32,
                sig.as_mut_ptr(),
                buf_size,
                &raw mut cb_sig,
                0,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("SignHash ECDSA (sign): 0x{status:08X}"));
        }
        sig.truncate(cb_sig as usize);
        Ok(sig)
    }

    fn verify_signature_pkcs1(
        dll: &KspDll,
        h_provider: usize,
        h_key: usize,
        hash: &[u8],
        signature: &[u8],
    ) -> Result<i32, String> {
        let verify_fn = dll
            .table
            .VerifySignature
            .ok_or("VerifySignature not in table")?;
        let sha256 = sha256_wide();
        let padding_info = BcryptPkcs1PaddingInfo {
            psz_alg_id: sha256.as_ptr(),
        };

        let status = unsafe {
            verify_fn(
                h_provider,
                h_key,
                (&raw const padding_info).cast(),
                hash.as_ptr(),
                hash.len() as u32,
                signature.as_ptr(),
                signature.len() as u32,
                BCRYPT_PAD_PKCS1,
            )
        };
        Ok(status)
    }

    fn verify_signature_ecdsa(
        dll: &KspDll,
        h_provider: usize,
        h_key: usize,
        hash: &[u8],
        signature: &[u8],
    ) -> Result<i32, String> {
        let verify_fn = dll
            .table
            .VerifySignature
            .ok_or("VerifySignature not in table")?;

        let status = unsafe {
            verify_fn(
                h_provider,
                h_key,
                ptr::null(),
                hash.as_ptr(),
                hash.len() as u32,
                signature.as_ptr(),
                signature.len() as u32,
                0,
            )
        };
        Ok(status)
    }

    fn encrypt_oaep(
        dll: &KspDll,
        h_provider: usize,
        h_key: usize,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let encrypt_fn = dll.table.Encrypt.ok_or("Encrypt not in table")?;
        let sha256 = sha256_wide();
        let padding_info = BcryptOaepPaddingInfo {
            psz_alg_id: sha256.as_ptr(),
            pb_label: ptr::null(),
            cb_label: 0,
        };

        let mut cb_out: u32 = 0;
        let status = unsafe {
            encrypt_fn(
                h_provider,
                h_key,
                plaintext.as_ptr(),
                plaintext.len() as u32,
                (&raw const padding_info).cast(),
                ptr::null_mut(),
                0,
                &raw mut cb_out,
                BCRYPT_PAD_OAEP,
            )
        };
        if status != ERROR_SUCCESS || cb_out == 0 {
            return Err(format!("Encrypt OAEP (size): 0x{status:08X}"));
        }

        let mut ct = vec![0_u8; cb_out as usize];
        let status = unsafe {
            encrypt_fn(
                h_provider,
                h_key,
                plaintext.as_ptr(),
                plaintext.len() as u32,
                (&raw const padding_info).cast(),
                ct.as_mut_ptr(),
                cb_out,
                &raw mut cb_out,
                BCRYPT_PAD_OAEP,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("Encrypt OAEP (encrypt): 0x{status:08X}"));
        }
        ct.truncate(cb_out as usize);
        Ok(ct)
    }

    fn decrypt_oaep(
        dll: &KspDll,
        h_provider: usize,
        h_key: usize,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let decrypt_fn = dll.table.Decrypt.ok_or("Decrypt not in table")?;
        let sha256 = sha256_wide();
        let padding_info = BcryptOaepPaddingInfo {
            psz_alg_id: sha256.as_ptr(),
            pb_label: ptr::null(),
            cb_label: 0,
        };

        let mut cb_out: u32 = 0;
        let status = unsafe {
            decrypt_fn(
                h_provider,
                h_key,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
                (&raw const padding_info).cast(),
                ptr::null_mut(),
                0,
                &raw mut cb_out,
                BCRYPT_PAD_OAEP,
            )
        };
        if status != ERROR_SUCCESS || cb_out == 0 {
            return Err(format!("Decrypt OAEP (size): 0x{status:08X}"));
        }

        let mut pt = vec![0_u8; cb_out as usize];
        let status = unsafe {
            decrypt_fn(
                h_provider,
                h_key,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
                (&raw const padding_info).cast(),
                pt.as_mut_ptr(),
                cb_out,
                &raw mut cb_out,
                BCRYPT_PAD_OAEP,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("Decrypt OAEP (decrypt): 0x{status:08X}"));
        }
        pt.truncate(cb_out as usize);
        Ok(pt)
    }

    fn delete_key(dll: &KspDll, h_provider: usize, h_key: usize) -> Result<(), String> {
        let delete_fn = dll.table.DeleteKey.ok_or("DeleteKey not in table")?;
        let status = unsafe { delete_fn(h_provider, h_key, 0) };
        if status != ERROR_SUCCESS {
            return Err(format!("DeleteKey: 0x{status:08X}"));
        }
        Ok(())
    }

    fn open_key(dll: &KspDll, h_provider: usize, name: &str) -> Result<usize, String> {
        let open_fn = dll.table.OpenKey.ok_or("OpenKey not in table")?;
        let wide_name = to_wide(name);
        let mut h_key: usize = 0;
        let status = unsafe { open_fn(h_provider, &raw mut h_key, wide_name.as_ptr(), 0, 0) };
        if status != ERROR_SUCCESS {
            return Err(format!("OpenKey({name}): 0x{status:08X}"));
        }
        Ok(h_key)
    }

    fn free_key(dll: &KspDll, h_provider: usize, h_key: usize) {
        if let Some(f) = dll.table.FreeKey {
            unsafe { f(h_provider, h_key) };
        }
    }

    // ── Output helpers ───────────────────────────────────────────────────

    fn step_ok(name: &str) {
        println!("  [OK]   {name}");
    }

    fn step_fail(name: &str, err: &dyn std::fmt::Display) {
        eprintln!("  [FAIL] {name}: {err}");
    }

    // ── Verification steps ───────────────────────────────────────────────

    fn verify_rsa_key_pair(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let rsa = rsa_wide();
        let h_key = create_persisted_key(dll, h_provider, &rsa, "verify-rsa-2048")?;
        let length_prop = ncrypt_length_property();
        set_key_property_dword(dll, h_provider, h_key, &length_prop, 2048)?;
        finalize_key(dll, h_provider, h_key)?;
        step_ok("RSA 2048 key pair created");

        let blob = export_key(dll, h_provider, h_key, "RSAPUBLICBLOB")?;
        if blob.len() < std::mem::size_of::<BCRYPT_RSAKEY_BLOB>() {
            return Err(format!("RSA public blob too small: {} bytes", blob.len()));
        }
        let header =
            unsafe { std::ptr::read_unaligned(blob.as_ptr().cast::<BCRYPT_RSAKEY_BLOB>()) };
        if header.Magic != KSP_RSAPUBLIC_MAGIC {
            return Err(format!("Bad RSA blob magic: 0x{:08X}", header.Magic));
        }
        step_ok(&format!(
            "RSA public key exported ({} bytes, {} bits)",
            blob.len(),
            header.BitLength
        ));

        let h_key2 = open_key(dll, h_provider, "verify-rsa-2048")?;
        free_key(dll, h_provider, h_key2);
        step_ok("RSA key opened by name");

        let hash: [u8; 32] = [0x55; 32];
        let sig = sign_hash_pkcs1(dll, h_provider, h_key, &hash)?;
        if sig.is_empty() {
            return Err("RSA PKCS1v15 signature is empty".to_owned());
        }
        step_ok(&format!("RSA PKCS1v15 sign OK ({} bytes)", sig.len()));

        delete_key(dll, h_provider, h_key)?;
        step_ok("RSA key deleted");
        Ok(())
    }

    fn verify_rsa_encrypt_decrypt(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let rsa = rsa_wide();
        let h_key = create_persisted_key(dll, h_provider, &rsa, "verify-rsa-enc")?;
        let length_prop = ncrypt_length_property();
        set_key_property_dword(dll, h_provider, h_key, &length_prop, 2048)?;
        let usage_prop = to_wide("KeyUsageProperty");
        set_key_property_dword(dll, h_provider, h_key, &usage_prop, 0x01)?;
        finalize_key(dll, h_provider, h_key)?;
        step_ok("RSA 2048 encrypt key created");

        let plaintext = b"hello CNG KSP verify tool";
        let ciphertext = encrypt_oaep(dll, h_provider, h_key, plaintext)?;
        if ciphertext.is_empty() {
            return Err("RSA OAEP ciphertext is empty".to_owned());
        }
        step_ok(&format!("RSA OAEP encrypt OK ({} bytes)", ciphertext.len()));

        let recovered = decrypt_oaep(dll, h_provider, h_key, &ciphertext)?;
        if recovered != plaintext {
            return Err(format!(
                "RSA OAEP round-trip mismatch: got {} bytes, expected {}",
                recovered.len(),
                plaintext.len()
            ));
        }
        step_ok("RSA OAEP decrypt round-trip OK");

        delete_key(dll, h_provider, h_key)?;
        Ok(())
    }

    fn verify_rsa_pss_sign(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let rsa = rsa_wide();
        let h_key = create_persisted_key(dll, h_provider, &rsa, "verify-rsa-pss")?;
        let length_prop = ncrypt_length_property();
        set_key_property_dword(dll, h_provider, h_key, &length_prop, 2048)?;
        finalize_key(dll, h_provider, h_key)?;

        let hash: [u8; 32] = [0x42; 32];
        let sig = sign_hash_pss(dll, h_provider, h_key, &hash, 32)?;
        if sig.len() != 256 {
            return Err(format!(
                "RSA-2048 PSS signature must be 256 bytes, got {}",
                sig.len()
            ));
        }
        step_ok("RSA-PSS sign OK (256 bytes)");

        delete_key(dll, h_provider, h_key)?;
        Ok(())
    }

    fn verify_rsa_signature_verify(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let rsa = rsa_wide();
        let h_key = create_persisted_key(dll, h_provider, &rsa, "verify-sig-rsa")?;
        let length_prop = ncrypt_length_property();
        set_key_property_dword(dll, h_provider, h_key, &length_prop, 2048)?;
        finalize_key(dll, h_provider, h_key)?;

        let hash: [u8; 32] = [0x55; 32];
        let sig = sign_hash_pkcs1(dll, h_provider, h_key, &hash)?;

        let status = verify_signature_pkcs1(dll, h_provider, h_key, &hash, &sig)?;
        if status != ERROR_SUCCESS {
            return Err(format!(
                "VerifySignature (valid): expected 0, got 0x{status:08X}"
            ));
        }
        step_ok("RSA PKCS1v15 verify OK (valid)");

        let wrong_hash: [u8; 32] = [0xAA; 32];
        let status = verify_signature_pkcs1(dll, h_provider, h_key, &wrong_hash, &sig)?;
        if status == ERROR_SUCCESS {
            return Err("VerifySignature should fail for wrong hash".to_owned());
        }
        step_ok("RSA PKCS1v15 verify OK (rejected wrong hash)");

        delete_key(dll, h_provider, h_key)?;
        Ok(())
    }

    fn verify_ec_key_pair(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let ecdsa_p256 = ecdsa_p256_wide();
        let h_key = create_persisted_key(dll, h_provider, &ecdsa_p256, "verify-ec-p256")?;
        finalize_key(dll, h_provider, h_key)?;
        step_ok("EC P-256 key pair created");

        let blob = export_key(dll, h_provider, h_key, "ECCPUBLICBLOB")?;
        if blob.len() < std::mem::size_of::<BCRYPT_ECCKEY_BLOB>() {
            return Err(format!("EC public blob too small: {} bytes", blob.len()));
        }
        let header =
            unsafe { std::ptr::read_unaligned(blob.as_ptr().cast::<BCRYPT_ECCKEY_BLOB>()) };
        if header.dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC {
            return Err(format!("Bad EC P-256 blob magic: 0x{:08X}", header.dwMagic));
        }
        step_ok(&format!(
            "EC P-256 public key exported ({} bytes)",
            blob.len()
        ));

        let hash: [u8; 32] = [0x77; 32];
        let sig = sign_hash_ecdsa(dll, h_provider, h_key, &hash)?;
        if sig.is_empty() {
            return Err("ECDSA P-256 signature is empty".to_owned());
        }
        step_ok(&format!("ECDSA P-256 sign OK ({} bytes)", sig.len()));

        delete_key(dll, h_provider, h_key)?;
        Ok(())
    }

    fn verify_ecdsa_signature_verify(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let ecdsa_p256 = ecdsa_p256_wide();
        let h_key = create_persisted_key(dll, h_provider, &ecdsa_p256, "verify-sig-ec")?;
        finalize_key(dll, h_provider, h_key)?;

        let hash: [u8; 32] = [0x77; 32];
        let sig = sign_hash_ecdsa(dll, h_provider, h_key, &hash)?;

        let status = verify_signature_ecdsa(dll, h_provider, h_key, &hash, &sig)?;
        if status != ERROR_SUCCESS {
            return Err(format!(
                "ECDSA VerifySignature (valid): expected 0, got 0x{status:08X}"
            ));
        }
        step_ok("ECDSA P-256 verify OK");

        delete_key(dll, h_provider, h_key)?;
        Ok(())
    }

    fn verify_ec_p384(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let ecdsa_p384 = ecdsa_p384_wide();
        let h_key = create_persisted_key(dll, h_provider, &ecdsa_p384, "verify-ec-p384")?;
        finalize_key(dll, h_provider, h_key)?;

        let blob = export_key(dll, h_provider, h_key, "ECCPUBLICBLOB")?;
        if blob.len() < std::mem::size_of::<BCRYPT_ECCKEY_BLOB>() {
            return Err("P-384 blob too small".to_owned());
        }
        step_ok(&format!(
            "EC P-384 key pair created + exported ({} bytes)",
            blob.len()
        ));

        let hash: [u8; 48] = [0xCD; 48];
        let sig = sign_hash_ecdsa(dll, h_provider, h_key, &hash)?;
        if sig.is_empty() {
            return Err("P-384 ECDSA signature must not be empty".to_owned());
        }
        step_ok(&format!("ECDSA P-384 sign OK ({} bytes)", sig.len()));

        delete_key(dll, h_provider, h_key)?;
        Ok(())
    }

    fn verify_ec_p521(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let ecdsa_p521 = ecdsa_p521_wide();
        let h_key = create_persisted_key(dll, h_provider, &ecdsa_p521, "verify-ec-p521")?;
        finalize_key(dll, h_provider, h_key)?;

        let blob = export_key(dll, h_provider, h_key, "ECCPUBLICBLOB")?;
        if blob.len() < std::mem::size_of::<BCRYPT_ECCKEY_BLOB>() {
            return Err("P-521 blob too small".to_owned());
        }
        step_ok(&format!(
            "EC P-521 key pair created + exported ({} bytes)",
            blob.len()
        ));

        delete_key(dll, h_provider, h_key)?;
        Ok(())
    }

    fn verify_destroy_and_lookup(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let rsa = rsa_wide();
        let h_key = create_persisted_key(dll, h_provider, &rsa, "verify-destroy")?;
        let length_prop = ncrypt_length_property();
        set_key_property_dword(dll, h_provider, h_key, &length_prop, 2048)?;
        finalize_key(dll, h_provider, h_key)?;
        step_ok("temporary key created");

        delete_key(dll, h_provider, h_key)?;
        step_ok("key deleted via DeleteKey");

        let open_fn = dll.table.OpenKey.ok_or("OpenKey not in table")?;
        let wide_name = to_wide("verify-destroy");
        let mut h_key2: usize = 0;
        let status = unsafe { open_fn(h_provider, &raw mut h_key2, wide_name.as_ptr(), 0, 0) };
        if status == ERROR_SUCCESS {
            free_key(dll, h_provider, h_key2);
            return Err("key should not be found after DeleteKey".to_owned());
        }
        if status != NTE_NO_KEY {
            return Err(format!(
                "OpenKey after delete: expected NTE_NO_KEY (0x{NTE_NO_KEY:08X}), got 0x{status:08X}"
            ));
        }
        step_ok("OpenKey confirms key is gone (NTE_NO_KEY)");
        Ok(())
    }

    fn verify_get_provider_property(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let get_prop = dll
            .table
            .GetProviderProperty
            .ok_or("GetProviderProperty not in table")?;

        let name_w = to_wide("Name");
        let mut cb_result: u32 = 0;
        let status = unsafe {
            get_prop(
                h_provider,
                name_w.as_ptr(),
                ptr::null_mut(),
                0,
                &raw mut cb_result,
                0,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("GetProviderProperty(Name) size: 0x{status:08X}"));
        }
        if cb_result == 0 {
            return Err("GetProviderProperty(Name) returned size 0".to_owned());
        }
        step_ok(&format!("GetProviderProperty(Name) size = {cb_result}"));

        let mut buf = vec![0_u8; cb_result as usize];
        let status = unsafe {
            get_prop(
                h_provider,
                name_w.as_ptr(),
                buf.as_mut_ptr(),
                cb_result,
                &raw mut cb_result,
                0,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("GetProviderProperty(Name) data: 0x{status:08X}"));
        }
        let wide: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = String::from_utf16_lossy(&wide);
        if !name.contains("Cosmian") {
            return Err(format!("Provider name unexpected: {name}"));
        }
        step_ok(&format!("GetProviderProperty(Name) = \"{name}\""));

        let impl_type_w = to_wide("Implementation Type");
        let mut cb: u32 = 0;
        let status = unsafe {
            get_prop(
                h_provider,
                impl_type_w.as_ptr(),
                ptr::null_mut(),
                0,
                &raw mut cb,
                0,
            )
        };
        if status != ERROR_SUCCESS || cb != 4 {
            return Err(format!(
                "GetProviderProperty(ImplType) size: status=0x{status:08X}, cb={cb}"
            ));
        }
        let mut val = [0_u8; 4];
        let status = unsafe {
            get_prop(
                h_provider,
                impl_type_w.as_ptr(),
                val.as_mut_ptr(),
                4,
                &raw mut cb,
                0,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!(
                "GetProviderProperty(ImplType) data: 0x{status:08X}"
            ));
        }
        let impl_flag = u32::from_le_bytes(val);
        step_ok(&format!(
            "GetProviderProperty(Implementation Type) = {impl_flag}"
        ));
        Ok(())
    }

    fn verify_get_key_property(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let get_prop = dll
            .table
            .GetKeyProperty
            .ok_or("GetKeyProperty not in table")?;

        let rsa = rsa_wide();
        let h_key = create_persisted_key(dll, h_provider, &rsa, "verify-key-prop")?;
        let length_prop = ncrypt_length_property();
        set_key_property_dword(dll, h_provider, h_key, &length_prop, 2048)?;
        finalize_key(dll, h_provider, h_key)?;

        let mut cb_result: u32 = 0;
        let status = unsafe {
            get_prop(
                h_provider,
                h_key,
                length_prop.as_ptr(),
                ptr::null_mut(),
                0,
                &raw mut cb_result,
                0,
            )
        };
        if status != ERROR_SUCCESS {
            delete_key(dll, h_provider, h_key)?;
            return Err(format!("GetKeyProperty(Length) size: 0x{status:08X}"));
        }
        if cb_result < 4 {
            delete_key(dll, h_provider, h_key)?;
            return Err(format!(
                "GetKeyProperty(Length) returned size {cb_result} < 4"
            ));
        }

        let mut val = [0_u8; 4];
        let status = unsafe {
            get_prop(
                h_provider,
                h_key,
                length_prop.as_ptr(),
                val.as_mut_ptr(),
                4,
                &raw mut cb_result,
                0,
            )
        };
        if status != ERROR_SUCCESS {
            delete_key(dll, h_provider, h_key)?;
            return Err(format!("GetKeyProperty(Length) data: 0x{status:08X}"));
        }
        let key_len = u32::from_le_bytes(val);
        if key_len != 2048 {
            delete_key(dll, h_provider, h_key)?;
            return Err(format!("Expected key length 2048, got {key_len}"));
        }
        step_ok(&format!("GetKeyProperty(Length) = {key_len}"));

        let alg_group_w = to_wide("Algorithm Group");
        let mut cb: u32 = 0;
        let status = unsafe {
            get_prop(
                h_provider,
                h_key,
                alg_group_w.as_ptr(),
                ptr::null_mut(),
                0,
                &raw mut cb,
                0,
            )
        };
        if status != ERROR_SUCCESS {
            delete_key(dll, h_provider, h_key)?;
            return Err(format!("GetKeyProperty(AlgGroup) size: 0x{status:08X}"));
        }
        let mut buf = vec![0_u8; cb as usize];
        let status = unsafe {
            get_prop(
                h_provider,
                h_key,
                alg_group_w.as_ptr(),
                buf.as_mut_ptr(),
                cb,
                &raw mut cb,
                0,
            )
        };
        if status != ERROR_SUCCESS {
            delete_key(dll, h_provider, h_key)?;
            return Err(format!("GetKeyProperty(AlgGroup) data: 0x{status:08X}"));
        }
        let wide: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let alg_group = String::from_utf16_lossy(&wide);
        step_ok(&format!(
            "GetKeyProperty(Algorithm Group) = \"{alg_group}\""
        ));

        delete_key(dll, h_provider, h_key)?;
        Ok(())
    }

    fn verify_is_alg_supported(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let is_alg = dll
            .table
            .IsAlgSupported
            .ok_or("IsAlgSupported not in table")?;

        for alg_name in &["RSA", "ECDSA_P256", "ECDSA_P384", "ECDSA_P521"] {
            let alg_w = to_wide(alg_name);
            let status = unsafe { is_alg(h_provider, alg_w.as_ptr(), 0) };
            if status != ERROR_SUCCESS {
                return Err(format!(
                    "IsAlgSupported({alg_name}) returned 0x{status:08X}, expected SUCCESS"
                ));
            }
        }
        step_ok("IsAlgSupported(RSA, ECDSA_P256/P384/P521) = SUCCESS");

        let bad_alg = to_wide("AES");
        let status = unsafe { is_alg(h_provider, bad_alg.as_ptr(), 0) };
        if status == ERROR_SUCCESS {
            return Err("IsAlgSupported(AES) should NOT return SUCCESS".to_owned());
        }
        step_ok(&format!(
            "IsAlgSupported(AES) correctly rejected (0x{status:08X})"
        ));
        Ok(())
    }

    fn verify_enum_algorithms(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let enum_alg = dll
            .table
            .EnumAlgorithms
            .ok_or("EnumAlgorithms not in table")?;

        let mut count: u32 = 0;
        let mut list: *mut windows_sys::Win32::Security::Cryptography::NCryptAlgorithmName =
            ptr::null_mut();
        let status = unsafe { enum_alg(h_provider, 0, &raw mut count, &raw mut list, 0) };
        if status != ERROR_SUCCESS {
            return Err(format!("EnumAlgorithms(all): 0x{status:08X}"));
        }
        if count == 0 {
            return Err("EnumAlgorithms returned 0 algorithms".to_owned());
        }
        step_ok(&format!("EnumAlgorithms(all) returned {count} algorithms"));

        if !list.is_null() {
            if let Some(free_buf) = dll.table.FreeBuffer {
                unsafe { free_buf(list.cast()) };
            }
        }

        let mut count_sign: u32 = 0;
        let mut list_sign: *mut windows_sys::Win32::Security::Cryptography::NCryptAlgorithmName =
            ptr::null_mut();
        let status = unsafe { enum_alg(h_provider, 1, &raw mut count_sign, &raw mut list_sign, 0) };
        if status != ERROR_SUCCESS {
            return Err(format!("EnumAlgorithms(sign): 0x{status:08X}"));
        }
        if count_sign == 0 {
            return Err("EnumAlgorithms(sign) returned 0 algorithms".to_owned());
        }
        step_ok(&format!(
            "EnumAlgorithms(sign operations) returned {count_sign} algorithms"
        ));

        if !list_sign.is_null() {
            if let Some(free_buf) = dll.table.FreeBuffer {
                unsafe { free_buf(list_sign.cast()) };
            }
        }
        Ok(())
    }

    fn verify_enum_keys(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let rsa = rsa_wide();
        let h_key = create_persisted_key(dll, h_provider, &rsa, "verify-enum-keys")?;
        let length_prop = ncrypt_length_property();
        set_key_property_dword(dll, h_provider, h_key, &length_prop, 2048)?;
        finalize_key(dll, h_provider, h_key)?;

        let enum_fn = dll.table.EnumKeys.ok_or("EnumKeys not in table")?;

        let mut key_name_ptr: *mut windows_sys::Win32::Security::Cryptography::NCryptKeyName =
            ptr::null_mut();
        let mut enum_state: *mut core::ffi::c_void = ptr::null_mut();
        let status = unsafe {
            enum_fn(
                h_provider,
                ptr::null(),
                &raw mut key_name_ptr,
                &raw mut enum_state,
                0,
            )
        };
        if status != ERROR_SUCCESS {
            delete_key(dll, h_provider, h_key)?;
            return Err(format!("EnumKeys first call: 0x{status:08X}"));
        }
        if key_name_ptr.is_null() {
            delete_key(dll, h_provider, h_key)?;
            return Err("EnumKeys returned null key name pointer".to_owned());
        }
        step_ok("EnumKeys returned at least one key");

        if let Some(free_buf) = dll.table.FreeBuffer {
            unsafe { free_buf(key_name_ptr.cast()) };
        }
        if !enum_state.is_null() {
            if let Some(free_buf) = dll.table.FreeBuffer {
                unsafe { free_buf(enum_state.cast()) };
            }
        }

        delete_key(dll, h_provider, h_key)?;
        Ok(())
    }

    fn verify_import_key_not_supported(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        let import_fn = dll.table.ImportKey.ok_or("ImportKey not in table")?;

        let blob_type = to_wide("RSAPUBLICBLOB");
        let mut h_key: usize = 0;
        let fake_data: [u8; 4] = [0; 4];
        let status = unsafe {
            import_fn(
                h_provider,
                0,
                blob_type.as_ptr(),
                ptr::null(),
                &raw mut h_key,
                fake_data.as_ptr(),
                4,
                0,
            )
        };
        if status != NTE_NOT_SUPPORTED {
            return Err(format!(
                "ImportKey expected NTE_NOT_SUPPORTED (0x{NTE_NOT_SUPPORTED:08X}), got 0x{status:08X}"
            ));
        }
        step_ok("ImportKey correctly returns NTE_NOT_SUPPORTED");
        Ok(())
    }

    // ── Runner ───────────────────────────────────────────────────────────

    type VerifyFn = fn(&KspDll, usize) -> Result<(), String>;

    fn run_all(dll: &KspDll, h_provider: usize) -> usize {
        let run_test = |name: &str, test_fn: VerifyFn| {
            println!("── {name} ──");
            match test_fn(dll, h_provider) {
                Ok(()) => {
                    println!("  => PASS\n");
                    false
                }
                Err(e) => {
                    step_fail(name, &e);
                    println!("  => FAIL\n");
                    true
                }
            }
        };

        let tests: Vec<(&str, VerifyFn)> = vec![
            ("RSA key pair + sign + export + lookup", verify_rsa_key_pair),
            ("RSA encrypt / decrypt (OAEP)", verify_rsa_encrypt_decrypt),
            ("RSA-PSS sign", verify_rsa_pss_sign),
            (
                "RSA signature verify (PKCS1v15)",
                verify_rsa_signature_verify,
            ),
            ("EC P-256 key pair + sign + export", verify_ec_key_pair),
            (
                "ECDSA signature verify (P-256)",
                verify_ecdsa_signature_verify,
            ),
            ("EC P-384 key pair + sign", verify_ec_p384),
            ("EC P-521 key pair + export", verify_ec_p521),
            ("DeleteKey + verify gone", verify_destroy_and_lookup),
            (
                "GetProviderProperty (Name, ImplType)",
                verify_get_provider_property,
            ),
            ("GetKeyProperty (Length, AlgGroup)", verify_get_key_property),
            ("IsAlgSupported", verify_is_alg_supported),
            ("EnumAlgorithms", verify_enum_algorithms),
            ("EnumKeys", verify_enum_keys),
            (
                "ImportKey (stub → NTE_NOT_SUPPORTED)",
                verify_import_key_not_supported,
            ),
        ];

        let mut failures = 0;
        for (name, test_fn) in &tests {
            if run_test(name, *test_fn) {
                failures += 1;
            }
        }
        failures
    }

    // ── Public entry point ───────────────────────────────────────────────

    pub(crate) fn run_verify(dll_path: &Path) -> KmsCliResult<()> {
        let dll_str = dll_path.to_str().ok_or_else(|| {
            KmsCliError::Default("DLL path contains non-UTF-8 characters".to_owned())
        })?;

        if !dll_path.exists() {
            return Err(KmsCliError::Default(format!(
                "DLL not found: {}",
                dll_path.display()
            )));
        }

        println!("=== Cosmian CNG KSP Verification ===\n");
        println!("Loading DLL: {dll_str}\n");

        let dll = KspDll::load(dll_str).map_err(KmsCliError::Default)?;

        let h_provider = open_provider(&dll).map_err(KmsCliError::Default)?;
        step_ok("OpenProvider");

        let failures = run_all(&dll, h_provider);
        free_provider(&dll, h_provider);

        println!("─────────────────────────────────────────");
        if failures == 0 {
            println!("All verification steps PASSED.");
            Ok(())
        } else {
            Err(KmsCliError::Default(format!(
                "{failures} verification step(s) FAILED."
            )))
        }
    }
}

#[cfg(not(windows))]
pub(crate) mod win {
    use std::path::Path;

    use crate::error::{KmsCliError, result::KmsCliResult};

    pub(crate) fn run_verify(_dll_path: &Path) -> KmsCliResult<()> {
        Err(KmsCliError::Default(
            "CNG KSP verification is only supported on Windows".to_owned(),
        ))
    }
}
