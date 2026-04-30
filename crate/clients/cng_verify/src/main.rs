//! # Cosmian CNG KSP Verification Tool
//!
//! Standalone binary that loads `cosmian_kms_cng_ksp.dll` at runtime and
//! exercises the KSP through the standard Windows `NCrypt` API surface — exactly
//! like any external CNG caller would.
//!
//! The tool dynamically loads the DLL, obtains the
//! `NCRYPT_KEY_STORAGE_FUNCTION_TABLE` via `GetKeyStorageInterface`, and calls
//! each `NCrypt` function pointer (`OpenProvider`, `CreatePersistedKey`, `FinalizeKey`,
//! `SignHash`, `ExportKey`, `DeleteKey`, …).
//!
//! ## Usage
//!
//! ```powershell
//! # The DLL must be in the same directory or on PATH:
//! cosmian_kms_cng_ksp_verify
//!
//! # Or specify an explicit DLL path:
//! cosmian_kms_cng_ksp_verify --dll "C:\path\to\cosmian_kms_cng_ksp.dll"
//! ```
//!
//! The tool exits with code 0 on success and 1 on any failure.

#![allow(unsafe_code)]

#[cfg(not(windows))]
fn main() {
    eprintln!("This tool only runs on Windows.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    win::run()
}

// ─── Windows implementation ──────────────────────────────────────────────────

#[cfg(windows)]
mod win {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, process::ExitCode, ptr};

    use windows_sys::Win32::{
        Foundation::{FreeLibrary, HMODULE},
        Security::Cryptography::{
            BCRYPT_ECCKEY_BLOB, BCRYPT_RSAKEY_BLOB, NCRYPT_KEY_STORAGE_FUNCTION_TABLE,
        },
        System::LibraryLoader::{GetProcAddress, LoadLibraryW},
    };

    // Per-curve ECDSA public-key blob magic constants.
    const BCRYPT_ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3136_5345; // "ES61"
    const _BCRYPT_ECDSA_PUBLIC_P384_MAGIC: u32 = 0x3336_5345; // "ES63"
    const _BCRYPT_ECDSA_PUBLIC_P521_MAGIC: u32 = 0x3536_5345; // "ES65"

    // RSA public-key blob magic — must match the CNG KSP's blob.rs value.
    const KSP_RSAPUBLIC_MAGIC: u32 = 0x3153_4152;

    // ── NCrypt/SECURITY_STATUS constants ─────────────────────────────────

    const ERROR_SUCCESS: i32 = 0;
    const NTE_NO_KEY: i32 = 0x8009_0008_u32 as i32;

    // BCrypt padding flags
    const BCRYPT_PAD_PKCS1: u32 = 0x0000_0002;
    const BCRYPT_PAD_OAEP: u32 = 0x0000_0004;
    const BCRYPT_PAD_PSS: u32 = 0x0000_0008;

    /// `BCRYPT_PKCS1_PADDING_INFO` — passed for PKCS#1 v1.5 sign/verify.
    #[repr(C)]
    struct BcryptPkcs1PaddingInfo {
        psz_alg_id: *const u16,
    }

    /// `BCRYPT_PSS_PADDING_INFO` — passed for PSS sign/verify.
    #[repr(C)]
    struct BcryptPssPaddingInfo {
        psz_alg_id: *const u16,
        cb_salt: u32,
    }

    /// `BCRYPT_OAEP_PADDING_INFO` — passed for OAEP encrypt/decrypt.
    #[repr(C)]
    struct BcryptOaepPaddingInfo {
        psz_alg_id: *const u16,
        pb_label: *const u8,
        cb_label: u32,
    }

    // ── Wide string helpers ──────────────────────────────────────────────

    /// Encode a Rust string as a null-terminated UTF-16 wide string.
    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Well-known algorithm names as wide strings.
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

    /// The NCrypt property name for key length ("Length\0").
    fn ncrypt_length_property() -> Vec<u16> {
        to_wide("Length")
    }

    // ── DLL loader ───────────────────────────────────────────────────────

    /// RAII wrapper around a loaded DLL.
    pub(crate) struct KspDll {
        handle: HMODULE,
        table: &'static NCRYPT_KEY_STORAGE_FUNCTION_TABLE,
    }

    impl KspDll {
        /// Load the DLL and obtain the function table.
        pub(crate) fn load(dll_path: &str) -> Result<Self, String> {
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

            // Cast to the GetKeyStorageInterface signature
            type GetKeyStorageInterfaceFn = unsafe extern "system" fn(
                *const u16,
                *mut *const NCRYPT_KEY_STORAGE_FUNCTION_TABLE,
                u32,
            ) -> i32;
            let get_interface: GetKeyStorageInterfaceFn = unsafe { std::mem::transmute(proc) };

            let mut table_ptr: *const NCRYPT_KEY_STORAGE_FUNCTION_TABLE = ptr::null();
            let provider_name = to_wide("Cosmian KMS Key Storage Provider");
            let status = unsafe { get_interface(provider_name.as_ptr(), &mut table_ptr, 0) };
            if status != ERROR_SUCCESS || table_ptr.is_null() {
                unsafe { FreeLibrary(handle) };
                return Err(format!("GetKeyStorageInterface returned 0x{status:08X}"));
            }

            let table = unsafe { &*table_ptr };
            Ok(Self { handle, table })
        }
    }

    impl Drop for KspDll {
        fn drop(&mut self) {
            unsafe { FreeLibrary(self.handle) };
        }
    }

    // ── NCrypt helper wrappers ───────────────────────────────────────────

    /// Open the provider, returning the NCRYPT_PROV_HANDLE.
    pub(crate) fn open_provider(dll: &KspDll) -> Result<usize, String> {
        let open_fn = dll.table.OpenProvider.ok_or("OpenProvider not in table")?;
        let provider_name = to_wide("Cosmian KMS Key Storage Provider");
        let mut h_provider: usize = 0;
        let status = unsafe { open_fn(&mut h_provider, provider_name.as_ptr(), 0) };
        if status != ERROR_SUCCESS {
            return Err(format!("OpenProvider: 0x{status:08X}"));
        }
        Ok(h_provider)
    }

    /// Free the provider handle.
    pub(crate) fn free_provider(dll: &KspDll, h_provider: usize) {
        if let Some(f) = dll.table.FreeProvider {
            unsafe { f(h_provider) };
        }
    }

    /// Create a persisted key (not yet finalized).
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
                &mut h_key,
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

    /// Set a key property (e.g. key length).
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

    /// Finalize a key (triggers actual creation in KMS).
    fn finalize_key(dll: &KspDll, h_provider: usize, h_key: usize) -> Result<(), String> {
        let finalize_fn = dll.table.FinalizeKey.ok_or("FinalizeKey not in table")?;
        let status = unsafe { finalize_fn(h_provider, h_key, 0) };
        if status != ERROR_SUCCESS {
            return Err(format!("FinalizeKey: 0x{status:08X}"));
        }
        Ok(())
    }

    /// Export the public key blob.
    fn export_key(
        dll: &KspDll,
        h_provider: usize,
        h_key: usize,
        blob_type: &str,
    ) -> Result<Vec<u8>, String> {
        let export_fn = dll.table.ExportKey.ok_or("ExportKey not in table")?;
        let blob_type_w = to_wide(blob_type);

        // First call: query size
        // Signature: (h_provider, h_key, h_export_key, blob_type, params, output, cb_output, pcb_result, flags)
        let mut cb_result: u32 = 0;
        let status = unsafe {
            export_fn(
                h_provider,
                h_key,
                0, // h_export_key (unused)
                blob_type_w.as_ptr(),
                ptr::null(),     // pParameterList
                ptr::null_mut(), // pb_output (null for size query)
                0,               // cb_output
                &mut cb_result,
                0, // flags
            )
        };
        if status != ERROR_SUCCESS || cb_result == 0 {
            return Err(format!("ExportKey (size query): 0x{status:08X}"));
        }

        // Second call: get data
        let mut buf = vec![0u8; cb_result as usize];
        let status = unsafe {
            export_fn(
                h_provider,
                h_key,
                0,
                blob_type_w.as_ptr(),
                ptr::null(),
                buf.as_mut_ptr(),
                cb_result,
                &mut cb_result,
                0,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("ExportKey (data): 0x{status:08X}"));
        }
        buf.truncate(cb_result as usize);
        Ok(buf)
    }

    /// Sign a hash with PKCS#1 v1.5 padding.
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

        // Signature: (h_provider, h_key, padding_info, hash, hash_len, sig, sig_len, pcb_result, flags)
        let mut cb_sig: u32 = 0;
        let status = unsafe {
            sign_fn(
                h_provider,
                h_key,
                &padding_info as *const _ as *const _,
                hash.as_ptr(),
                hash.len() as u32,
                ptr::null_mut(),
                0,
                &mut cb_sig,
                BCRYPT_PAD_PKCS1,
            )
        };
        if status != ERROR_SUCCESS || cb_sig == 0 {
            return Err(format!("SignHash PKCS1 (size): 0x{status:08X}"));
        }

        let mut sig = vec![0u8; cb_sig as usize];
        let status = unsafe {
            sign_fn(
                h_provider,
                h_key,
                &padding_info as *const _ as *const _,
                hash.as_ptr(),
                hash.len() as u32,
                sig.as_mut_ptr(),
                cb_sig,
                &mut cb_sig,
                BCRYPT_PAD_PKCS1,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("SignHash PKCS1 (sign): 0x{status:08X}"));
        }
        sig.truncate(cb_sig as usize);
        Ok(sig)
    }

    /// Sign a hash with PSS padding.
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
                &padding_info as *const _ as *const _,
                hash.as_ptr(),
                hash.len() as u32,
                ptr::null_mut(),
                0,
                &mut cb_sig,
                BCRYPT_PAD_PSS,
            )
        };
        if status != ERROR_SUCCESS || cb_sig == 0 {
            return Err(format!("SignHash PSS (size): 0x{status:08X}"));
        }

        let mut sig = vec![0u8; cb_sig as usize];
        let status = unsafe {
            sign_fn(
                h_provider,
                h_key,
                &padding_info as *const _ as *const _,
                hash.as_ptr(),
                hash.len() as u32,
                sig.as_mut_ptr(),
                cb_sig,
                &mut cb_sig,
                BCRYPT_PAD_PSS,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("SignHash PSS (sign): 0x{status:08X}"));
        }
        sig.truncate(cb_sig as usize);
        Ok(sig)
    }

    /// Sign a hash with ECDSA (no explicit padding).
    fn sign_hash_ecdsa(
        dll: &KspDll,
        h_provider: usize,
        h_key: usize,
        hash: &[u8],
    ) -> Result<Vec<u8>, String> {
        let sign_fn = dll.table.SignHash.ok_or("SignHash not in table")?;

        // Query size (no padding info for ECDSA)
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
                &mut cb_sig,
                0, // no padding flag
            )
        };
        if status != ERROR_SUCCESS || cb_sig == 0 {
            return Err(format!("SignHash ECDSA (size): 0x{status:08X}"));
        }

        // Pad the buffer: ECDSA signatures have variable DER length,
        // and the second sign call may produce a slightly larger signature.
        let buf_size = cb_sig + 16;
        let mut sig = vec![0u8; buf_size as usize];
        let status = unsafe {
            sign_fn(
                h_provider,
                h_key,
                ptr::null(),
                hash.as_ptr(),
                hash.len() as u32,
                sig.as_mut_ptr(),
                buf_size,
                &mut cb_sig,
                0,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("SignHash ECDSA (sign): 0x{status:08X}"));
        }
        sig.truncate(cb_sig as usize);
        Ok(sig)
    }

    /// Verify a signature with PKCS#1 v1.5 padding.
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

        // Signature: (h_provider, h_key, padding_info, hash, hash_len, sig, sig_len, flags)
        let status = unsafe {
            verify_fn(
                h_provider,
                h_key,
                &padding_info as *const _ as *const _,
                hash.as_ptr(),
                hash.len() as u32,
                signature.as_ptr(),
                signature.len() as u32,
                BCRYPT_PAD_PKCS1,
            )
        };
        Ok(status)
    }

    /// Verify a signature with ECDSA (no padding).
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

    /// Encrypt with OAEP padding.
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

        // Signature: (h_provider, h_key, input, cb_input, padding_info, output, cb_output, pcb_result, flags)
        let mut cb_out: u32 = 0;
        let status = unsafe {
            encrypt_fn(
                h_provider,
                h_key,
                plaintext.as_ptr(),
                plaintext.len() as u32,
                &padding_info as *const _ as *const _,
                ptr::null_mut(),
                0,
                &mut cb_out,
                BCRYPT_PAD_OAEP,
            )
        };
        if status != ERROR_SUCCESS || cb_out == 0 {
            return Err(format!("Encrypt OAEP (size): 0x{status:08X}"));
        }

        let mut ct = vec![0u8; cb_out as usize];
        let status = unsafe {
            encrypt_fn(
                h_provider,
                h_key,
                plaintext.as_ptr(),
                plaintext.len() as u32,
                &padding_info as *const _ as *const _,
                ct.as_mut_ptr(),
                cb_out,
                &mut cb_out,
                BCRYPT_PAD_OAEP,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("Encrypt OAEP (encrypt): 0x{status:08X}"));
        }
        ct.truncate(cb_out as usize);
        Ok(ct)
    }

    /// Decrypt with OAEP padding.
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

        // Query plaintext size
        let mut cb_out: u32 = 0;
        let status = unsafe {
            decrypt_fn(
                h_provider,
                h_key,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
                &padding_info as *const _ as *const _,
                ptr::null_mut(),
                0,
                &mut cb_out,
                BCRYPT_PAD_OAEP,
            )
        };
        if status != ERROR_SUCCESS || cb_out == 0 {
            return Err(format!("Decrypt OAEP (size): 0x{status:08X}"));
        }

        let mut pt = vec![0u8; cb_out as usize];
        let status = unsafe {
            decrypt_fn(
                h_provider,
                h_key,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
                &padding_info as *const _ as *const _,
                pt.as_mut_ptr(),
                cb_out,
                &mut cb_out,
                BCRYPT_PAD_OAEP,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("Decrypt OAEP (decrypt): 0x{status:08X}"));
        }
        pt.truncate(cb_out as usize);
        Ok(pt)
    }

    /// Delete a key (revoke + destroy in KMS).
    fn delete_key(dll: &KspDll, h_provider: usize, h_key: usize) -> Result<(), String> {
        let delete_fn = dll.table.DeleteKey.ok_or("DeleteKey not in table")?;
        let status = unsafe { delete_fn(h_provider, h_key, 0) };
        if status != ERROR_SUCCESS {
            return Err(format!("DeleteKey: 0x{status:08X}"));
        }
        Ok(())
    }

    /// Open an existing key by name.
    fn open_key(dll: &KspDll, h_provider: usize, name: &str) -> Result<usize, String> {
        let open_fn = dll.table.OpenKey.ok_or("OpenKey not in table")?;
        let wide_name = to_wide(name);
        let mut h_key: usize = 0;
        let status = unsafe { open_fn(h_provider, &mut h_key, wide_name.as_ptr(), 0, 0) };
        if status != ERROR_SUCCESS {
            return Err(format!("OpenKey({name}): 0x{status:08X}"));
        }
        Ok(h_key)
    }

    /// Free a key handle.
    fn free_key(dll: &KspDll, h_provider: usize, h_key: usize) {
        if let Some(f) = dll.table.FreeKey {
            unsafe { f(h_provider, h_key) };
        }
    }

    // ── Test output helpers ──────────────────────────────────────────────

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

        // Export public key blob
        let blob = export_key(dll, h_provider, h_key, "RSAPUBLICBLOB")?;
        if blob.len() < std::mem::size_of::<BCRYPT_RSAKEY_BLOB>() {
            return Err(format!("RSA public blob too small: {} bytes", blob.len()));
        }
        let header = unsafe { &*(blob.as_ptr() as *const BCRYPT_RSAKEY_BLOB) };
        if header.Magic != KSP_RSAPUBLIC_MAGIC {
            return Err(format!("Bad RSA blob magic: 0x{:08X}", header.Magic));
        }
        step_ok(&format!(
            "RSA public key exported ({} bytes, {} bits)",
            blob.len(),
            header.BitLength
        ));

        // Open the same key by name
        let h_key2 = open_key(dll, h_provider, "verify-rsa-2048")?;
        free_key(dll, h_provider, h_key2);
        step_ok("RSA key opened by name");

        // Sign (PKCS1 v1.5 + SHA-256)
        let hash: [u8; 32] = [0x55; 32];
        let sig = sign_hash_pkcs1(dll, h_provider, h_key, &hash)?;
        if sig.is_empty() {
            return Err("RSA PKCS1v15 signature is empty".to_owned());
        }
        step_ok(&format!("RSA PKCS1v15 sign OK ({} bytes)", sig.len()));

        // Cleanup
        delete_key(dll, h_provider, h_key)?;
        step_ok("RSA key deleted");
        Ok(())
    }

    fn verify_rsa_encrypt_decrypt(dll: &KspDll, h_provider: usize) -> Result<(), String> {
        // Create an RSA key for encryption (use NCRYPT_ALLOW_DECRYPT_FLAG=2)
        let rsa = rsa_wide();
        let h_key = create_persisted_key(dll, h_provider, &rsa, "verify-rsa-enc")?;
        let length_prop = ncrypt_length_property();
        set_key_property_dword(dll, h_provider, h_key, &length_prop, 2048)?;

        // Set key usage to encrypt/decrypt
        let usage_prop = to_wide("KeyUsageProperty");
        // KSP's KeyUsage::DECRYPT = 0x01 (differs from Windows CNG's NCRYPT_ALLOW_DECRYPT_FLAG = 0x02)
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

        // Verify with correct hash
        let status = verify_signature_pkcs1(dll, h_provider, h_key, &hash, &sig)?;
        if status != ERROR_SUCCESS {
            return Err(format!(
                "VerifySignature (valid): expected 0, got 0x{status:08X}"
            ));
        }
        step_ok("RSA PKCS1v15 verify OK (valid)");

        // Verify with wrong hash
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

        // Export public key blob
        let blob = export_key(dll, h_provider, h_key, "ECCPUBLICBLOB")?;
        if blob.len() < std::mem::size_of::<BCRYPT_ECCKEY_BLOB>() {
            return Err(format!("EC public blob too small: {} bytes", blob.len()));
        }
        let header = unsafe { &*(blob.as_ptr() as *const BCRYPT_ECCKEY_BLOB) };
        if header.dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC {
            return Err(format!("Bad EC P-256 blob magic: 0x{:08X}", header.dwMagic));
        }
        step_ok(&format!(
            "EC P-256 public key exported ({} bytes)",
            blob.len()
        ));

        // ECDSA sign
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

        // ECDSA sign with a SHA-384 hash (48 bytes)
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

        // Delete (revoke + destroy in KMS)
        delete_key(dll, h_provider, h_key)?;
        step_ok("key deleted via DeleteKey");

        // Verify it's gone — OpenKey should fail with NTE_NO_KEY
        let open_fn = dll.table.OpenKey.ok_or("OpenKey not in table")?;
        let wide_name = to_wide("verify-destroy");
        let mut h_key2: usize = 0;
        let status = unsafe { open_fn(h_provider, &mut h_key2, wide_name.as_ptr(), 0, 0) };
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

    // ── Runner ───────────────────────────────────────────────────────────

    pub(crate) fn run_all(dll: &KspDll, h_provider: usize) -> usize {
        let tests: Vec<(&str, fn(&KspDll, usize) -> Result<(), String>)> = vec![
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
        ];

        let mut failures = 0;
        for (name, test_fn) in &tests {
            println!("── {name} ──");
            match test_fn(dll, h_provider) {
                Ok(()) => println!("  => PASS\n"),
                Err(e) => {
                    step_fail(name, &e);
                    println!("  => FAIL\n");
                    failures += 1;
                }
            }
        }
        failures
    }

    // ── Locate the DLL ───────────────────────────────────────────────────

    fn find_dll(explicit: Option<&str>) -> Result<String, String> {
        if let Some(p) = explicit {
            if std::path::Path::new(p).exists() {
                return Ok(p.to_owned());
            }
            return Err(format!("DLL not found at explicit path: {p}"));
        }

        // Try next to the current exe
        if let Ok(exe) = std::env::current_exe() {
            let dir = exe.parent().unwrap_or(std::path::Path::new("."));
            let candidate = dir.join("cosmian_kms_cng_ksp.dll");
            if candidate.exists() {
                return Ok(candidate.to_string_lossy().into_owned());
            }
        }

        // Try in target/debug and target/release
        for profile in &["debug", "release"] {
            let candidate = format!("target\\{profile}\\cosmian_kms_cng_ksp.dll");
            if std::path::Path::new(&candidate).exists() {
                return Ok(candidate);
            }
        }

        Err("Could not find cosmian_kms_cng_ksp.dll. Use --dll <path> to specify.".to_owned())
    }

    // ── Entry point ──────────────────────────────────────────────────────

    pub(crate) fn run() -> ExitCode {
        cosmian_logger::log_init(None);

        // Parse --dll <path> from argv
        let args: Vec<String> = std::env::args().collect();
        let dll_path_arg = args
            .iter()
            .position(|a| a == "--dll")
            .and_then(|i| args.get(i + 1))
            .map(String::as_str);

        println!("=== Cosmian CNG KSP Verification Tool ===\n");

        let dll_path = match find_dll(dll_path_arg) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("ERROR: {e}");
                return ExitCode::FAILURE;
            }
        };

        println!("Loading DLL: {dll_path}\n");
        let dll = match KspDll::load(&dll_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("ERROR: {e}");
                return ExitCode::FAILURE;
            }
        };

        let h_provider = match open_provider(&dll) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("ERROR: {e}");
                return ExitCode::FAILURE;
            }
        };
        step_ok("OpenProvider");

        let failures = run_all(&dll, h_provider);
        free_provider(&dll, h_provider);

        println!("─────────────────────────────────────────");
        if failures == 0 {
            println!("All verification steps PASSED.");
            ExitCode::SUCCESS
        } else {
            eprintln!("{failures} verification step(s) FAILED.");
            ExitCode::FAILURE
        }
    }
}

// ─── In-process test (for cargo test) ────────────────────────────────────────

#[cfg(all(test, windows))]
mod tests {
    use std::path::Path;

    fn find_test_dll() -> String {
        // The build.rs ensures the DLL is built; look in target/debug
        for profile in &["debug", "release"] {
            let candidate = format!("target\\{profile}\\cosmian_kms_cng_ksp.dll");
            if Path::new(&candidate).exists() {
                return candidate;
            }
        }
        // Try relative from workspace root
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let ws_root = Path::new(manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .unwrap_or(Path::new("."));
        let candidate = ws_root
            .join("target")
            .join("debug")
            .join("cosmian_kms_cng_ksp.dll");
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
        panic!(
            "cosmian_kms_cng_ksp.dll not found — run `cargo build -p cosmian_kms_cng_ksp` first"
        );
    }

    /// Write a minimal `ckms.toml` that the DLL will read via `CKMS_CONF`.
    fn write_test_config(port: u16) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("cosmian_cng_verify_test");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("ckms.toml");
        let content = format!("[http_config]\nserver_url = \"http://localhost:{port}\"\n");
        std::fs::write(&path, content).expect("write ckms.toml");
        path
    }

    #[test]
    fn verify_all() {
        // Start in-process KMS server
        let rt = tokio::runtime::Runtime::new().expect("failed to create setup runtime");
        let ctx = rt.block_on(async { test_kms_server::start_default_test_kms_server().await });

        // Write a ckms.toml pointing at the test server and tell the DLL where it is
        let config_path = write_test_config(ctx.server_port);
        unsafe { std::env::set_var("CKMS_CONF", &config_path) };

        // Drop the setup runtime before calling DLL functions (they use their own)
        drop(rt);

        let dll_path = find_test_dll();
        println!("Loading DLL: {dll_path}");

        let dll = super::win::KspDll::load(&dll_path).expect("failed to load DLL");
        let h_provider = super::win::open_provider(&dll).expect("OpenProvider failed");

        let failures = super::win::run_all(&dll, h_provider);
        super::win::free_provider(&dll, h_provider);

        // Clean up
        unsafe { std::env::remove_var("CKMS_CONF") };
        drop(std::fs::remove_file(&config_path));

        assert_eq!(failures, 0, "{failures} verification step(s) failed");
    }
}
