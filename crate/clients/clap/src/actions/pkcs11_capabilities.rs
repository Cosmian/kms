//! PKCS#11 mechanism conformance report for `ckms pkcs11 capabilities`.
//!
//! Unlike `ckms pkcs11 verify` (session/discovery-level API sequence only), this
//! command actually **executes** every cryptographic mechanism the `cosmian_pkcs11`
//! provider implements — key generation, encryption/decryption, and signing/
//! verification — end to end through the real `C_*` entry points, and reports a
//! ✅ / ❌ / ⏭️ per mechanism.
//!
//! `C_GenerateKeyPair` is not implemented by this provider (asymmetric keys are
//! provisioned through the KMS REST API, not PKCS#11), so RSA/EC/Ed25519 key pairs
//! are created via [`KmsClient`] first, then located on the PKCS#11 slot by their
//! `CKA_ID` (which the provider always sets to the KMIP unique identifier — see
//! `crate/clients/pkcs11/module/src/core/object.rs`). Only the AES secret key is
//! generated live via `C_GenerateKey`/`CKM_AES_KEY_GEN`.

#![allow(unsafe_code, clippy::print_stdout)]

use std::{env, ffi::c_void, mem::size_of, path::Path, ptr, sync::Mutex};

use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_0::kmip_types::RevocationReasonCode,
    kmip_2_1::{
        kmip_types::{RecommendedCurve, UniqueIdentifier},
        requests::{create_ec_key_pair_request, create_rsa_key_pair_request},
    },
};
use libloading::Library;
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_FUNCTION_LIST, CK_FUNCTION_LIST_3_0, CK_GCM_PARAMS, CK_KEY_TYPE,
    CK_MECHANISM, CK_MECHANISM_PTR, CK_MECHANISM_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE,
    CK_RSA_PKCS_PSS_PARAMS, CK_SESSION_HANDLE, CK_SLOT_ID, CK_TRUE, CK_ULONG, CK_VOID_PTR,
    CKA_CLASS, CKA_EXTRACTABLE, CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKA_SENSITIVE, CKA_VALUE_LEN,
    CKG_MGF1_SHA256, CKK_AES, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_GCM, CKM_AES_KEY_GEN,
    CKM_ECDSA, CKM_EDDSA, CKM_RSA_PKCS, CKM_RSA_PKCS_PSS, CKM_SHA1_RSA_PKCS, CKM_SHA256,
    CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY,
    CKR_OK,
};

use super::pkcs11_verify::{
    call_get_function_list, call_get_function_list_3_0, call_get_slot_list, call_login,
    call_open_session, check_rv, ckr_name,
};
use crate::{
    actions::shared::utils::{destroy, revoke},
    error::{KmsCliError, result::KmsCliResult},
};

/// Thread-safe guard for the `CKMS_CONF` environment variable (mirrors `pkcs11_verify`).
static CKMS_CONF_LOCK: Mutex<()> = Mutex::new(());

/// Fallible `usize -> CK_ULONG` conversion (mirrors the `pkcs11_verify` convention of
/// never using `as` for length/size conversions across the FFI boundary).
fn ck_ulong(value: usize) -> Result<CK_ULONG, String> {
    CK_ULONG::try_from(value).map_err(|e| format!("length {value} does not fit in CK_ULONG: {e}"))
}

/// Fallible `CK_ULONG -> usize` conversion.
fn ck_usize(value: CK_ULONG) -> Result<usize, String> {
    usize::try_from(value).map_err(|e| format!("CK_ULONG {value} does not fit in usize: {e}"))
}

/// Tag applied to every object this command provisions on the KMS, so a run is easy
/// to identify (and clean up manually if `--keep-keys` was used).
const CAPABILITIES_TAG: &str = "pkcs11-capabilities";

/// The outcome of one mechanism check.
enum Outcome {
    Pass,
    Fail(String),
    Skip(String),
}

/// One row of the final report.
struct CheckResult {
    mechanism: &'static str,
    detail: &'static str,
    outcome: Outcome,
}

/// The set of KMS objects this run provisioned, kept so they can be destroyed at
/// the end regardless of whether the mechanism checks succeeded.
#[derive(Default)]
struct ProvisionedKeys {
    /// `(private_key_id, public_key_id)` pairs created via `create_key_pair`.
    key_pairs: Vec<(String, String)>,
}

/// Run the full PKCS#11 mechanism-capability report.
///
/// # Errors
/// Returns an error if the shared library cannot be loaded, or if the PKCS#11
/// session cannot be initialized/opened — i.e. setup/connectivity failures. Actual
/// per-mechanism failures are never returned as an `Err`: they are recorded and
/// printed as a ❌ row in the report, so this command always exits successfully
/// once a session was established.
pub(crate) async fn run_capabilities(
    so_path: &Path,
    conf: Option<&Path>,
    token: Option<&str>,
    kms_rest_client: KmsClient,
    keep_keys: bool,
) -> KmsCliResult<()> {
    println!("[capabilities] Provisioning KMS test keys...");
    let provisioned = provision_keys(&kms_rest_client).await?;
    println!("[capabilities] KMS test keys provisioned.");
    println!();

    let guard = CKMS_CONF_LOCK
        .lock()
        .map_err(|_lock_err| KmsCliError::Default("CKMS_CONF_LOCK poisoned".to_owned()))?;
    if let Some(conf_path) = conf {
        // SAFETY: protected by mutex to ensure exclusive access to environment variables.
        unsafe { env::set_var("CKMS_CONF", conf_path) };
    }
    drop(guard);

    println!("[load] Opening: {}", so_path.display());
    let lib = unsafe { Library::new(so_path) }.map_err(|e| {
        KmsCliError::Default(format!(
            "FAIL [load]: cannot open '{}': {e}",
            so_path.display()
        ))
    })?;

    let func_list_ptr = call_get_function_list(&lib)?;
    let func_list: &CK_FUNCTION_LIST = unsafe { &*func_list_ptr };
    // The v3.0 message-based signing functions (`C_MessageSignInit`/`C_SignMessage`/
    // `C_MessageSignFinal`) are not part of the legacy `CK_FUNCTION_LIST` returned by
    // `C_GetFunctionList` above; resolve the extended v3.0 table via `C_GetInterface`.
    let func_list_3_0_ptr = call_get_function_list_3_0(&lib)?;
    let func_list_3_0: &CK_FUNCTION_LIST_3_0 = unsafe { &*func_list_3_0_ptr };

    let c_initialize = func_list.C_Initialize.ok_or_else(|| {
        KmsCliError::Default("FAIL [C_Initialize]: not present in function list".to_owned())
    })?;
    check_rv(
        unsafe { c_initialize(ptr::null_mut::<c_void>()) },
        "C_Initialize",
    )?;

    let slot_id = call_get_slot_list(func_list)?;
    let session = call_open_session(func_list, slot_id)?;
    if let Some(tok) = token {
        call_login(func_list, session, tok)?;
    }
    println!("[capabilities] PKCS#11 session opened on slot {slot_id}.");
    println!();

    // Locate the KMS-provisioned RSA/EC/Ed25519 objects on the PKCS#11 slot by
    // `CKA_ID` (the KMIP unique identifier).
    let key_handles = KeyHandles::locate(func_list, session, &provisioned);

    let mut results = Vec::new();
    run_aes_checks(func_list, session, &mut results);
    run_rsa_checks(func_list, slot_id, key_handles.rsa, &mut results);
    run_ecdsa_checks(func_list, slot_id, &key_handles.ec, &mut results);
    run_eddsa_checks(
        func_list,
        func_list_3_0,
        slot_id,
        key_handles.ed25519,
        &mut results,
    );

    // Best-effort teardown: never let a session-close failure hide the report.
    if let Some(c_close_session) = func_list.C_CloseSession {
        let _ = unsafe { c_close_session(session) };
    }
    if let Some(c_finalize) = func_list.C_Finalize {
        let _ = unsafe { c_finalize(ptr::null_mut::<c_void>()) };
    }

    if keep_keys {
        println!(
            "[capabilities] --keep-keys set: leaving provisioned KMS objects in place \
             (tag: {CAPABILITIES_TAG})."
        );
    } else {
        cleanup_keys(&kms_rest_client, provisioned).await;
    }
    println!();

    print_report(&results);

    Ok(())
}

// ---------------------------------------------------------------------------
// KMS key provisioning / cleanup
// ---------------------------------------------------------------------------

/// RSA key length used for the provisioned test key pair.
const RSA_KEY_BITS: usize = 2048;

async fn provision_keys(kms_rest_client: &KmsClient) -> KmsCliResult<ProvisionedKeys> {
    let vendor_id = kms_rest_client.config.vendor_id.as_str();
    let mut provisioned = ProvisionedKeys::default();

    let rsa_request = create_rsa_key_pair_request(
        vendor_id,
        None,
        [CAPABILITIES_TAG],
        RSA_KEY_BITS,
        false,
        None,
    )
    .map_err(|e| KmsCliError::Default(format!("failed building the RSA key pair request: {e}")))?;
    let rsa_response = kms_rest_client
        .create_key_pair(rsa_request)
        .await
        .map_err(|e| {
            KmsCliError::Default(format!("failed provisioning the RSA test key pair: {e}"))
        })?;
    provisioned.key_pairs.push((
        unique_identifier_to_string(&rsa_response.private_key_unique_identifier)?,
        unique_identifier_to_string(&rsa_response.public_key_unique_identifier)?,
    ));

    // P-256 is FIPS-approved, so it is always provisioned.
    provision_ec_curve(kms_rest_client, RecommendedCurve::P256, &mut provisioned).await?;

    // secp256k1 and Ed25519 are not FIPS-approved; only attempt them in a
    // `non-fips` build, where the server actually allows creating them.
    if cfg!(feature = "non-fips") {
        provision_ec_curve(
            kms_rest_client,
            RecommendedCurve::SECP256K1,
            &mut provisioned,
        )
        .await?;
        provision_ec_curve(
            kms_rest_client,
            RecommendedCurve::CURVEED25519,
            &mut provisioned,
        )
        .await?;
    }

    Ok(provisioned)
}

async fn provision_ec_curve(
    kms_rest_client: &KmsClient,
    curve: RecommendedCurve,
    provisioned: &mut ProvisionedKeys,
) -> KmsCliResult<()> {
    let vendor_id = kms_rest_client.config.vendor_id.as_str();
    let request =
        create_ec_key_pair_request(vendor_id, None, [CAPABILITIES_TAG], curve, false, None)
            .map_err(|e| {
                KmsCliError::Default(format!(
                    "failed building the {curve:?} key pair request: {e}"
                ))
            })?;
    let response = kms_rest_client
        .create_key_pair(request)
        .await
        .map_err(|e| {
            KmsCliError::Default(format!(
                "failed provisioning the {curve:?} test key pair: {e}"
            ))
        })?;
    provisioned.key_pairs.push((
        unique_identifier_to_string(&response.private_key_unique_identifier)?,
        unique_identifier_to_string(&response.public_key_unique_identifier)?,
    ));
    Ok(())
}

fn unique_identifier_to_string(id: &UniqueIdentifier) -> KmsCliResult<String> {
    id.as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| KmsCliError::Default("the server did not return a string id".to_owned()))
}

/// Destroys every KMS object provisioned by this run. Best-effort: a failure to
/// destroy one object is logged but does not fail the command, since the mechanism
/// report itself has already succeeded or failed independently.
async fn cleanup_keys(kms_rest_client: &KmsClient, provisioned: ProvisionedKeys) {
    for (private_key_id, _public_key_id) in provisioned.key_pairs {
        // A freshly-created key pair is `PreActive`/`Active`; the KMIP object
        // lifecycle state machine requires `Revoke` before `Destroy` is allowed
        // (destroying an active object is denied). Best-effort: if `Revoke`
        // itself fails, still attempt `Destroy` in case the object is already
        // in a destroyable state.
        if let Err(e) = revoke(
            kms_rest_client.clone(),
            &private_key_id,
            "capabilities run cleanup",
            RevocationReasonCode::CessationOfOperation,
        )
        .await
        {
            println!("[capabilities] WARN: failed to revoke key {private_key_id}: {e}");
        }
        // `destroy` cascades from the private key to its paired public key.
        if let Err(e) = destroy(kms_rest_client.clone(), &private_key_id, true, None).await {
            println!("[capabilities] WARN: failed to clean up key {private_key_id}: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// PKCS#11 object lookup
// ---------------------------------------------------------------------------

struct KeyHandles {
    rsa: Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>,
    ec: Vec<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>,
    ed25519: Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>,
}

impl KeyHandles {
    fn locate(
        func_list: &CK_FUNCTION_LIST,
        session: CK_SESSION_HANDLE,
        provisioned: &ProvisionedKeys,
    ) -> Self {
        // Index 0 is always the RSA pair (see `provision_keys`); index 1 is P-256;
        // any further pairs (non-fips only) are secp256k1 then Ed25519, all reported
        // through the generic `ec` list except the last one, which is Ed25519 when
        // present.
        let mut pairs = provisioned.key_pairs.iter();
        let rsa = pairs
            .next()
            .and_then(|(sk, pk)| find_key_pair(func_list, session, sk, pk));

        let mut ec = Vec::new();
        let mut ed25519 = None;
        let remaining: Vec<_> = pairs.collect();
        for (idx, (sk, pk)) in remaining.iter().enumerate() {
            let handles = find_key_pair(func_list, session, sk, pk);
            let is_last_and_non_fips = cfg!(feature = "non-fips") && idx == remaining.len() - 1;
            if is_last_and_non_fips {
                ed25519 = handles;
            } else if let Some(handles) = handles {
                ec.push(handles);
            }
        }

        Self { rsa, ec, ed25519 }
    }
}

fn find_key_pair(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    private_key_id: &str,
    public_key_id: &str,
) -> Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    let sk = find_object_by_id(
        func_list,
        session,
        CKO_PRIVATE_KEY,
        private_key_id.as_bytes(),
    )?;
    let pk = find_object_by_id(func_list, session, CKO_PUBLIC_KEY, public_key_id.as_bytes())?;
    Some((sk, pk))
}

/// `C_FindObjectsInit`/`C_FindObjects`/`C_FindObjectsFinal` for a single object
/// matching `class` and `CKA_ID == id`.
fn find_object_by_id(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    class: CK_OBJECT_CLASS,
    id: &[u8],
) -> Option<CK_OBJECT_HANDLE> {
    let mut class = class;
    let class_len = ck_ulong(size_of::<CK_OBJECT_CLASS>()).ok()?;
    let id_len = ck_ulong(id.len()).ok()?;
    let template = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: (&raw mut class).cast::<c_void>(),
            ulValueLen: class_len,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID,
            pValue: id.as_ptr().cast_mut().cast::<c_void>(),
            ulValueLen: id_len,
        },
    ];

    let c_find_init = func_list.C_FindObjectsInit?;
    let template_len = ck_ulong(template.len()).ok()?;
    // SAFETY: `template` is a valid `CK_ATTRIBUTE` array kept alive on the stack for
    // the duration of this call.
    if unsafe { c_find_init(session, template.as_ptr().cast_mut(), template_len) } != CKR_OK {
        return None;
    }

    let c_find = func_list.C_FindObjects?;
    let mut handles: [CK_OBJECT_HANDLE; 4] = [0; 4];
    let mut found: CK_ULONG = 0;
    let handles_len = ck_ulong(handles.len()).ok()?;
    // SAFETY: `handles` has room for `handles.len()` entries, matching `ulMaxObjectCount`.
    let find_rv = unsafe { c_find(session, handles.as_mut_ptr(), handles_len, &raw mut found) };

    if let Some(c_find_final) = func_list.C_FindObjectsFinal {
        // SAFETY: closes the search context opened above.
        let _ = unsafe { c_find_final(session) };
    }

    if find_rv != CKR_OK || found == 0 {
        return None;
    }
    Some(handles[0])
}

// ---------------------------------------------------------------------------
// Mechanism checks
// ---------------------------------------------------------------------------

const AES_IV_SIZE: usize = 16;
const AES_GCM_IV_SIZE: usize = 12;

/// `CKM_AES_KEY_GEN` (via `C_GenerateKey`) + `CKM_AES_CBC` / `CKM_AES_CBC_PAD` /
/// `CKM_AES_GCM` round-trip encrypt/decrypt.
fn run_aes_checks(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    results: &mut Vec<CheckResult>,
) {
    let key_handle = match generate_aes_key(func_list, session) {
        Ok(handle) => {
            results.push(CheckResult {
                mechanism: "CKM_AES_KEY_GEN",
                detail: "C_GenerateKey",
                outcome: Outcome::Pass,
            });
            handle
        }
        Err(e) => {
            let reason = e;
            for (mechanism, detail) in [
                ("CKM_AES_KEY_GEN", "C_GenerateKey"),
                ("CKM_AES_CBC", "encrypt/decrypt round-trip"),
                ("CKM_AES_CBC_PAD", "encrypt/decrypt round-trip"),
                ("CKM_AES_GCM", "encrypt/decrypt round-trip"),
            ] {
                results.push(CheckResult {
                    mechanism,
                    detail,
                    outcome: Outcome::Fail(reason.clone()),
                });
            }
            return;
        }
    };

    // `CKM_AES_CBC` (no padding) requires an exact multiple of the 16-byte AES
    // block size; `CKM_AES_CBC_PAD` and `CKM_AES_GCM` accept arbitrary lengths.
    let cbc_plaintext = b"cosmian pkcs11 capabilities AES CBC block test!!"[..48].to_vec(); // 48 bytes
    let arbitrary_plaintext = b"cosmian pkcs11 capabilities AES round-trip test message";

    for (ck_mechanism, mechanism, iv_len, plaintext) in [
        (
            CKM_AES_CBC,
            "CKM_AES_CBC",
            AES_IV_SIZE,
            cbc_plaintext.as_slice(),
        ),
        (
            CKM_AES_CBC_PAD,
            "CKM_AES_CBC_PAD",
            AES_IV_SIZE,
            arbitrary_plaintext.as_slice(),
        ),
        (
            CKM_AES_GCM,
            "CKM_AES_GCM",
            AES_GCM_IV_SIZE,
            arbitrary_plaintext.as_slice(),
        ),
    ] {
        let outcome = match aes_round_trip(
            func_list,
            session,
            key_handle,
            ck_mechanism,
            iv_len,
            plaintext,
        ) {
            Ok(()) => Outcome::Pass,
            Err(e) => Outcome::Fail(e),
        };
        results.push(CheckResult {
            mechanism,
            detail: "encrypt/decrypt round-trip",
            outcome,
        });
    }

    if let Some(c_destroy) = func_list.C_DestroyObject {
        // SAFETY: `key_handle` is a valid handle returned by `C_GenerateKey` above.
        let _ = unsafe { c_destroy(session, key_handle) };
    }
}

fn generate_aes_key(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
) -> Result<CK_OBJECT_HANDLE, String> {
    let c_generate_key = func_list
        .C_GenerateKey
        .ok_or_else(|| "C_GenerateKey not present in function list".to_owned())?;

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut key_type = CKK_AES;
    let mut value_len: CK_ULONG = 32;
    let mut sensitive_true: CK_BBOOL = CK_TRUE;
    let mut extractable_true: CK_BBOOL = CK_TRUE;
    let label = "ckms-pkcs11-capabilities-aes";
    let mut template = [
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: (&raw mut key_type).cast::<c_void>(),
            ulValueLen: ck_ulong(size_of::<CK_KEY_TYPE>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: label.as_ptr().cast_mut().cast::<c_void>(),
            ulValueLen: ck_ulong(label.len())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE,
            pValue: (&raw mut sensitive_true).cast::<c_void>(),
            ulValueLen: ck_ulong(size_of::<CK_BBOOL>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE,
            pValue: (&raw mut extractable_true).cast::<c_void>(),
            ulValueLen: ck_ulong(size_of::<CK_BBOOL>())?,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN,
            pValue: (&raw mut value_len).cast::<c_void>(),
            ulValueLen: ck_ulong(size_of::<CK_ULONG>())?,
        },
    ];

    let mut key_handle: CK_OBJECT_HANDLE = 0;
    let template_len = ck_ulong(template.len())?;
    let rv = unsafe {
        c_generate_key(
            session,
            &raw mut mechanism,
            template.as_mut_ptr(),
            template_len,
            &raw mut key_handle,
        )
    };
    if rv != CKR_OK {
        return Err(format!(
            "C_GenerateKey returned {} (0x{rv:08X})",
            ckr_name(rv)
        ));
    }
    Ok(key_handle)
}

fn aes_round_trip(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    key_handle: CK_OBJECT_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    iv_len: usize,
    plaintext: &[u8],
) -> Result<(), String> {
    let mut iv = vec![0_u8; iv_len];
    let mut aad = Vec::new();
    let iv_len_ck = ck_ulong(iv_len)?;
    let mut gcm_params = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv_len_ck,
        ulIvBits: ck_ulong(iv_len * 8)?,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: ck_ulong(aad.len())?,
        ulTagBits: 128,
    };
    let mut mechanism = if mechanism_type == CKM_AES_GCM {
        CK_MECHANISM {
            mechanism: mechanism_type,
            pParameter: (&raw mut gcm_params).cast::<c_void>(),
            ulParameterLen: ck_ulong(size_of::<CK_GCM_PARAMS>())?,
        }
    } else {
        CK_MECHANISM {
            mechanism: mechanism_type,
            pParameter: iv.as_mut_ptr().cast::<c_void>(),
            ulParameterLen: iv_len_ck,
        }
    };
    let _ = &aad;

    let c_encrypt_init = func_list
        .C_EncryptInit
        .ok_or_else(|| "C_EncryptInit not present in function list".to_owned())?;
    let rv = unsafe { c_encrypt_init(session, &raw mut mechanism, key_handle) };
    if rv != CKR_OK {
        return Err(format!(
            "C_EncryptInit returned {} (0x{rv:08X})",
            ckr_name(rv)
        ));
    }

    let c_encrypt = func_list
        .C_Encrypt
        .ok_or_else(|| "C_Encrypt not present in function list".to_owned())?;
    let mut input = plaintext.to_vec();
    let input_len = ck_ulong(input.len())?;
    let mut ciphertext = vec![0_u8; plaintext.len() + 32];
    let mut ciphertext_len = ck_ulong(ciphertext.len())?;
    let rv = unsafe {
        c_encrypt(
            session,
            input.as_mut_ptr(),
            input_len,
            ciphertext.as_mut_ptr(),
            &raw mut ciphertext_len,
        )
    };
    if rv != CKR_OK {
        return Err(format!("C_Encrypt returned {} (0x{rv:08X})", ckr_name(rv)));
    }
    ciphertext.truncate(ck_usize(ciphertext_len)?);

    let mut mechanism = if mechanism_type == CKM_AES_GCM {
        CK_MECHANISM {
            mechanism: mechanism_type,
            pParameter: (&raw mut gcm_params).cast::<c_void>(),
            ulParameterLen: ck_ulong(size_of::<CK_GCM_PARAMS>())?,
        }
    } else {
        CK_MECHANISM {
            mechanism: mechanism_type,
            pParameter: iv.as_mut_ptr().cast::<c_void>(),
            ulParameterLen: iv_len_ck,
        }
    };

    let c_decrypt_init = func_list
        .C_DecryptInit
        .ok_or_else(|| "C_DecryptInit not present in function list".to_owned())?;
    let rv = unsafe { c_decrypt_init(session, &raw mut mechanism, key_handle) };
    if rv != CKR_OK {
        return Err(format!(
            "C_DecryptInit returned {} (0x{rv:08X})",
            ckr_name(rv)
        ));
    }

    let c_decrypt = func_list
        .C_Decrypt
        .ok_or_else(|| "C_Decrypt not present in function list".to_owned())?;
    let ciphertext_len_ck = ck_ulong(ciphertext.len())?;
    let mut decrypted = vec![0_u8; ciphertext.len()];
    let mut decrypted_len = ck_ulong(decrypted.len())?;
    let rv = unsafe {
        c_decrypt(
            session,
            ciphertext.as_mut_ptr(),
            ciphertext_len_ck,
            decrypted.as_mut_ptr(),
            &raw mut decrypted_len,
        )
    };
    if rv != CKR_OK {
        return Err(format!("C_Decrypt returned {} (0x{rv:08X})", ckr_name(rv)));
    }
    decrypted.truncate(ck_usize(decrypted_len)?);

    if decrypted != plaintext {
        return Err("decrypted plaintext does not match the original".to_owned());
    }
    Ok(())
}

/// `CKM_RSA_PKCS`, `CKM_SHA{1,256,384,512}_RSA_PKCS`, `CKM_RSA_PKCS_PSS` sign/verify.
fn run_rsa_checks(
    func_list: &CK_FUNCTION_LIST,
    slot_id: CK_SLOT_ID,
    handles: Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>,
    results: &mut Vec<CheckResult>,
) {
    let Some((sk, pk)) = handles else {
        for mechanism in [
            "CKM_RSA_PKCS",
            "CKM_SHA1_RSA_PKCS",
            "CKM_SHA256_RSA_PKCS",
            "CKM_SHA384_RSA_PKCS",
            "CKM_SHA512_RSA_PKCS",
            "CKM_RSA_PKCS_PSS",
        ] {
            results.push(CheckResult {
                mechanism,
                detail: "sign/verify",
                outcome: Outcome::Fail(
                    "the KMS-provisioned RSA key pair was not found on the PKCS#11 slot".to_owned(),
                ),
            });
        }
        return;
    };

    let raw_message = b"cosmian pkcs11 capabilities RSA raw sign test data 32b";
    let digest = [0x5A_u8; 32];

    for (mechanism, ck_mechanism, data) in [
        ("CKM_RSA_PKCS", CKM_RSA_PKCS, &raw_message[..32]),
        (
            "CKM_SHA1_RSA_PKCS",
            CKM_SHA1_RSA_PKCS,
            raw_message.as_slice(),
        ),
        (
            "CKM_SHA256_RSA_PKCS",
            CKM_SHA256_RSA_PKCS,
            raw_message.as_slice(),
        ),
        (
            "CKM_SHA384_RSA_PKCS",
            CKM_SHA384_RSA_PKCS,
            raw_message.as_slice(),
        ),
        (
            "CKM_SHA512_RSA_PKCS",
            CKM_SHA512_RSA_PKCS,
            raw_message.as_slice(),
        ),
    ] {
        let outcome = match sign_verify(func_list, slot_id, sk, pk, ck_mechanism, None, data) {
            Ok(()) => Outcome::Pass,
            // `CKM_SHA1_RSA_PKCS` is expected to fail: the KMS server's algorithm
            // policy unconditionally denies the deprecated `SHA1WithRSAEncryption`
            // signature algorithm (see
            // `crate/server/src/core/operations/algorithm_policy.rs`), regardless of
            // the FIPS/non-FIPS build. This is a genuine capability limitation of the
            // server, not a bug in this tool or the PKCS#11 provider.
            Err(e) if mechanism == "CKM_SHA1_RSA_PKCS" => Outcome::Fail(format!(
                "{e} (expected: SHA-1 RSA signing is denied by the KMS server's \
                 deprecated-algorithm policy)"
            )),
            Err(e) => Outcome::Fail(e),
        };
        results.push(CheckResult {
            mechanism,
            detail: "sign/verify",
            outcome,
        });
    }

    // CKM_RSA_PKCS_PSS is a "bare" PSS mechanism: it expects a pre-computed digest,
    // not the raw message (PKCS#11 v3.1 §6.4.7).
    let mut pss_params = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        sLen: 32,
    };
    let outcome = match ck_ulong(size_of::<CK_RSA_PKCS_PSS_PARAMS>()) {
        Ok(pss_params_len) => {
            let pss_parameter = Some(((&raw mut pss_params).cast::<c_void>(), pss_params_len));
            match sign_verify(
                func_list,
                slot_id,
                sk,
                pk,
                CKM_RSA_PKCS_PSS,
                pss_parameter,
                &digest,
            ) {
                Ok(()) => Outcome::Pass,
                Err(e) => Outcome::Fail(e),
            }
        }
        Err(e) => Outcome::Fail(e),
    };
    results.push(CheckResult {
        mechanism: "CKM_RSA_PKCS_PSS",
        detail: "sign/verify",
        outcome,
    });
}

/// `CKM_ECDSA` sign/verify over every provisioned EC key pair (P-256, and — in a
/// `non-fips` build — secp256k1).
fn run_ecdsa_checks(
    func_list: &CK_FUNCTION_LIST,
    slot_id: CK_SLOT_ID,
    handles: &[(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)],
    results: &mut Vec<CheckResult>,
) {
    if handles.is_empty() {
        results.push(CheckResult {
            mechanism: "CKM_ECDSA",
            detail: "sign/verify",
            outcome: Outcome::Fail(
                "no KMS-provisioned EC key pair was found on the PKCS#11 slot".to_owned(),
            ),
        });
        return;
    }

    // CKM_ECDSA expects a pre-computed digest, not the raw message.
    let digest = [0x24_u8; 32];
    for (idx, (sk, pk)) in handles.iter().enumerate() {
        let outcome = match sign_verify(func_list, slot_id, *sk, *pk, CKM_ECDSA, None, &digest) {
            Ok(()) => Outcome::Pass,
            Err(e) => Outcome::Fail(e),
        };
        results.push(CheckResult {
            mechanism: "CKM_ECDSA",
            detail: if idx == 0 {
                "sign/verify (P-256)"
            } else {
                "sign/verify (secp256k1)"
            },
            outcome,
        });
    }
}

/// One-shot `CKM_EDDSA` sign/verify, plus the v3.0 message-based
/// `C_MessageSignInit`/`C_SignMessage`/`C_MessageSignFinal` flow — both gated
/// behind the `non-fips` feature, since Ed25519 is not FIPS-approved.
fn run_eddsa_checks(
    func_list: &CK_FUNCTION_LIST,
    func_list_3_0: &CK_FUNCTION_LIST_3_0,
    slot_id: CK_SLOT_ID,
    handles: Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>,
    results: &mut Vec<CheckResult>,
) {
    if !cfg!(feature = "non-fips") {
        results.push(CheckResult {
            mechanism: "CKM_EDDSA",
            detail: "sign/verify (one-shot)",
            outcome: Outcome::Skip(
                "Ed25519 is not FIPS-approved; built without --features non-fips".to_owned(),
            ),
        });
        results.push(CheckResult {
            mechanism: "CKM_EDDSA",
            detail: "C_MessageSignInit/C_SignMessage/C_MessageSignFinal",
            outcome: Outcome::Skip(
                "Ed25519 is not FIPS-approved; built without --features non-fips".to_owned(),
            ),
        });
        return;
    }

    let Some((sk, pk)) = handles else {
        for detail in [
            "sign/verify (one-shot)",
            "C_MessageSignInit/C_SignMessage/C_MessageSignFinal",
        ] {
            results.push(CheckResult {
                mechanism: "CKM_EDDSA",
                detail,
                outcome: Outcome::Fail(
                    "the KMS-provisioned Ed25519 key pair was not found on the PKCS#11 slot"
                        .to_owned(),
                ),
            });
        }
        return;
    };

    let message = b"cosmian pkcs11 capabilities EdDSA one-shot sign test message";
    let outcome = match sign_verify(func_list, slot_id, sk, pk, CKM_EDDSA, None, message) {
        Ok(()) => Outcome::Pass,
        Err(e) => Outcome::Fail(e),
    };
    results.push(CheckResult {
        mechanism: "CKM_EDDSA",
        detail: "sign/verify (one-shot)",
        outcome,
    });

    let outcome =
        match eddsa_message_sign_verify(func_list, func_list_3_0, slot_id, sk, pk, message) {
            Ok(()) => Outcome::Pass,
            Err(e) => Outcome::Fail(e),
        };
    results.push(CheckResult {
        mechanism: "CKM_EDDSA",
        detail: "C_MessageSignInit/C_SignMessage/C_MessageSignFinal",
        outcome,
    });
}

/// Generic `C_SignInit`/`C_Sign` + `C_VerifyInit`/`C_Verify` round trip.
fn sign_verify(
    func_list: &CK_FUNCTION_LIST,
    slot_id: CK_SLOT_ID,
    private_key: CK_OBJECT_HANDLE,
    public_key: CK_OBJECT_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    parameter: Option<(CK_VOID_PTR, CK_ULONG)>,
    data: &[u8],
) -> Result<(), String> {
    // Each mechanism gets its own session: some providers leave a session's
    // sign/verify context "active" after a failed `C_Sign`/`C_Verify` (rather
    // than terminating it, as PKCS#11 v3.1 §5.2 requires for anything other
    // than `CKR_BUFFER_TOO_SMALL`), which would otherwise cascade a single
    // mechanism failure into `CKR_OPERATION_ACTIVE` for every check that follows.
    let session = call_open_session(func_list, slot_id).map_err(|e| e.to_string())?;
    let result = sign_verify_on_session(
        func_list,
        session,
        private_key,
        public_key,
        mechanism_type,
        parameter,
        data,
    );
    if let Some(c_close_session) = func_list.C_CloseSession {
        // SAFETY: `session` was just opened above and is closed unconditionally,
        // regardless of whether the sign/verify check succeeded.
        let _ = unsafe { c_close_session(session) };
    }
    result
}

fn sign_verify_on_session(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    private_key: CK_OBJECT_HANDLE,
    public_key: CK_OBJECT_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    parameter: Option<(CK_VOID_PTR, CK_ULONG)>,
    data: &[u8],
) -> Result<(), String> {
    let (pparam, plen) = parameter.unwrap_or((ptr::null_mut(), 0));
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        pParameter: pparam,
        ulParameterLen: plen,
    };

    let c_sign_init = func_list
        .C_SignInit
        .ok_or_else(|| "C_SignInit not present in function list".to_owned())?;
    let rv = unsafe { c_sign_init(session, &raw mut mechanism, private_key) };
    if rv != CKR_OK {
        return Err(format!("C_SignInit returned {} (0x{rv:08X})", ckr_name(rv)));
    }

    let c_sign = func_list
        .C_Sign
        .ok_or_else(|| "C_Sign not present in function list".to_owned())?;
    let mut input = data.to_vec();
    let input_len = ck_ulong(input.len())?;
    let mut signature = vec![0_u8; 1024];
    let mut signature_len = ck_ulong(signature.len())?;
    let rv = unsafe {
        c_sign(
            session,
            input.as_mut_ptr(),
            input_len,
            signature.as_mut_ptr(),
            &raw mut signature_len,
        )
    };
    if rv != CKR_OK {
        return Err(format!("C_Sign returned {} (0x{rv:08X})", ckr_name(rv)));
    }
    signature.truncate(ck_usize(signature_len)?);

    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        pParameter: pparam,
        ulParameterLen: plen,
    };
    let c_verify_init = func_list
        .C_VerifyInit
        .ok_or_else(|| "C_VerifyInit not present in function list".to_owned())?;
    let rv = unsafe { c_verify_init(session, &raw mut mechanism, public_key) };
    if rv != CKR_OK {
        return Err(format!(
            "C_VerifyInit returned {} (0x{rv:08X})",
            ckr_name(rv)
        ));
    }

    let c_verify = func_list
        .C_Verify
        .ok_or_else(|| "C_Verify not present in function list".to_owned())?;
    let mut input = data.to_vec();
    let input_len = ck_ulong(input.len())?;
    let mut sig = signature;
    let sig_len = ck_ulong(sig.len())?;
    let rv = unsafe {
        c_verify(
            session,
            input.as_mut_ptr(),
            input_len,
            sig.as_mut_ptr(),
            sig_len,
        )
    };
    if rv != CKR_OK {
        return Err(format!("C_Verify returned {} (0x{rv:08X})", ckr_name(rv)));
    }
    Ok(())
}

fn eddsa_message_sign_verify(
    func_list: &CK_FUNCTION_LIST,
    func_list_3_0: &CK_FUNCTION_LIST_3_0,
    slot_id: CK_SLOT_ID,
    private_key: CK_OBJECT_HANDLE,
    public_key: CK_OBJECT_HANDLE,
    message: &[u8],
) -> Result<(), String> {
    // Isolated from the one-shot `CKM_EDDSA` check above: give the message-based
    // flow its own session, for the same reason `sign_verify` does.
    let session = call_open_session(func_list, slot_id).map_err(|e| e.to_string())?;
    let result = eddsa_message_sign_verify_on_session(
        func_list,
        func_list_3_0,
        session,
        private_key,
        public_key,
        message,
    );
    if let Some(c_close_session) = func_list.C_CloseSession {
        // SAFETY: `session` was just opened above and is closed unconditionally.
        let _ = unsafe { c_close_session(session) };
    }
    result
}

fn eddsa_message_sign_verify_on_session(
    func_list: &CK_FUNCTION_LIST,
    func_list_3_0: &CK_FUNCTION_LIST_3_0,
    session: CK_SESSION_HANDLE,
    private_key: CK_OBJECT_HANDLE,
    public_key: CK_OBJECT_HANDLE,
    message: &[u8],
) -> Result<(), String> {
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let c_message_sign_init: CK_MECHANISM_PTR = &raw mut sign_mechanism;
    let init = func_list_3_0
        .C_MessageSignInit
        .ok_or_else(|| "C_MessageSignInit not present in function list".to_owned())?;
    let rv = unsafe { init(session, c_message_sign_init, private_key) };
    if rv != CKR_OK {
        return Err(format!(
            "C_MessageSignInit returned {} (0x{rv:08X})",
            ckr_name(rv)
        ));
    }

    let sign = func_list_3_0
        .C_SignMessage
        .ok_or_else(|| "C_SignMessage not present in function list".to_owned())?;
    let mut input = message.to_vec();
    let input_len = ck_ulong(input.len())?;
    let mut signature = vec![0_u8; 128];
    let mut signature_len = ck_ulong(signature.len())?;
    let rv = unsafe {
        sign(
            session,
            ptr::null_mut(),
            0,
            input.as_mut_ptr(),
            input_len,
            signature.as_mut_ptr(),
            &raw mut signature_len,
        )
    };
    if rv != CKR_OK {
        return Err(format!(
            "C_SignMessage returned {} (0x{rv:08X})",
            ckr_name(rv)
        ));
    }
    signature.truncate(ck_usize(signature_len)?);

    if let Some(finalize) = func_list_3_0.C_MessageSignFinal {
        // SAFETY: `session` is a valid, open session with an active message-sign
        // context started by `C_MessageSignInit` above.
        let rv = unsafe { finalize(session) };
        if rv != CKR_OK {
            return Err(format!(
                "C_MessageSignFinal returned {} (0x{rv:08X})",
                ckr_name(rv)
            ));
        }
    }

    // Verify the message-signed signature with the one-shot C_Verify path — the
    // provider produces the same signature format either way for EdDSA.
    let mut verify_mechanism = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let c_verify_init = func_list
        .C_VerifyInit
        .ok_or_else(|| "C_VerifyInit not present in function list".to_owned())?;
    let rv = unsafe { c_verify_init(session, &raw mut verify_mechanism, public_key) };
    if rv != CKR_OK {
        return Err(format!(
            "C_VerifyInit returned {} (0x{rv:08X})",
            ckr_name(rv)
        ));
    }
    let c_verify = func_list
        .C_Verify
        .ok_or_else(|| "C_Verify not present in function list".to_owned())?;
    let mut verify_input = message.to_vec();
    let verify_input_len = ck_ulong(verify_input.len())?;
    let signature_len = ck_ulong(signature.len())?;
    let rv = unsafe {
        c_verify(
            session,
            verify_input.as_mut_ptr(),
            verify_input_len,
            signature.as_mut_ptr(),
            signature_len,
        )
    };
    if rv != CKR_OK {
        return Err(format!("C_Verify returned {} (0x{rv:08X})", ckr_name(rv)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Report rendering
// ---------------------------------------------------------------------------

fn print_report(results: &[CheckResult]) {
    println!("PKCS#11 mechanism capability report");
    println!("====================================");
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    for result in results {
        let (icon, detail) = match &result.outcome {
            Outcome::Pass => {
                passed += 1;
                ("✅".to_owned(), String::new())
            }
            Outcome::Fail(reason) => {
                failed += 1;
                ("❌".to_owned(), format!(": {reason}"))
            }
            Outcome::Skip(reason) => {
                skipped += 1;
                ("⏭️ ".to_owned(), format!(" (skipped: {reason})"))
            }
        };
        println!("{icon} {} — {}{detail}", result.mechanism, result.detail);
    }
    println!();
    println!("{passed} passed, {failed} failed, {skipped} skipped.");
}
