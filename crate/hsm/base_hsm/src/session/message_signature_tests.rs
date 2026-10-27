//! Tests of the persistent, auto-selected PKCS#11 v3.0 message-signature contexts, against
//! `tests/fixtures/minimal_pkcs11.c` built with `-DWITH_MESSAGE_SIGNATURE` (deterministic
//! stub: signatures are 64 bytes of `0x5A`).

use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{collections::HashMap, ffi::CString, os::raw::c_char, sync::Arc};

#[cfg(unix)]
use cosmian_kms_interfaces::EcCurve;
use cosmian_kms_interfaces::HashingAlgorithm;
use libloading::Library;
use pkcs11_sys::CK_ULONG;
#[cfg(unix)]
use pkcs11_sys::{CK_RV, CKM_ECDSA, CKR_OK};

use crate::{
    HError, HResult, HsmSigningAlgorithm, Session,
    hsm_capabilities::HsmCapabilities,
    hsm_lib::HsmLib,
    test_fixtures::{compile_fixture, fixture_session},
};
#[cfg(unix)]
use crate::{
    RsaKeySize, SlotManager,
    hsm_capabilities::HsmProvider,
    test_helpers::{get_hsm_password, get_hsm_slot_id},
    tests_shared as shared,
};

// Indices of the stub's call counters (see `minimal_pkcs11.c`).
const SIGN_INIT_MSG: usize = 0;
const SIGN_MSG: usize = 1;
const SIGN_FINAL_MSG: usize = 2;
const VERIFY_INIT_MSG: usize = 3;
const VERIFY_MSG: usize = 4;
const VERIFY_FINAL_MSG: usize = 5;
const SIGN_INIT: usize = 6;
const VERIFY_INIT: usize = 7;

const SHA256_RSA: HsmSigningAlgorithm = HsmSigningAlgorithm::Sha256WithRsa;
const STUB_SIGNATURE: [u8; 64] = [0x5A; 64];

/// Compiles the stub and opens the same path a second time: `dlopen` returns the same loaded
/// image, so the counters read through this handle are the ones the `HsmLib` increments.
fn stub() -> HResult<(PathBuf, Library)> {
    let path = compile_fixture("minimal_pkcs11.c", &["-DWITH_MESSAGE_SIGNATURE"])?;
    #[expect(unsafe_code)]
    // SAFETY: loading a freshly compiled test fixture whose initializers are trivial.
    let library = unsafe { Library::new(&path) }
        .map_err(|e| HError::Default(format!("failed to load the stub fixture: {e}")))?;
    Ok((path, library))
}

fn read_counts(library: &Library, symbol: &[u8]) -> HResult<[CK_ULONG; 8]> {
    let mut out = [0; 8];
    #[expect(unsafe_code)]
    // SAFETY: the fixture's counts function writes exactly 8 `CK_ULONG`s into `out`.
    unsafe {
        let f = library
            .get::<unsafe extern "C" fn(*mut CK_ULONG)>(symbol)
            .map_err(|e| HError::Default(format!("missing fixture counts function: {e}")))?;
        f(out.as_mut_ptr());
    }
    Ok(out)
}

fn counts(library: &Library) -> HResult<[CK_ULONG; 8]> {
    read_counts(library, b"fixture_message_counts")
}

fn fail_next(library: &Library, mode: CK_ULONG) -> HResult<()> {
    #[expect(unsafe_code)]
    // SAFETY: `fixture_fail_next_message` only stores its argument.
    unsafe {
        let f = library
            .get::<unsafe extern "C" fn(CK_ULONG)>(b"fixture_fail_next_message")
            .map_err(|e| HError::Default(format!("missing fixture_fail_next_message: {e}")))?;
        f(mode);
    }
    Ok(())
}

fn session(path: &Path, enabled: bool) -> HResult<Session> {
    Ok(fixture_session(
        HsmLib::instantiate(path)?,
        HsmCapabilities {
            supports_message_sign_verify: enabled,
            ..HsmCapabilities::default()
        },
    ))
}

#[test]
fn context_persists_across_signatures() -> HResult<()> {
    let (path, lib) = stub()?;
    let session = session(&path, true)?;
    for _ in 0..3 {
        assert_eq!(session.sign(1, SHA256_RSA, b"m")?, STUB_SIGNATURE);
    }
    let c = counts(&lib)?;
    assert_eq!(
        (
            c[SIGN_INIT_MSG],
            c[SIGN_MSG],
            c[SIGN_FINAL_MSG],
            c[SIGN_INIT]
        ),
        (1, 3, 0, 0)
    );
    Ok(())
}

#[test]
fn key_change_finalizes_previous_context() -> HResult<()> {
    let (path, lib) = stub()?;
    let session = session(&path, true)?;
    session.sign(1, SHA256_RSA, b"m")?;
    session.sign(2, SHA256_RSA, b"m")?;
    let c = counts(&lib)?;
    assert_eq!((c[SIGN_INIT_MSG], c[SIGN_FINAL_MSG]), (2, 1));
    Ok(())
}

#[test]
fn rejected_mechanism_falls_back_and_is_cached() -> HResult<()> {
    let (path, lib) = stub()?;
    let session = session(&path, true)?;
    let ecdsa = HsmSigningAlgorithm::Ecdsa {
        hashing_algorithm: HashingAlgorithm::SHA256,
        prehashed: true,
    };
    session.sign(1, ecdsa, &[0_u8; 32])?;
    session.sign(1, ecdsa, &[0_u8; 32])?;
    let c = counts(&lib)?;
    // The second call skips the message probe: the rejection is cached per slot.
    assert_eq!((c[SIGN_INIT_MSG], c[SIGN_INIT]), (1, 2));
    Ok(())
}

#[test]
fn sign_message_error_ends_context() -> HResult<()> {
    let (path, lib) = stub()?;
    let session = session(&path, true)?;
    fail_next(&lib, 2)?;
    let err = session
        .sign(1, SHA256_RSA, b"m")
        .expect_err("injected CKR_DEVICE_ERROR must fail the signature");
    assert!(err.to_string().contains("Failed to sign message"), "{err}");
    assert_eq!(counts(&lib)?[SIGN_FINAL_MSG], 1);
    session.sign(1, SHA256_RSA, b"m")?;
    assert_eq!(counts(&lib)?[SIGN_INIT_MSG], 2);
    Ok(())
}

#[test]
fn terminated_context_is_reinitialized_once() -> HResult<()> {
    let (path, lib) = stub()?;
    let session = session(&path, true)?;
    session.sign(1, SHA256_RSA, b"m")?;
    fail_next(&lib, 1)?;
    session.sign(1, SHA256_RSA, b"m")?;
    let c = counts(&lib)?;
    assert_eq!((c[SIGN_INIT_MSG], c[SIGN_MSG]), (2, 3));
    Ok(())
}

#[test]
fn verify_uses_message_path() -> HResult<()> {
    let (path, lib) = stub()?;
    let session = session(&path, true)?;
    assert!(session.verify(1, HsmSigningAlgorithm::RsaPkcsV15, b"m", &STUB_SIGNATURE)?);
    assert!(!session.verify(1, HsmSigningAlgorithm::RsaPkcsV15, b"m", &[0_u8; 64])?);
    let c = counts(&lib)?;
    assert_eq!(
        (c[VERIFY_INIT_MSG], c[VERIFY_MSG], c[VERIFY_INIT]),
        (1, 2, 0)
    );
    Ok(())
}

#[test]
fn end_message_operations_closes_both_contexts() -> HResult<()> {
    let (path, lib) = stub()?;
    let session = session(&path, true)?;
    session.sign(1, SHA256_RSA, b"m")?;
    session.verify(1, HsmSigningAlgorithm::RsaPkcsV15, b"m", &STUB_SIGNATURE)?;
    session.end_message_operations();
    let c = counts(&lib)?;
    assert_eq!((c[SIGN_FINAL_MSG], c[VERIFY_FINAL_MSG]), (1, 1));
    session.end_message_operations();
    let c = counts(&lib)?;
    assert_eq!((c[SIGN_FINAL_MSG], c[VERIFY_FINAL_MSG]), (1, 1));
    Ok(())
}

#[test]
fn disabled_flag_keeps_classic_path() -> HResult<()> {
    let (path, lib) = stub()?;
    let session = session(&path, false)?;
    session.sign(1, SHA256_RSA, b"m")?;
    let c = counts(&lib)?;
    assert_eq!((c[SIGN_INIT_MSG], c[SIGN_INIT]), (0, 1));
    Ok(())
}

#[test]
fn public_api_shares_the_context() -> HResult<()> {
    let (path, lib) = stub()?;
    let session = session(&path, true)?;
    session.message_sign_init(1, SHA256_RSA)?;
    session.sign_message(b"m")?;
    // `sign()` reuses the explicitly opened context.
    session.sign(1, SHA256_RSA, b"m")?;
    session.message_sign_final()?;
    let c = counts(&lib)?;
    assert_eq!(
        (c[SIGN_INIT_MSG], c[SIGN_MSG], c[SIGN_FINAL_MSG]),
        (1, 2, 1)
    );
    Ok(())
}

/// Adapter test: real `SoftHSM2` crypto behind the PKCS#11 v3.0 message functions, provided by
/// `tests/fixtures/v3_message_adapter.c`. Run through `mise run test:hsm-softhsm2`.
#[cfg(unix)]
/// The `SoftHSM2` capability profile with the message-signature path enabled.
struct V3AdapterProvider;

#[cfg(unix)]
impl HsmProvider for V3AdapterProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 32,
            supports_aes_sensitive_attribute: true,
            supports_rsa_sensitive_attribute: true,
            supports_ec_sensitive_attribute: true,
            supports_aes_gcm_caller_iv: true,
            supports_aes_gcm_message: false,
            supports_message_sign_verify: true,
            rsa_oaep_requires_source_data_ptr: true,
            max_label_len: None,
            supports_key_dates: false,
            supports_rsa_oaep_key_wrap: false,
            enforces_ecdsa_digest_strength: false,
            max_concurrent_sessions: 128,
        }
    }
}

#[cfg(unix)]
fn adapter_counts(library: &Library) -> HResult<[CK_ULONG; 8]> {
    read_counts(library, b"v3_adapter_counts")
}

#[cfg(unix)]
fn new_id() -> String {
    format!("v3-adapter-{}", uuid::Uuid::new_v4())
}

#[cfg(unix)]
/// Sign then verify (and verify a tampered message) on one session, for each algorithm.
fn sign_verify_round_trips(slot: &Arc<SlotManager>) -> HResult<()> {
    let session = slot.open_session(true)?;
    let data = b"v3 message round trip";
    let check = |sk, pk, algorithm: HsmSigningAlgorithm, data: &[u8]| -> HResult<()> {
        let signature = session.sign(sk, algorithm, data)?;
        assert!(session.verify(pk, algorithm, data, &signature)?);
        assert!(!session.verify(pk, algorithm, b"tampered", &signature)?);
        Ok(())
    };

    let sk_id = new_id();
    let pk_id = sk_id.clone() + "_pk";
    let (sk, pk) = session.generate_rsa_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        RsaKeySize::Rsa2048,
        true,
        None,
    )?;
    check(sk, pk, HsmSigningAlgorithm::Sha256WithRsa, data)?;
    check(
        sk,
        pk,
        HsmSigningAlgorithm::RsaPss {
            hashing_algorithm: HashingAlgorithm::SHA256,
            mask_generator_hashing_algorithm: HashingAlgorithm::SHA256,
            salt_length: None,
            prehashed: false,
        },
        data,
    )?;

    let sk_id = new_id();
    let pk_id = sk_id.clone() + "_pk";
    let (sk, pk) = session.generate_ec_key_pair(
        sk_id.as_bytes(),
        pk_id.as_bytes(),
        EcCurve::P256,
        true,
        None,
    )?;
    // SoftHSM2 has no CKM_ECDSA_SHA256: sign a pre-computed digest with CKM_ECDSA.
    check(
        sk,
        pk,
        HsmSigningAlgorithm::Ecdsa {
            hashing_algorithm: HashingAlgorithm::SHA256,
            prehashed: true,
        },
        &[0x11_u8; 32],
    )?;

    #[cfg(feature = "non-fips")]
    {
        let sk_id = new_id();
        let pk_id = sk_id.clone() + "_pk";
        let (sk, pk) = session.generate_ec_key_pair(
            sk_id.as_bytes(),
            pk_id.as_bytes(),
            EcCurve::Ed25519,
            true,
            None,
        )?;
        check(sk, pk, HsmSigningAlgorithm::Ed25519, data)?;
    }
    Ok(())
}

#[cfg(unix)]
#[test]
#[ignore = "Requires SoftHSM2 and HSM environment (mise run test:hsm-softhsm2)"]
fn softhsm2_v3_adapter_message_signature() -> HResult<()> {
    let extra: &[&str] = if cfg!(target_os = "macos") {
        &[]
    } else {
        &["-ldl", "-lpthread"]
    };
    let adapter = compile_fixture("v3_message_adapter.c", extra)?;
    #[expect(unsafe_code)]
    // SAFETY: loading a freshly compiled test fixture whose initializers are trivial.
    let library = unsafe { Library::new(&adapter) }
        .map_err(|e| HError::Default(format!("failed to load the v3 adapter: {e}")))?;

    let target = shared::lib_path("SOFTHSM2_PKCS11_LIB", "/usr/lib/softhsm/libsofthsm2.so");
    if target.is_empty() {
        return Err(HError::Default(
            "SOFTHSM2_PKCS11_LIB is empty: the adapter needs the SoftHSM2 library path".to_owned(),
        ));
    }
    let target = CString::new(target)
        .map_err(|e| HError::Default(format!("invalid SoftHSM2 library path: {e}")))?;
    #[expect(unsafe_code)]
    // SAFETY: `v3_adapter_set_target` takes a NUL-terminated path and returns a `CK_RV`.
    let rv = unsafe {
        let f = library
            .get::<unsafe extern "C" fn(*const c_char) -> CK_RV>(b"v3_adapter_set_target")
            .map_err(|e| HError::Default(format!("missing v3_adapter_set_target: {e}")))?;
        f(target.as_ptr())
    };
    if rv != CKR_OK {
        return Err(HError::Default(format!(
            "the v3 adapter could not load SoftHSM2 ({target:?}): return code {rv}"
        )));
    }

    let slot_id = get_hsm_slot_id()?;
    let cfg = shared::HsmTestConfig {
        lib_path: adapter.to_string_lossy().into_owned(),
        slot_ids_and_passwords: HashMap::from([(slot_id, Some(get_hsm_password()?))]),
        slot_id_for_tests: slot_id,
        threads: 4,
    };
    let hsm = shared::instantiate::<V3AdapterProvider>(&cfg)?;
    assert!(hsm.hsm_lib().supports_message_sign() && hsm.hsm_lib().supports_message_verify());
    let slot = shared::get_slot::<V3AdapterProvider>(&hsm, &cfg)?;

    shared::destroy_all(&slot)?;
    shared::rsa_pkcs_v15_sign(&slot)?;
    shared::rsa_sha256_sign(&slot)?;
    shared::rsa_sign_all_algorithms(&slot)?;
    shared::rsa_pss_sign_all_algorithms(&slot)?;
    shared::ecdsa_sign_all_curves_and_hashes(&slot)?;
    #[cfg(feature = "non-fips")]
    shared::eddsa_sign_all_curves(&slot)?;
    shared::concurrent_sign_does_not_degrade(&slot)?;
    sign_verify_round_trips(&slot)?;

    // Every signature went through the message path, with persistent contexts.
    let c = adapter_counts(&library)?;
    assert!(c[SIGN_INIT_MSG] > 0, "no C_MessageSignInit: {c:?}");
    assert!(c[SIGN_MSG] > c[SIGN_INIT_MSG], "contexts not reused: {c:?}");
    assert_eq!(c[SIGN_INIT], 0, "classic C_SignInit used: {c:?}");
    assert!(c[VERIFY_MSG] > 0, "no C_VerifyMessage: {c:?}");
    assert_eq!(c[VERIFY_INIT], 0, "classic C_VerifyInit used: {c:?}");

    // A mechanism the token rejects at message init: one probe, then classic calls.
    let before = c;
    let rejected: [CK_ULONG; 1] = [CKM_ECDSA];
    #[expect(unsafe_code)]
    // SAFETY: `v3_adapter_set_rejected` copies `n` mechanism types from the pointer.
    unsafe {
        let f = library
            .get::<unsafe extern "C" fn(*const CK_ULONG, CK_ULONG)>(b"v3_adapter_set_rejected")
            .map_err(|e| HError::Default(format!("missing v3_adapter_set_rejected: {e}")))?;
        f(rejected.as_ptr(), 1);
    }
    {
        let session = slot.open_session(true)?;
        let sk_id = new_id();
        let pk_id = sk_id.clone() + "_pk";
        let (sk, pk) = session.generate_ec_key_pair(
            sk_id.as_bytes(),
            pk_id.as_bytes(),
            EcCurve::P256,
            true,
            None,
        )?;
        // SoftHSM2 has no CKM_ECDSA_SHA256: sign a pre-computed digest with CKM_ECDSA.
        let ecdsa = HsmSigningAlgorithm::Ecdsa {
            hashing_algorithm: HashingAlgorithm::SHA256,
            prehashed: true,
        };
        let digest = [0x11_u8; 32];
        for _ in 0..2 {
            let signature = session.sign(sk, ecdsa, &digest)?;
            assert!(session.verify(pk, ecdsa, &digest, &signature)?);
        }
    }
    let after = adapter_counts(&library)?;
    let delta = |i: usize| after[i] - before[i];
    assert_eq!(delta(SIGN_INIT_MSG), 1, "{before:?} -> {after:?}");
    assert_eq!(delta(SIGN_INIT), 2, "{before:?} -> {after:?}");
    assert_eq!(delta(VERIFY_INIT_MSG), 1, "{before:?} -> {after:?}");
    assert_eq!(delta(VERIFY_INIT), 2, "{before:?} -> {after:?}");

    shared::destroy_all(&slot)?;
    // `SlotManager` is `Arc`-shared; keep `hsm` alive until here.
    drop(hsm);
    Ok(())
}
