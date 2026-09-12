//! PKCS#11 v3.0/v3.1-specific conformance tests for `cosmian_pkcs11_module`.
//!
//! Per explicit project direction, PKCS#11 v2.40-era baseline tests (init, slot/token/session
//! lifecycle, object find/fallback — see `tests.rs`) must never be mixed with PKCS#11
//! v3.0/v3.1-specific conformance tests in the same file. This module is the sibling home for
//! the latter: `to_ck_key_type()`/`KeyAlgorithm` regression tests and the "not supported"
//! function-stub conformance table.

use pkcs11_sys::{
    CKK_AES, CKK_EC, CKK_EC_EDWARDS, CKK_EC_MONTGOMERY, CKK_RSA, CKR_FUNCTION_NOT_SUPPORTED,
};

use crate::{
    pkcs11::{
        C_CopyObject, C_DecryptDigestUpdate, C_DecryptMessage, C_DecryptMessageBegin,
        C_DecryptMessageNext, C_DecryptVerifyUpdate, C_DeriveKey, C_Digest, C_DigestEncryptUpdate,
        C_DigestFinal, C_DigestInit, C_DigestKey, C_DigestUpdate, C_EncryptFinal, C_EncryptMessage,
        C_EncryptMessageBegin, C_EncryptMessageNext, C_EncryptUpdate, C_GenerateKeyPair,
        C_GetObjectSize, C_GetOperationState, C_MessageDecryptFinal, C_MessageDecryptInit,
        C_MessageEncryptFinal, C_MessageEncryptInit, C_MessageVerifyFinal, C_MessageVerifyInit,
        C_SessionCancel, C_SetOperationState, C_SignEncryptUpdate, C_SignMessageBegin,
        C_SignMessageNext, C_SignRecover, C_SignRecoverInit, C_UnwrapKey, C_VerifyMessage,
        C_VerifyMessageBegin, C_VerifyMessageNext, C_VerifyRecover, C_VerifyRecoverInit,
        C_WaitForSlotEvent, C_WrapKey,
    },
    traits::KeyAlgorithm,
};

/// Regression test for issue #1183: PKCS#11 v2.40+ requires Edwards-curve
/// (Ed25519/Ed448) and Montgomery-curve (X25519/X448) keys to be reported with the
/// dedicated `CKK_EC_EDWARDS`/`CKK_EC_MONTGOMERY` key types, distinct from the
/// generic `CKK_EC` used by NIST/SECG curves (P-256/P-384/P-521/secp256k1/secp224k1).
/// Before the fix, all EC-family keys — including Ed25519/Ed448 — were reported as
/// plain `CKK_EC`, which made `CKA_KEY_TYPE`-aware clients such as `OpenSC`'s
/// `pkcs11-tool --mechanism EDDSA` fail to find Ed25519/Ed448 keys.
#[test]
fn test_to_ck_key_type_reports_distinct_types_per_curve_family() {
    assert_eq!(KeyAlgorithm::Aes256.to_ck_key_type(), CKK_AES);
    assert_eq!(KeyAlgorithm::Rsa.to_ck_key_type(), CKK_RSA);

    for nist_secg in [
        KeyAlgorithm::EccP256,
        KeyAlgorithm::EccP384,
        KeyAlgorithm::EccP521,
        KeyAlgorithm::Secp224k1,
        KeyAlgorithm::Secp256k1,
    ] {
        assert_eq!(
            nist_secg.to_ck_key_type(),
            CKK_EC,
            "{nist_secg:?} must report CKK_EC"
        );
    }

    for edwards in [KeyAlgorithm::Ed25519, KeyAlgorithm::Ed448] {
        assert_eq!(
            edwards.to_ck_key_type(),
            CKK_EC_EDWARDS,
            "{edwards:?} must report CKK_EC_EDWARDS, not CKK_EC"
        );
    }

    for montgomery in [KeyAlgorithm::X25519, KeyAlgorithm::X448] {
        assert_eq!(
            montgomery.to_ck_key_type(),
            CKK_EC_MONTGOMERY,
            "{montgomery:?} must report CKK_EC_MONTGOMERY, not CKK_EC"
        );
    }
}

/// PKCS#11 v3.0 conformance requirement (§5.2): every function pointer declared in the
/// `CK_FUNCTION_LIST_3_0` slot table must be non-null, even for functions this module does not
/// implement (recoverable-signature operations, key wrap/unwrap/derive, digest, message-based
/// bulk crypto, operation state save/restore, `C_CopyObject`/`C_GetObjectSize`,
/// `C_WaitForSlotEvent`). A non-null pointer alone is not sufficient: calling it must return
/// exactly `CKR_FUNCTION_NOT_SUPPORTED`, never crash, never silently succeed (`CKR_OK`), and
/// never return an unrelated error code. All of these `#[unsafe(no_mangle)] pub extern "C" fn`
/// stubs ignore their arguments and return immediately, so calling them with null/zeroed
/// arguments is safe and exercises the exact conformance contract.
#[test]
fn test_unsupported_functions_return_function_not_supported() {
    use std::ptr::null_mut;

    assert_eq!(
        C_GetOperationState(0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_SetOperationState(0, null_mut(), 0, 0, 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_CopyObject(0, 0, null_mut(), 0, null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_GetObjectSize(0, 0, null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_EncryptUpdate(0, null_mut(), 0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_EncryptFinal(0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(C_DigestInit(0, null_mut()), CKR_FUNCTION_NOT_SUPPORTED);
    assert_eq!(
        C_Digest(0, null_mut(), 0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(C_DigestUpdate(0, null_mut(), 0), CKR_FUNCTION_NOT_SUPPORTED);
    assert_eq!(C_DigestKey(0, 0), CKR_FUNCTION_NOT_SUPPORTED);
    assert_eq!(
        C_DigestFinal(0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_SignRecoverInit(0, null_mut(), 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_SignRecover(0, null_mut(), 0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_VerifyRecoverInit(0, null_mut(), 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_VerifyRecover(0, null_mut(), 0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_DigestEncryptUpdate(0, null_mut(), 0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_DecryptDigestUpdate(0, null_mut(), 0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_SignEncryptUpdate(0, null_mut(), 0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_DecryptVerifyUpdate(0, null_mut(), 0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_GenerateKeyPair(
            0,
            null_mut(),
            null_mut(),
            0,
            null_mut(),
            0,
            null_mut(),
            null_mut()
        ),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_WrapKey(0, null_mut(), 0, 0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_UnwrapKey(0, null_mut(), 0, null_mut(), 0, null_mut(), 0, null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_DeriveKey(0, null_mut(), 0, null_mut(), 0, null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_WaitForSlotEvent(0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(C_SessionCancel(0, 0), CKR_FUNCTION_NOT_SUPPORTED);

    // Unsupported v3.0 message-based bulk crypto functions remain conformant
    // non-null stubs. One-shot EdDSA message signing
    // (`C_MessageSignInit`/`C_SignMessage`/`C_MessageSignFinal`) is implemented
    // and tested separately.
    assert_eq!(
        C_MessageEncryptInit(0, null_mut(), 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_EncryptMessage(
            0,
            null_mut(),
            0,
            null_mut(),
            0,
            null_mut(),
            0,
            null_mut(),
            null_mut()
        ),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_EncryptMessageBegin(0, null_mut(), 0, null_mut(), 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_EncryptMessageNext(0, null_mut(), 0, null_mut(), 0, null_mut(), null_mut(), 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(C_MessageEncryptFinal(0), CKR_FUNCTION_NOT_SUPPORTED);
    assert_eq!(
        C_MessageDecryptInit(0, null_mut(), 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_DecryptMessage(
            0,
            null_mut(),
            0,
            null_mut(),
            0,
            null_mut(),
            0,
            null_mut(),
            null_mut()
        ),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_DecryptMessageBegin(0, null_mut(), 0, null_mut(), 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_DecryptMessageNext(0, null_mut(), 0, null_mut(), 0, null_mut(), null_mut(), 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(C_MessageDecryptFinal(0), CKR_FUNCTION_NOT_SUPPORTED);
    assert_eq!(
        C_SignMessageBegin(0, null_mut(), 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_SignMessageNext(0, null_mut(), 0, null_mut(), 0, null_mut(), null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_MessageVerifyInit(0, null_mut(), 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_VerifyMessage(0, null_mut(), 0, null_mut(), 0, null_mut(), 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_VerifyMessageBegin(0, null_mut(), 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(
        C_VerifyMessageNext(0, null_mut(), 0, null_mut(), 0, null_mut(), 0),
        CKR_FUNCTION_NOT_SUPPORTED
    );
    assert_eq!(C_MessageVerifyFinal(0), CKR_FUNCTION_NOT_SUPPORTED);
}
