//! Exhaustive PKCS#11 v2/v3 conformance report for `ckms pkcs11 capabilities`.
//!
//! Unlike `ckms pkcs11 verify` (session/discovery-level API sequence only), this
//! command reports on the **entire** PKCS#11 surface `pkcs11-sys` v0.2.25 defines:
//! all 442 real `CKM_*` mechanisms (`CKM_VENDOR_DEFINED` excluded — a range-marker
//! sentinel, not an operation) and all 92 `C_*` functions in `CK_FUNCTION_LIST_3_0`.
//! Two independent report sections are printed, each with its own summary line:
//!
//! - **"PKCS#11 mechanism coverage"**: the ~12 mechanisms `cosmian_pkcs11` actually
//!   advertises are deep-tested end to end (key generation, encryption/decryption,
//!   signing/verification, across every provisioned curve); every other mechanism
//!   is probed via `C_GetMechanismInfo` alone (`CKR_MECHANISM_INVALID` ⇒ ❌ not
//!   implemented).
//! - **"PKCS#11 API function coverage"**: functions already exercised for real
//!   elsewhere (bootstrap, session lifecycle, object lookup, the deep mechanism
//!   checks) are reported by reuse; three destructive/authentication-changing
//!   functions (`C_InitToken`/`C_InitPIN`/`C_SetPIN`) are never invoked (⬛
//!   excluded — deliberately not probed, so their real support status is
//!   unknown, unlike a genuine ❌ not-implemented finding); the remainder get one
//!   real, minimal-precondition shallow probe each.
//!
//! Every row is always printed individually (all 442 mechanisms, all 92
//! functions): the whole point of this report is to show exactly what is and is
//! not supported, so nothing is collapsed or hidden by default. A real, attempted
//! operation that failed (❌ Fail) and a mechanism/function the provider simply
//! does not implement (❌ `NotImplemented`) are both rendered as a red cross, since
//! from the caller's perspective both mean "you cannot use this" — the report's
//! trailing summary line still tracks them as separate counts for diagnostics.
//!
//! `C_GenerateKeyPair` is not implemented by this provider (asymmetric keys are
//! provisioned through the KMS REST API, not PKCS#11), so RSA/EC/Ed25519/Ed448 key
//! pairs are created via [`KmsClient`] first, then located on the PKCS#11 slot by
//! their `CKA_ID` (which the provider always sets to the KMIP unique identifier —
//! see `crate/clients/pkcs11/module/src/core/object.rs`). Only the AES secret key
//! is generated live via `C_GenerateKey`/`CKM_AES_KEY_GEN`.

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
// A glob import is used (rather than an itemized list) because this module needs
// the *entire* `CKM_*` mechanism universe (442 constants) and the full `CK_*`
// function-pointer/struct surface for the exhaustive coverage report — see
// `plan.md` (Decision 1) for why an itemized list is impractical here.
#[allow(clippy::wildcard_imports)]
use pkcs11_sys::*;

use super::verify::{
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

/// All 442 real PKCS#11 `CKM_*` mechanisms defined by `pkcs11-sys` v0.2.25,
/// excluding `CKM_VENDOR_DEFINED` (a non-mechanism range-marker sentinel, not a
/// real operation). Generated from `pkcs11-sys`'s `CKM_*` constant list; see
/// `plan.md` for provenance. Order matches declaration order in `pkcs11-sys`.
const ALL_MECHANISMS: &[(&str, CK_MECHANISM_TYPE)] = &[
    ("CKM_RSA_PKCS_KEY_PAIR_GEN", CKM_RSA_PKCS_KEY_PAIR_GEN),
    ("CKM_RSA_PKCS", CKM_RSA_PKCS),
    ("CKM_RSA_9796", CKM_RSA_9796),
    ("CKM_RSA_X_509", CKM_RSA_X_509),
    ("CKM_MD2_RSA_PKCS", CKM_MD2_RSA_PKCS),
    ("CKM_MD5_RSA_PKCS", CKM_MD5_RSA_PKCS),
    ("CKM_SHA1_RSA_PKCS", CKM_SHA1_RSA_PKCS),
    ("CKM_RIPEMD128_RSA_PKCS", CKM_RIPEMD128_RSA_PKCS),
    ("CKM_RIPEMD160_RSA_PKCS", CKM_RIPEMD160_RSA_PKCS),
    ("CKM_RSA_PKCS_OAEP", CKM_RSA_PKCS_OAEP),
    ("CKM_RSA_X9_31_KEY_PAIR_GEN", CKM_RSA_X9_31_KEY_PAIR_GEN),
    ("CKM_RSA_X9_31", CKM_RSA_X9_31),
    ("CKM_SHA1_RSA_X9_31", CKM_SHA1_RSA_X9_31),
    ("CKM_RSA_PKCS_PSS", CKM_RSA_PKCS_PSS),
    ("CKM_SHA1_RSA_PKCS_PSS", CKM_SHA1_RSA_PKCS_PSS),
    ("CKM_DSA_KEY_PAIR_GEN", CKM_DSA_KEY_PAIR_GEN),
    ("CKM_DSA", CKM_DSA),
    ("CKM_DSA_SHA1", CKM_DSA_SHA1),
    ("CKM_DSA_SHA224", CKM_DSA_SHA224),
    ("CKM_DSA_SHA256", CKM_DSA_SHA256),
    ("CKM_DSA_SHA384", CKM_DSA_SHA384),
    ("CKM_DSA_SHA512", CKM_DSA_SHA512),
    ("CKM_DSA_SHA3_224", CKM_DSA_SHA3_224),
    ("CKM_DSA_SHA3_256", CKM_DSA_SHA3_256),
    ("CKM_DSA_SHA3_384", CKM_DSA_SHA3_384),
    ("CKM_DSA_SHA3_512", CKM_DSA_SHA3_512),
    ("CKM_DH_PKCS_KEY_PAIR_GEN", CKM_DH_PKCS_KEY_PAIR_GEN),
    ("CKM_DH_PKCS_DERIVE", CKM_DH_PKCS_DERIVE),
    ("CKM_X9_42_DH_KEY_PAIR_GEN", CKM_X9_42_DH_KEY_PAIR_GEN),
    ("CKM_X9_42_DH_DERIVE", CKM_X9_42_DH_DERIVE),
    ("CKM_X9_42_DH_HYBRID_DERIVE", CKM_X9_42_DH_HYBRID_DERIVE),
    ("CKM_X9_42_MQV_DERIVE", CKM_X9_42_MQV_DERIVE),
    ("CKM_SHA256_RSA_PKCS", CKM_SHA256_RSA_PKCS),
    ("CKM_SHA384_RSA_PKCS", CKM_SHA384_RSA_PKCS),
    ("CKM_SHA512_RSA_PKCS", CKM_SHA512_RSA_PKCS),
    ("CKM_SHA256_RSA_PKCS_PSS", CKM_SHA256_RSA_PKCS_PSS),
    ("CKM_SHA384_RSA_PKCS_PSS", CKM_SHA384_RSA_PKCS_PSS),
    ("CKM_SHA512_RSA_PKCS_PSS", CKM_SHA512_RSA_PKCS_PSS),
    ("CKM_SHA224_RSA_PKCS", CKM_SHA224_RSA_PKCS),
    ("CKM_SHA224_RSA_PKCS_PSS", CKM_SHA224_RSA_PKCS_PSS),
    ("CKM_SHA512_224", CKM_SHA512_224),
    ("CKM_SHA512_224_HMAC", CKM_SHA512_224_HMAC),
    ("CKM_SHA512_224_HMAC_GENERAL", CKM_SHA512_224_HMAC_GENERAL),
    (
        "CKM_SHA512_224_KEY_DERIVATION",
        CKM_SHA512_224_KEY_DERIVATION,
    ),
    ("CKM_SHA512_256", CKM_SHA512_256),
    ("CKM_SHA512_256_HMAC", CKM_SHA512_256_HMAC),
    ("CKM_SHA512_256_HMAC_GENERAL", CKM_SHA512_256_HMAC_GENERAL),
    (
        "CKM_SHA512_256_KEY_DERIVATION",
        CKM_SHA512_256_KEY_DERIVATION,
    ),
    ("CKM_SHA512_T", CKM_SHA512_T),
    ("CKM_SHA512_T_HMAC", CKM_SHA512_T_HMAC),
    ("CKM_SHA512_T_HMAC_GENERAL", CKM_SHA512_T_HMAC_GENERAL),
    ("CKM_SHA512_T_KEY_DERIVATION", CKM_SHA512_T_KEY_DERIVATION),
    ("CKM_SHA3_256_RSA_PKCS", CKM_SHA3_256_RSA_PKCS),
    ("CKM_SHA3_384_RSA_PKCS", CKM_SHA3_384_RSA_PKCS),
    ("CKM_SHA3_512_RSA_PKCS", CKM_SHA3_512_RSA_PKCS),
    ("CKM_SHA3_256_RSA_PKCS_PSS", CKM_SHA3_256_RSA_PKCS_PSS),
    ("CKM_SHA3_384_RSA_PKCS_PSS", CKM_SHA3_384_RSA_PKCS_PSS),
    ("CKM_SHA3_512_RSA_PKCS_PSS", CKM_SHA3_512_RSA_PKCS_PSS),
    ("CKM_SHA3_224_RSA_PKCS", CKM_SHA3_224_RSA_PKCS),
    ("CKM_SHA3_224_RSA_PKCS_PSS", CKM_SHA3_224_RSA_PKCS_PSS),
    ("CKM_RC2_KEY_GEN", CKM_RC2_KEY_GEN),
    ("CKM_RC2_ECB", CKM_RC2_ECB),
    ("CKM_RC2_CBC", CKM_RC2_CBC),
    ("CKM_RC2_MAC", CKM_RC2_MAC),
    ("CKM_RC2_MAC_GENERAL", CKM_RC2_MAC_GENERAL),
    ("CKM_RC2_CBC_PAD", CKM_RC2_CBC_PAD),
    ("CKM_RC4_KEY_GEN", CKM_RC4_KEY_GEN),
    ("CKM_RC4", CKM_RC4),
    ("CKM_DES_KEY_GEN", CKM_DES_KEY_GEN),
    ("CKM_DES_ECB", CKM_DES_ECB),
    ("CKM_DES_CBC", CKM_DES_CBC),
    ("CKM_DES_MAC", CKM_DES_MAC),
    ("CKM_DES_MAC_GENERAL", CKM_DES_MAC_GENERAL),
    ("CKM_DES_CBC_PAD", CKM_DES_CBC_PAD),
    ("CKM_DES2_KEY_GEN", CKM_DES2_KEY_GEN),
    ("CKM_DES3_KEY_GEN", CKM_DES3_KEY_GEN),
    ("CKM_DES3_ECB", CKM_DES3_ECB),
    ("CKM_DES3_CBC", CKM_DES3_CBC),
    ("CKM_DES3_MAC", CKM_DES3_MAC),
    ("CKM_DES3_MAC_GENERAL", CKM_DES3_MAC_GENERAL),
    ("CKM_DES3_CBC_PAD", CKM_DES3_CBC_PAD),
    ("CKM_DES3_CMAC_GENERAL", CKM_DES3_CMAC_GENERAL),
    ("CKM_DES3_CMAC", CKM_DES3_CMAC),
    ("CKM_CDMF_KEY_GEN", CKM_CDMF_KEY_GEN),
    ("CKM_CDMF_ECB", CKM_CDMF_ECB),
    ("CKM_CDMF_CBC", CKM_CDMF_CBC),
    ("CKM_CDMF_MAC", CKM_CDMF_MAC),
    ("CKM_CDMF_MAC_GENERAL", CKM_CDMF_MAC_GENERAL),
    ("CKM_CDMF_CBC_PAD", CKM_CDMF_CBC_PAD),
    ("CKM_DES_OFB64", CKM_DES_OFB64),
    ("CKM_DES_OFB8", CKM_DES_OFB8),
    ("CKM_DES_CFB64", CKM_DES_CFB64),
    ("CKM_DES_CFB8", CKM_DES_CFB8),
    ("CKM_MD2", CKM_MD2),
    ("CKM_MD2_HMAC", CKM_MD2_HMAC),
    ("CKM_MD2_HMAC_GENERAL", CKM_MD2_HMAC_GENERAL),
    ("CKM_MD5", CKM_MD5),
    ("CKM_MD5_HMAC", CKM_MD5_HMAC),
    ("CKM_MD5_HMAC_GENERAL", CKM_MD5_HMAC_GENERAL),
    ("CKM_SHA_1", CKM_SHA_1),
    ("CKM_SHA_1_HMAC", CKM_SHA_1_HMAC),
    ("CKM_SHA_1_HMAC_GENERAL", CKM_SHA_1_HMAC_GENERAL),
    ("CKM_RIPEMD128", CKM_RIPEMD128),
    ("CKM_RIPEMD128_HMAC", CKM_RIPEMD128_HMAC),
    ("CKM_RIPEMD128_HMAC_GENERAL", CKM_RIPEMD128_HMAC_GENERAL),
    ("CKM_RIPEMD160", CKM_RIPEMD160),
    ("CKM_RIPEMD160_HMAC", CKM_RIPEMD160_HMAC),
    ("CKM_RIPEMD160_HMAC_GENERAL", CKM_RIPEMD160_HMAC_GENERAL),
    ("CKM_SHA256", CKM_SHA256),
    ("CKM_SHA256_HMAC", CKM_SHA256_HMAC),
    ("CKM_SHA256_HMAC_GENERAL", CKM_SHA256_HMAC_GENERAL),
    ("CKM_SHA224", CKM_SHA224),
    ("CKM_SHA224_HMAC", CKM_SHA224_HMAC),
    ("CKM_SHA224_HMAC_GENERAL", CKM_SHA224_HMAC_GENERAL),
    ("CKM_SHA384", CKM_SHA384),
    ("CKM_SHA384_HMAC", CKM_SHA384_HMAC),
    ("CKM_SHA384_HMAC_GENERAL", CKM_SHA384_HMAC_GENERAL),
    ("CKM_SHA512", CKM_SHA512),
    ("CKM_SHA512_HMAC", CKM_SHA512_HMAC),
    ("CKM_SHA512_HMAC_GENERAL", CKM_SHA512_HMAC_GENERAL),
    ("CKM_SECURID_KEY_GEN", CKM_SECURID_KEY_GEN),
    ("CKM_SECURID", CKM_SECURID),
    ("CKM_HOTP_KEY_GEN", CKM_HOTP_KEY_GEN),
    ("CKM_HOTP", CKM_HOTP),
    ("CKM_ACTI", CKM_ACTI),
    ("CKM_ACTI_KEY_GEN", CKM_ACTI_KEY_GEN),
    ("CKM_SHA3_256", CKM_SHA3_256),
    ("CKM_SHA3_256_HMAC", CKM_SHA3_256_HMAC),
    ("CKM_SHA3_256_HMAC_GENERAL", CKM_SHA3_256_HMAC_GENERAL),
    ("CKM_SHA3_256_KEY_GEN", CKM_SHA3_256_KEY_GEN),
    ("CKM_SHA3_224", CKM_SHA3_224),
    ("CKM_SHA3_224_HMAC", CKM_SHA3_224_HMAC),
    ("CKM_SHA3_224_HMAC_GENERAL", CKM_SHA3_224_HMAC_GENERAL),
    ("CKM_SHA3_224_KEY_GEN", CKM_SHA3_224_KEY_GEN),
    ("CKM_SHA3_384", CKM_SHA3_384),
    ("CKM_SHA3_384_HMAC", CKM_SHA3_384_HMAC),
    ("CKM_SHA3_384_HMAC_GENERAL", CKM_SHA3_384_HMAC_GENERAL),
    ("CKM_SHA3_384_KEY_GEN", CKM_SHA3_384_KEY_GEN),
    ("CKM_SHA3_512", CKM_SHA3_512),
    ("CKM_SHA3_512_HMAC", CKM_SHA3_512_HMAC),
    ("CKM_SHA3_512_HMAC_GENERAL", CKM_SHA3_512_HMAC_GENERAL),
    ("CKM_SHA3_512_KEY_GEN", CKM_SHA3_512_KEY_GEN),
    ("CKM_CAST_KEY_GEN", CKM_CAST_KEY_GEN),
    ("CKM_CAST_ECB", CKM_CAST_ECB),
    ("CKM_CAST_CBC", CKM_CAST_CBC),
    ("CKM_CAST_MAC", CKM_CAST_MAC),
    ("CKM_CAST_MAC_GENERAL", CKM_CAST_MAC_GENERAL),
    ("CKM_CAST_CBC_PAD", CKM_CAST_CBC_PAD),
    ("CKM_CAST3_KEY_GEN", CKM_CAST3_KEY_GEN),
    ("CKM_CAST3_ECB", CKM_CAST3_ECB),
    ("CKM_CAST3_CBC", CKM_CAST3_CBC),
    ("CKM_CAST3_MAC", CKM_CAST3_MAC),
    ("CKM_CAST3_MAC_GENERAL", CKM_CAST3_MAC_GENERAL),
    ("CKM_CAST3_CBC_PAD", CKM_CAST3_CBC_PAD),
    ("CKM_CAST5_KEY_GEN", CKM_CAST5_KEY_GEN),
    ("CKM_CAST128_KEY_GEN", CKM_CAST128_KEY_GEN),
    ("CKM_CAST5_ECB", CKM_CAST5_ECB),
    ("CKM_CAST128_ECB", CKM_CAST128_ECB),
    ("CKM_CAST5_CBC", CKM_CAST5_CBC),
    ("CKM_CAST128_CBC", CKM_CAST128_CBC),
    ("CKM_CAST5_MAC", CKM_CAST5_MAC),
    ("CKM_CAST128_MAC", CKM_CAST128_MAC),
    ("CKM_CAST5_MAC_GENERAL", CKM_CAST5_MAC_GENERAL),
    ("CKM_CAST128_MAC_GENERAL", CKM_CAST128_MAC_GENERAL),
    ("CKM_CAST5_CBC_PAD", CKM_CAST5_CBC_PAD),
    ("CKM_CAST128_CBC_PAD", CKM_CAST128_CBC_PAD),
    ("CKM_RC5_KEY_GEN", CKM_RC5_KEY_GEN),
    ("CKM_RC5_ECB", CKM_RC5_ECB),
    ("CKM_RC5_CBC", CKM_RC5_CBC),
    ("CKM_RC5_MAC", CKM_RC5_MAC),
    ("CKM_RC5_MAC_GENERAL", CKM_RC5_MAC_GENERAL),
    ("CKM_RC5_CBC_PAD", CKM_RC5_CBC_PAD),
    ("CKM_IDEA_KEY_GEN", CKM_IDEA_KEY_GEN),
    ("CKM_IDEA_ECB", CKM_IDEA_ECB),
    ("CKM_IDEA_CBC", CKM_IDEA_CBC),
    ("CKM_IDEA_MAC", CKM_IDEA_MAC),
    ("CKM_IDEA_MAC_GENERAL", CKM_IDEA_MAC_GENERAL),
    ("CKM_IDEA_CBC_PAD", CKM_IDEA_CBC_PAD),
    ("CKM_GENERIC_SECRET_KEY_GEN", CKM_GENERIC_SECRET_KEY_GEN),
    ("CKM_CONCATENATE_BASE_AND_KEY", CKM_CONCATENATE_BASE_AND_KEY),
    (
        "CKM_CONCATENATE_BASE_AND_DATA",
        CKM_CONCATENATE_BASE_AND_DATA,
    ),
    (
        "CKM_CONCATENATE_DATA_AND_BASE",
        CKM_CONCATENATE_DATA_AND_BASE,
    ),
    ("CKM_XOR_BASE_AND_DATA", CKM_XOR_BASE_AND_DATA),
    ("CKM_EXTRACT_KEY_FROM_KEY", CKM_EXTRACT_KEY_FROM_KEY),
    ("CKM_SSL3_PRE_MASTER_KEY_GEN", CKM_SSL3_PRE_MASTER_KEY_GEN),
    ("CKM_SSL3_MASTER_KEY_DERIVE", CKM_SSL3_MASTER_KEY_DERIVE),
    ("CKM_SSL3_KEY_AND_MAC_DERIVE", CKM_SSL3_KEY_AND_MAC_DERIVE),
    (
        "CKM_SSL3_MASTER_KEY_DERIVE_DH",
        CKM_SSL3_MASTER_KEY_DERIVE_DH,
    ),
    ("CKM_TLS_PRE_MASTER_KEY_GEN", CKM_TLS_PRE_MASTER_KEY_GEN),
    ("CKM_TLS_MASTER_KEY_DERIVE", CKM_TLS_MASTER_KEY_DERIVE),
    ("CKM_TLS_KEY_AND_MAC_DERIVE", CKM_TLS_KEY_AND_MAC_DERIVE),
    ("CKM_TLS_MASTER_KEY_DERIVE_DH", CKM_TLS_MASTER_KEY_DERIVE_DH),
    ("CKM_TLS_PRF", CKM_TLS_PRF),
    ("CKM_SSL3_MD5_MAC", CKM_SSL3_MD5_MAC),
    ("CKM_SSL3_SHA1_MAC", CKM_SSL3_SHA1_MAC),
    ("CKM_MD5_KEY_DERIVATION", CKM_MD5_KEY_DERIVATION),
    ("CKM_MD2_KEY_DERIVATION", CKM_MD2_KEY_DERIVATION),
    ("CKM_SHA1_KEY_DERIVATION", CKM_SHA1_KEY_DERIVATION),
    ("CKM_SHA256_KEY_DERIVATION", CKM_SHA256_KEY_DERIVATION),
    ("CKM_SHA384_KEY_DERIVATION", CKM_SHA384_KEY_DERIVATION),
    ("CKM_SHA512_KEY_DERIVATION", CKM_SHA512_KEY_DERIVATION),
    ("CKM_SHA224_KEY_DERIVATION", CKM_SHA224_KEY_DERIVATION),
    ("CKM_SHA3_256_KEY_DERIVATION", CKM_SHA3_256_KEY_DERIVATION),
    ("CKM_SHA3_224_KEY_DERIVATION", CKM_SHA3_224_KEY_DERIVATION),
    ("CKM_SHA3_384_KEY_DERIVATION", CKM_SHA3_384_KEY_DERIVATION),
    ("CKM_SHA3_512_KEY_DERIVATION", CKM_SHA3_512_KEY_DERIVATION),
    ("CKM_SHAKE_128_KEY_DERIVATION", CKM_SHAKE_128_KEY_DERIVATION),
    ("CKM_SHAKE_256_KEY_DERIVATION", CKM_SHAKE_256_KEY_DERIVATION),
    ("CKM_SHA3_256_KEY_DERIVE", CKM_SHA3_256_KEY_DERIVE),
    ("CKM_SHA3_224_KEY_DERIVE", CKM_SHA3_224_KEY_DERIVE),
    ("CKM_SHA3_384_KEY_DERIVE", CKM_SHA3_384_KEY_DERIVE),
    ("CKM_SHA3_512_KEY_DERIVE", CKM_SHA3_512_KEY_DERIVE),
    ("CKM_SHAKE_128_KEY_DERIVE", CKM_SHAKE_128_KEY_DERIVE),
    ("CKM_SHAKE_256_KEY_DERIVE", CKM_SHAKE_256_KEY_DERIVE),
    ("CKM_PBE_MD2_DES_CBC", CKM_PBE_MD2_DES_CBC),
    ("CKM_PBE_MD5_DES_CBC", CKM_PBE_MD5_DES_CBC),
    ("CKM_PBE_MD5_CAST_CBC", CKM_PBE_MD5_CAST_CBC),
    ("CKM_PBE_MD5_CAST3_CBC", CKM_PBE_MD5_CAST3_CBC),
    ("CKM_PBE_MD5_CAST5_CBC", CKM_PBE_MD5_CAST5_CBC),
    ("CKM_PBE_MD5_CAST128_CBC", CKM_PBE_MD5_CAST128_CBC),
    ("CKM_PBE_SHA1_CAST5_CBC", CKM_PBE_SHA1_CAST5_CBC),
    ("CKM_PBE_SHA1_CAST128_CBC", CKM_PBE_SHA1_CAST128_CBC),
    ("CKM_PBE_SHA1_RC4_128", CKM_PBE_SHA1_RC4_128),
    ("CKM_PBE_SHA1_RC4_40", CKM_PBE_SHA1_RC4_40),
    ("CKM_PBE_SHA1_DES3_EDE_CBC", CKM_PBE_SHA1_DES3_EDE_CBC),
    ("CKM_PBE_SHA1_DES2_EDE_CBC", CKM_PBE_SHA1_DES2_EDE_CBC),
    ("CKM_PBE_SHA1_RC2_128_CBC", CKM_PBE_SHA1_RC2_128_CBC),
    ("CKM_PBE_SHA1_RC2_40_CBC", CKM_PBE_SHA1_RC2_40_CBC),
    ("CKM_PKCS5_PBKD2", CKM_PKCS5_PBKD2),
    ("CKM_PBA_SHA1_WITH_SHA1_HMAC", CKM_PBA_SHA1_WITH_SHA1_HMAC),
    ("CKM_WTLS_PRE_MASTER_KEY_GEN", CKM_WTLS_PRE_MASTER_KEY_GEN),
    ("CKM_WTLS_MASTER_KEY_DERIVE", CKM_WTLS_MASTER_KEY_DERIVE),
    (
        "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC",
        CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
    ),
    ("CKM_WTLS_PRF", CKM_WTLS_PRF),
    (
        "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
        CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
    ),
    (
        "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
        CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
    ),
    ("CKM_TLS10_MAC_SERVER", CKM_TLS10_MAC_SERVER),
    ("CKM_TLS10_MAC_CLIENT", CKM_TLS10_MAC_CLIENT),
    ("CKM_TLS12_MAC", CKM_TLS12_MAC),
    ("CKM_TLS12_KDF", CKM_TLS12_KDF),
    ("CKM_TLS12_MASTER_KEY_DERIVE", CKM_TLS12_MASTER_KEY_DERIVE),
    ("CKM_TLS12_KEY_AND_MAC_DERIVE", CKM_TLS12_KEY_AND_MAC_DERIVE),
    (
        "CKM_TLS12_MASTER_KEY_DERIVE_DH",
        CKM_TLS12_MASTER_KEY_DERIVE_DH,
    ),
    ("CKM_TLS12_KEY_SAFE_DERIVE", CKM_TLS12_KEY_SAFE_DERIVE),
    ("CKM_TLS_MAC", CKM_TLS_MAC),
    ("CKM_TLS_KDF", CKM_TLS_KDF),
    ("CKM_KEY_WRAP_LYNKS", CKM_KEY_WRAP_LYNKS),
    ("CKM_KEY_WRAP_SET_OAEP", CKM_KEY_WRAP_SET_OAEP),
    ("CKM_CMS_SIG", CKM_CMS_SIG),
    ("CKM_KIP_DERIVE", CKM_KIP_DERIVE),
    ("CKM_KIP_WRAP", CKM_KIP_WRAP),
    ("CKM_KIP_MAC", CKM_KIP_MAC),
    ("CKM_CAMELLIA_KEY_GEN", CKM_CAMELLIA_KEY_GEN),
    ("CKM_CAMELLIA_ECB", CKM_CAMELLIA_ECB),
    ("CKM_CAMELLIA_CBC", CKM_CAMELLIA_CBC),
    ("CKM_CAMELLIA_MAC", CKM_CAMELLIA_MAC),
    ("CKM_CAMELLIA_MAC_GENERAL", CKM_CAMELLIA_MAC_GENERAL),
    ("CKM_CAMELLIA_CBC_PAD", CKM_CAMELLIA_CBC_PAD),
    (
        "CKM_CAMELLIA_ECB_ENCRYPT_DATA",
        CKM_CAMELLIA_ECB_ENCRYPT_DATA,
    ),
    (
        "CKM_CAMELLIA_CBC_ENCRYPT_DATA",
        CKM_CAMELLIA_CBC_ENCRYPT_DATA,
    ),
    ("CKM_CAMELLIA_CTR", CKM_CAMELLIA_CTR),
    ("CKM_ARIA_KEY_GEN", CKM_ARIA_KEY_GEN),
    ("CKM_ARIA_ECB", CKM_ARIA_ECB),
    ("CKM_ARIA_CBC", CKM_ARIA_CBC),
    ("CKM_ARIA_MAC", CKM_ARIA_MAC),
    ("CKM_ARIA_MAC_GENERAL", CKM_ARIA_MAC_GENERAL),
    ("CKM_ARIA_CBC_PAD", CKM_ARIA_CBC_PAD),
    ("CKM_ARIA_ECB_ENCRYPT_DATA", CKM_ARIA_ECB_ENCRYPT_DATA),
    ("CKM_ARIA_CBC_ENCRYPT_DATA", CKM_ARIA_CBC_ENCRYPT_DATA),
    ("CKM_SEED_KEY_GEN", CKM_SEED_KEY_GEN),
    ("CKM_SEED_ECB", CKM_SEED_ECB),
    ("CKM_SEED_CBC", CKM_SEED_CBC),
    ("CKM_SEED_MAC", CKM_SEED_MAC),
    ("CKM_SEED_MAC_GENERAL", CKM_SEED_MAC_GENERAL),
    ("CKM_SEED_CBC_PAD", CKM_SEED_CBC_PAD),
    ("CKM_SEED_ECB_ENCRYPT_DATA", CKM_SEED_ECB_ENCRYPT_DATA),
    ("CKM_SEED_CBC_ENCRYPT_DATA", CKM_SEED_CBC_ENCRYPT_DATA),
    ("CKM_SKIPJACK_KEY_GEN", CKM_SKIPJACK_KEY_GEN),
    ("CKM_SKIPJACK_ECB64", CKM_SKIPJACK_ECB64),
    ("CKM_SKIPJACK_CBC64", CKM_SKIPJACK_CBC64),
    ("CKM_SKIPJACK_OFB64", CKM_SKIPJACK_OFB64),
    ("CKM_SKIPJACK_CFB64", CKM_SKIPJACK_CFB64),
    ("CKM_SKIPJACK_CFB32", CKM_SKIPJACK_CFB32),
    ("CKM_SKIPJACK_CFB16", CKM_SKIPJACK_CFB16),
    ("CKM_SKIPJACK_CFB8", CKM_SKIPJACK_CFB8),
    ("CKM_SKIPJACK_WRAP", CKM_SKIPJACK_WRAP),
    ("CKM_SKIPJACK_PRIVATE_WRAP", CKM_SKIPJACK_PRIVATE_WRAP),
    ("CKM_SKIPJACK_RELAYX", CKM_SKIPJACK_RELAYX),
    ("CKM_KEA_KEY_PAIR_GEN", CKM_KEA_KEY_PAIR_GEN),
    ("CKM_KEA_KEY_DERIVE", CKM_KEA_KEY_DERIVE),
    ("CKM_KEA_DERIVE", CKM_KEA_DERIVE),
    ("CKM_FORTEZZA_TIMESTAMP", CKM_FORTEZZA_TIMESTAMP),
    ("CKM_BATON_KEY_GEN", CKM_BATON_KEY_GEN),
    ("CKM_BATON_ECB128", CKM_BATON_ECB128),
    ("CKM_BATON_ECB96", CKM_BATON_ECB96),
    ("CKM_BATON_CBC128", CKM_BATON_CBC128),
    ("CKM_BATON_COUNTER", CKM_BATON_COUNTER),
    ("CKM_BATON_SHUFFLE", CKM_BATON_SHUFFLE),
    ("CKM_BATON_WRAP", CKM_BATON_WRAP),
    ("CKM_ECDSA_KEY_PAIR_GEN", CKM_ECDSA_KEY_PAIR_GEN),
    ("CKM_EC_KEY_PAIR_GEN", CKM_EC_KEY_PAIR_GEN),
    ("CKM_ECDSA", CKM_ECDSA),
    ("CKM_ECDSA_SHA1", CKM_ECDSA_SHA1),
    ("CKM_ECDSA_SHA224", CKM_ECDSA_SHA224),
    ("CKM_ECDSA_SHA256", CKM_ECDSA_SHA256),
    ("CKM_ECDSA_SHA384", CKM_ECDSA_SHA384),
    ("CKM_ECDSA_SHA512", CKM_ECDSA_SHA512),
    (
        "CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS",
        CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS,
    ),
    ("CKM_ECDH1_DERIVE", CKM_ECDH1_DERIVE),
    ("CKM_ECDH1_COFACTOR_DERIVE", CKM_ECDH1_COFACTOR_DERIVE),
    ("CKM_ECMQV_DERIVE", CKM_ECMQV_DERIVE),
    ("CKM_ECDH_AES_KEY_WRAP", CKM_ECDH_AES_KEY_WRAP),
    ("CKM_RSA_AES_KEY_WRAP", CKM_RSA_AES_KEY_WRAP),
    ("CKM_JUNIPER_KEY_GEN", CKM_JUNIPER_KEY_GEN),
    ("CKM_JUNIPER_ECB128", CKM_JUNIPER_ECB128),
    ("CKM_JUNIPER_CBC128", CKM_JUNIPER_CBC128),
    ("CKM_JUNIPER_COUNTER", CKM_JUNIPER_COUNTER),
    ("CKM_JUNIPER_SHUFFLE", CKM_JUNIPER_SHUFFLE),
    ("CKM_JUNIPER_WRAP", CKM_JUNIPER_WRAP),
    ("CKM_FASTHASH", CKM_FASTHASH),
    ("CKM_AES_XTS", CKM_AES_XTS),
    ("CKM_AES_XTS_KEY_GEN", CKM_AES_XTS_KEY_GEN),
    ("CKM_AES_KEY_GEN", CKM_AES_KEY_GEN),
    ("CKM_AES_ECB", CKM_AES_ECB),
    ("CKM_AES_CBC", CKM_AES_CBC),
    ("CKM_AES_MAC", CKM_AES_MAC),
    ("CKM_AES_MAC_GENERAL", CKM_AES_MAC_GENERAL),
    ("CKM_AES_CBC_PAD", CKM_AES_CBC_PAD),
    ("CKM_AES_CTR", CKM_AES_CTR),
    ("CKM_AES_GCM", CKM_AES_GCM),
    ("CKM_AES_CCM", CKM_AES_CCM),
    ("CKM_AES_CTS", CKM_AES_CTS),
    ("CKM_AES_CMAC", CKM_AES_CMAC),
    ("CKM_AES_CMAC_GENERAL", CKM_AES_CMAC_GENERAL),
    ("CKM_AES_XCBC_MAC", CKM_AES_XCBC_MAC),
    ("CKM_AES_XCBC_MAC_96", CKM_AES_XCBC_MAC_96),
    ("CKM_AES_GMAC", CKM_AES_GMAC),
    ("CKM_BLOWFISH_KEY_GEN", CKM_BLOWFISH_KEY_GEN),
    ("CKM_BLOWFISH_CBC", CKM_BLOWFISH_CBC),
    ("CKM_TWOFISH_KEY_GEN", CKM_TWOFISH_KEY_GEN),
    ("CKM_TWOFISH_CBC", CKM_TWOFISH_CBC),
    ("CKM_BLOWFISH_CBC_PAD", CKM_BLOWFISH_CBC_PAD),
    ("CKM_TWOFISH_CBC_PAD", CKM_TWOFISH_CBC_PAD),
    ("CKM_DES_ECB_ENCRYPT_DATA", CKM_DES_ECB_ENCRYPT_DATA),
    ("CKM_DES_CBC_ENCRYPT_DATA", CKM_DES_CBC_ENCRYPT_DATA),
    ("CKM_DES3_ECB_ENCRYPT_DATA", CKM_DES3_ECB_ENCRYPT_DATA),
    ("CKM_DES3_CBC_ENCRYPT_DATA", CKM_DES3_CBC_ENCRYPT_DATA),
    ("CKM_AES_ECB_ENCRYPT_DATA", CKM_AES_ECB_ENCRYPT_DATA),
    ("CKM_AES_CBC_ENCRYPT_DATA", CKM_AES_CBC_ENCRYPT_DATA),
    ("CKM_GOSTR3410_KEY_PAIR_GEN", CKM_GOSTR3410_KEY_PAIR_GEN),
    ("CKM_GOSTR3410", CKM_GOSTR3410),
    ("CKM_GOSTR3410_WITH_GOSTR3411", CKM_GOSTR3410_WITH_GOSTR3411),
    ("CKM_GOSTR3410_KEY_WRAP", CKM_GOSTR3410_KEY_WRAP),
    ("CKM_GOSTR3410_DERIVE", CKM_GOSTR3410_DERIVE),
    ("CKM_GOSTR3411", CKM_GOSTR3411),
    ("CKM_GOSTR3411_HMAC", CKM_GOSTR3411_HMAC),
    ("CKM_GOST28147_KEY_GEN", CKM_GOST28147_KEY_GEN),
    ("CKM_GOST28147_ECB", CKM_GOST28147_ECB),
    ("CKM_GOST28147", CKM_GOST28147),
    ("CKM_GOST28147_MAC", CKM_GOST28147_MAC),
    ("CKM_GOST28147_KEY_WRAP", CKM_GOST28147_KEY_WRAP),
    ("CKM_CHACHA20_KEY_GEN", CKM_CHACHA20_KEY_GEN),
    ("CKM_CHACHA20", CKM_CHACHA20),
    ("CKM_POLY1305_KEY_GEN", CKM_POLY1305_KEY_GEN),
    ("CKM_POLY1305", CKM_POLY1305),
    ("CKM_DSA_PARAMETER_GEN", CKM_DSA_PARAMETER_GEN),
    ("CKM_DH_PKCS_PARAMETER_GEN", CKM_DH_PKCS_PARAMETER_GEN),
    ("CKM_X9_42_DH_PARAMETER_GEN", CKM_X9_42_DH_PARAMETER_GEN),
    (
        "CKM_DSA_PROBABILISTIC_PARAMETER_GEN",
        CKM_DSA_PROBABILISTIC_PARAMETER_GEN,
    ),
    (
        // Legacy misspelling of the constant above, kept in pkcs11-sys for
        // backward compatibility; same numeric value (8195), distinct symbol.
        "CKM_DSA_PROBABLISTIC_PARAMETER_GEN",
        CKM_DSA_PROBABLISTIC_PARAMETER_GEN,
    ),
    (
        "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN",
        CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
    ),
    ("CKM_DSA_FIPS_G_GEN", CKM_DSA_FIPS_G_GEN),
    ("CKM_AES_OFB", CKM_AES_OFB),
    ("CKM_AES_CFB64", CKM_AES_CFB64),
    ("CKM_AES_CFB8", CKM_AES_CFB8),
    ("CKM_AES_CFB128", CKM_AES_CFB128),
    ("CKM_AES_CFB1", CKM_AES_CFB1),
    ("CKM_AES_KEY_WRAP", CKM_AES_KEY_WRAP),
    ("CKM_AES_KEY_WRAP_PAD", CKM_AES_KEY_WRAP_PAD),
    ("CKM_AES_KEY_WRAP_KWP", CKM_AES_KEY_WRAP_KWP),
    ("CKM_AES_KEY_WRAP_PKCS7", CKM_AES_KEY_WRAP_PKCS7),
    ("CKM_RSA_PKCS_TPM_1_1", CKM_RSA_PKCS_TPM_1_1),
    ("CKM_RSA_PKCS_OAEP_TPM_1_1", CKM_RSA_PKCS_OAEP_TPM_1_1),
    ("CKM_SHA_1_KEY_GEN", CKM_SHA_1_KEY_GEN),
    ("CKM_SHA224_KEY_GEN", CKM_SHA224_KEY_GEN),
    ("CKM_SHA256_KEY_GEN", CKM_SHA256_KEY_GEN),
    ("CKM_SHA384_KEY_GEN", CKM_SHA384_KEY_GEN),
    ("CKM_SHA512_KEY_GEN", CKM_SHA512_KEY_GEN),
    ("CKM_SHA512_224_KEY_GEN", CKM_SHA512_224_KEY_GEN),
    ("CKM_SHA512_256_KEY_GEN", CKM_SHA512_256_KEY_GEN),
    ("CKM_SHA512_T_KEY_GEN", CKM_SHA512_T_KEY_GEN),
    ("CKM_NULL", CKM_NULL),
    ("CKM_BLAKE2B_160", CKM_BLAKE2B_160),
    ("CKM_BLAKE2B_160_HMAC", CKM_BLAKE2B_160_HMAC),
    ("CKM_BLAKE2B_160_HMAC_GENERAL", CKM_BLAKE2B_160_HMAC_GENERAL),
    ("CKM_BLAKE2B_160_KEY_DERIVE", CKM_BLAKE2B_160_KEY_DERIVE),
    ("CKM_BLAKE2B_160_KEY_GEN", CKM_BLAKE2B_160_KEY_GEN),
    ("CKM_BLAKE2B_256", CKM_BLAKE2B_256),
    ("CKM_BLAKE2B_256_HMAC", CKM_BLAKE2B_256_HMAC),
    ("CKM_BLAKE2B_256_HMAC_GENERAL", CKM_BLAKE2B_256_HMAC_GENERAL),
    ("CKM_BLAKE2B_256_KEY_DERIVE", CKM_BLAKE2B_256_KEY_DERIVE),
    ("CKM_BLAKE2B_256_KEY_GEN", CKM_BLAKE2B_256_KEY_GEN),
    ("CKM_BLAKE2B_384", CKM_BLAKE2B_384),
    ("CKM_BLAKE2B_384_HMAC", CKM_BLAKE2B_384_HMAC),
    ("CKM_BLAKE2B_384_HMAC_GENERAL", CKM_BLAKE2B_384_HMAC_GENERAL),
    ("CKM_BLAKE2B_384_KEY_DERIVE", CKM_BLAKE2B_384_KEY_DERIVE),
    ("CKM_BLAKE2B_384_KEY_GEN", CKM_BLAKE2B_384_KEY_GEN),
    ("CKM_BLAKE2B_512", CKM_BLAKE2B_512),
    ("CKM_BLAKE2B_512_HMAC", CKM_BLAKE2B_512_HMAC),
    ("CKM_BLAKE2B_512_HMAC_GENERAL", CKM_BLAKE2B_512_HMAC_GENERAL),
    ("CKM_BLAKE2B_512_KEY_DERIVE", CKM_BLAKE2B_512_KEY_DERIVE),
    ("CKM_BLAKE2B_512_KEY_GEN", CKM_BLAKE2B_512_KEY_GEN),
    ("CKM_SALSA20", CKM_SALSA20),
    ("CKM_CHACHA20_POLY1305", CKM_CHACHA20_POLY1305),
    ("CKM_SALSA20_POLY1305", CKM_SALSA20_POLY1305),
    ("CKM_X3DH_INITIALIZE", CKM_X3DH_INITIALIZE),
    ("CKM_X3DH_RESPOND", CKM_X3DH_RESPOND),
    ("CKM_X2RATCHET_INITIALIZE", CKM_X2RATCHET_INITIALIZE),
    ("CKM_X2RATCHET_RESPOND", CKM_X2RATCHET_RESPOND),
    ("CKM_X2RATCHET_ENCRYPT", CKM_X2RATCHET_ENCRYPT),
    ("CKM_X2RATCHET_DECRYPT", CKM_X2RATCHET_DECRYPT),
    ("CKM_XEDDSA", CKM_XEDDSA),
    ("CKM_HKDF_DERIVE", CKM_HKDF_DERIVE),
    ("CKM_HKDF_DATA", CKM_HKDF_DATA),
    ("CKM_HKDF_KEY_GEN", CKM_HKDF_KEY_GEN),
    ("CKM_SALSA20_KEY_GEN", CKM_SALSA20_KEY_GEN),
    ("CKM_ECDSA_SHA3_224", CKM_ECDSA_SHA3_224),
    ("CKM_ECDSA_SHA3_256", CKM_ECDSA_SHA3_256),
    ("CKM_ECDSA_SHA3_384", CKM_ECDSA_SHA3_384),
    ("CKM_ECDSA_SHA3_512", CKM_ECDSA_SHA3_512),
    ("CKM_EC_EDWARDS_KEY_PAIR_GEN", CKM_EC_EDWARDS_KEY_PAIR_GEN),
    (
        "CKM_EC_MONTGOMERY_KEY_PAIR_GEN",
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    ),
    ("CKM_EDDSA", CKM_EDDSA),
    ("CKM_SP800_108_COUNTER_KDF", CKM_SP800_108_COUNTER_KDF),
    ("CKM_SP800_108_FEEDBACK_KDF", CKM_SP800_108_FEEDBACK_KDF),
    (
        "CKM_SP800_108_DOUBLE_PIPELINE_KDF",
        CKM_SP800_108_DOUBLE_PIPELINE_KDF,
    ),
    ("CKM_IKE2_PRF_PLUS_DERIVE", CKM_IKE2_PRF_PLUS_DERIVE),
    ("CKM_IKE_PRF_DERIVE", CKM_IKE_PRF_DERIVE),
    ("CKM_IKE1_PRF_DERIVE", CKM_IKE1_PRF_DERIVE),
    ("CKM_IKE1_EXTENDED_DERIVE", CKM_IKE1_EXTENDED_DERIVE),
    ("CKM_HSS_KEY_PAIR_GEN", CKM_HSS_KEY_PAIR_GEN),
    ("CKM_HSS", CKM_HSS),
];

/// All 92 `C_*` functions of `pkcs11-sys`'s `CK_FUNCTION_LIST_3_0` (a strict
/// superset of the legacy 68-field `CK_FUNCTION_LIST`), in struct declaration
/// order. Used only to size-check/reconcile the function-coverage pass — see
/// `plan.md` for provenance.
const ALL_FUNCTIONS: &[&str] = &[
    "C_Initialize",
    "C_Finalize",
    "C_GetInfo",
    "C_GetFunctionList",
    "C_GetSlotList",
    "C_GetSlotInfo",
    "C_GetTokenInfo",
    "C_GetMechanismList",
    "C_GetMechanismInfo",
    "C_InitToken",
    "C_InitPIN",
    "C_SetPIN",
    "C_OpenSession",
    "C_CloseSession",
    "C_CloseAllSessions",
    "C_GetSessionInfo",
    "C_GetOperationState",
    "C_SetOperationState",
    "C_Login",
    "C_Logout",
    "C_CreateObject",
    "C_CopyObject",
    "C_DestroyObject",
    "C_GetObjectSize",
    "C_GetAttributeValue",
    "C_SetAttributeValue",
    "C_FindObjectsInit",
    "C_FindObjects",
    "C_FindObjectsFinal",
    "C_EncryptInit",
    "C_Encrypt",
    "C_EncryptUpdate",
    "C_EncryptFinal",
    "C_DecryptInit",
    "C_Decrypt",
    "C_DecryptUpdate",
    "C_DecryptFinal",
    "C_DigestInit",
    "C_Digest",
    "C_DigestUpdate",
    "C_DigestKey",
    "C_DigestFinal",
    "C_SignInit",
    "C_Sign",
    "C_SignUpdate",
    "C_SignFinal",
    "C_SignRecoverInit",
    "C_SignRecover",
    "C_VerifyInit",
    "C_Verify",
    "C_VerifyUpdate",
    "C_VerifyFinal",
    "C_VerifyRecoverInit",
    "C_VerifyRecover",
    "C_DigestEncryptUpdate",
    "C_DecryptDigestUpdate",
    "C_SignEncryptUpdate",
    "C_DecryptVerifyUpdate",
    "C_GenerateKey",
    "C_GenerateKeyPair",
    "C_WrapKey",
    "C_UnwrapKey",
    "C_DeriveKey",
    "C_SeedRandom",
    "C_GenerateRandom",
    "C_GetFunctionStatus",
    "C_CancelFunction",
    "C_WaitForSlotEvent",
    "C_GetInterfaceList",
    "C_GetInterface",
    "C_LoginUser",
    "C_SessionCancel",
    "C_MessageEncryptInit",
    "C_EncryptMessage",
    "C_EncryptMessageBegin",
    "C_EncryptMessageNext",
    "C_MessageEncryptFinal",
    "C_MessageDecryptInit",
    "C_DecryptMessage",
    "C_DecryptMessageBegin",
    "C_DecryptMessageNext",
    "C_MessageDecryptFinal",
    "C_MessageSignInit",
    "C_SignMessage",
    "C_SignMessageBegin",
    "C_SignMessageNext",
    "C_MessageSignFinal",
    "C_MessageVerifyInit",
    "C_VerifyMessage",
    "C_VerifyMessageBegin",
    "C_VerifyMessageNext",
    "C_MessageVerifyFinal",
];

/// The outcome of one mechanism or function check.
enum Outcome {
    /// ✅ the real operation was attempted and behaved as expected.
    Pass,
    /// ❌ the real operation was attempted and did not behave as expected.
    Fail(String),
    /// ⏭️ the check was not attempted at all because it requires a non-FIPS-only
    /// algorithm and this binary was built without `--features non-fips`.
    Skip(String),
    /// ❌ the mechanism/function is not implemented by `cosmian_pkcs11`,
    /// dynamically detected via `CKR_MECHANISM_INVALID`/`CKR_FUNCTION_NOT_SUPPORTED`
    /// (or, for `C_GetInterfaceList`/`C_GetInterface`, a `None` function-list slot).
    /// Rendered as a red cross, same as `Fail`: from the caller's perspective "not
    /// implemented" and "attempted but failed" both mean "you cannot use this".
    NotImplemented(String),
    /// ⬛ deliberately never invoked for safety (see `EXCLUDED_FUNCTIONS`) — unlike
    /// `NotImplemented`, this does *not* mean the function is unsupported: it means
    /// its real support status is unknown because probing it would reinitialize
    /// the token or change its authentication state.
    Excluded(String),
}

/// One row of the final report.
struct CheckResult {
    name: &'static str,
    detail: String,
    outcome: Outcome,
}

/// The set of KMS objects this run provisioned, kept so they can be destroyed at
/// the end regardless of whether the mechanism checks succeeded.
#[derive(Default)]
struct ProvisionedKeys {
    /// `(label, private_key_id, public_key_id)` triples created via
    /// `create_key_pair`/`create_ec_key_pair_request`. `label` identifies the
    /// key's algorithm/curve (e.g. `"RSA"`, `"P-384"`, `"Ed448"`) so
    /// [`KeyHandles::locate`] can address each pair by identity rather than by a
    /// fragile positional index into the list (see `plan.md`'s "Provisioning
    /// scope increase").
    key_pairs: Vec<(&'static str, String, String)>,
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
    run_rsa_checks(func_list, slot_id, key_handles.get("RSA"), &mut results);
    run_ecdsa_checks(func_list, slot_id, &key_handles.ec_curves(), &mut results);
    run_eddsa_checks(
        func_list,
        func_list_3_0,
        slot_id,
        &key_handles.ed_curves(),
        &mut results,
    );

    // The two coverage passes are computed *before* teardown: they issue real
    // FFI calls of their own (shallow function probes, `C_GetMechanismInfo`
    // sweeps) that need the still-open session/slot.
    let mechanism_results = run_mechanism_coverage(func_list, slot_id, &results);
    let function_results = run_function_coverage(
        func_list,
        func_list_3_0,
        slot_id,
        session,
        key_handles.get("RSA"),
        &results,
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

    // Two independent sections, each with its own summary (Decision 3 of
    // `plan.md`): the mechanism and function universes are unrelated, so a
    // merged grand total would be misleading.
    let mut all_mechanism_results = results;
    all_mechanism_results.extend(mechanism_results);
    print_section("PKCS#11 API function coverage", &function_results);
    println!();
    print_section("PKCS#11 mechanism coverage", &all_mechanism_results);

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
        "RSA",
        unique_identifier_to_string(&rsa_response.private_key_unique_identifier)?,
        unique_identifier_to_string(&rsa_response.public_key_unique_identifier)?,
    ));

    // P-256, P-384, and P-521 are all FIPS-approved and have distinct code paths in
    // the provider (different signature/point lengths), so all three are always
    // provisioned (see `plan.md` Decision 7).
    provision_ec_curve(
        kms_rest_client,
        "P-256",
        RecommendedCurve::P256,
        &mut provisioned,
    )
    .await?;
    provision_ec_curve(
        kms_rest_client,
        "P-384",
        RecommendedCurve::P384,
        &mut provisioned,
    )
    .await?;
    provision_ec_curve(
        kms_rest_client,
        "P-521",
        RecommendedCurve::P521,
        &mut provisioned,
    )
    .await?;

    // secp256k1, Ed25519, and Ed448 are not FIPS-approved; only attempt them in a
    // `non-fips` build, where the server actually allows creating them.
    if cfg!(feature = "non-fips") {
        provision_ec_curve(
            kms_rest_client,
            "secp256k1",
            RecommendedCurve::SECP256K1,
            &mut provisioned,
        )
        .await?;
        provision_ec_curve(
            kms_rest_client,
            "Ed25519",
            RecommendedCurve::CURVEED25519,
            &mut provisioned,
        )
        .await?;
        provision_ec_curve(
            kms_rest_client,
            "Ed448",
            RecommendedCurve::CURVEED448,
            &mut provisioned,
        )
        .await?;
    }

    Ok(provisioned)
}

async fn provision_ec_curve(
    kms_rest_client: &KmsClient,
    label: &'static str,
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
        label,
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
    for (_label, private_key_id, _public_key_id) in provisioned.key_pairs {
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
    /// Keyed by the same `label` provisioning used (`"RSA"`, `"P-256"`, `"P-384"`,
    /// `"P-521"`, `"secp256k1"`, `"Ed25519"`, `"Ed448"`), rather than by list
    /// position, so adding/removing curves never silently misattributes a handle
    /// to the wrong row (see `plan.md`'s "Provisioning scope increase").
    by_label: std::collections::BTreeMap<&'static str, (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>,
}

impl KeyHandles {
    fn locate(
        func_list: &CK_FUNCTION_LIST,
        session: CK_SESSION_HANDLE,
        provisioned: &ProvisionedKeys,
    ) -> Self {
        let mut by_label = std::collections::BTreeMap::new();
        for (label, sk, pk) in &provisioned.key_pairs {
            if let Some(handles) = find_key_pair(func_list, session, sk, pk) {
                by_label.insert(*label, handles);
            }
        }
        Self { by_label }
    }

    fn get(&self, label: &str) -> Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
        self.by_label.get(label).copied()
    }

    /// All EC (non-EdDSA) key pairs, paired with their curve label, in a stable
    /// order (P-256, P-384, P-521, then secp256k1 when present).
    fn ec_curves(&self) -> Vec<(&'static str, (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE))> {
        ["P-256", "P-384", "P-521", "secp256k1"]
            .into_iter()
            .filter_map(|label| self.get(label).map(|handles| (label, handles)))
            .collect()
    }

    /// All `EdDSA` key pairs, paired with their curve label, in a stable order
    /// (Ed25519, then Ed448).
    fn ed_curves(&self) -> Vec<(&'static str, (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE))> {
        ["Ed25519", "Ed448"]
            .into_iter()
            .filter_map(|label| self.get(label).map(|handles| (label, handles)))
            .collect()
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
                name: "CKM_AES_KEY_GEN",
                detail: "C_GenerateKey".to_owned(),
                outcome: Outcome::Pass,
            });
            handle
        }
        Err(e) => {
            let reason = e;
            for (name, detail) in [
                ("CKM_AES_KEY_GEN", "C_GenerateKey"),
                ("CKM_AES_CBC", "encrypt/decrypt round-trip"),
                ("CKM_AES_CBC_PAD", "encrypt/decrypt round-trip"),
                ("CKM_AES_GCM", "encrypt/decrypt round-trip"),
            ] {
                results.push(CheckResult {
                    name,
                    detail: detail.to_owned(),
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

    for (ck_mechanism, name, iv_len, plaintext) in [
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
            name,
            detail: "encrypt/decrypt round-trip".to_owned(),
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
        for name in [
            "CKM_RSA_PKCS",
            "CKM_SHA1_RSA_PKCS",
            "CKM_SHA256_RSA_PKCS",
            "CKM_SHA384_RSA_PKCS",
            "CKM_SHA512_RSA_PKCS",
            "CKM_RSA_PKCS_PSS",
        ] {
            results.push(CheckResult {
                name,
                detail: "sign/verify".to_owned(),
                outcome: Outcome::Fail(
                    "the KMS-provisioned RSA key pair was not found on the PKCS#11 slot".to_owned(),
                ),
            });
        }
        return;
    };

    let raw_message = b"cosmian pkcs11 capabilities RSA raw sign test data 32b";
    let digest = [0x5A_u8; 32];

    for (name, ck_mechanism, data) in [
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
            Err(e) if name == "CKM_SHA1_RSA_PKCS" => Outcome::Fail(format!(
                "{e} (expected: SHA-1 RSA signing is denied by the KMS server's \
                 deprecated-algorithm policy)"
            )),
            Err(e) => Outcome::Fail(e),
        };
        results.push(CheckResult {
            name,
            detail: "sign/verify".to_owned(),
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
        name: "CKM_RSA_PKCS_PSS",
        detail: "sign/verify".to_owned(),
        outcome,
    });
}

/// `CKM_ECDSA` sign/verify over every provisioned EC key pair (P-256, P-384,
/// P-521, and — in a `non-fips` build — secp256k1).
fn run_ecdsa_checks(
    func_list: &CK_FUNCTION_LIST,
    slot_id: CK_SLOT_ID,
    handles: &[(&'static str, (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE))],
    results: &mut Vec<CheckResult>,
) {
    if handles.is_empty() {
        results.push(CheckResult {
            name: "CKM_ECDSA",
            detail: "sign/verify".to_owned(),
            outcome: Outcome::Fail(
                "no KMS-provisioned EC key pair was found on the PKCS#11 slot".to_owned(),
            ),
        });
        return;
    }

    // CKM_ECDSA expects a pre-computed digest, not the raw message.
    let digest = [0x24_u8; 32];
    for (label, (sk, pk)) in handles {
        let outcome = match sign_verify(func_list, slot_id, *sk, *pk, CKM_ECDSA, None, &digest) {
            Ok(()) => Outcome::Pass,
            Err(e) => Outcome::Fail(e),
        };
        let suffix = match *label {
            "P-256" => "sign/verify (P-256)",
            "P-384" => "sign/verify (P-384)",
            "P-521" => "sign/verify (P-521)",
            "secp256k1" => "sign/verify (secp256k1, non-fips)",
            // Unreachable in practice: `handles` only ever contains the curve
            // labels this module itself assigns in `provision_keys`. Fall back to
            // a generic label rather than panicking on unexpected input.
            _ => "sign/verify",
        };
        results.push(CheckResult {
            name: "CKM_ECDSA",
            detail: suffix.to_owned(),
            outcome,
        });
    }
}

/// One-shot `CKM_EDDSA` sign/verify, plus the v3.0 message-based
/// `C_MessageSignInit`/`C_SignMessage`/`C_MessageSignFinal` flow, for every
/// provisioned `EdDSA` curve (Ed25519, Ed448) — both gated behind the `non-fips`
/// feature, since neither curve is FIPS-approved.
fn run_eddsa_checks(
    func_list: &CK_FUNCTION_LIST,
    func_list_3_0: &CK_FUNCTION_LIST_3_0,
    slot_id: CK_SLOT_ID,
    handles: &[(&'static str, (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE))],
    results: &mut Vec<CheckResult>,
) {
    for label in ["Ed25519", "Ed448"] {
        let one_shot_detail = format!("sign/verify (one-shot, {label})");
        let message_detail =
            format!("C_MessageSignInit/C_SignMessage/C_MessageSignFinal ({label})");

        if !cfg!(feature = "non-fips") {
            for detail in [one_shot_detail, message_detail] {
                results.push(CheckResult {
                    name: "CKM_EDDSA",
                    detail,
                    outcome: Outcome::Skip(format!(
                        "{label} is not FIPS-approved; built without --features non-fips"
                    )),
                });
            }
            continue;
        }

        let Some((sk, pk)) = handles
            .iter()
            .find(|(curve, _)| *curve == label)
            .map(|(_, h)| *h)
        else {
            for detail in [one_shot_detail, message_detail] {
                results.push(CheckResult {
                    name: "CKM_EDDSA",
                    detail,
                    outcome: Outcome::Fail(format!(
                        "the KMS-provisioned {label} key pair was not found on the PKCS#11 slot"
                    )),
                });
            }
            continue;
        };

        let message = b"cosmian pkcs11 capabilities EdDSA one-shot sign test message";
        let outcome = match sign_verify(func_list, slot_id, sk, pk, CKM_EDDSA, None, message) {
            Ok(()) => Outcome::Pass,
            Err(e) => Outcome::Fail(e),
        };
        results.push(CheckResult {
            name: "CKM_EDDSA",
            detail: one_shot_detail,
            outcome,
        });

        let outcome =
            match eddsa_message_sign_verify(func_list, func_list_3_0, slot_id, sk, pk, message) {
                Ok(()) => Outcome::Pass,
                Err(e) => Outcome::Fail(e),
            };
        results.push(CheckResult {
            name: "CKM_EDDSA",
            detail: message_detail,
            outcome,
        });
    }
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
// Mechanism coverage pass (Decision 6: dynamic `C_GetMechanismInfo` probe of all
// 442 real `CKM_*` mechanisms)
// ---------------------------------------------------------------------------

/// Probes every mechanism in [`ALL_MECHANISMS`] that was *not* already exercised
/// by a deep round-trip check above (`deep_results`), via `C_GetMechanismInfo`.
///
/// `CKR_MECHANISM_INVALID` means the provider does not implement it at all (❌
/// not implemented); any other return code means the provider advertises it but
/// this tool has no deep test for it, which — given the module currently only
/// advertises the ~12 mechanisms already deep-tested above — should not happen
/// in practice, but is reported as a genuine ❌ Fail rather than silently
/// ignored if it ever does (e.g. after a future provider change adds a new
/// mechanism this tool doesn't know how to exercise yet).
fn probe_mechanism_info(
    func_list: &CK_FUNCTION_LIST,
    slot_id: CK_SLOT_ID,
    ckm: CK_MECHANISM_TYPE,
) -> Outcome {
    let Some(c_get_mechanism_info) = func_list.C_GetMechanismInfo else {
        return Outcome::NotImplemented(
            "C_GetMechanismInfo is not present in the function list".to_owned(),
        );
    };
    let mut info = CK_MECHANISM_INFO::default();
    // SAFETY: `info` is a valid, correctly-sized out-parameter for the duration
    // of this call.
    let rv = unsafe { c_get_mechanism_info(slot_id, ckm, &raw mut info) };
    if rv == CKR_MECHANISM_INVALID {
        Outcome::NotImplemented("not advertised by cosmian_pkcs11".to_owned())
    } else if rv == CKR_OK {
        Outcome::Fail(
            "C_GetMechanismInfo reports this mechanism as advertised, but this tool has no \
             round-trip test wired up for it yet"
                .to_owned(),
        )
    } else {
        Outcome::Fail(format!(
            "C_GetMechanismInfo returned {} (0x{rv:08X})",
            ckr_name(rv)
        ))
    }
}

fn run_mechanism_coverage(
    func_list: &CK_FUNCTION_LIST,
    slot_id: CK_SLOT_ID,
    deep_results: &[CheckResult],
) -> Vec<CheckResult> {
    let already_tested: std::collections::BTreeSet<&str> =
        deep_results.iter().map(|r| r.name).collect();

    let mut rows = Vec::with_capacity(ALL_MECHANISMS.len());
    for &(name, ckm) in ALL_MECHANISMS {
        if already_tested.contains(name) {
            continue;
        }
        rows.push(CheckResult {
            name,
            detail: "C_GetMechanismInfo".to_owned(),
            outcome: probe_mechanism_info(func_list, slot_id, ckm),
        });
    }
    rows
}

// ---------------------------------------------------------------------------
// Function coverage pass (Decision 5: shallow single-call probe of all 92 `C_*`
// functions)
// ---------------------------------------------------------------------------

/// Functions never invoked for real, because doing so would be destructive or
/// would change the token's authentication state in a way no other check can
/// safely recover from (see `plan.md` Decision 4).
const EXCLUDED_FUNCTIONS: &[(&str, &str)] = &[
    ("C_InitToken", "would reinitialize/wipe the token"),
    ("C_InitPIN", "would change the token's authentication state"),
    ("C_SetPIN", "would change the token's authentication state"),
];

/// Functions already exercised for real elsewhere in this command (module
/// bootstrap, session setup, key-pair lookup, or one of the deep mechanism
/// checks) and therefore deliberately *not* shallow-probed again here, to avoid
/// reporting two different, possibly contradictory, results for the same entry
/// point (see `plan.md` Decision 5).
const REUSED_FUNCTIONS: &[&str] = &[
    "C_Initialize",
    "C_Finalize",
    "C_GetFunctionList",
    "C_GetSlotList",
    "C_OpenSession",
    "C_CloseSession",
    "C_Login",
    "C_GetMechanismInfo",
    "C_FindObjectsInit",
    "C_FindObjects",
    "C_FindObjectsFinal",
    "C_GenerateKey",
    "C_DestroyObject",
    "C_EncryptInit",
    "C_Encrypt",
    "C_DecryptInit",
    "C_Decrypt",
    "C_SignInit",
    "C_Sign",
    "C_VerifyInit",
    "C_Verify",
    "C_MessageSignInit",
    "C_SignMessage",
    "C_MessageSignFinal",
];

/// Classifies one raw `CK_RV` shallow-probe result. `CKR_FUNCTION_NOT_SUPPORTED`
/// always means "not implemented" (❌), regardless of the function's own
/// `expected_ok` code, since `cryptoki_fn_not_supported!`-stubbed functions in
/// `cosmian_pkcs11` return exactly this code unconditionally.
fn classify_function_probe(rv: CK_RV, expected_ok: CK_RV) -> Outcome {
    if rv == CKR_FUNCTION_NOT_SUPPORTED {
        Outcome::NotImplemented("stubbed by cosmian_pkcs11 (CKR_FUNCTION_NOT_SUPPORTED)".to_owned())
    } else if rv == expected_ok {
        Outcome::Pass
    } else {
        Outcome::Fail(format!("returned {} (0x{rv:08X})", ckr_name(rv)))
    }
}

/// Shared, minimal-precondition context used to shallow-probe the ~63 `C_*`
/// functions that are neither excluded (Decision 4) nor already reused
/// (Decision 5). A single throwaway AES key handle stands in for "an object" /
/// "a key" wherever a function merely needs *some* valid handle to reach its
/// real logic; the RSA key pair (if provisioned) stands in for sign/verify
/// recover-family probes.
struct FunctionProbeCtx<'a> {
    func_list: &'a CK_FUNCTION_LIST,
    slot_id: CK_SLOT_ID,
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    rsa: Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>,
}

/// Runs the full 92-function coverage pass: `EXCLUDED_FUNCTIONS` are reported
/// without ever being invoked; `REUSED_FUNCTIONS` are reported `Pass`/`Fail`
/// based on whether any deep mechanism check that used them succeeded; every
/// other function gets a single, real, minimal-precondition shallow call.
fn run_function_coverage(
    func_list: &CK_FUNCTION_LIST,
    func_list_3_0: &CK_FUNCTION_LIST_3_0,
    slot_id: CK_SLOT_ID,
    session: CK_SESSION_HANDLE,
    rsa: Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>,
    deep_results: &[CheckResult],
) -> Vec<CheckResult> {
    let mut rows = Vec::with_capacity(ALL_FUNCTIONS.len());

    for &(name, reason) in EXCLUDED_FUNCTIONS {
        rows.push(CheckResult {
            name,
            detail: "C_*".to_owned(),
            outcome: Outcome::Excluded(reason.to_owned()),
        });
    }

    for &name in REUSED_FUNCTIONS {
        // A "reused" function passes if at least one deep check that depends on
        // it actually succeeded; if every attempt failed, report the first
        // failure reason; if it was never exercised at all (e.g. `C_Login` when
        // no `--token` was supplied), report it as skipped rather than guessing.
        let mut any_pass = false;
        let mut first_fail: Option<&str> = None;
        for r in deep_results {
            match &r.outcome {
                Outcome::Pass => any_pass = true,
                Outcome::Fail(reason) if first_fail.is_none() => first_fail = Some(reason),
                _ => {}
            }
        }
        let outcome = if any_pass {
            Outcome::Pass
        } else if let Some(reason) = first_fail {
            Outcome::Fail(format!(
                "no deep check using {name} succeeded; last observed reason: {reason}"
            ))
        } else {
            Outcome::Skip(
                "exercised only indirectly by setup/deep checks, none of which ran".to_owned(),
            )
        };
        rows.push(CheckResult {
            name,
            detail: "reused from setup/deep mechanism checks".to_owned(),
            outcome,
        });
    }

    // `C_GetInterfaceList`/`C_GetInterface`: the function-list slots themselves
    // are `None` (see `crate/clients/pkcs11/module/src/pkcs11.rs`), so there is
    // nothing to call — classify directly rather than dereferencing `None`.
    for name in ["C_GetInterfaceList", "C_GetInterface"] {
        rows.push(CheckResult {
            name,
            detail: "C_*".to_owned(),
            outcome: Outcome::NotImplemented("function-list slot is None".to_owned()),
        });
    }

    let object = generate_aes_key(func_list, session).unwrap_or_default();
    let ctx = FunctionProbeCtx {
        func_list,
        slot_id,
        session,
        object,
        rsa,
    };
    shallow_probe_functions(&ctx, func_list_3_0, &mut rows);
    if object != 0 {
        if let Some(c_destroy) = func_list.C_DestroyObject {
            // SAFETY: `object` was just created above by `generate_aes_key`.
            let _ = unsafe { c_destroy(session, object) };
        }
    }

    rows
}

/// Records the outcome of one shallow probe.
fn push_probe(rows: &mut Vec<CheckResult>, name: &'static str, rv: CK_RV, expected_ok: CK_RV) {
    rows.push(CheckResult {
        name,
        detail: "shallow probe (minimal-precondition C_* call)".to_owned(),
        outcome: classify_function_probe(rv, expected_ok),
    });
}

/// Issues one real, minimal-precondition call to each of the 63 `C_*` functions
/// that are neither excluded, reused, nor structurally `None`. Every call is
/// spec-legal to issue (even if the provider ultimately rejects it for lack of
/// an active operation/session state), so no `unsafe` invariant beyond "the
/// pointer/length pairs below are valid for the duration of the call" is
/// required. Functions with a spec-mandated non-`CKR_OK` "working" response
/// (`C_GetFunctionStatus`, `C_CancelFunction`) use an overridden `expected_ok`.
fn shallow_probe_functions(
    ctx: &FunctionProbeCtx,
    func_list_3_0: &CK_FUNCTION_LIST_3_0,
    rows: &mut Vec<CheckResult>,
) {
    let f = ctx.func_list;
    let session = ctx.session;
    let object = ctx.object;
    let slot_id = ctx.slot_id;

    // ---- Slot/token/session introspection ---------------------------------
    {
        let mut info = CK_INFO::default();
        let rv = f
            .C_GetInfo
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe { c(&raw mut info) });
        push_probe(rows, "C_GetInfo", rv, CKR_OK);
    }
    {
        let mut info = CK_SLOT_INFO::default();
        let rv = f
            .C_GetSlotInfo
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(slot_id, &raw mut info)
            });
        push_probe(rows, "C_GetSlotInfo", rv, CKR_OK);
    }
    {
        let mut info = CK_TOKEN_INFO::default();
        let rv = f
            .C_GetTokenInfo
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(slot_id, &raw mut info)
            });
        push_probe(rows, "C_GetTokenInfo", rv, CKR_OK);
    }
    {
        let mut count: CK_ULONG = 0;
        let rv = f
            .C_GetMechanismList
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(slot_id, ptr::null_mut(), &raw mut count)
            });
        push_probe(rows, "C_GetMechanismList", rv, CKR_OK);
    }
    {
        let mut info = CK_SESSION_INFO::default();
        let rv = f
            .C_GetSessionInfo
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, &raw mut info)
            });
        push_probe(rows, "C_GetSessionInfo", rv, CKR_OK);
    }
    {
        let mut len: CK_ULONG = 0;
        let rv = f
            .C_GetOperationState
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, ptr::null_mut(), &raw mut len)
            });
        push_probe(rows, "C_GetOperationState", rv, CKR_OK);
    }
    {
        let mut state = [0_u8; 1];
        let rv = f
            .C_SetOperationState
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, state.as_mut_ptr(), 1, 0, 0)
            });
        push_probe(rows, "C_SetOperationState", rv, CKR_OK);
    }

    // ---- Object management --------------------------------------------------
    {
        let mut class = CKO_DATA;
        let label = "ckms-pkcs11-capabilities-probe-object";
        let template_result = (|| -> Result<(), String> {
            let class_len = ck_ulong(size_of::<CK_OBJECT_CLASS>())?;
            let label_len = ck_ulong(label.len())?;
            let mut template = [
                CK_ATTRIBUTE {
                    type_: CKA_CLASS,
                    pValue: (&raw mut class).cast::<c_void>(),
                    ulValueLen: class_len,
                },
                CK_ATTRIBUTE {
                    type_: CKA_LABEL,
                    pValue: label.as_ptr().cast_mut().cast::<c_void>(),
                    ulValueLen: label_len,
                },
            ];
            let template_len = ck_ulong(template.len())?;
            let mut handle: CK_OBJECT_HANDLE = 0;
            let rv = f
                .C_CreateObject
                .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                    c(
                        session,
                        template.as_mut_ptr(),
                        template_len,
                        &raw mut handle,
                    )
                });
            push_probe(rows, "C_CreateObject", rv, CKR_OK);
            if rv == CKR_OK {
                if let Some(c_destroy) = f.C_DestroyObject {
                    // SAFETY: `handle` was just created above.
                    let _ = unsafe { c_destroy(session, handle) };
                }
            }
            Ok(())
        })();
        if let Err(e) = template_result {
            rows.push(CheckResult {
                name: "C_CreateObject",
                detail: "shallow probe (minimal-precondition C_* call)".to_owned(),
                outcome: Outcome::Fail(e),
            });
        }
    }
    {
        let mut copy: CK_OBJECT_HANDLE = 0;
        let rv = f
            .C_CopyObject
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, object, ptr::null_mut(), 0, &raw mut copy)
            });
        push_probe(rows, "C_CopyObject", rv, CKR_OK);
    }
    {
        let mut size: CK_ULONG = 0;
        let rv = f
            .C_GetObjectSize
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, object, &raw mut size)
            });
        push_probe(rows, "C_GetObjectSize", rv, CKR_OK);
    }
    {
        let mut class: CK_OBJECT_CLASS = 0;
        let class_len = ck_ulong(size_of::<CK_OBJECT_CLASS>()).unwrap_or(0);
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: (&raw mut class).cast::<c_void>(),
            ulValueLen: class_len,
        }];
        let rv = f
            .C_GetAttributeValue
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, object, template.as_mut_ptr(), 1)
            });
        push_probe(rows, "C_GetAttributeValue", rv, CKR_OK);
    }
    {
        let label = "ckms-pkcs11-capabilities-probe";
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: label.as_ptr().cast_mut().cast::<c_void>(),
            ulValueLen: ck_ulong(label.len()).unwrap_or(0),
        }];
        let rv = f
            .C_SetAttributeValue
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, object, template.as_mut_ptr(), 1)
            });
        push_probe(rows, "C_SetAttributeValue", rv, CKR_OK);
    }

    // ---- Encrypt/Decrypt streaming (not covered by the one-shot AES deep
    // test above) ------------------------------------------------------------
    {
        let mut part = [0_u8; 16];
        let mut part_len = ck_ulong(part.len()).unwrap_or(0);
        let rv = f
            .C_EncryptUpdate
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    part.as_mut_ptr(),
                    16,
                    part.as_mut_ptr(),
                    &raw mut part_len,
                )
            });
        push_probe(rows, "C_EncryptUpdate", rv, CKR_OK);
    }
    {
        let mut part = [0_u8; 16];
        let mut part_len = ck_ulong(part.len()).unwrap_or(0);
        let rv = f
            .C_EncryptFinal
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, part.as_mut_ptr(), &raw mut part_len)
            });
        push_probe(rows, "C_EncryptFinal", rv, CKR_OK);
    }
    {
        let mut part = [0_u8; 16];
        let mut part_len = ck_ulong(part.len()).unwrap_or(0);
        let rv = f
            .C_DecryptUpdate
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    part.as_mut_ptr(),
                    16,
                    part.as_mut_ptr(),
                    &raw mut part_len,
                )
            });
        push_probe(rows, "C_DecryptUpdate", rv, CKR_OK);
    }
    {
        let mut part = [0_u8; 16];
        let mut part_len = ck_ulong(part.len()).unwrap_or(0);
        let rv = f
            .C_DecryptFinal
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, part.as_mut_ptr(), &raw mut part_len)
            });
        push_probe(rows, "C_DecryptFinal", rv, CKR_OK);
    }

    // ---- Digest family --------------------------------------------------
    {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_SHA256,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = f
            .C_DigestInit
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, &raw mut mechanism)
            });
        push_probe(rows, "C_DigestInit", rv, CKR_OK);
    }
    {
        let data = b"probe";
        let mut out = [0_u8; 64];
        let mut out_len = ck_ulong(out.len()).unwrap_or(0);
        let rv = f.C_Digest.map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
            c(
                session,
                data.as_ptr().cast_mut(),
                ck_ulong(data.len()).unwrap_or(0),
                out.as_mut_ptr(),
                &raw mut out_len,
            )
        });
        push_probe(rows, "C_Digest", rv, CKR_OK);
    }
    {
        let data = b"probe";
        let rv = f
            .C_DigestUpdate
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    data.as_ptr().cast_mut(),
                    ck_ulong(data.len()).unwrap_or(0),
                )
            });
        push_probe(rows, "C_DigestUpdate", rv, CKR_OK);
    }
    {
        let rv = f
            .C_DigestKey
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, object)
            });
        push_probe(rows, "C_DigestKey", rv, CKR_OK);
    }
    {
        let mut out = [0_u8; 64];
        let mut out_len = ck_ulong(out.len()).unwrap_or(0);
        let rv = f
            .C_DigestFinal
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, out.as_mut_ptr(), &raw mut out_len)
            });
        push_probe(rows, "C_DigestFinal", rv, CKR_OK);
    }

    // ---- Sign/Verify streaming + recover family -----------------------------
    {
        let mut part = [0_u8; 16];
        let rv = f
            .C_SignUpdate
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, part.as_mut_ptr(), 16)
            });
        push_probe(rows, "C_SignUpdate", rv, CKR_OK);
    }
    {
        let mut out = [0_u8; 128];
        let mut out_len = ck_ulong(out.len()).unwrap_or(0);
        let rv = f
            .C_SignFinal
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, out.as_mut_ptr(), &raw mut out_len)
            });
        push_probe(rows, "C_SignFinal", rv, CKR_OK);
    }
    if let Some((sk, pk)) = ctx.rsa {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = f
            .C_SignRecoverInit
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, &raw mut mechanism, sk)
            });
        push_probe(rows, "C_SignRecoverInit", rv, CKR_OK);

        let data = [0x11_u8; 32];
        let mut out = [0_u8; 256];
        let mut out_len = ck_ulong(out.len()).unwrap_or(0);
        let rv = f
            .C_SignRecover
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    data.as_ptr().cast_mut(),
                    ck_ulong(data.len()).unwrap_or(0),
                    out.as_mut_ptr(),
                    &raw mut out_len,
                )
            });
        push_probe(rows, "C_SignRecover", rv, CKR_OK);

        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = f
            .C_VerifyRecoverInit
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, &raw mut mechanism, pk)
            });
        push_probe(rows, "C_VerifyRecoverInit", rv, CKR_OK);

        let sig = [0x22_u8; 256];
        let mut out = [0_u8; 256];
        let mut out_len = ck_ulong(out.len()).unwrap_or(0);
        let rv = f
            .C_VerifyRecover
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    sig.as_ptr().cast_mut(),
                    ck_ulong(sig.len()).unwrap_or(0),
                    out.as_mut_ptr(),
                    &raw mut out_len,
                )
            });
        push_probe(rows, "C_VerifyRecover", rv, CKR_OK);
    } else {
        for name in [
            "C_SignRecoverInit",
            "C_SignRecover",
            "C_VerifyRecoverInit",
            "C_VerifyRecover",
        ] {
            rows.push(CheckResult {
                name,
                detail: "shallow probe (minimal-precondition C_* call)".to_owned(),
                outcome: Outcome::Fail(
                    "no KMS-provisioned RSA key pair was found on the PKCS#11 slot".to_owned(),
                ),
            });
        }
    }
    {
        let mut part = [0_u8; 16];
        let rv = f
            .C_VerifyUpdate
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, part.as_mut_ptr(), 16)
            });
        push_probe(rows, "C_VerifyUpdate", rv, CKR_OK);
    }
    {
        let sig = [0_u8; 128];
        let rv = f
            .C_VerifyFinal
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, sig.as_ptr().cast_mut(), 128)
            });
        push_probe(rows, "C_VerifyFinal", rv, CKR_OK);
    }

    // ---- Dual-function *Update combos --------------------------------------
    {
        let mut part = [0_u8; 16];
        let mut part_len = ck_ulong(part.len()).unwrap_or(0);
        let rv = f
            .C_DigestEncryptUpdate
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    part.as_mut_ptr(),
                    16,
                    part.as_mut_ptr(),
                    &raw mut part_len,
                )
            });
        push_probe(rows, "C_DigestEncryptUpdate", rv, CKR_OK);
    }
    {
        let mut part = [0_u8; 16];
        let mut part_len = ck_ulong(part.len()).unwrap_or(0);
        let rv = f
            .C_DecryptDigestUpdate
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    part.as_mut_ptr(),
                    16,
                    part.as_mut_ptr(),
                    &raw mut part_len,
                )
            });
        push_probe(rows, "C_DecryptDigestUpdate", rv, CKR_OK);
    }
    {
        let mut part = [0_u8; 16];
        let mut part_len = ck_ulong(part.len()).unwrap_or(0);
        let rv = f
            .C_SignEncryptUpdate
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    part.as_mut_ptr(),
                    16,
                    part.as_mut_ptr(),
                    &raw mut part_len,
                )
            });
        push_probe(rows, "C_SignEncryptUpdate", rv, CKR_OK);
    }
    {
        let mut part = [0_u8; 16];
        let mut part_len = ck_ulong(part.len()).unwrap_or(0);
        let rv = f
            .C_DecryptVerifyUpdate
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    part.as_mut_ptr(),
                    16,
                    part.as_mut_ptr(),
                    &raw mut part_len,
                )
            });
        push_probe(rows, "C_DecryptVerifyUpdate", rv, CKR_OK);
    }

    // ---- Key management (generate/wrap/unwrap/derive) -----------------------
    {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut pk: CK_OBJECT_HANDLE = 0;
        let mut sk: CK_OBJECT_HANDLE = 0;
        let rv = f
            .C_GenerateKeyPair
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    &raw mut mechanism,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    0,
                    &raw mut pk,
                    &raw mut sk,
                )
            });
        push_probe(rows, "C_GenerateKeyPair", rv, CKR_OK);
    }
    {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut wrapped = [0_u8; 256];
        let mut wrapped_len = ck_ulong(wrapped.len()).unwrap_or(0);
        let rv = f.C_WrapKey.map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
            c(
                session,
                &raw mut mechanism,
                object,
                object,
                wrapped.as_mut_ptr(),
                &raw mut wrapped_len,
            )
        });
        push_probe(rows, "C_WrapKey", rv, CKR_OK);
    }
    {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut wrapped = [0_u8; 32];
        let mut handle: CK_OBJECT_HANDLE = 0;
        let rv = f
            .C_UnwrapKey
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    &raw mut mechanism,
                    object,
                    wrapped.as_mut_ptr(),
                    ck_ulong(wrapped.len()).unwrap_or(0),
                    ptr::null_mut(),
                    0,
                    &raw mut handle,
                )
            });
        push_probe(rows, "C_UnwrapKey", rv, CKR_OK);
    }
    {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut handle: CK_OBJECT_HANDLE = 0;
        let rv = f
            .C_DeriveKey
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    &raw mut mechanism,
                    object,
                    ptr::null_mut(),
                    0,
                    &raw mut handle,
                )
            });
        push_probe(rows, "C_DeriveKey", rv, CKR_OK);
    }
    {
        let seed = [0x42_u8; 16];
        let rv = f
            .C_SeedRandom
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    seed.as_ptr().cast_mut(),
                    ck_ulong(seed.len()).unwrap_or(0),
                )
            });
        push_probe(rows, "C_SeedRandom", rv, CKR_OK);
    }
    {
        let mut random = [0_u8; 16];
        let rv = f
            .C_GenerateRandom
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, random.as_mut_ptr(), 16)
            });
        push_probe(rows, "C_GenerateRandom", rv, CKR_OK);
    }

    // ---- Legacy parallel-function-manager stubs (spec-mandated to always
    // return `CKR_FUNCTION_NOT_PARALLEL`, never `CKR_OK`) ---------------------
    {
        let rv = f
            .C_GetFunctionStatus
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe { c(session) });
        push_probe(rows, "C_GetFunctionStatus", rv, CKR_FUNCTION_NOT_PARALLEL);
    }
    {
        let rv = f
            .C_CancelFunction
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe { c(session) });
        push_probe(rows, "C_CancelFunction", rv, CKR_FUNCTION_NOT_PARALLEL);
    }
    {
        let mut event_slot: CK_SLOT_ID = 0;
        // Called with `CKF_DONT_BLOCK` (Decision 4): a spec-legal non-blocking
        // poll, never risking a hang.
        let rv = f
            .C_WaitForSlotEvent
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(CKF_DONT_BLOCK, &raw mut event_slot, ptr::null_mut())
            });
        push_probe(rows, "C_WaitForSlotEvent", rv, CKR_OK);
    }
    {
        let pin = b"0000";
        let rv = func_list_3_0
            .C_LoginUser
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    CKU_USER,
                    pin.as_ptr().cast_mut(),
                    ck_ulong(pin.len()).unwrap_or(0),
                    ptr::null_mut(),
                    0,
                )
            });
        push_probe(rows, "C_LoginUser", rv, CKR_OK);
    }
    {
        let rv = func_list_3_0
            .C_SessionCancel
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe { c(session, 0) });
        push_probe(rows, "C_SessionCancel", rv, CKR_OK);
    }

    // ---- v3.0 message-based encrypt/decrypt/verify families (all stubs in
    // cosmian_pkcs11 today) ---------------------------------------------------
    {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = func_list_3_0
            .C_MessageEncryptInit
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, &raw mut mechanism, object)
            });
        push_probe(rows, "C_MessageEncryptInit", rv, CKR_OK);
    }
    {
        let mut pt = [0_u8; 16];
        let mut ct = [0_u8; 32];
        let mut ct_len = ck_ulong(ct.len()).unwrap_or(0);
        let rv = func_list_3_0
            .C_EncryptMessage
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    0,
                    pt.as_mut_ptr(),
                    16,
                    ct.as_mut_ptr(),
                    &raw mut ct_len,
                )
            });
        push_probe(rows, "C_EncryptMessage", rv, CKR_OK);
    }
    {
        let mut pt = [0_u8; 16];
        let mut ct = [0_u8; 32];
        let mut ct_len = ck_ulong(ct.len()).unwrap_or(0);
        let rv = func_list_3_0
            .C_EncryptMessageBegin
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, ptr::null_mut(), 0, ptr::null_mut(), 0)
            });
        push_probe(rows, "C_EncryptMessageBegin", rv, CKR_OK);
        let rv =
            func_list_3_0
                .C_EncryptMessageNext
                .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                    c(
                        session,
                        ptr::null_mut(),
                        0,
                        pt.as_mut_ptr(),
                        16,
                        ct.as_mut_ptr(),
                        &raw mut ct_len,
                        0,
                    )
                });
        push_probe(rows, "C_EncryptMessageNext", rv, CKR_OK);
    }
    {
        let rv = func_list_3_0
            .C_MessageEncryptFinal
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe { c(session) });
        push_probe(rows, "C_MessageEncryptFinal", rv, CKR_OK);
    }
    {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = func_list_3_0
            .C_MessageDecryptInit
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, &raw mut mechanism, object)
            });
        push_probe(rows, "C_MessageDecryptInit", rv, CKR_OK);
    }
    {
        let mut ct = [0_u8; 16];
        let mut pt = [0_u8; 32];
        let mut pt_len = ck_ulong(pt.len()).unwrap_or(0);
        let rv = func_list_3_0
            .C_DecryptMessage
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    0,
                    ct.as_mut_ptr(),
                    16,
                    pt.as_mut_ptr(),
                    &raw mut pt_len,
                )
            });
        push_probe(rows, "C_DecryptMessage", rv, CKR_OK);
    }
    {
        let mut ct = [0_u8; 16];
        let mut pt = [0_u8; 32];
        let mut pt_len = ck_ulong(pt.len()).unwrap_or(0);
        let rv = func_list_3_0
            .C_DecryptMessageBegin
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, ptr::null_mut(), 0, ptr::null_mut(), 0)
            });
        push_probe(rows, "C_DecryptMessageBegin", rv, CKR_OK);
        let rv =
            func_list_3_0
                .C_DecryptMessageNext
                .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                    c(
                        session,
                        ptr::null_mut(),
                        0,
                        ct.as_mut_ptr(),
                        16,
                        pt.as_mut_ptr(),
                        &raw mut pt_len,
                        0,
                    )
                });
        push_probe(rows, "C_DecryptMessageNext", rv, CKR_OK);
    }
    {
        let rv = func_list_3_0
            .C_MessageDecryptFinal
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe { c(session) });
        push_probe(rows, "C_MessageDecryptFinal", rv, CKR_OK);
    }
    {
        let mut sig = [0_u8; 128];
        let mut sig_len = ck_ulong(sig.len()).unwrap_or(0);
        let rv = func_list_3_0
            .C_SignMessageBegin
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, ptr::null_mut(), 0)
            });
        push_probe(rows, "C_SignMessageBegin", rv, CKR_OK);
        let mut data = [0_u8; 16];
        let rv = func_list_3_0
            .C_SignMessageNext
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    ptr::null_mut(),
                    0,
                    data.as_mut_ptr(),
                    16,
                    sig.as_mut_ptr(),
                    &raw mut sig_len,
                )
            });
        push_probe(rows, "C_SignMessageNext", rv, CKR_OK);
    }
    {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = func_list_3_0
            .C_MessageVerifyInit
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, &raw mut mechanism, object)
            });
        push_probe(rows, "C_MessageVerifyInit", rv, CKR_OK);
    }
    {
        let mut data = [0_u8; 16];
        let mut sig = [0_u8; 128];
        let rv = func_list_3_0
            .C_VerifyMessage
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    ptr::null_mut(),
                    0,
                    data.as_mut_ptr(),
                    16,
                    sig.as_mut_ptr(),
                    128,
                )
            });
        push_probe(rows, "C_VerifyMessage", rv, CKR_OK);
    }
    {
        let rv = func_list_3_0
            .C_VerifyMessageBegin
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(session, ptr::null_mut(), 0)
            });
        push_probe(rows, "C_VerifyMessageBegin", rv, CKR_OK);
        let mut data = [0_u8; 16];
        let mut sig = [0_u8; 128];
        let rv = func_list_3_0
            .C_VerifyMessageNext
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe {
                c(
                    session,
                    ptr::null_mut(),
                    0,
                    data.as_mut_ptr(),
                    16,
                    sig.as_mut_ptr(),
                    128,
                )
            });
        push_probe(rows, "C_VerifyMessageNext", rv, CKR_OK);
    }
    {
        let rv = func_list_3_0
            .C_MessageVerifyFinal
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe { c(session) });
        push_probe(rows, "C_MessageVerifyFinal", rv, CKR_OK);
    }

    // ---- Session/token-lifecycle-terminating functions (called last: they
    // invalidate `session`/log the token out, so no other probe can safely
    // run afterward) -----------------------------------------------------------
    {
        let rv = f
            .C_Logout
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe { c(session) });
        push_probe(rows, "C_Logout", rv, CKR_OK);
    }
    {
        let rv = f
            .C_CloseAllSessions
            .map_or(CKR_FUNCTION_NOT_SUPPORTED, |c| unsafe { c(slot_id) });
        push_probe(rows, "C_CloseAllSessions", rv, CKR_OK);
    }
}

/// Prints one report section (either "PKCS#11 API function coverage" or "PKCS#11
/// mechanism coverage"). Every row is always printed individually — the whole
/// point of this report is to show exactly what is and is not supported, so
/// nothing is collapsed or hidden.
fn print_section(title: &str, results: &[CheckResult]) {
    println!("{title}");
    println!("{}", "=".repeat(title.chars().count()));
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    let mut not_implemented = 0;
    let mut excluded = 0;
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
            Outcome::NotImplemented(reason) => {
                not_implemented += 1;
                ("❌".to_owned(), format!(" (not implemented: {reason})"))
            }
            Outcome::Excluded(reason) => {
                excluded += 1;
                ("⬛".to_owned(), format!(" (excluded: {reason})"))
            }
        };
        println!("{icon} {} — {}{detail}", result.name, result.detail);
    }
    println!();
    println!(
        "{passed} passed, {failed} failed, {skipped} skipped, {not_implemented} not \
         implemented, {excluded} excluded ({} total).",
        results.len()
    );
    println!();
}
