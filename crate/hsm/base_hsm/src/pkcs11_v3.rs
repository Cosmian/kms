//! Safe wrappers around the PKCS#11 v3.0 interface-discovery bindings.
//!
//! `pkcs11-sys` v0.2.25 already provides the Cryptoki v3.0 ABI types used here.
//! This module adds the owned representation needed by [`HsmLib`](crate::HsmLib)
//! to report interfaces without exposing native pointers, **and** the function-table
//! resolution helpers used as a fallback when a loaded library does not export
//! individual `C_XXX` symbols directly (see `get_v3_function_list`/`get_v2_function_list`
//! below).
//!
//! Per the OASIS Cryptoki specification, the *only* function-resolution mechanism a
//! conformant library is required to support is the function-table entry points
//! (`C_GetFunctionList` since v2.0, `C_GetInterfaceList`/`C_GetInterface` since v3.0).
//! Exporting every `C_XXX` symbol individually (so it can be resolved with a plain
//! per-symbol `dlsym`) is a de facto convention followed by `SoftHSM2`, Utimaco,
//! Proteccio, etc. — but it is *not* mandated by the spec, and strictly
//! spec-conformant libraries (e.g. the Kryoptic PKCS#11 v3.0 software token used for
//! v3.0 conformance testing, see `test_helpers::kryoptic`) export only the three
//! table-entry symbols. `HsmLib::instantiate` therefore tries per-symbol `dlsym`
//! first (preserving today's exact behavior for every supported production HSM
//! backend) and falls back to the function table — preferring the v3.0 interface
//! (a superset of the v2.40 one) over the base `C_GetFunctionList` result — only for
//! symbols that per-symbol resolution could not find.
use std::{ffi::CStr, os::raw::c_char};

use libloading::Library;
use pkcs11_sys::{
    CK_C_GetFunctionList, CK_C_GetInterface, CK_C_GetInterfaceList, CK_FUNCTION_LIST,
    CK_FUNCTION_LIST_3_0, CK_INTERFACE, CK_INTERFACE_PTR, CK_RV, CK_VERSION, CKR_OK,
};

pub(crate) type CkInterface = CK_INTERFACE;
pub(crate) type CkCGetInterfaceList = CK_C_GetInterfaceList;

/// Resolves the PKCS#11 v3.0 "PKCS 11" interface's function list, if the library
/// exports `C_GetInterface` and reports a version-3.x interface.
///
/// Requests the interface with `pVersion = NULL_PTR` (accept the library's newest
/// "PKCS 11" interface, of *any* 3.x minor version — per OASIS Cryptoki v3.1 §5.2,
/// an exact-match request would incorrectly reject a conformant v3.1/v3.2-only
/// library), then verifies the returned interface's version is actually a 3.x one
/// before treating `pFunctionList` as a `CK_FUNCTION_LIST_3_0`.
///
/// Returns `None` for any library that does not export `C_GetInterface` (e.g. every
/// v2.40-only HSM backend supported today) or that does not expose a v3.0 (or
/// later 3.x) "PKCS 11" interface. Never fails `instantiate`.
///
/// # Safety
///
/// `library` must be a validly loaded PKCS#11 shared library. This function performs
/// FFI calls into it and dereferences the pointers it returns, trusting it to behave
/// according to the OASIS Cryptoki v3.0 specification for `C_GetInterface`.
#[expect(unsafe_code)]
pub(crate) unsafe fn get_v3_function_list(library: &Library) -> Option<CK_FUNCTION_LIST_3_0> {
    // SAFETY: `library` is a validly loaded shared library (guaranteed by the caller,
    // `HsmLib::instantiate`). `library.get` only performs symbol lookup, which is safe
    // regardless of the symbol's actual signature; the transmuted function pointer type
    // is only invoked below, where the real safety requirement applies.
    let get_interface: CK_C_GetInterface = unsafe { *library.get(b"C_GetInterface").ok()? };
    let get_interface = get_interface?;

    let mut name = *b"PKCS 11\0";
    // Per OASIS Cryptoki v3.1 §5.2 `C_GetInterface`: "If pVersion is not NULL_PTR,
    // the version of the interface returned must match [exactly]. If pVersion is
    // NULL_PTR, the cryptoki library can return an interface of any version."
    // Passing a hardcoded `{major: 3, minor: 0}` here would make this call fail for
    // any strictly conformant library whose "PKCS 11" interface is versioned 3.1 or
    // 3.2 (an exact-match request for 3.0 does not match a 3.1/3.2 interface),
    // causing `HsmLib` to wrongly report *no* v3 support at all for a fully v3.1/3.2
    // capable library. Passing NULL here lets the library return its own newest
    // "PKCS 11" interface version; the returned version is then checked below.
    let mut p_interface: CK_INTERFACE_PTR = std::ptr::null_mut();
    // SAFETY: `name` is a NUL-terminated buffer we own for the duration of this call,
    // as required by `C_GetInterface`. `p_interface` is a valid, properly aligned
    // local out-parameter. `get_interface` was resolved from the loaded library and
    // is trusted to implement the documented `C_GetInterface` ABI.
    let rv: CK_RV = unsafe {
        get_interface(
            name.as_mut_ptr(),
            std::ptr::null_mut(),
            &raw mut p_interface,
            0,
        )
    };
    if rv != CKR_OK || p_interface.is_null() {
        return None;
    }
    // SAFETY: `p_interface` was just returned as non-null by a successful
    // `C_GetInterface` call.
    let interface = unsafe { *p_interface };
    if interface.pFunctionList.is_null() {
        return None;
    }
    // The "PKCS 11" interface's `pFunctionList` is a `CK_VERSION` in its first two
    // bytes (the `version` field shared by every `CK_FUNCTION_LIST*` layout since
    // v2.0), so its major version can be checked before committing to the
    // `CK_FUNCTION_LIST_3_0` cast below. Reject anything that isn't a 3.x "PKCS 11"
    // interface (e.g. a library that, despite the NULL version request, returned its
    // v2.40 interface instead) — `pkcs11-sys` 0.2.25 defines a single
    // `CK_FUNCTION_LIST_3_0` struct shape shared by v3.0/3.1/3.2 (the spec did not
    // change the base function-list layout in 3.1/3.2, only added mechanisms/flags),
    // so this cast is valid for any 3.x minor version, not just 3.0.
    // SAFETY: `pFunctionList` is non-null (checked above) and, per spec, points to a
    // struct beginning with a `CK_VERSION` for the lifetime of the library.
    let version = unsafe { *interface.pFunctionList.cast::<CK_VERSION>() };
    if version.major != 3 {
        return None;
    }
    // SAFETY: see above — `pFunctionList` is guaranteed by the spec, for a
    // successfully negotiated 3.x "PKCS 11" interface, to point to a valid
    // `CK_FUNCTION_LIST_3_0` for the lifetime of the library.
    Some(unsafe { *interface.pFunctionList.cast::<CK_FUNCTION_LIST_3_0>() })
}

/// Resolves the base PKCS#11 v2.40 function list via `C_GetFunctionList`, the
/// spec-mandated entry point present in every conformant Cryptoki library since
/// v2.0. Returns `None` only if the library does not export `C_GetFunctionList` at
/// all (a spec violation, but handled defensively) or the call itself fails.
///
/// # Safety
///
/// `library` must be a validly loaded PKCS#11 shared library, as for
/// `get_v3_function_list`.
#[expect(unsafe_code)]
pub(crate) unsafe fn get_v2_function_list(library: &Library) -> Option<CK_FUNCTION_LIST> {
    // SAFETY: see `get_v3_function_list` — symbol lookup alone is safe.
    let get_function_list: CK_C_GetFunctionList =
        unsafe { *library.get(b"C_GetFunctionList").ok()? };
    let get_function_list = get_function_list?;

    let mut p_list = std::ptr::null_mut();
    // SAFETY: `p_list` is a valid, properly aligned local out-parameter;
    // `get_function_list` was resolved from the loaded library and is trusted to
    // implement the documented `C_GetFunctionList` ABI.
    let rv: CK_RV = unsafe { get_function_list(&raw mut p_list) };
    if rv != CKR_OK || p_list.is_null() {
        return None;
    }
    // SAFETY: `p_list` was just returned as non-null by a successful
    // `C_GetFunctionList` call, which per spec must point to a valid
    // `CK_FUNCTION_LIST` for the lifetime of the library.
    Some(unsafe { *p_list })
}

/// A capability-probe-only description of a PKCS#11 v3.0 interface entry.
///
/// This intentionally does not expose `pFunctionList`: safely consuming it would
/// require binding the full v3.0 function-list layout, which is out of scope for the
/// capability probe introduced by this change (see issue #1153).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDescriptor {
    /// The interface name reported by the library, e.g. `"PKCS 11"` or `"Vendor PKCS 11"`.
    pub name: String,
    /// Raw `CK_FLAGS` reported for this interface.
    pub flags: u64,
}

/// Parses raw `CK_INTERFACE` entries returned by `C_GetInterfaceList` into safe, owned
/// descriptors.
///
/// # Safety
///
/// Each `p_interface_name` pointer, when non-null, must point to a NUL-terminated C
/// string valid for the duration of this call, as guaranteed by the PKCS#11 v3.0
/// specification for `C_GetInterfaceList`.
pub(crate) fn parse_interfaces(raw: &[CkInterface]) -> Vec<InterfaceDescriptor> {
    raw.iter()
        .map(|entry| {
            let name = if entry.pInterfaceName.is_null() {
                String::new()
            } else {
                // SAFETY: `pInterfaceName` is guaranteed by the PKCS#11 v3.0 spec to
                // point to a NUL-terminated string for the duration of this call.
                #[expect(unsafe_code)]
                unsafe {
                    CStr::from_ptr(entry.pInterfaceName.cast::<c_char>())
                        .to_string_lossy()
                        .into_owned()
                }
            };
            InterfaceDescriptor {
                name,
                #[cfg(target_os = "windows")]
                flags: u64::from(entry.flags),
                #[cfg(not(target_os = "windows"))]
                flags: entry.flags,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{CkInterface, InterfaceDescriptor, parse_interfaces};

    #[test]
    fn parse_interfaces_empty() {
        assert_eq!(parse_interfaces(&[]), Vec::new());
    }

    #[test]
    fn parse_interfaces_null_name() {
        let raw = [CkInterface::default()];
        assert_eq!(
            parse_interfaces(&raw),
            vec![InterfaceDescriptor {
                name: String::new(),
                flags: 0,
            }]
        );
    }

    #[test]
    fn parse_interfaces_named() {
        let name = c"PKCS 11";
        let raw = [CkInterface {
            pInterfaceName: name.as_ptr().cast_mut().cast(),
            pFunctionList: std::ptr::null_mut(),
            flags: 3,
        }];
        assert_eq!(
            parse_interfaces(&raw),
            vec![InterfaceDescriptor {
                name: "PKCS 11".to_owned(),
                flags: 3,
            }]
        );
    }
}
