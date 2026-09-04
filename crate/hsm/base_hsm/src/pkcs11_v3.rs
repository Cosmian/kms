//! Minimal, hand-written PKCS#11 v3.0 additions.
//!
//! The vendored `pkcs11-sys` crate (v0.2.25) only binds the Cryptoki v2.40 header
//! surface: it has no `CK_INTERFACE`, no `C_GetInterfaceList`/`C_GetInterface`, and
//! none of the v3.0 mechanism constants. Forking/regenerating `pkcs11-sys` in full is
//! out of scope for this change (see issue #1153); instead this module hand-writes
//! only the small additional FFI surface required to *detect* whether a loaded
//! PKCS#11 library exposes the v3.0 "interfaces" discovery mechanism.
//!
//! This is a **capability probe only**: it is purely additive and optional.
//! `HsmLib` keeps resolving every Cryptoki function by stable per-symbol name as it
//! always has (see `hsm_lib.rs`), so v2.x-only HSMs (e.g. `SoftHSM2`, which only
//! implements Cryptoki v2.40) are completely unaffected — `C_GetInterfaceList` is
//! simply absent from the library and the probe reports "not supported".
use std::{ffi::CStr, os::raw::c_char};

use pkcs11_sys::{CK_CHAR_PTR, CK_FLAGS, CK_RV, CK_ULONG_PTR, CK_VOID_PTR};

/// Mirrors the PKCS#11 v3.0 `CK_INTERFACE` structure (OASIS Cryptoki v3.0 §3.2).
///
/// The layout must match the native C struct exactly: it is populated in place by
/// `C_GetInterfaceList`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CkInterface {
    pub(crate) p_interface_name: CK_CHAR_PTR,
    pub(crate) p_function_list: CK_VOID_PTR,
    pub(crate) flags: CK_FLAGS,
}

impl Default for CkInterface {
    fn default() -> Self {
        Self {
            p_interface_name: std::ptr::null_mut(),
            p_function_list: std::ptr::null_mut(),
            flags: 0,
        }
    }
}

pub(crate) type CkInterfacePtr = *mut CkInterface;

/// `CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfacesList, CK_ULONG_PTR pulCount);`
///
/// Per the OASIS Cryptoki v3.0 spec, this follows the same two-call convention as the
/// pre-existing `C_GetMechanismList`/`C_FindObjects` usage in this crate: call once with
/// a `NULL` buffer to obtain the count, then again with an allocated buffer of that size.
pub(crate) type CkCGetInterfaceList = Option<
    unsafe extern "C" fn(p_interfaces_list: CkInterfacePtr, pul_count: CK_ULONG_PTR) -> CK_RV,
>;

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
            let name = if entry.p_interface_name.is_null() {
                String::new()
            } else {
                // SAFETY: `p_interface_name` is guaranteed by the PKCS#11 v3.0 spec to
                // point to a NUL-terminated string for the duration of this call.
                #[expect(unsafe_code)]
                unsafe {
                    CStr::from_ptr(entry.p_interface_name.cast::<c_char>())
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
    use std::ffi::CString;

    use super::{CkInterface, parse_interfaces};

    #[test]
    fn parse_interfaces_empty() {
        assert_eq!(parse_interfaces(&[]), Vec::new());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_interfaces_null_name() {
        let raw = [CkInterface::default()];
        let parsed = parse_interfaces(&raw);
        assert_eq!(parsed.len(), 1);
        let entry = parsed.first().expect("one entry expected");
        assert_eq!(entry.name, "");
        assert_eq!(entry.flags, 0);
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unreachable)]
    fn parse_interfaces_named() {
        let Ok(name) = CString::new("PKCS 11") else {
            unreachable!("literal without NUL bytes is always a valid C string")
        };
        let raw = [CkInterface {
            p_interface_name: name.as_ptr().cast_mut().cast(),
            p_function_list: std::ptr::null_mut(),
            flags: 3,
        }];
        let parsed = parse_interfaces(&raw);
        assert_eq!(parsed.len(), 1);
        let entry = parsed.first().expect("one entry expected");
        assert_eq!(entry.name, "PKCS 11");
        assert_eq!(entry.flags, 3);
    }
}
