//! Safe wrappers around the PKCS#11 v3.0 interface-discovery bindings.
//!
//! `pkcs11-sys` v0.2.25 already provides the Cryptoki v3.0 ABI types used here.
//! This module adds only the owned representation needed by [`HsmLib`](crate::HsmLib)
//! to report interfaces without exposing native pointers.
//!
//! This is a **capability probe only**: it is purely additive and optional.
//! `HsmLib` keeps resolving every Cryptoki function by stable per-symbol name as it
//! always has (see `hsm_lib.rs`), so v2.x-only HSMs are completely unaffected —
//! `C_GetInterfaceList` is
//! simply absent from the library and the probe reports "not supported".
use std::{ffi::CStr, os::raw::c_char};

use pkcs11_sys::{CK_C_GetInterfaceList, CK_INTERFACE};

pub(crate) type CkInterface = CK_INTERFACE;
pub(crate) type CkCGetInterfaceList = CK_C_GetInterfaceList;

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
