#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pkcs11_raw_abi_check.py — Raw Cryptoki C-ABI harness for `cosmian_pkcs11`.

`pkcs11-tool` has no CLI flag for a handful of PKCS#11 functions this module
implements or deliberately stubs out. This script `ctypes.CDLL()`s the built
`cosmian_pkcs11` cdylib directly and calls the raw, exported `C_*` symbols by
hand — a genuinely independent caller (neither `pkcs11-tool` nor the crate's
own Rust test harness).

Ground truth for expected return codes comes directly from
`crate/clients/pkcs11/module/src/pkcs11.rs`:
  - Functions built with the `cryptoki_fn_not_supported!` macro ignore their
    arguments entirely and return `CKR_FUNCTION_NOT_SUPPORTED` (0x54) — safe
    to call with null/zeroed arguments.
  - `C_SeedRandom` returns `CKR_RANDOM_NO_RNG` (0x121) — a valid, spec-
    sanctioned "we don't accept externally-seeded entropy" response, not a bug.
  - `C_GetFunctionStatus`/`C_CancelFunction` return `CKR_FUNCTION_NOT_PARALLEL`
    (0x51) — the spec-sanctioned response for a module with no parallel
    operations to report on/cancel, not a bug.
  - `C_MessageSignInit` only accepts `CKM_EDDSA` (any other mechanism ->
    `CKR_FUNCTION_NOT_SUPPORTED`); a genuine end-to-end
    C_MessageSignInit/C_SignMessage/C_MessageSignFinal round trip is only
    exercised for EdDSA keys.

Output contract: exactly one line per check on stdout — a green "\u2705" for a
real, working PASS, or a red "\u274c" for either a genuine FAIL or an expected
"declared but not supported" boundary check (both cases print red so
unsupported-by-design behavior is visually distinct from a real failure; only
the latter increments the internal failure/exit-code count). Non-zero exit if
any check failed.

Usage:
  python3 pkcs11_raw_abi_check.py --module /path/to/libcosmian_pkcs11.so \
      --check not-supported
  python3 pkcs11_raw_abi_check.py --module ... --check legacy-ok
  python3 pkcs11_raw_abi_check.py --module ... --check message-sign \
      --priv-id <kms-uid> --pub-id <kms-uid> --mechanism EDDSA --expect ok
"""

from __future__ import annotations

import argparse
import ctypes
import os
import sys

CK_ULONG = ctypes.c_ulong
CK_RV = CK_ULONG
CK_FLAGS = CK_ULONG
CK_SESSION_HANDLE = CK_ULONG
CK_SLOT_ID = CK_ULONG
CK_OBJECT_HANDLE = CK_ULONG
CK_OBJECT_CLASS = CK_ULONG
CK_MECHANISM_TYPE = CK_ULONG
CK_ATTRIBUTE_TYPE = CK_ULONG
CK_USER_TYPE = CK_ULONG
CK_BBOOL = ctypes.c_ubyte

CKR_OK = 0
CKR_FUNCTION_NOT_PARALLEL = 0x51
CKR_FUNCTION_NOT_SUPPORTED = 0x54
CKR_RANDOM_NO_RNG = 0x121

CKF_SERIAL_SESSION = 0x4
CKF_RW_SESSION = 0x2

CKU_SO = 0
CKU_USER = 1

CKO_PUBLIC_KEY = 2
CKO_PRIVATE_KEY = 3

CKA_CLASS = 0x00
CKA_ID = 0x102

CKM_RSA_PKCS = 0x1
CKM_ECDSA = 0x1041
CKM_EDDSA = 0x1057

MECHANISM_NAME_TO_CKM = {
    'RSA-PKCS': CKM_RSA_PKCS,
    'SHA1-RSA-PKCS': 0x6,
    'SHA256-RSA-PKCS': 0x40,
    'SHA384-RSA-PKCS': 0x41,
    'SHA512-RSA-PKCS': 0x42,
    'RSA-PKCS-PSS': 0xD,
    'ECDSA': CKM_ECDSA,
    'EDDSA': CKM_EDDSA,
}


class CK_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ('type_', CK_ATTRIBUTE_TYPE),
        ('pValue', ctypes.c_void_p),
        ('ulValueLen', CK_ULONG),
    ]


class CK_MECHANISM(ctypes.Structure):
    _fields_ = [
        ('mechanism', CK_MECHANISM_TYPE),
        ('pParameter', ctypes.c_void_p),
        ('ulParameterLen', CK_ULONG),
    ]


def rv_name(rv: int) -> str:
    return {
        CKR_OK: 'CKR_OK',
        CKR_FUNCTION_NOT_PARALLEL: 'CKR_FUNCTION_NOT_PARALLEL',
        CKR_FUNCTION_NOT_SUPPORTED: 'CKR_FUNCTION_NOT_SUPPORTED',
        CKR_RANDOM_NO_RNG: 'CKR_RANDOM_NO_RNG',
    }.get(rv, f"0x{rv:x}")


class Harness:
    """Owns the dlopen()'d library, the module lifecycle, and one open,
    logged-in session — shared setup for every check in this script."""

    def __init__(self, module_path: str, ckms_conf: str | None) -> None:
        if ckms_conf:
            os.environ['CKMS_CONF'] = ckms_conf
        self.lib = ctypes.CDLL(module_path)
        self._declare_signatures()
        self.total = 0
        self.failed = 0

        # Per the PKCS#11 spec, C_GetFunctionList is the very first function a
        # real caller invokes to discover the module's entry points; this
        # module also lazily registers its KMS backend (and initializes
        # logging) the first time C_GetFunctionList/C_GetInterface{,List} is
        # called (see `ensure_backend_registered` in
        # crate/clients/pkcs11/provider/src/lib.rs). Skipping this call
        # leaves the backend unregistered, so every later call that needs it
        # (e.g. C_FindObjectsInit) fails with a spurious CKR_USER_NOT_LOGGED_IN
        # even after a successful C_Login.
        self.lib.C_GetFunctionList.argtypes = [ctypes.c_void_p]
        self.lib.C_GetFunctionList.restype = CK_RV
        function_list_ptr = ctypes.c_void_p()
        rv = self.lib.C_GetFunctionList(ctypes.byref(function_list_ptr))
        if rv != CKR_OK:
            raise RuntimeError(f"C_GetFunctionList failed: {rv_name(rv)}")

        rv = self.lib.C_Initialize(None)
        if rv != CKR_OK:
            raise RuntimeError(f"C_Initialize failed: {rv_name(rv)}")

        # Discover the real slot ID for the present token dynamically instead
        # of assuming slot 0: this module's slot numbering reserves slot 0 for
        # "no token present" and the actual token lives on slot 1 (matching
        # what `pkcs11-tool -L`/`-T` report), so a hardcoded slot 0 here would
        # always fail C_OpenSession with CKR_SLOT_ID_INVALID.
        slot_count = CK_ULONG(0)
        rv = self.lib.C_GetSlotList(CK_BBOOL(1), None, ctypes.byref(slot_count))
        if rv != CKR_OK or slot_count.value == 0:
            raise RuntimeError(
                f"C_GetSlotList (count) failed: {rv_name(rv)}, count={slot_count.value}"
            )
        slots = (CK_SLOT_ID * slot_count.value)()
        rv = self.lib.C_GetSlotList(CK_BBOOL(1), slots, ctypes.byref(slot_count))
        if rv != CKR_OK:
            raise RuntimeError(f"C_GetSlotList (fetch) failed: {rv_name(rv)}")
        slot_id = slots[0]

        session = CK_SESSION_HANDLE(0)
        rv = self.lib.C_OpenSession(
            CK_SLOT_ID(slot_id),
            CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION),
            None,
            None,
            ctypes.byref(session),
        )
        if rv != CKR_OK:
            raise RuntimeError(f"C_OpenSession failed: {rv_name(rv)}")
        self.session = session

        # Any PIN succeeds in this suite's ckms.toml/server_url-based config
        # (login_with_pin() only inspects the PIN under OIDC pin-as-access-
        # token mode) — see pkcs11.rs::login_with_pin.
        pin = b'0000'
        rv = self.lib.C_Login(
            self.session,
            CK_USER_TYPE(CKU_SO),
            ctypes.cast(pin, ctypes.c_void_p),
            CK_ULONG(len(pin)),
        )
        if rv != CKR_OK:
            raise RuntimeError(f"C_Login failed: {rv_name(rv)}")

    def _declare_signatures(self) -> None:
        self.lib.C_Initialize.argtypes = [ctypes.c_void_p]
        self.lib.C_Initialize.restype = CK_RV
        self.lib.C_GetSlotList.argtypes = [
            CK_BBOOL,
            ctypes.POINTER(CK_SLOT_ID),
            ctypes.POINTER(CK_ULONG),
        ]
        self.lib.C_GetSlotList.restype = CK_RV
        self.lib.C_OpenSession.argtypes = [
            CK_SLOT_ID,
            CK_FLAGS,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(CK_SESSION_HANDLE),
        ]
        self.lib.C_OpenSession.restype = CK_RV
        self.lib.C_Login.argtypes = [
            CK_SESSION_HANDLE,
            CK_USER_TYPE,
            ctypes.c_void_p,
            CK_ULONG,
        ]
        self.lib.C_Login.restype = CK_RV
        self.lib.C_FindObjectsInit.argtypes = [
            CK_SESSION_HANDLE,
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
        ]
        self.lib.C_FindObjectsInit.restype = CK_RV
        self.lib.C_FindObjects.argtypes = [
            CK_SESSION_HANDLE,
            ctypes.POINTER(CK_OBJECT_HANDLE),
            CK_ULONG,
            ctypes.POINTER(CK_ULONG),
        ]
        self.lib.C_FindObjects.restype = CK_RV
        self.lib.C_FindObjectsFinal.argtypes = [CK_SESSION_HANDLE]
        self.lib.C_FindObjectsFinal.restype = CK_RV

    def check(self, label: str, ok: bool, detail: str = '') -> None:
        self.total += 1
        if ok:
            print(f"\u2705 {label}")
        else:
            self.failed += 1
            print(f"\u274c {label}: {detail}")

    def check_unsupported(self, label: str, ok: bool, detail: str = '') -> None:
        """Like `check`, but for the "declared but not supported" boundary:
        a clean `CKR_FUNCTION_NOT_SUPPORTED`-class rejection is the expected,
        correct outcome (still counts as an overall PASS, does not increment
        `self.failed`), but the function is genuinely unimplemented, so the
        line is always printed with a red cross to make unsupported-by-design
        behavior visually distinct from real, working functionality."""
        self.total += 1
        if ok:
            print(f"\u274c {label} (unsupported by design)")
        else:
            self.failed += 1
            print(f"\u274c {label}: {detail}")

    def find_key_handle(self, kms_uid: str, cko_class: int) -> int | None:
        """Look up the PKCS#11 object handle for a KMS unique identifier by
        its CKA_ID (the module stores the KMS UID, UTF-8 encoded, as
        CKA_ID — see crate/clients/pkcs11/module/src/traits/mod.rs)."""
        id_bytes = kms_uid.encode('utf-8')
        id_buf = ctypes.create_string_buffer(id_bytes, len(id_bytes))
        class_buf = CK_OBJECT_CLASS(cko_class)
        template = (CK_ATTRIBUTE * 2)(
            CK_ATTRIBUTE(CKA_ID, ctypes.cast(id_buf, ctypes.c_void_p), len(id_bytes)),
            CK_ATTRIBUTE(
                CKA_CLASS,
                ctypes.cast(ctypes.byref(class_buf), ctypes.c_void_p),
                ctypes.sizeof(class_buf),
            ),
        )
        rv = self.lib.C_FindObjectsInit(self.session, template, CK_ULONG(2))
        if rv != CKR_OK:
            return None
        handle = CK_OBJECT_HANDLE(0)
        count = CK_ULONG(0)
        rv = self.lib.C_FindObjects(
            self.session, ctypes.byref(handle), CK_ULONG(1), ctypes.byref(count)
        )
        self.lib.C_FindObjectsFinal(self.session)
        if rv != CKR_OK or count.value == 0:
            return None
        return handle.value


def run_not_supported_battery(h: Harness) -> None:
    """Every function stubbed with `cryptoki_fn_not_supported!` ignores its
    arguments entirely (see the macro definition in pkcs11.rs), so it is safe
    to call each with null/zeroed arguments and assert the exact,
    documented CKR_FUNCTION_NOT_SUPPORTED return code."""
    lib = h.lib
    s = h.session

    def declare(name: str, argtypes: list) -> ctypes._FuncPointer:
        fn = getattr(lib, name)
        fn.argtypes = argtypes
        fn.restype = CK_RV
        return fn

    checks = [
        (
            'C_CopyObject',
            declare(
                'C_CopyObject',
                [
                    CK_SESSION_HANDLE,
                    CK_OBJECT_HANDLE,
                    ctypes.c_void_p,
                    CK_ULONG,
                    ctypes.c_void_p,
                ],
            ),
            (s, CK_OBJECT_HANDLE(0), None, CK_ULONG(0), None),
        ),
        (
            'C_GetObjectSize',
            declare(
                'C_GetObjectSize',
                [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, ctypes.c_void_p],
            ),
            (s, CK_OBJECT_HANDLE(0), None),
        ),
        (
            'C_GetOperationState',
            declare(
                'C_GetOperationState',
                [CK_SESSION_HANDLE, ctypes.c_void_p, ctypes.c_void_p],
            ),
            (s, None, None),
        ),
        (
            'C_SetOperationState',
            declare(
                'C_SetOperationState',
                [
                    CK_SESSION_HANDLE,
                    ctypes.c_void_p,
                    CK_ULONG,
                    CK_OBJECT_HANDLE,
                    CK_OBJECT_HANDLE,
                ],
            ),
            (s, None, CK_ULONG(0), CK_OBJECT_HANDLE(0), CK_OBJECT_HANDLE(0)),
        ),
        (
            'C_SignRecoverInit',
            declare(
                'C_SignRecoverInit',
                [CK_SESSION_HANDLE, ctypes.c_void_p, CK_OBJECT_HANDLE],
            ),
            (s, None, CK_OBJECT_HANDLE(0)),
        ),
        (
            'C_SignRecover',
            declare(
                'C_SignRecover',
                [
                    CK_SESSION_HANDLE,
                    ctypes.c_void_p,
                    CK_ULONG,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ],
            ),
            (s, None, CK_ULONG(0), None, None),
        ),
        (
            'C_VerifyRecoverInit',
            declare(
                'C_VerifyRecoverInit',
                [CK_SESSION_HANDLE, ctypes.c_void_p, CK_OBJECT_HANDLE],
            ),
            (s, None, CK_OBJECT_HANDLE(0)),
        ),
        (
            'C_VerifyRecover',
            declare(
                'C_VerifyRecover',
                [
                    CK_SESSION_HANDLE,
                    ctypes.c_void_p,
                    CK_ULONG,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ],
            ),
            (s, None, CK_ULONG(0), None, None),
        ),
        (
            'C_DigestEncryptUpdate',
            declare(
                'C_DigestEncryptUpdate',
                [
                    CK_SESSION_HANDLE,
                    ctypes.c_void_p,
                    CK_ULONG,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ],
            ),
            (s, None, CK_ULONG(0), None, None),
        ),
        (
            'C_DecryptDigestUpdate',
            declare(
                'C_DecryptDigestUpdate',
                [
                    CK_SESSION_HANDLE,
                    ctypes.c_void_p,
                    CK_ULONG,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ],
            ),
            (s, None, CK_ULONG(0), None, None),
        ),
        (
            'C_SignEncryptUpdate',
            declare(
                'C_SignEncryptUpdate',
                [
                    CK_SESSION_HANDLE,
                    ctypes.c_void_p,
                    CK_ULONG,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ],
            ),
            (s, None, CK_ULONG(0), None, None),
        ),
        (
            'C_DecryptVerifyUpdate',
            declare(
                'C_DecryptVerifyUpdate',
                [
                    CK_SESSION_HANDLE,
                    ctypes.c_void_p,
                    CK_ULONG,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ],
            ),
            (s, None, CK_ULONG(0), None, None),
        ),
        (
            'C_SessionCancel',
            declare('C_SessionCancel', [CK_SESSION_HANDLE, CK_FLAGS]),
            (s, CK_FLAGS(0)),
        ),
        (
            'C_WaitForSlotEvent',
            declare('C_WaitForSlotEvent', [CK_FLAGS, ctypes.c_void_p, ctypes.c_void_p]),
            (CK_FLAGS(0), None, None),
        ),
        (
            'C_MessageVerifyInit',
            declare(
                'C_MessageVerifyInit',
                [CK_SESSION_HANDLE, ctypes.c_void_p, CK_OBJECT_HANDLE],
            ),
            (s, None, CK_OBJECT_HANDLE(0)),
        ),
        (
            'C_VerifyMessage',
            declare(
                'C_VerifyMessage',
                [
                    CK_SESSION_HANDLE,
                    ctypes.c_void_p,
                    CK_ULONG,
                    ctypes.c_void_p,
                    CK_ULONG,
                    ctypes.c_void_p,
                    CK_ULONG,
                ],
            ),
            (s, None, CK_ULONG(0), None, CK_ULONG(0), None, CK_ULONG(0)),
        ),
        (
            'C_SignMessageBegin',
            declare(
                'C_SignMessageBegin', [CK_SESSION_HANDLE, ctypes.c_void_p, CK_ULONG]
            ),
            (s, None, CK_ULONG(0)),
        ),
        (
            'C_SignMessageNext',
            declare(
                'C_SignMessageNext',
                [
                    CK_SESSION_HANDLE,
                    ctypes.c_void_p,
                    CK_ULONG,
                    ctypes.c_void_p,
                    CK_ULONG,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ],
            ),
            (s, None, CK_ULONG(0), None, CK_ULONG(0), None, None),
        ),
    ]

    for name, fn, args in checks:
        rv = fn(*args)
        h.check_unsupported(
            f"{name} correctly rejected (CKR_FUNCTION_NOT_SUPPORTED, raw-ABI)",
            rv == CKR_FUNCTION_NOT_SUPPORTED,
            f"got {rv_name(rv)}",
        )


def run_legacy_ok_battery(h: Harness) -> None:
    """C_SeedRandom, C_GetFunctionStatus, C_CancelFunction are legacy v2.x
    no-op functions with no pkcs11-tool CLI flag. Their documented, spec-
    sanctioned return codes (CKR_RANDOM_NO_RNG / CKR_FUNCTION_NOT_PARALLEL)
    are correct behavior, not bugs."""
    lib = h.lib
    s = h.session

    lib.C_SeedRandom.argtypes = [CK_SESSION_HANDLE, ctypes.c_void_p, CK_ULONG]
    lib.C_SeedRandom.restype = CK_RV
    seed = (ctypes.c_ubyte * 8)(*range(8))
    rv = lib.C_SeedRandom(s, ctypes.cast(seed, ctypes.c_void_p), CK_ULONG(8))
    h.check(
        'C_SeedRandom returns CKR_RANDOM_NO_RNG (raw-ABI, spec-sanctioned rejection of externally-seeded entropy)',
        rv == CKR_RANDOM_NO_RNG,
        f"got {rv_name(rv)}",
    )

    lib.C_GetFunctionStatus.argtypes = [CK_SESSION_HANDLE]
    lib.C_GetFunctionStatus.restype = CK_RV
    rv = lib.C_GetFunctionStatus(s)
    h.check(
        'C_GetFunctionStatus returns CKR_FUNCTION_NOT_PARALLEL (raw-ABI, spec-sanctioned legacy response)',
        rv == CKR_FUNCTION_NOT_PARALLEL,
        f"got {rv_name(rv)}",
    )

    lib.C_CancelFunction.argtypes = [CK_SESSION_HANDLE]
    lib.C_CancelFunction.restype = CK_RV
    rv = lib.C_CancelFunction(s)
    h.check(
        'C_CancelFunction returns CKR_FUNCTION_NOT_PARALLEL (raw-ABI, spec-sanctioned legacy response)',
        rv == CKR_FUNCTION_NOT_PARALLEL,
        f"got {rv_name(rv)}",
    )


def run_message_sign_check(
    h: Harness, priv_id: str, pub_id: str, mechanism_name: str, expect: str
) -> None:
    """C_MessageSignInit/C_SignMessage/C_MessageSignFinal have no pkcs11-tool
    CLI equivalent. `cosmian_pkcs11` only accepts CKM_EDDSA here (see
    pkcs11.rs::C_MessageSignInit) — every other mechanism must be cleanly
    rejected with CKR_FUNCTION_NOT_SUPPORTED, which is correct behavior, not
    a bug. `expect` is "ok" (real round trip expected) or
    "not-supported" (clean rejection expected)."""
    lib = h.lib
    s = h.session
    label = f"CKM_{mechanism_name} via C_MessageSignInit/C_SignMessage/C_MessageSignFinal (raw-ABI)"

    lib.C_MessageSignInit.argtypes = [
        CK_SESSION_HANDLE,
        ctypes.POINTER(CK_MECHANISM),
        CK_OBJECT_HANDLE,
    ]
    lib.C_MessageSignInit.restype = CK_RV
    lib.C_SignMessage.argtypes = [
        CK_SESSION_HANDLE,
        ctypes.c_void_p,
        CK_ULONG,
        ctypes.c_void_p,
        CK_ULONG,
        ctypes.c_void_p,
        ctypes.POINTER(CK_ULONG),
    ]
    lib.C_SignMessage.restype = CK_RV
    lib.C_MessageSignFinal.argtypes = [CK_SESSION_HANDLE]
    lib.C_MessageSignFinal.restype = CK_RV

    ckm = MECHANISM_NAME_TO_CKM.get(mechanism_name)
    if ckm is None:
        h.check(label, False, f"unknown mechanism name '{mechanism_name}'")
        return

    priv_handle = h.find_key_handle(priv_id, CKO_PRIVATE_KEY)
    if priv_handle is None:
        h.check(
            label, False, f"could not resolve private key handle for KMS UID {priv_id}"
        )
        return

    mech = CK_MECHANISM(ckm, None, 0)
    rv = lib.C_MessageSignInit(s, ctypes.byref(mech), CK_OBJECT_HANDLE(priv_handle))

    if expect == 'not-supported':
        h.check_unsupported(
            label,
            rv == CKR_FUNCTION_NOT_SUPPORTED,
            f"C_MessageSignInit got {rv_name(rv)}, expected CKR_FUNCTION_NOT_SUPPORTED",
        )
        return

    if rv != CKR_OK:
        h.check(label, False, f"C_MessageSignInit got {rv_name(rv)}, expected CKR_OK")
        return

    data = b'cosmian_pkcs11 raw-ABI C_MessageSignInit/C_SignMessage/C_MessageSignFinal conformance payload'
    sig_len = CK_ULONG(0)
    rv = lib.C_SignMessage(
        s,
        None,
        CK_ULONG(0),
        ctypes.cast(data, ctypes.c_void_p),
        CK_ULONG(len(data)),
        None,
        ctypes.byref(sig_len),
    )
    if rv != CKR_OK or sig_len.value == 0:
        h.check(label, False, f"C_SignMessage (size query) got {rv_name(rv)}")
        lib.C_MessageSignFinal(s)
        return

    sig_buf = ctypes.create_string_buffer(sig_len.value)
    rv = lib.C_SignMessage(
        s,
        None,
        CK_ULONG(0),
        ctypes.cast(data, ctypes.c_void_p),
        CK_ULONG(len(data)),
        sig_buf,
        ctypes.byref(sig_len),
    )
    if rv != CKR_OK:
        h.check(label, False, f"C_SignMessage (actual sign) got {rv_name(rv)}")
        lib.C_MessageSignFinal(s)
        return

    rv = lib.C_MessageSignFinal(s)
    if rv != CKR_OK:
        h.check(label, False, f"C_MessageSignFinal got {rv_name(rv)}")
        return

    signature = sig_buf.raw[: sig_len.value]

    # Verify the produced signature via the module's own C_VerifyInit/C_Verify
    # against the paired public key, closing the loop on a genuinely working
    # round trip (not just "some bytes came back").
    pub_handle = h.find_key_handle(pub_id, CKO_PUBLIC_KEY)
    if pub_handle is None:
        h.check(
            label,
            False,
            'signature produced but could not resolve public key handle to verify it',
        )
        return

    lib.C_VerifyInit.argtypes = [
        CK_SESSION_HANDLE,
        ctypes.POINTER(CK_MECHANISM),
        CK_OBJECT_HANDLE,
    ]
    lib.C_VerifyInit.restype = CK_RV
    lib.C_Verify.argtypes = [
        CK_SESSION_HANDLE,
        ctypes.c_void_p,
        CK_ULONG,
        ctypes.c_void_p,
        CK_ULONG,
    ]
    lib.C_Verify.restype = CK_RV

    verify_mech = CK_MECHANISM(ckm, None, 0)
    rv = lib.C_VerifyInit(s, ctypes.byref(verify_mech), CK_OBJECT_HANDLE(pub_handle))
    if rv != CKR_OK:
        h.check(label, False, f"signature produced but C_VerifyInit got {rv_name(rv)}")
        return
    rv = lib.C_Verify(
        s,
        ctypes.cast(data, ctypes.c_void_p),
        CK_ULONG(len(data)),
        ctypes.cast(signature, ctypes.c_void_p),
        CK_ULONG(len(signature)),
    )
    h.check(
        label,
        rv == CKR_OK,
        f"signature produced but C_Verify got {rv_name(rv)} (round trip did not verify)",
    )


CKM_AES_CBC = 0x1082
CKM_AES_GCM = 0x1087
CKO_SECRET_KEY = 4
# Cryptoki CK_GENERATOR_FUNCTION values: CKG_GENERATE_RANDOM is 3, not 1.
CKG_NO_GENERATE = 0
CKG_GENERATE_RANDOM = 3


class CK_GCM_MESSAGE_PARAMS(ctypes.Structure):
    _fields_ = [
        ('pIv', ctypes.c_void_p),
        ('ulIvLen', CK_ULONG),
        ('ulIvFixedBits', CK_ULONG),
        ('ivGenerator', CK_ULONG),
        ('pTag', ctypes.c_void_p),
        ('ulTagBits', CK_ULONG),
    ]


def _raw_declare(lib: ctypes.CDLL, name: str, argtypes: list) -> ctypes._FuncPointer:
    fn = getattr(lib, name)
    fn.argtypes = argtypes
    fn.restype = CK_RV
    return fn


def run_multipart_check(h: Harness, priv_id: str, pub_id: str, secret_id: str) -> None:
    """Exercise implemented sign/verify multipart paths and rejected cipher paths."""
    lib = h.lib
    s = h.session
    priv = h.find_key_handle(priv_id, CKO_PRIVATE_KEY)
    pub = h.find_key_handle(pub_id, CKO_PUBLIC_KEY)
    secret = h.find_key_handle(secret_id, CKO_SECRET_KEY)
    if priv is None or pub is None or secret is None:
        h.check(
            'multipart key lookup', False, 'could not resolve supplied key identifiers'
        )
        return

    sign_init = _raw_declare(
        lib,
        'C_SignInit',
        [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE],
    )
    sign = _raw_declare(
        lib,
        'C_Sign',
        [
            CK_SESSION_HANDLE,
            ctypes.c_void_p,
            CK_ULONG,
            ctypes.c_void_p,
            ctypes.POINTER(CK_ULONG),
        ],
    )
    sign_update = _raw_declare(
        lib, 'C_SignUpdate', [CK_SESSION_HANDLE, ctypes.c_void_p, CK_ULONG]
    )
    sign_final = _raw_declare(
        lib,
        'C_SignFinal',
        [CK_SESSION_HANDLE, ctypes.c_void_p, ctypes.POINTER(CK_ULONG)],
    )
    verify_init = _raw_declare(
        lib,
        'C_VerifyInit',
        [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE],
    )
    verify_update = _raw_declare(
        lib, 'C_VerifyUpdate', [CK_SESSION_HANDLE, ctypes.c_void_p, CK_ULONG]
    )
    verify_final = _raw_declare(
        lib, 'C_VerifyFinal', [CK_SESSION_HANDLE, ctypes.c_void_p, CK_ULONG]
    )
    mech = CK_MECHANISM(CKM_EDDSA, None, 0)
    data = bytes((i * 17) % 251 for i in range(8192))
    data_buf = ctypes.create_string_buffer(data)

    rv = sign_init(s, ctypes.byref(mech), CK_OBJECT_HANDLE(priv))
    one_len = CK_ULONG(0)
    rv_one_query = (
        sign(s, data_buf, len(data), None, ctypes.byref(one_len))
        if rv == CKR_OK
        else rv
    )
    one_buf = ctypes.create_string_buffer(one_len.value)
    rv_one = (
        sign(s, data_buf, len(data), one_buf, ctypes.byref(one_len))
        if rv_one_query == CKR_OK
        else rv_one_query
    )
    one_shot = one_buf.raw[: one_len.value]
    h.check(
        'C_SignInit/C_Sign one-shot EdDSA baseline',
        rv == CKR_OK and rv_one_query == CKR_OK and rv_one == CKR_OK,
    )

    rv = sign_init(s, ctypes.byref(mech), CK_OBJECT_HANDLE(priv))
    update_ok = rv == CKR_OK
    for offset in range(0, len(data), 1024):
        chunk = ctypes.create_string_buffer(data[offset : offset + 1024])
        update_ok = update_ok and sign_update(s, chunk, 1024) == CKR_OK
    final_len = CK_ULONG(0)
    rv_query = sign_final(s, None, ctypes.byref(final_len))
    final_buf = ctypes.create_string_buffer(final_len.value)
    rv_final = sign_final(s, final_buf, ctypes.byref(final_len))
    multipart_sig = final_buf.raw[: final_len.value]
    h.check(
        'C_SignUpdate/C_SignFinal matches C_Sign',
        update_ok
        and rv_query == CKR_OK
        and rv_final == CKR_OK
        and multipart_sig == one_shot,
        f'query={rv_name(rv_query)}, final={rv_name(rv_final)}',
    )

    rv = verify_init(s, ctypes.byref(mech), CK_OBJECT_HANDLE(pub))
    verify_ok = rv == CKR_OK
    for offset in range(0, len(data), 1024):
        chunk = ctypes.create_string_buffer(data[offset : offset + 1024])
        verify_ok = verify_ok and verify_update(s, chunk, 1024) == CKR_OK
    rv = verify_final(
        s, ctypes.cast(multipart_sig, ctypes.c_void_p), len(multipart_sig)
    )
    h.check(
        'C_VerifyUpdate/C_VerifyFinal accepts multipart EdDSA',
        verify_ok and rv == CKR_OK,
        rv_name(rv),
    )

    probe = ctypes.create_string_buffer(b'x')
    rv = sign_update(s, probe, 1)
    h.check(
        'C_SignUpdate after C_SignFinal rejects inactive operation',
        rv != CKR_OK,
        rv_name(rv),
    )

    encrypt_init = _raw_declare(
        lib,
        'C_EncryptInit',
        [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE],
    )
    encrypt_update = _raw_declare(
        lib,
        'C_EncryptUpdate',
        [
            CK_SESSION_HANDLE,
            ctypes.c_void_p,
            CK_ULONG,
            ctypes.c_void_p,
            ctypes.POINTER(CK_ULONG),
        ],
    )
    encrypt_final = _raw_declare(
        lib,
        'C_EncryptFinal',
        [CK_SESSION_HANDLE, ctypes.c_void_p, ctypes.POINTER(CK_ULONG)],
    )
    decrypt_init = _raw_declare(
        lib,
        'C_DecryptInit',
        [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE],
    )
    decrypt_update = _raw_declare(
        lib,
        'C_DecryptUpdate',
        [
            CK_SESSION_HANDLE,
            ctypes.c_void_p,
            CK_ULONG,
            ctypes.c_void_p,
            ctypes.POINTER(CK_ULONG),
        ],
    )
    decrypt_final = _raw_declare(
        lib,
        'C_DecryptFinal',
        [CK_SESSION_HANDLE, ctypes.c_void_p, ctypes.POINTER(CK_ULONG)],
    )
    iv = (ctypes.c_ubyte * 16)()
    cipher_mech = CK_MECHANISM(CKM_AES_CBC, ctypes.cast(iv, ctypes.c_void_p), 16)
    out = ctypes.create_string_buffer(64)
    out_len = CK_ULONG(64)
    encrypt_init(s, ctypes.byref(cipher_mech), CK_OBJECT_HANDLE(secret))
    rv_update = encrypt_update(s, data_buf, 16, out, ctypes.byref(out_len))
    rv_final = encrypt_final(s, out, ctypes.byref(out_len))
    h.check_unsupported(
        'C_EncryptUpdate/C_EncryptFinal reject multipart encryption',
        rv_update == CKR_FUNCTION_NOT_SUPPORTED
        and rv_final == CKR_FUNCTION_NOT_SUPPORTED,
        f'update={rv_name(rv_update)}, final={rv_name(rv_final)}',
    )
    decrypt_init(s, ctypes.byref(cipher_mech), CK_OBJECT_HANDLE(secret))
    out_len = CK_ULONG(64)
    rv_update = decrypt_update(s, data_buf, 16, out, ctypes.byref(out_len))
    rv_final = decrypt_final(s, out, ctypes.byref(out_len))
    h.check_unsupported(
        'C_DecryptUpdate/C_DecryptFinal reject multipart decryption',
        rv_update == CKR_FUNCTION_NOT_SUPPORTED
        and rv_final == CKR_FUNCTION_NOT_SUPPORTED,
        f'update={rv_name(rv_update)}, final={rv_name(rv_final)}',
    )


def _message_encrypt_artifacts(
    h: Harness, secret_id: str
) -> tuple[int, int, int, int, bytes, bytes, bytes, bytes] | None:
    lib = h.lib
    s = h.session
    key = h.find_key_handle(secret_id, CKO_SECRET_KEY)
    if key is None:
        return None
    init = _raw_declare(
        lib,
        'C_MessageEncryptInit',
        [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE],
    )
    encrypt = _raw_declare(
        lib,
        'C_EncryptMessage',
        [
            CK_SESSION_HANDLE,
            ctypes.c_void_p,
            CK_ULONG,
            ctypes.c_void_p,
            CK_ULONG,
            ctypes.c_void_p,
            CK_ULONG,
            ctypes.c_void_p,
            ctypes.POINTER(CK_ULONG),
        ],
    )
    final = _raw_declare(lib, 'C_MessageEncryptFinal', [CK_SESSION_HANDLE])
    mechanism = CK_MECHANISM(CKM_AES_GCM, None, 0)
    iv = (ctypes.c_ubyte * 12)()
    tag = (ctypes.c_ubyte * 16)()
    params = CK_GCM_MESSAGE_PARAMS(
        ctypes.cast(iv, ctypes.c_void_p),
        12,
        0,
        CKG_GENERATE_RANDOM,
        ctypes.cast(tag, ctypes.c_void_p),
        128,
    )
    aad_bytes = b'raw-abi-aad'
    aad = ctypes.create_string_buffer(aad_bytes)
    plaintext = bytes((i * 13) % 251 for i in range(8192))
    plain_buf = ctypes.create_string_buffer(plaintext)
    rv_init = init(s, ctypes.byref(mechanism), CK_OBJECT_HANDLE(key))
    needed = CK_ULONG(0)
    rv_query = encrypt(
        s,
        ctypes.byref(params),
        ctypes.sizeof(params),
        aad,
        len(aad_bytes),
        plain_buf,
        len(plaintext),
        None,
        ctypes.byref(needed),
    )
    ciphertext = ctypes.create_string_buffer(needed.value)
    actual_len = CK_ULONG(needed.value)
    rv_encrypt = encrypt(
        s,
        ctypes.byref(params),
        ctypes.sizeof(params),
        aad,
        len(aad_bytes),
        plain_buf,
        len(plaintext),
        ciphertext,
        ctypes.byref(actual_len),
    )
    rv_final = final(s)
    return (
        rv_init,
        rv_query,
        rv_encrypt,
        rv_final,
        plaintext,
        ciphertext.raw[: actual_len.value],
        bytes(iv),
        bytes(tag),
    )


def run_message_encrypt_check(h: Harness, secret_id: str) -> None:
    artifacts = _message_encrypt_artifacts(h, secret_id)
    if artifacts is None:
        h.check('message-encrypt secret-key lookup', False, 'key not found')
        return
    rv_init, rv_query, rv_encrypt, rv_final, plaintext, ciphertext, iv, tag = artifacts
    h.check(
        'C_MessageEncryptInit/C_EncryptMessage/C_MessageEncryptFinal AES-GCM',
        rv_init == CKR_OK
        and rv_query == CKR_OK
        and rv_encrypt == CKR_OK
        and rv_final == CKR_OK
        and len(ciphertext) == len(plaintext),
        f'init={rv_name(rv_init)}, query={rv_name(rv_query)}, encrypt={rv_name(rv_encrypt)}, final={rv_name(rv_final)}',
    )


def run_message_decrypt_check(h: Harness, secret_id: str) -> None:
    artifacts = _message_encrypt_artifacts(h, secret_id)
    if artifacts is None:
        h.check('message-decrypt secret-key lookup', False, 'key not found')
        return
    _, _, _, _, plaintext, ciphertext, iv_bytes, tag_bytes = artifacts
    lib = h.lib
    s = h.session
    key = h.find_key_handle(secret_id, CKO_SECRET_KEY)
    init = _raw_declare(
        lib,
        'C_MessageDecryptInit',
        [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE],
    )
    decrypt = _raw_declare(
        lib,
        'C_DecryptMessage',
        [
            CK_SESSION_HANDLE,
            ctypes.c_void_p,
            CK_ULONG,
            ctypes.c_void_p,
            CK_ULONG,
            ctypes.c_void_p,
            CK_ULONG,
            ctypes.c_void_p,
            ctypes.POINTER(CK_ULONG),
        ],
    )
    final = _raw_declare(lib, 'C_MessageDecryptFinal', [CK_SESSION_HANDLE])
    mechanism = CK_MECHANISM(CKM_AES_GCM, None, 0)
    iv = (ctypes.c_ubyte * 12).from_buffer_copy(iv_bytes)
    tag = (ctypes.c_ubyte * 16).from_buffer_copy(tag_bytes)
    params = CK_GCM_MESSAGE_PARAMS(
        ctypes.cast(iv, ctypes.c_void_p),
        12,
        0,
        CKG_NO_GENERATE,
        ctypes.cast(tag, ctypes.c_void_p),
        128,
    )
    aad_bytes = b'raw-abi-aad'
    aad = ctypes.create_string_buffer(aad_bytes)
    cipher_buf = ctypes.create_string_buffer(ciphertext)
    rv_init = init(s, ctypes.byref(mechanism), CK_OBJECT_HANDLE(key))
    needed = CK_ULONG(0)
    rv_query = decrypt(
        s,
        ctypes.byref(params),
        ctypes.sizeof(params),
        aad,
        len(aad_bytes),
        cipher_buf,
        len(ciphertext),
        None,
        ctypes.byref(needed),
    )
    plain_buf = ctypes.create_string_buffer(needed.value)
    actual_len = CK_ULONG(needed.value)
    rv_decrypt = decrypt(
        s,
        ctypes.byref(params),
        ctypes.sizeof(params),
        aad,
        len(aad_bytes),
        cipher_buf,
        len(ciphertext),
        plain_buf,
        ctypes.byref(actual_len),
    )
    rv_final = final(s)
    h.check(
        'C_MessageDecryptInit/C_DecryptMessage/C_MessageDecryptFinal AES-GCM round trip',
        rv_init == CKR_OK
        and rv_query == CKR_OK
        and rv_decrypt == CKR_OK
        and rv_final == CKR_OK
        and plain_buf.raw[: actual_len.value] == plaintext,
        f'init={rv_name(rv_init)}, query={rv_name(rv_query)}, decrypt={rv_name(rv_decrypt)}, final={rv_name(rv_final)}',
    )


def run_message_verify_boundary(h: Harness) -> None:
    lib = h.lib
    s = h.session
    init = _raw_declare(
        lib,
        'C_MessageVerifyInit',
        [CK_SESSION_HANDLE, ctypes.c_void_p, CK_OBJECT_HANDLE],
    )
    verify = _raw_declare(
        lib,
        'C_VerifyMessage',
        [
            CK_SESSION_HANDLE,
            ctypes.c_void_p,
            CK_ULONG,
            ctypes.c_void_p,
            CK_ULONG,
            ctypes.c_void_p,
            CK_ULONG,
        ],
    )
    final = _raw_declare(lib, 'C_MessageVerifyFinal', [CK_SESSION_HANDLE])
    rv_init = init(s, None, 0)
    rv_verify = verify(s, None, 0, None, 0, None, 0)
    rv_final = final(s)
    h.check_unsupported(
        'C_MessageVerifyInit/C_VerifyMessage/C_MessageVerifyFinal remain unsupported',
        rv_init == CKR_FUNCTION_NOT_SUPPORTED
        and rv_verify == CKR_FUNCTION_NOT_SUPPORTED
        and rv_final == CKR_FUNCTION_NOT_SUPPORTED,
        f'init={rv_name(rv_init)}, verify={rv_name(rv_verify)}, final={rv_name(rv_final)}',
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--module', required=True, help='Path to the built cosmian_pkcs11 cdylib'
    )
    parser.add_argument(
        '--ckms-conf', default=None, help='Path to ckms.toml (defaults to $CKMS_CONF)'
    )
    parser.add_argument(
        '--check',
        required=True,
        choices=[
            'not-supported',
            'legacy-ok',
            'message-sign',
            'multipart',
            'message-encrypt',
            'message-decrypt',
            'message-verify',
        ],
    )
    parser.add_argument(
        '--priv-id',
        default=None,
        help='KMS private-key identifier (message-sign/multipart check)',
    )
    parser.add_argument(
        '--pub-id',
        default=None,
        help='KMS public-key identifier (message-sign/multipart check)',
    )
    parser.add_argument(
        '--secret-id',
        default=None,
        help='KMS AES-key identifier (message-encrypt/message-decrypt/multipart check)',
    )
    parser.add_argument(
        '--mechanism',
        default=None,
        help='pkcs11-tool mechanism name, e.g. EDDSA or ECDSA (message-sign check)',
    )
    parser.add_argument(
        '--expect',
        default='not-supported',
        choices=['ok', 'not-supported'],
        help='message-sign check expected outcome',
    )
    args = parser.parse_args()

    h = Harness(args.module, args.ckms_conf)

    if args.check == 'not-supported':
        run_not_supported_battery(h)
    elif args.check == 'legacy-ok':
        run_legacy_ok_battery(h)
    elif args.check == 'message-sign':
        if not args.priv_id or not args.pub_id or not args.mechanism:
            print(
                'FAIL message-sign: --priv-id, --pub-id and --mechanism are required',
                file=sys.stderr,
            )
            return 1
        run_message_sign_check(
            h, args.priv_id, args.pub_id, args.mechanism, args.expect
        )
    elif args.check == 'multipart':
        if not args.priv_id or not args.pub_id or not args.secret_id:
            print(
                'FAIL multipart: --priv-id, --pub-id and --secret-id are required',
                file=sys.stderr,
            )
            return 1
        run_multipart_check(h, args.priv_id, args.pub_id, args.secret_id)
    elif args.check == 'message-encrypt':
        if not args.secret_id:
            print('FAIL message-encrypt: --secret-id is required', file=sys.stderr)
            return 1
        run_message_encrypt_check(h, args.secret_id)
    elif args.check == 'message-decrypt':
        if not args.secret_id:
            print('FAIL message-decrypt: --secret-id is required', file=sys.stderr)
            return 1
        run_message_decrypt_check(h, args.secret_id)
    elif args.check == 'message-verify':
        run_message_verify_boundary(h)

    # Machine-parseable footer line: lets the calling bash script fold this
    # harness's own pass/fail accounting into its running totals without
    # having to infer failure state from the emoji glyph alone (a "declared
    # but not supported" boundary check also prints a red cross on success,
    # so a plain `grep -c '^❌'` would over-count real failures).
    print(f"::HARNESS_SUMMARY:: total={h.total} failed={h.failed}")

    return 1 if h.failed > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
