#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Standalone probe: how does a PKCS#11 library handle AES-GCM IVs? (Python/ctypes twin of
`pkcs11_gcm_iv_probe.c`, for hosts without a C compiler.)

It replays the calls the KMS server makes for AES-GCM with an HSM key:
  - FIPS build:     C_EncryptInit(CKM_AES_GCM) with an all-zero 12-byte IV buffer that the HSM must
                    overwrite with the IV it generates (then a length query and the real C_Encrypt);
  - non-FIPS build: the same call with a random IV chosen by the caller.
It also reports the exported PKCS#11 v3.0 message symbols and the C_GetInterface version.

Non-destructive: only a temporary AES session key (CKA_TOKEN=false, CKA_SENSITIVE=true) is created
and destroyed; no token object is written. Use a test slot. The PIN is read from PKCS11_PIN.

Usage: PKCS11_PIN=... python3 pkcs11_gcm_iv_probe.py /path/to/libvendor.so <slot-id> [user|so]
"""
import ctypes as C
import os
import sys

CKM_AES_KEY_GEN, CKM_AES_GCM = 0x1080, 0x1087
CKA_CLASS, CKA_TOKEN, CKA_KEY_TYPE, CKA_SENSITIVE = 0x0, 0x1, 0x100, 0x103
CKA_ENCRYPT, CKA_DECRYPT, CKA_VALUE_LEN = 0x104, 0x105, 0x161
CKO_SECRET_KEY, CKK_AES = 4, 0x1F
IV_LEN, TAG_BYTES = 12, 16
RV_NAMES = {
    0x00: 'CKR_OK',
    0x05: 'CKR_GENERAL_ERROR',
    0x06: 'CKR_FUNCTION_FAILED',
    0x07: 'CKR_ARGUMENTS_BAD',
    0x1B: 'CKR_ACTION_PROHIBITED',
    0x54: 'CKR_FUNCTION_NOT_SUPPORTED',
    0x60: 'CKR_KEY_HANDLE_INVALID',
    0x70: 'CKR_MECHANISM_INVALID',
    0x71: 'CKR_MECHANISM_PARAM_INVALID',
    0x90: 'CKR_OPERATION_ACTIVE',
    0x150: 'CKR_BUFFER_TOO_SMALL',
}


def rv_name(rv):
    return RV_NAMES.get(rv, '(see PKCS#11 headers)')


class Attr(C.Structure):
    _fields_ = [('type', C.c_ulong), ('value', C.c_void_p), ('len', C.c_ulong)]


class Mech(C.Structure):
    _fields_ = [('mechanism', C.c_ulong), ('param', C.c_void_p), ('len', C.c_ulong)]


class GcmParams(C.Structure):
    _fields_ = [
        ('iv', C.c_void_p),
        ('iv_len', C.c_ulong),
        ('iv_bits', C.c_ulong),
        ('aad', C.c_void_p),
        ('aad_len', C.c_ulong),
        ('tag_bits', C.c_ulong),
    ]


class Version(C.Structure):
    _fields_ = [('major', C.c_ubyte), ('minor', C.c_ubyte)]


class Interface(C.Structure):
    _fields_ = [
        ('name', C.c_void_p),
        ('function_list', C.c_void_p),
        ('flags', C.c_ulong),
    ]


# The first entries of CK_FUNCTION_LIST are identical in v2.40 and v3.0.
FN_NAMES = (
    'C_Initialize C_Finalize C_GetInfo C_GetFunctionList C_GetSlotList C_GetSlotInfo '
    'C_GetTokenInfo C_GetMechanismList C_GetMechanismInfo C_InitToken C_InitPIN C_SetPIN '
    'C_OpenSession C_CloseSession C_CloseAllSessions C_GetSessionInfo C_GetOperationState '
    'C_SetOperationState C_Login C_Logout C_CreateObject C_CopyObject C_DestroyObject '
    'C_GetObjectSize C_GetAttributeValue C_SetAttributeValue C_FindObjectsInit C_FindObjects '
    'C_FindObjectsFinal C_EncryptInit C_Encrypt C_EncryptUpdate C_EncryptFinal C_DecryptInit '
    'C_Decrypt C_DecryptUpdate C_DecryptFinal C_DigestInit C_Digest C_DigestUpdate C_DigestKey '
    'C_DigestFinal C_SignInit C_Sign C_SignUpdate C_SignFinal C_SignRecoverInit C_SignRecover '
    'C_VerifyInit C_Verify C_VerifyUpdate C_VerifyFinal C_VerifyRecoverInit C_VerifyRecover '
    'C_DigestEncryptUpdate C_DecryptDigestUpdate C_SignEncryptUpdate C_DecryptVerifyUpdate '
    'C_GenerateKey'
).split()


class FnList(C.Structure):
    _fields_ = [('version', Version)] + [(n, C.c_void_p) for n in FN_NAMES]


def fn(table, name, restype, *argtypes):
    return C.CFUNCTYPE(restype, *argtypes)(getattr(table, name))


def hexs(buf):
    return bytes(buf).hex()


def main():
    if len(sys.argv) < 3:
        sys.exit(
            'usage: PKCS11_PIN=... %s <library.so> <slot-id> [user|so]' % sys.argv[0]
        )
    lib = C.CDLL(sys.argv[1])
    print('library:', sys.argv[1])
    print(
        'exported PKCS#11 v3.0 message symbols (the KMS treats the message API as available '
        'when they are present, even as stubs):'
    )
    for sym in (
        'C_MessageEncryptInit',
        'C_EncryptMessage',
        'C_MessageEncryptFinal',
        'C_MessageDecryptInit',
        'C_DecryptMessage',
        'C_MessageDecryptFinal',
    ):
        print('    %-24s %s' % (sym, 'exported' if hasattr(lib, sym) else 'absent'))
    if not hasattr(lib, 'C_GetInterface'):
        print('    C_GetInterface           absent (no v3.0 interface table)')
    else:
        get_if = lib.C_GetInterface
        get_if.argtypes = [
            C.c_void_p,
            C.c_void_p,
            C.POINTER(C.POINTER(Interface)),
            C.c_ulong,
        ]
        get_if.restype = C.c_ulong
        ifc = C.POINTER(Interface)()
        rv = get_if(None, None, C.byref(ifc), 0)
        if rv == 0 and ifc and ifc.contents.function_list:
            v = C.cast(ifc.contents.function_list, C.POINTER(Version)).contents
            print(
                '    C_GetInterface           default interface version %d.%d'
                % (v.major, v.minor)
            )
        else:
            print('    C_GetInterface           -> %#x %s' % (rv, rv_name(rv)))

    lib.C_GetFunctionList.argtypes = [C.POINTER(C.POINTER(FnList))]
    lib.C_GetFunctionList.restype = C.c_ulong
    table_ptr = C.POINTER(FnList)()
    if lib.C_GetFunctionList(C.byref(table_ptr)) != 0 or not table_ptr:
        sys.exit('C_GetFunctionList failed')
    t = table_ptr.contents
    ul, vp, bp = C.c_ulong, C.c_void_p, C.POINTER(C.c_ubyte)
    c_init = fn(t, 'C_Initialize', ul, vp)
    c_open = fn(t, 'C_OpenSession', ul, ul, ul, vp, vp, C.POINTER(ul))
    c_login = fn(t, 'C_Login', ul, ul, ul, C.c_char_p, ul)
    c_gen = fn(
        t, 'C_GenerateKey', ul, ul, C.POINTER(Mech), C.POINTER(Attr), ul, C.POINTER(ul)
    )
    c_einit = fn(t, 'C_EncryptInit', ul, ul, C.POINTER(Mech), ul)
    c_enc = fn(t, 'C_Encrypt', ul, ul, C.c_char_p, ul, vp, C.POINTER(ul))
    c_dinit = fn(t, 'C_DecryptInit', ul, ul, C.POINTER(Mech), ul)
    c_dec = fn(t, 'C_Decrypt', ul, ul, vp, ul, vp, C.POINTER(ul))
    c_destroy = fn(t, 'C_DestroyObject', ul, ul, ul)
    c_close = fn(t, 'C_CloseSession', ul, ul)
    c_fin = fn(t, 'C_Finalize', ul, vp)

    rv = c_init(None)
    if rv not in (0, 0x191):
        sys.exit('C_Initialize -> %#x %s' % (rv, rv_name(rv)))
    session = ul()
    rv = c_open(int(sys.argv[2], 0), 0x6, None, None, C.byref(session))
    if rv != 0:
        sys.exit('C_OpenSession -> %#x %s' % (rv, rv_name(rv)))
    pin = os.environ.get('PKCS11_PIN')
    if pin:
        rv = c_login(
            session,
            0 if len(sys.argv) > 3 and sys.argv[3] == 'so' else 1,
            pin.encode(),
            len(pin),
        )
        if rv not in (0, 0x100):
            sys.exit('C_Login -> %#x %s' % (rv, rv_name(rv)))

    yes, no = C.c_ubyte(1), C.c_ubyte(0)
    cls, ktype, klen = ul(CKO_SECRET_KEY), ul(CKK_AES), ul(32)
    tmpl = (Attr * 7)(
        Attr(CKA_CLASS, C.addressof(cls), 8),
        Attr(CKA_KEY_TYPE, C.addressof(ktype), 8),
        Attr(CKA_VALUE_LEN, C.addressof(klen), 8),
        Attr(CKA_TOKEN, C.addressof(no), 1),
        Attr(CKA_SENSITIVE, C.addressof(yes), 1),
        Attr(CKA_ENCRYPT, C.addressof(yes), 1),
        Attr(CKA_DECRYPT, C.addressof(yes), 1),
    )
    key = ul()
    gen = Mech(CKM_AES_KEY_GEN, None, 0)
    rv = c_gen(session, C.byref(gen), tmpl, 7, C.byref(key))
    print(
        '\nC_GenerateKey (temporary AES-256 session key) -> %#x %s' % (rv, rv_name(rv))
    )
    if rv != 0:
        sys.exit(2)

    plain = b'0123456789abcdef0123456789abcdef'

    def scenario(title, mode):
        # mode 0: zero IV + length query (KMS FIPS sequence); 1: zero IV, single call;
        #      2: random caller IV + length query (KMS non-FIPS sequence); 3: NULL pIv, ulIvLen 0.
        print('\n[%s]' % title)
        iv = (C.c_ubyte * IV_LEN)(*(os.urandom(IV_LEN) if mode == 2 else bytes(IV_LEN)))
        sent = bytes(iv)
        null_iv = mode == 3
        p = GcmParams(
            None if null_iv else C.addressof(iv),
            0 if null_iv else IV_LEN,
            0 if null_iv else IV_LEN * 8,
            None,
            0,
            TAG_BYTES * 8,
        )
        m = Mech(CKM_AES_GCM, C.addressof(p), C.sizeof(p))
        rv = c_einit(session, C.byref(m), key)
        print('    C_EncryptInit            -> %#x %s' % (rv, rv_name(rv)))
        if rv != 0:
            return
        if mode in (0, 2):
            qlen = ul(0)
            rv = c_enc(session, plain, len(plain), None, C.byref(qlen))
            print(
                '    C_Encrypt (length query) -> %#x %s (len %d)'
                % (rv, rv_name(rv), qlen.value)
            )
            if rv != 0:
                return
        out = C.create_string_buffer(len(plain) + TAG_BYTES)
        outlen = ul(len(out))
        rv = c_enc(session, plain, len(plain), out, C.byref(outlen))
        print(
            '    C_Encrypt                -> %#x %s (len %d)'
            % (rv, rv_name(rv), outlen.value)
        )
        if rv != 0:
            return
        if not null_iv:
            print('    IV sent    :', sent.hex())
            print('    IV after   :', hexs(iv))
        if mode in (0, 1):
            if not any(iv):
                print(
                    '    RESULT: call accepted but the HSM did NOT write a generated IV (IV still '
                    'zero): the KMS FIPS build refuses this'
                )
            else:
                print(
                    '    RESULT: the HSM generated and returned an IV: the KMS FIPS build can '
                    'use this'
                )
        elif mode == 2:
            print(
                '    RESULT: a caller-chosen IV is accepted (the KMS non-FIPS build can use this)'
            )
        else:
            print(
                '    RESULT: accepted with a NULL IV, but the IV is not returned in pIv: not '
                'usable by the KMS'
            )
            return
        dp = GcmParams(C.addressof(iv), IV_LEN, IV_LEN * 8, None, 0, TAG_BYTES * 8)
        dm = Mech(CKM_AES_GCM, C.addressof(dp), C.sizeof(dp))
        back = C.create_string_buffer(len(plain) + TAG_BYTES)
        backlen = ul(len(back))
        rv = c_dinit(session, C.byref(dm), key)
        if rv == 0:
            rv = c_dec(session, out, outlen.value, back, C.byref(backlen))
        ok = rv == 0 and back.raw[: backlen.value] == plain
        print(
            '    decrypt round trip       -> %#x %s%s'
            % (rv, rv_name(rv), ' (plaintext matches)' if ok else '')
        )

    scenario('A. KMS FIPS build: zero IV buffer, length query, then encrypt', 0)
    scenario('B. zero IV buffer, single C_Encrypt call (no length query)', 1)
    scenario('C. KMS non-FIPS build: random IV chosen by the caller', 2)
    scenario(
        "D. NULL pIv / ulIvLen 0 (is this the HSM's convention for 'generate the IV'?)",
        3,
    )

    c_destroy(session, key)
    c_close(session)
    c_fin(None)


if __name__ == '__main__':
    main()
