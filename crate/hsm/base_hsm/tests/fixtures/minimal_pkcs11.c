/* Minimal, strictly spec-conformant PKCS#11 v3.0 shim for
 * regression-testing HsmLib's C_GetFunctionList/C_GetInterface fallback
 * resolution path.
 *
 * Deliberately exports *only* C_GetFunctionList and C_GetInterface -- no
 * individual C_XXX symbols -- mirroring how a strictly spec-conformant
 * library (e.g. Kryoptic) behaves, per PKCS#11 v3.1 section 5.4.4:
 * "C_GetFunctionList, C_GetInterfaceList, and C_GetInterface are the only
 * Cryptoki functions which an application may call before calling
 * C_Initialize." C_GetInterfaceList itself is reachable only through the
 * function table (as a real conformant library would allow), not as its
 * own exported symbol.
 *
 * `C_SignInit`/`C_VerifyInit`/`C_DeriveKey` are additionally stubbed to reject
 * the v3.0-only `CKM_EDDSA`/`CKM_HKDF_DERIVE` mechanisms with
 * `CKR_MECHANISM_INVALID`, exactly as a real v2.40-only library would, so the
 * `Session` graceful-degradation paths can be exercised end-to-end against a
 * real dynamically-loaded library without implementing real EdDSA/HKDF crypto.
 *
 * Field layout mirrors pkcs11-sys 0.2.25's CK_FUNCTION_LIST_3_0 exactly
 * (92 function-pointer fields after the CK_VERSION header: the 68 v2.40
 * fields, unchanged, followed by the 24 fields added in v3.0), verified
 * against that crate's own field-order/offset assertions. Designated
 * initializers (C99) are used below so field order in this file need not
 * match declaration order, and every unlisted field is implicitly NULL.
 */

typedef unsigned long CK_RV;
typedef void *CK_VOID_PTR;
typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef CK_ULONG *CK_ULONG_PTR;
typedef unsigned char CK_UTF8CHAR;
typedef CK_UTF8CHAR *CK_UTF8CHAR_PTR;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL

typedef struct CkVersion {
  unsigned char major;
  unsigned char minor;
} CkVersion;

/* pkcs11-sys 0.2.25 declares `CK_INTERFACE`/`CK_FUNCTION_LIST_3_0` as
 * `#[repr(C, packed)]` on Windows (mirroring the official Cryptoki headers'
 * `#pragma pack(push, cryptoki, 1)`), but as plain `#[repr(C)]` (natural
 * alignment) on Unix. Without matching that, MSVC inserts 6 bytes of padding
 * after the 2-byte `CkVersion` header to 8-byte-align the first function
 * pointer, while the Rust side expects it packed at offset 2 -- every field
 * read through the struct is then misaligned/garbage, and calling through
 * one of those bogus function pointers is what produced the
 * `STATUS_ACCESS_VIOLATION` crash on Windows CI. Push 1-byte packing for
 * these two structs on Windows only; Unix already matches natural alignment
 * with no pragma needed. */
#if defined(_WIN32)
#pragma pack(push, 1)
#endif

typedef struct CkInterface {
  CK_UTF8CHAR_PTR pInterfaceName;
  CK_VOID_PTR pFunctionList;
  CK_ULONG flags;
} CkInterface;

/* Generic function-pointer slot: every CK_FUNCTION_LIST_3_0 field is
 * pointer-sized regardless of its real parameter list, so a single
 * generic prototype is sufficient for layout purposes -- the same
 * assumption libloading/pkcs11-sys already rely on when resolving
 * symbols by name. */
typedef CK_RV (*CkGenericFn)(void);

typedef struct CkFunctionList30 {
  CkVersion version;
  CkGenericFn C_Initialize;
  CkGenericFn C_Finalize;
  CkGenericFn C_GetInfo;
  CkGenericFn C_GetFunctionList;
  CkGenericFn C_GetSlotList;
  CkGenericFn C_GetSlotInfo;
  CkGenericFn C_GetTokenInfo;
  CkGenericFn C_GetMechanismList;
  CkGenericFn C_GetMechanismInfo;
  CkGenericFn C_InitToken;
  CkGenericFn C_InitPIN;
  CkGenericFn C_SetPIN;
  CkGenericFn C_OpenSession;
  CkGenericFn C_CloseSession;
  CkGenericFn C_CloseAllSessions;
  CkGenericFn C_GetSessionInfo;
  CkGenericFn C_GetOperationState;
  CkGenericFn C_SetOperationState;
  CkGenericFn C_Login;
  CkGenericFn C_Logout;
  CkGenericFn C_CreateObject;
  CkGenericFn C_CopyObject;
  CkGenericFn C_DestroyObject;
  CkGenericFn C_GetObjectSize;
  CkGenericFn C_GetAttributeValue;
  CkGenericFn C_SetAttributeValue;
  CkGenericFn C_FindObjectsInit;
  CkGenericFn C_FindObjects;
  CkGenericFn C_FindObjectsFinal;
  CkGenericFn C_EncryptInit;
  CkGenericFn C_Encrypt;
  CkGenericFn C_EncryptUpdate;
  CkGenericFn C_EncryptFinal;
  CkGenericFn C_DecryptInit;
  CkGenericFn C_Decrypt;
  CkGenericFn C_DecryptUpdate;
  CkGenericFn C_DecryptFinal;
  CkGenericFn C_DigestInit;
  CkGenericFn C_Digest;
  CkGenericFn C_DigestUpdate;
  CkGenericFn C_DigestKey;
  CkGenericFn C_DigestFinal;
  CkGenericFn C_SignInit;
  CkGenericFn C_Sign;
  CkGenericFn C_SignUpdate;
  CkGenericFn C_SignFinal;
  CkGenericFn C_SignRecoverInit;
  CkGenericFn C_SignRecover;
  CkGenericFn C_VerifyInit;
  CkGenericFn C_Verify;
  CkGenericFn C_VerifyUpdate;
  CkGenericFn C_VerifyFinal;
  CkGenericFn C_VerifyRecoverInit;
  CkGenericFn C_VerifyRecover;
  CkGenericFn C_DigestEncryptUpdate;
  CkGenericFn C_DecryptDigestUpdate;
  CkGenericFn C_SignEncryptUpdate;
  CkGenericFn C_DecryptVerifyUpdate;
  CkGenericFn C_GenerateKey;
  CkGenericFn C_GenerateKeyPair;
  CkGenericFn C_WrapKey;
  CkGenericFn C_UnwrapKey;
  CkGenericFn C_DeriveKey;
  CkGenericFn C_SeedRandom;
  CkGenericFn C_GenerateRandom;
  CkGenericFn C_GetFunctionStatus;
  CkGenericFn C_CancelFunction;
  CkGenericFn C_WaitForSlotEvent;
  CkGenericFn C_GetInterfaceList;
  CkGenericFn C_GetInterface;
  CkGenericFn C_LoginUser;
  CkGenericFn C_SessionCancel;
  CkGenericFn C_MessageEncryptInit;
  CkGenericFn C_EncryptMessage;
  CkGenericFn C_EncryptMessageBegin;
  CkGenericFn C_EncryptMessageNext;
  CkGenericFn C_MessageEncryptFinal;
  CkGenericFn C_MessageDecryptInit;
  CkGenericFn C_DecryptMessage;
  CkGenericFn C_DecryptMessageBegin;
  CkGenericFn C_DecryptMessageNext;
  CkGenericFn C_MessageDecryptFinal;
  CkGenericFn C_MessageSignInit;
  CkGenericFn C_SignMessage;
  CkGenericFn C_SignMessageBegin;
  CkGenericFn C_SignMessageNext;
  CkGenericFn C_MessageSignFinal;
  CkGenericFn C_MessageVerifyInit;
  CkGenericFn C_VerifyMessage;
  CkGenericFn C_VerifyMessageBegin;
  CkGenericFn C_VerifyMessageNext;
  CkGenericFn C_MessageVerifyFinal;
} CkFunctionList30;

#if defined(_WIN32)
#pragma pack(pop)
#endif

static CK_RV stub_ok(void) { return CKR_OK; }

/* PKCS#11 v3.1 mechanism/return-code constants needed by the mechanism-aware
 * stubs below (kept local to this fixture, deliberately not `#include`-ing any
 * real Cryptoki header, to stay strictly self-contained). */
typedef unsigned long CK_MECHANISM_TYPE;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;
#define CKM_EDDSA 4183UL
#define CKM_HKDF_DERIVE 16426UL
#define CKR_MECHANISM_INVALID 112UL

/* Layout mirrors pkcs11-sys's `CK_MECHANISM` exactly: a mechanism type followed
 * by an opaque parameter pointer/length pair. Like `CK_FUNCTION_LIST_3_0`
 * above, `CK_MECHANISM` is `#[repr(C, packed)]` on Windows only, so this must
 * be packed there too or `pMechanism->mechanism` reads the wrong bytes
 * (`mechanism` is 4 bytes, `pParameter` needs 8-byte alignment, so MSVC's
 * natural layout inserts 4 bytes of padding that the packed Rust caller never
 * wrote). */
#if defined(_WIN32)
#pragma pack(push, 1)
#endif

typedef struct CkMechanism {
  CK_MECHANISM_TYPE mechanism;
  CK_VOID_PTR pParameter;
  CK_ULONG ulParameterLen;
} CkMechanism;

#if defined(_WIN32)
#pragma pack(pop)
#endif

/* `C_SignInit`/`C_VerifyInit` share the same (session, mechanism, key)
 * signature. Real conformant v2.40-only libraries reject v3.0-only mechanisms
 * (`CKM_EDDSA`) with `CKR_MECHANISM_INVALID` -- this stub reproduces exactly
 * that behaviour so the graceful-degradation path can be exercised end-to-end
 * through a real dynamically-loaded library, without implementing real EdDSA
 * crypto. */
static CK_RV stub_init_reject_eddsa(CK_SESSION_HANDLE hSession, CkMechanism *pMechanism,
                                    CK_OBJECT_HANDLE hKey) {
  (void)hSession;
  (void)hKey;
  if (pMechanism != 0 && pMechanism->mechanism == CKM_EDDSA) {
    return CKR_MECHANISM_INVALID;
  }
  return CKR_OK;
}

/* `C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey)`:
 * rejects `CKM_HKDF_DERIVE` the same way, mirroring a v2.40-only library that
 * does not implement the v3.0 HKDF mechanism. */
static CK_RV stub_derive_reject_hkdf(CK_SESSION_HANDLE hSession, CkMechanism *pMechanism,
                                     CK_OBJECT_HANDLE hBaseKey, CK_VOID_PTR pTemplate,
                                     CK_ULONG ulAttributeCount, CK_ULONG_PTR phKey) {
  (void)hSession;
  (void)hBaseKey;
  (void)pTemplate;
  (void)ulAttributeCount;
  if (pMechanism != 0 && pMechanism->mechanism == CKM_HKDF_DERIVE) {
    return CKR_MECHANISM_INVALID;
  }
  if (phKey != 0) { *phKey = 42UL; }
  return CKR_OK;
}

/* Real C_GetInterfaceList implementation (PKCS#11 v3.1 section 5.4.5):
 * standard two-call idiom -- a null buffer queries the required count,
 * a non-null buffer of that exact size receives the interface entries. */
static CkInterface g_interface;
static CK_RV get_interface_list(CkInterface *pInterfaceList, CK_ULONG_PTR pulCount) {
  if (pulCount == 0) { return CKR_ARGUMENTS_BAD; }
  if (pInterfaceList == 0) {
    *pulCount = 1;
    return CKR_OK;
  }
  pInterfaceList[0] = g_interface;
  *pulCount = 1;
  return CKR_OK;
}

static CkFunctionList30 g_function_list = {
  .version = {3, 0},
  .C_Initialize = (CkGenericFn)stub_ok,
  .C_Finalize = (CkGenericFn)stub_ok,
  .C_OpenSession = (CkGenericFn)stub_ok,
  .C_CloseSession = (CkGenericFn)stub_ok,
  .C_SignInit = (CkGenericFn)stub_init_reject_eddsa,
  .C_Sign = (CkGenericFn)stub_ok,
  .C_VerifyInit = (CkGenericFn)stub_init_reject_eddsa,
  .C_Verify = (CkGenericFn)stub_ok,
  .C_DeriveKey = (CkGenericFn)stub_derive_reject_hkdf,
  .C_GetInterfaceList = (CkGenericFn)get_interface_list,
};

static CkInterface g_interface = {
  .pInterfaceName = (CK_UTF8CHAR_PTR)"PKCS 11",
  .pFunctionList = &g_function_list,
  .flags = 0,
};

#if defined(_WIN32)
#define CK_EXPORT __declspec(dllexport)
#else
#define CK_EXPORT __attribute__((visibility("default")))
#endif

CK_EXPORT CK_RV C_GetFunctionList(CkFunctionList30 **ppFunctionList) {
  if (ppFunctionList == 0) { return CKR_ARGUMENTS_BAD; }
  *ppFunctionList = &g_function_list;
  return CKR_OK;
}

CK_EXPORT CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CkVersion *pVersion,
                               CkInterface **ppInterface, CK_ULONG flags) {
  (void)pInterfaceName;
  (void)pVersion;
  (void)flags;
  if (ppInterface == 0) { return CKR_ARGUMENTS_BAD; }
  *ppInterface = &g_interface;
  return CKR_OK;
}
