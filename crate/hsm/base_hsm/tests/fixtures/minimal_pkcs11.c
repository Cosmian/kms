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

#include "pkcs11_fixture.h"

static CK_RV stub_ok(void) { return CKR_OK; }

#define CKM_EDDSA 4183UL
#define CKM_HKDF_DERIVE 16426UL
#define CKR_MECHANISM_INVALID 112UL

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

#ifdef WITH_MESSAGE_SIGNATURE
/* Deterministic PKCS#11 v3.0 message sign/verify stubs: a signature is 64 bytes of 0x5A and
 * verification accepts exactly that. One active flag per family (tests use a single session).
 * `CKM_ECDSA` is rejected at message init to simulate a per-mechanism rejection while the
 * classic stubs still accept it. `g_counts` records every call (indices documented in
 * `fixture_message_counts`'s callers). */
#define CKM_ECDSA 4161UL
#define CKR_DEVICE_ERROR 48UL
#define CKR_FUNCTION_NOT_SUPPORTED 84UL
#define CKR_OPERATION_ACTIVE 144UL
#define CKR_OPERATION_NOT_INITIALIZED 145UL
#define CKR_SIGNATURE_INVALID 192UL
#define CKR_BUFFER_TOO_SMALL 336UL

enum {
  CNT_SIGN_INIT_MSG, CNT_SIGN_MSG, CNT_SIGN_FINAL_MSG,
  CNT_VERIFY_INIT_MSG, CNT_VERIFY_MSG, CNT_VERIFY_FINAL_MSG,
  CNT_SIGN_INIT, CNT_VERIFY_INIT, CNT_LEN
};
static CK_ULONG g_counts[CNT_LEN];
static int g_sign_active;
static int g_verify_active;
static CK_ULONG g_fail_mode; /* 0 none, 1 NOT_INITIALIZED, 2 DEVICE_ERROR */

static CK_RV stub_sign_init(CK_SESSION_HANDLE h, CkMechanism *m, CK_OBJECT_HANDLE k) {
  g_counts[CNT_SIGN_INIT]++;
  return stub_init_reject_eddsa(h, m, k);
}
static CK_RV stub_verify_init(CK_SESSION_HANDLE h, CkMechanism *m, CK_OBJECT_HANDLE k) {
  g_counts[CNT_VERIFY_INIT]++;
  return stub_init_reject_eddsa(h, m, k);
}
static CK_RV stub_not_supported(void) { return CKR_FUNCTION_NOT_SUPPORTED; }

static CK_RV message_init(int *active, CkMechanism *m) {
  if (m != 0 && m->mechanism == CKM_ECDSA) { return CKR_MECHANISM_INVALID; }
  if (*active) { return CKR_OPERATION_ACTIVE; }
  *active = 1;
  return CKR_OK;
}
static CK_RV stub_message_sign_init(CK_SESSION_HANDLE h, CkMechanism *m, CK_OBJECT_HANDLE k) {
  (void)h; (void)k;
  g_counts[CNT_SIGN_INIT_MSG]++;
  return message_init(&g_sign_active, m);
}
static CK_RV stub_message_verify_init(CK_SESSION_HANDLE h, CkMechanism *m, CK_OBJECT_HANDLE k) {
  (void)h; (void)k;
  g_counts[CNT_VERIFY_INIT_MSG]++;
  return message_init(&g_verify_active, m);
}

/* Applies a pending injected failure; returns non-zero when `*rv` was set. */
static int apply_fail_mode(int *active, CK_RV *rv) {
  if (g_fail_mode == 1) { g_fail_mode = 0; *active = 0; *rv = CKR_OPERATION_NOT_INITIALIZED; return 1; }
  if (g_fail_mode == 2) { g_fail_mode = 0; *rv = CKR_DEVICE_ERROR; return 1; }
  return 0;
}

static CK_RV stub_sign_message(CK_SESSION_HANDLE h, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
                               CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pSignature,
                               CK_ULONG_PTR pulSignatureLen) {
  CK_RV rv;
  CK_ULONG i;
  (void)h; (void)pParameter; (void)ulParameterLen; (void)pData; (void)ulDataLen;
  g_counts[CNT_SIGN_MSG]++;
  if (!g_sign_active) { return CKR_OPERATION_NOT_INITIALIZED; }
  if (apply_fail_mode(&g_sign_active, &rv)) { return rv; }
  if (pSignature == 0) { *pulSignatureLen = 64; return CKR_OK; }
  if (*pulSignatureLen < 64) { *pulSignatureLen = 64; return CKR_BUFFER_TOO_SMALL; }
  for (i = 0; i < 64; i++) { pSignature[i] = 0x5A; }
  *pulSignatureLen = 64;
  return CKR_OK;
}

static CK_RV stub_verify_message(CK_SESSION_HANDLE h, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
                                 CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pSignature,
                                 CK_ULONG ulSignatureLen) {
  CK_RV rv;
  CK_ULONG i;
  (void)h; (void)pParameter; (void)ulParameterLen; (void)pData; (void)ulDataLen;
  g_counts[CNT_VERIFY_MSG]++;
  if (!g_verify_active) { return CKR_OPERATION_NOT_INITIALIZED; }
  if (apply_fail_mode(&g_verify_active, &rv)) { return rv; }
  if (ulSignatureLen != 64) { return CKR_SIGNATURE_INVALID; }
  for (i = 0; i < 64; i++) {
    if (pSignature[i] != 0x5A) { return CKR_SIGNATURE_INVALID; }
  }
  return CKR_OK;
}

static CK_RV message_final(int *active) {
  if (!*active) { return CKR_OPERATION_NOT_INITIALIZED; }
  *active = 0;
  return CKR_OK;
}
static CK_RV stub_message_sign_final(CK_SESSION_HANDLE h) {
  (void)h;
  g_counts[CNT_SIGN_FINAL_MSG]++;
  return message_final(&g_sign_active);
}
static CK_RV stub_message_verify_final(CK_SESSION_HANDLE h) {
  (void)h;
  g_counts[CNT_VERIFY_FINAL_MSG]++;
  return message_final(&g_verify_active);
}

CK_EXPORT void fixture_message_counts(CK_ULONG out[8]) {
  CK_ULONG i;
  for (i = 0; i < CNT_LEN; i++) { out[i] = g_counts[i]; }
}
CK_EXPORT void fixture_fail_next_message(CK_ULONG mode) { g_fail_mode = mode; }

#define SIGN_INIT_FN stub_sign_init
#define VERIFY_INIT_FN stub_verify_init
#else
#define SIGN_INIT_FN stub_init_reject_eddsa
#define VERIFY_INIT_FN stub_init_reject_eddsa
#endif

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
  .C_SignInit = (CkGenericFn)SIGN_INIT_FN,
  .C_Sign = (CkGenericFn)stub_ok,
  .C_VerifyInit = (CkGenericFn)VERIFY_INIT_FN,
  .C_Verify = (CkGenericFn)stub_ok,
  .C_DeriveKey = (CkGenericFn)stub_derive_reject_hkdf,
  .C_GetInterfaceList = (CkGenericFn)get_interface_list,
#ifdef WITH_MESSAGE_SIGNATURE
  .C_MessageSignInit = (CkGenericFn)stub_message_sign_init,
  .C_SignMessage = (CkGenericFn)stub_sign_message,
  .C_SignMessageBegin = (CkGenericFn)stub_not_supported,
  .C_SignMessageNext = (CkGenericFn)stub_not_supported,
  .C_MessageSignFinal = (CkGenericFn)stub_message_sign_final,
  .C_MessageVerifyInit = (CkGenericFn)stub_message_verify_init,
  .C_VerifyMessage = (CkGenericFn)stub_verify_message,
  .C_VerifyMessageBegin = (CkGenericFn)stub_not_supported,
  .C_VerifyMessageNext = (CkGenericFn)stub_not_supported,
  .C_MessageVerifyFinal = (CkGenericFn)stub_message_verify_final,
#endif
};

static CkInterface g_interface = {
  .pInterfaceName = (CK_UTF8CHAR_PTR)"PKCS 11",
  .pFunctionList = &g_function_list,
  .flags = 0,
};

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
