/* PKCS#11 v2.40-style HSM running in FIPS mode, for regression-testing how the KMS
 * drives classic `C_EncryptInit`/`C_Encrypt` with `CKM_AES_GCM`.
 *
 * FIPS 140-3 IG C.H requires the module to generate GCM encryption IVs itself, so a
 * module in FIPS mode refuses any caller-chosen nonce. This fixture reproduces that:
 *
 *  - a non-zero `pIv` buffer is rejected at the `C_Encrypt` output-length query
 *    (`CKR_MECHANISM_PARAM_INVALID`), which is where a real FIPS-mode HSM reports
 *    "ALGORITHM NOT ALLOWED USING FIPS MODE" for a caller nonce;
 *  - an all-zero `pIv` buffer is accepted: the module draws a fresh IV and writes it back
 *    into `pIv` when the data is actually encrypted (never during the length query).
 *
 * Exports no PKCS#11 v3.0 message functions, so `Session` must use the classic flow. The
 * "ciphertext" is the plaintext XOR 0x42 followed by a 16-byte 0x7E tag: only the framing
 * and IV handling are meaningful. */

#include "pkcs11_fixture.h"

#define CKM_AES_GCM 4231UL
#define CKR_MECHANISM_INVALID 112UL
#define CKR_MECHANISM_PARAM_INVALID 113UL
#define CKR_OPERATION_NOT_INITIALIZED 145UL
#define CKR_BUFFER_TOO_SMALL 336UL

#define GCM_IV_LEN 12UL
#define GCM_TAG_LEN 16UL

/* Layout mirrors pkcs11-sys's `CK_AES_GCM_PARAMS` (packed on Windows only, like the
 * other structs in `pkcs11_fixture.h`). */
#if defined(_WIN32)
#pragma pack(push, 1)
#endif
typedef struct CkAesGcmParams {
  CK_BYTE *pIv;
  CK_ULONG ulIvLen;
  CK_ULONG ulIvBits;
  CK_BYTE *pAAD;
  CK_ULONG ulAADLen;
  CK_ULONG ulTagBits;
} CkAesGcmParams;
#if defined(_WIN32)
#pragma pack(pop)
#endif

static CK_RV stub_ok(void) { return CKR_OK; }

static CkAesGcmParams *g_params;
static CK_ULONG g_generated_ivs;
static int g_message_active;
static CK_ULONG g_message_final_calls;

static CK_RV message_encrypt_init(CK_SESSION_HANDLE hSession, CkMechanism *pMechanism,
                                 CK_OBJECT_HANDLE hKey) {
  (void)hSession;
  (void)pMechanism;
  (void)hKey;
  g_message_active = 1;
  return CKR_OK;
}

static CK_RV encrypt_message(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen,
                             CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen,
                             CK_BYTE *pPlaintext, CK_ULONG ulPlaintextLen,
                             CK_BYTE *pCiphertext, CK_ULONG_PTR pulCiphertextLen) {
  (void)hSession;
  (void)pParameter;
  (void)ulParameterLen;
  (void)pAssociatedData;
  (void)ulAssociatedDataLen;
  (void)pPlaintext;
  (void)ulPlaintextLen;
  (void)pCiphertext;
  (void)pulCiphertextLen;
  return 5UL;
}

static CK_RV message_encrypt_final(CK_SESSION_HANDLE hSession) {
  (void)hSession;
  g_message_active = 0;
  g_message_final_calls++;
  return CKR_OK;
}

static CK_RV encrypt_init(CK_SESSION_HANDLE hSession, CkMechanism *pMechanism,
                          CK_OBJECT_HANDLE hKey) {
  (void)hSession;
  (void)hKey;
#ifdef REQUIRE_V3_MESSAGE
  if (g_message_final_calls == 0) { return 144UL; }
#endif
  if (g_message_active) { return 144UL; }
  if (pMechanism == 0 || pMechanism->mechanism != CKM_AES_GCM) {
    return CKR_MECHANISM_INVALID;
  }
  if (pMechanism->pParameter == 0 || pMechanism->ulParameterLen != sizeof(CkAesGcmParams)) {
    return CKR_MECHANISM_PARAM_INVALID;
  }
  g_params = (CkAesGcmParams *)pMechanism->pParameter;
  return CKR_OK;
}

static CK_RV encrypt(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen,
                     CK_BYTE *pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
  CK_ULONG i;
  CK_ULONG out_len;
  (void)hSession;
  if (g_params == 0) { return CKR_OPERATION_NOT_INITIALIZED; }
  if (g_params->pIv == 0 || g_params->ulIvLen != GCM_IV_LEN) {
    return CKR_MECHANISM_PARAM_INVALID;
  }
  /* FIPS mode: the nonce must come from the module, never from the caller. */
  for (i = 0; i < GCM_IV_LEN; i++) {
    if (g_params->pIv[i] != 0) { return CKR_MECHANISM_PARAM_INVALID; }
  }
  out_len = ulDataLen + GCM_TAG_LEN;
  if (pEncryptedData == 0) {
    *pulEncryptedDataLen = out_len;
    return CKR_OK;
  }
  if (*pulEncryptedDataLen < out_len) {
    *pulEncryptedDataLen = out_len;
    return CKR_BUFFER_TOO_SMALL;
  }
  /* The module draws a fresh IV and returns it through the parameter buffer
   * (-DIGNORE_IV_BUFFER emulates a library that never writes it back). */
  g_generated_ivs++;
#ifndef IGNORE_IV_BUFFER
  for (i = 0; i < GCM_IV_LEN; i++) {
    g_params->pIv[i] = (CK_BYTE)(0xA0UL + g_generated_ivs + i);
  }
#endif
  for (i = 0; i < ulDataLen; i++) { pEncryptedData[i] = (CK_BYTE)(pData[i] ^ 0x42); }
  for (i = 0; i < GCM_TAG_LEN; i++) { pEncryptedData[ulDataLen + i] = 0x7E; }
  *pulEncryptedDataLen = out_len;
  g_params = 0;
  return CKR_OK;
}

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

static CK_RV message_encrypt_init(CK_SESSION_HANDLE hSession, CkMechanism *pMechanism,
                                 CK_OBJECT_HANDLE hKey);
static CK_RV encrypt_message(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen,
                             CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen,
                             CK_BYTE *pPlaintext, CK_ULONG ulPlaintextLen,
                             CK_BYTE *pCiphertext, CK_ULONG_PTR pulCiphertextLen);
static CK_RV message_encrypt_final(CK_SESSION_HANDLE hSession);

static CkFunctionList30 g_function_list = {
  .C_SignInit = (CkGenericFn)stub_ok,
  .C_Sign = (CkGenericFn)stub_ok,
  .C_VerifyInit = (CkGenericFn)stub_ok,
  .C_Verify = (CkGenericFn)stub_ok,
  .C_DeriveKey = (CkGenericFn)stub_ok,
  .version = {3, 0},
  .C_Initialize = (CkGenericFn)stub_ok,
  .C_Finalize = (CkGenericFn)stub_ok,
  .C_OpenSession = (CkGenericFn)stub_ok,
  .C_CloseSession = (CkGenericFn)stub_ok,
  .C_EncryptInit = (CkGenericFn)encrypt_init,
  .C_Encrypt = (CkGenericFn)encrypt,
  .C_MessageEncryptInit = (CkGenericFn)message_encrypt_init,
  .C_EncryptMessage = (CkGenericFn)encrypt_message,
  .C_MessageEncryptFinal = (CkGenericFn)message_encrypt_final,
  .C_EncryptMessageBegin = (CkGenericFn)stub_ok,
  .C_EncryptMessageNext = (CkGenericFn)stub_ok,
  .C_GetInterfaceList = (CkGenericFn)get_interface_list,
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
