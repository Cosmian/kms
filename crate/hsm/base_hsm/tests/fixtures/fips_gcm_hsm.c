/* Non-cryptographic AES-GCM routing fixture: ciphertext is plaintext XOR 0x42,
 * with a fixed 16-byte 0x7E tag. This tests framing, IV ownership and dispatch,
 * not cryptography or FIPS validation.
 *
 * Compiler modes (encryption and decryption families are independent):
 * EXPECT_CALLER_IV: classic encryption requires a nonzero IV and preserves it;
 *   otherwise it requires zero input and writes 0xA1+i into the 12-byte IV.
 * IGNORE_IV_BUFFER: suppress classic generated-IV writeback.
 * MESSAGE_SUCCESS: message encryption succeeds with IV 0xB0+i; otherwise its
 *   message call returns CKR_GENERAL_ERROR, requiring Final before fallback.
 * NO_MESSAGE_ENCRYPT / NO_MESSAGE_DECRYPT: omit the corresponding whole family.
 * MISSING_MESSAGE_ENCRYPT_FINAL / MISSING_MESSAGE_DECRYPT_FINAL: omit only Final.
 * REQUIRE_V3_MESSAGE: classic encryption requires a preceding message Final.
 * MESSAGE_DECRYPT_FAILURE: message decryption returns CKR_GENERAL_ERROR.
 * REQUIRE_MESSAGE_DECRYPT: classic decrypt Init returns CKR_GENERAL_ERROR.
 * REJECT_DRIVER_OPERATIONS: all encrypt/decrypt Init calls return that error,
 *   so public input validation must reject invalid input without reaching them.
 * MESSAGE_FINAL_FAILURE: both message Final calls report an error after clearing state.
 * MESSAGE_BAD_LENGTH: successful message calls report one byte too many (without writing it).
 * MESSAGE_ZERO_IV: successful message encryption leaves its IV buffer untouched.
 * CLASSIC_BAD_LENGTH: classic decrypt reports one byte beyond the supplied capacity.
 * MESSAGE_DECRYPT_TERMINATES_ON_ERROR: authentication failure ends the process before Final.
 *
 * Decryption always requires the original stored IV 0x31+i, independently of
 * encryption's IV mode. A tampered tag returns CKR_ENCRYPTED_DATA_INVALID before
 * any plaintext is written. Successful message encryption uses detached tags.
 */

#include "pkcs11_fixture.h"

#define CKM_AES_GCM 4231UL
#define CKR_GENERAL_ERROR 5UL
#define CKR_ENCRYPTED_DATA_INVALID 64UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE 65UL
#define CKR_MECHANISM_INVALID 112UL
#define CKR_MECHANISM_PARAM_INVALID 113UL
#define CKR_OPERATION_ACTIVE 144UL
#define CKR_OPERATION_NOT_INITIALIZED 145UL
#define CKR_BUFFER_TOO_SMALL 336UL
#define CKG_NO_GENERATE 0UL
#define CKG_GENERATE_RANDOM 3UL

#define GCM_IV_LEN 12UL
#define GCM_TAG_LEN 16UL

/* Match pkcs11-sys layouts, including its Windows-only packing. */
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

typedef struct CkGcmMessageParams {
  CK_BYTE *pIv;
  CK_ULONG ulIvLen;
  CK_ULONG ulIvFixedBits;
  CK_ULONG ivGenerator;
  CK_BYTE *pTag;
  CK_ULONG ulTagBits;
} CkGcmMessageParams;
#if defined(_WIN32)
#pragma pack(pop)
#endif

static CK_RV stub_ok(void) { return CKR_OK; }

static CkAesGcmParams *g_params;
static CkAesGcmParams *g_decrypt_params;
static int g_message_active;
static int g_message_decrypt_active;
static CK_ULONG g_message_final_calls;

static CK_RV validate_classic_params(CkMechanism *mechanism) {
  CkAesGcmParams *params;
  if (mechanism == 0 || mechanism->mechanism != CKM_AES_GCM) {
    return CKR_MECHANISM_INVALID;
  }
  if (mechanism->pParameter == 0 ||
      mechanism->ulParameterLen != sizeof(CkAesGcmParams)) {
    return CKR_MECHANISM_PARAM_INVALID;
  }
  params = (CkAesGcmParams *)mechanism->pParameter;
  if (params->pIv == 0 || params->ulIvLen != GCM_IV_LEN ||
      params->ulIvBits != GCM_IV_LEN * 8 || params->ulTagBits != GCM_TAG_LEN * 8 ||
      (params->ulAADLen != 0 && params->pAAD == 0)) {
    return CKR_MECHANISM_PARAM_INVALID;
  }
  return CKR_OK;
}

static CK_RV validate_message_mechanism(CkMechanism *mechanism) {
  if (mechanism == 0 || mechanism->mechanism != CKM_AES_GCM) {
    return CKR_MECHANISM_INVALID;
  }
  if (mechanism->pParameter != 0 || mechanism->ulParameterLen != 0) {
    return CKR_MECHANISM_PARAM_INVALID;
  }
  return CKR_OK;
}

static CK_RV validate_message_params(void *parameter, CK_ULONG length,
                                     CK_ULONG generator) {
  CkGcmMessageParams *params;
  if (parameter == 0 || length != sizeof(CkGcmMessageParams)) {
    return CKR_MECHANISM_PARAM_INVALID;
  }
  params = (CkGcmMessageParams *)parameter;
  if (params->pIv == 0 || params->ulIvLen != GCM_IV_LEN ||
      params->ulIvFixedBits != 0 || params->ivGenerator != generator ||
      params->pTag == 0 || params->ulTagBits != GCM_TAG_LEN * 8) {
    return CKR_MECHANISM_PARAM_INVALID;
  }
  return CKR_OK;
}

static CK_RV validate_stored_iv(CK_BYTE *iv) {
  CK_ULONG i;
  for (i = 0; i < GCM_IV_LEN; i++) {
    if (iv[i] != (CK_BYTE)(0x31UL + i)) {
      return CKR_MECHANISM_PARAM_INVALID;
    }
  }
  return CKR_OK;
}

static CK_RV validate_tag(CK_BYTE *tag) {
  CK_ULONG i;
  for (i = 0; i < GCM_TAG_LEN; i++) {
    if (tag[i] != 0x7E) { return CKR_ENCRYPTED_DATA_INVALID; }
  }
  return CKR_OK;
}

static CK_RV message_encrypt_init(CK_SESSION_HANDLE hSession, CkMechanism *pMechanism,
                                 CK_OBJECT_HANDLE hKey) {
  CK_RV rv;
  (void)hSession;
  (void)hKey;
#ifdef REJECT_DRIVER_OPERATIONS
  return CKR_GENERAL_ERROR;
#endif
  if (g_message_active) { return CKR_OPERATION_ACTIVE; }
  rv = validate_message_mechanism(pMechanism);
  if (rv != CKR_OK) { return rv; }
  g_message_active = 1;
  return CKR_OK;
}

static CK_RV encrypt_message(CK_SESSION_HANDLE hSession, void *pParameter,
                             CK_ULONG ulParameterLen, CK_BYTE *pAssociatedData,
                             CK_ULONG ulAssociatedDataLen, CK_BYTE *pPlaintext,
                             CK_ULONG ulPlaintextLen, CK_BYTE *pCiphertext,
                             CK_ULONG_PTR pulCiphertextLen) {
  CK_RV rv;
  CK_ULONG i;
  CkGcmMessageParams *params;
  (void)hSession;
  if (!g_message_active) { return CKR_OPERATION_NOT_INITIALIZED; }
  rv = validate_message_params(pParameter, ulParameterLen, CKG_GENERATE_RANDOM);
  if (rv != CKR_OK) { return rv; }
  if (pulCiphertextLen == 0 || (ulPlaintextLen != 0 && pPlaintext == 0) ||
      (ulAssociatedDataLen != 0 && pAssociatedData == 0)) {
    return CKR_ARGUMENTS_BAD;
  }
#ifndef MESSAGE_SUCCESS
  return CKR_GENERAL_ERROR;
#endif
  if (pCiphertext == 0) {
    *pulCiphertextLen = ulPlaintextLen;
    return CKR_OK;
  }
  if (*pulCiphertextLen < ulPlaintextLen) {
    *pulCiphertextLen = ulPlaintextLen;
    return CKR_BUFFER_TOO_SMALL;
  }
  params = (CkGcmMessageParams *)pParameter;
#ifndef MESSAGE_ZERO_IV
  for (i = 0; i < GCM_IV_LEN; i++) { params->pIv[i] = (CK_BYTE)(0xB0UL + i); }
#endif
  for (i = 0; i < ulPlaintextLen; i++) {
    pCiphertext[i] = (CK_BYTE)(pPlaintext[i] ^ 0x42);
  }
  for (i = 0; i < GCM_TAG_LEN; i++) { params->pTag[i] = 0x7E; }
  *pulCiphertextLen = ulPlaintextLen;
#ifdef MESSAGE_BAD_LENGTH
  *pulCiphertextLen = ulPlaintextLen + 1;
#endif
  return CKR_OK;
}

static CK_RV message_encrypt_final(CK_SESSION_HANDLE hSession) {
  (void)hSession;
  if (!g_message_active) { return CKR_OPERATION_NOT_INITIALIZED; }
  g_message_active = 0;
  g_message_final_calls++;
#ifdef MESSAGE_FINAL_FAILURE
  return CKR_GENERAL_ERROR;
#endif
  return CKR_OK;
}

static CK_RV encrypt_init(CK_SESSION_HANDLE hSession, CkMechanism *pMechanism,
                          CK_OBJECT_HANDLE hKey) {
  CK_RV rv;
  (void)hSession;
  (void)hKey;
#ifdef REJECT_DRIVER_OPERATIONS
  return CKR_GENERAL_ERROR;
#endif
#ifdef REQUIRE_V3_MESSAGE
  if (g_message_final_calls == 0) { return CKR_OPERATION_ACTIVE; }
#endif
  if (g_message_active) { return CKR_OPERATION_ACTIVE; }
  rv = validate_classic_params(pMechanism);
  if (rv != CKR_OK) { return rv; }
  g_params = (CkAesGcmParams *)pMechanism->pParameter;
  return CKR_OK;
}

static CK_RV encrypt(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen,
                     CK_BYTE *pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
  CK_ULONG i;
  CK_ULONG out_len;
  int nonzero_iv = 0;
  (void)hSession;
  if (g_params == 0) { return CKR_OPERATION_NOT_INITIALIZED; }
  if (pulEncryptedDataLen == 0 || (ulDataLen != 0 && pData == 0) ||
      ulDataLen > (~0UL - GCM_TAG_LEN)) {
    return CKR_ARGUMENTS_BAD;
  }
  for (i = 0; i < GCM_IV_LEN; i++) {
    if (g_params->pIv[i] != 0) { nonzero_iv = 1; }
  }
#ifdef EXPECT_CALLER_IV
  if (!nonzero_iv) { return CKR_MECHANISM_PARAM_INVALID; }
#else
  if (nonzero_iv) { return CKR_MECHANISM_PARAM_INVALID; }
#endif
  out_len = ulDataLen + GCM_TAG_LEN;
  if (pEncryptedData == 0) {
    *pulEncryptedDataLen = out_len;
    return CKR_OK;
  }
  if (*pulEncryptedDataLen < out_len) {
    *pulEncryptedDataLen = out_len;
    return CKR_BUFFER_TOO_SMALL;
  }
#if !defined(EXPECT_CALLER_IV) && !defined(IGNORE_IV_BUFFER)
  for (i = 0; i < GCM_IV_LEN; i++) {
    g_params->pIv[i] = (CK_BYTE)(0xA1UL + i);
  }
#endif
  for (i = 0; i < ulDataLen; i++) { pEncryptedData[i] = (CK_BYTE)(pData[i] ^ 0x42); }
  for (i = 0; i < GCM_TAG_LEN; i++) { pEncryptedData[ulDataLen + i] = 0x7E; }
  *pulEncryptedDataLen = out_len;
  g_params = 0;
  return CKR_OK;
}

static CK_RV decrypt_init(CK_SESSION_HANDLE hSession, CkMechanism *pMechanism,
                          CK_OBJECT_HANDLE hKey) {
  CK_RV rv;
  (void)hSession;
  (void)hKey;
#if defined(REJECT_DRIVER_OPERATIONS) || defined(REQUIRE_MESSAGE_DECRYPT)
  return CKR_GENERAL_ERROR;
#endif
  rv = validate_classic_params(pMechanism);
  if (rv != CKR_OK) { return rv; }
  g_decrypt_params = (CkAesGcmParams *)pMechanism->pParameter;
  return validate_stored_iv(g_decrypt_params->pIv);
}

static CK_RV decrypt(CK_SESSION_HANDLE hSession, CK_BYTE *pEncryptedData,
                     CK_ULONG ulEncryptedDataLen, CK_BYTE *pData,
                     CK_ULONG_PTR pulDataLen) {
  CK_RV rv;
  CK_ULONG i;
  CK_ULONG out_len;
  (void)hSession;
  if (g_decrypt_params == 0) { return CKR_OPERATION_NOT_INITIALIZED; }
  if (pulDataLen == 0 || pEncryptedData == 0) { return CKR_ARGUMENTS_BAD; }
  if (ulEncryptedDataLen < GCM_TAG_LEN) { return CKR_ENCRYPTED_DATA_LEN_RANGE; }
  rv = validate_stored_iv(g_decrypt_params->pIv);
  if (rv != CKR_OK) { return rv; }
  out_len = ulEncryptedDataLen - GCM_TAG_LEN;
  rv = validate_tag(pEncryptedData + out_len);
  if (rv != CKR_OK) { return rv; }
  if (pData == 0) {
    *pulDataLen = out_len;
    return CKR_OK;
  }
  if (*pulDataLen < out_len) {
    *pulDataLen = out_len;
    return CKR_BUFFER_TOO_SMALL;
  }
  for (i = 0; i < out_len; i++) { pData[i] = (CK_BYTE)(pEncryptedData[i] ^ 0x42); }
  *pulDataLen = out_len;
#ifdef CLASSIC_BAD_LENGTH
  *pulDataLen = ulEncryptedDataLen + 1;
#endif
  g_decrypt_params = 0;
  return CKR_OK;
}

static CK_RV message_decrypt_init(CK_SESSION_HANDLE hSession, CkMechanism *pMechanism,
                                 CK_OBJECT_HANDLE hKey) {
  CK_RV rv;
  (void)hSession;
  (void)hKey;
#ifdef REJECT_DRIVER_OPERATIONS
  return CKR_GENERAL_ERROR;
#endif
  if (g_message_decrypt_active) { return CKR_OPERATION_ACTIVE; }
  rv = validate_message_mechanism(pMechanism);
  if (rv != CKR_OK) { return rv; }
  g_message_decrypt_active = 1;
  return CKR_OK;
}

static CK_RV decrypt_message(CK_SESSION_HANDLE hSession, void *pParameter,
                             CK_ULONG ulParameterLen, CK_BYTE *pAssociatedData,
                             CK_ULONG ulAssociatedDataLen, CK_BYTE *pCiphertext,
                             CK_ULONG ulCiphertextLen, CK_BYTE *pPlaintext,
                             CK_ULONG_PTR pulPlaintextLen) {
  CK_RV rv;
  CK_ULONG i;
  CkGcmMessageParams *params;
  (void)hSession;
  if (!g_message_decrypt_active) { return CKR_OPERATION_NOT_INITIALIZED; }
  rv = validate_message_params(pParameter, ulParameterLen, CKG_NO_GENERATE);
  if (rv != CKR_OK) { return rv; }
  if (pulPlaintextLen == 0 || (ulCiphertextLen != 0 && pCiphertext == 0) ||
      (ulAssociatedDataLen != 0 && pAssociatedData == 0)) {
    return CKR_ARGUMENTS_BAD;
  }
  params = (CkGcmMessageParams *)pParameter;
  rv = validate_stored_iv(params->pIv);
  if (rv != CKR_OK) { return rv; }
  rv = validate_tag(params->pTag);
#ifdef MESSAGE_DECRYPT_TERMINATES_ON_ERROR
  if (rv != CKR_OK) { g_message_decrypt_active = 0; }
#endif
  if (rv != CKR_OK) { return rv; }
#ifdef MESSAGE_DECRYPT_FAILURE
  return CKR_GENERAL_ERROR;
#endif
  if (pPlaintext == 0) {
    *pulPlaintextLen = ulCiphertextLen;
    return CKR_OK;
  }
  if (*pulPlaintextLen < ulCiphertextLen) {
    *pulPlaintextLen = ulCiphertextLen;
    return CKR_BUFFER_TOO_SMALL;
  }
  for (i = 0; i < ulCiphertextLen; i++) {
    pPlaintext[i] = (CK_BYTE)(pCiphertext[i] ^ 0x42);
  }
  *pulPlaintextLen = ulCiphertextLen;
#ifdef MESSAGE_BAD_LENGTH
  *pulPlaintextLen = ulCiphertextLen + 1;
#endif
  return CKR_OK;
}

static CK_RV message_decrypt_final(CK_SESSION_HANDLE hSession) {
  (void)hSession;
  if (!g_message_decrypt_active) { return CKR_OPERATION_NOT_INITIALIZED; }
  g_message_decrypt_active = 0;
#ifdef MESSAGE_FINAL_FAILURE
  return CKR_GENERAL_ERROR;
#endif
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
  .C_DecryptInit = (CkGenericFn)decrypt_init,
  .C_Decrypt = (CkGenericFn)decrypt,
#ifndef NO_MESSAGE_ENCRYPT
  .C_MessageEncryptInit = (CkGenericFn)message_encrypt_init,
  .C_EncryptMessage = (CkGenericFn)encrypt_message,
#ifndef MISSING_MESSAGE_ENCRYPT_FINAL
  .C_MessageEncryptFinal = (CkGenericFn)message_encrypt_final,
#endif
  .C_EncryptMessageBegin = (CkGenericFn)stub_ok,
  .C_EncryptMessageNext = (CkGenericFn)stub_ok,
#endif
#ifndef NO_MESSAGE_DECRYPT
  .C_MessageDecryptInit = (CkGenericFn)message_decrypt_init,
  .C_DecryptMessage = (CkGenericFn)decrypt_message,
  .C_DecryptMessageBegin = (CkGenericFn)stub_ok,
  .C_DecryptMessageNext = (CkGenericFn)stub_ok,
#ifndef MISSING_MESSAGE_DECRYPT_FINAL
  .C_MessageDecryptFinal = (CkGenericFn)message_decrypt_final,
#endif
#endif
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
