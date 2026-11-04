/* Shared declarations for the self-contained PKCS#11 test fixtures
 * (`minimal_pkcs11.c`, `v3_message_adapter.c`). Deliberately does not
 * `#include` any real Cryptoki header, to stay strictly self-contained. */
#ifndef PKCS11_FIXTURE_H
#define PKCS11_FIXTURE_H

typedef unsigned long CK_RV;
typedef void *CK_VOID_PTR;
typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef CK_ULONG *CK_ULONG_PTR;
typedef unsigned char CK_UTF8CHAR;
typedef CK_UTF8CHAR *CK_UTF8CHAR_PTR;

typedef unsigned long CK_MECHANISM_TYPE;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;

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

#if defined(_WIN32)
#define CK_EXPORT __declspec(dllexport)
#else
#define CK_EXPORT __attribute__((visibility("default")))
#endif

#endif /* PKCS11_FIXTURE_H */
