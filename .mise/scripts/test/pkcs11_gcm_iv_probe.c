/* Standalone probe: how does a PKCS#11 library handle AES-GCM IVs?
 *
 * It replays, outside the KMS, the exact calls the KMS server makes for AES-GCM with an HSM key:
 *   - FIPS build:     C_EncryptInit(CKM_AES_GCM) with an all-zero 12-byte IV buffer that the HSM
 *                     must overwrite with the IV it generates (then a length query and the real
 *                     C_Encrypt, as the KMS does);
 *   - non-FIPS build: the same call with a random IV chosen by the caller.
 * It also reports which PKCS#11 v3.0 message functions the library exports.
 *
 * Only a temporary AES session key is created (CKA_TOKEN=false) and destroyed at the end; no token
 * object is written. The PIN is read from the PKCS11_PIN environment variable, never from argv.
 *
 * Build (Linux/macOS):  cc -O2 -o pkcs11_gcm_iv_probe pkcs11_gcm_iv_probe.c -ldl
 * Run:                  PKCS11_PIN=... ./pkcs11_gcm_iv_probe /path/to/libvendor.so <slot-id> [user|so]
 *
 * Self-contained on purpose: it needs no Cryptoki header.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_FLAGS, CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
    CK_MECHANISM_TYPE, CK_ATTRIBUTE_TYPE;
typedef unsigned char CK_BYTE, CK_BBOOL;

typedef struct {
  CK_ATTRIBUTE_TYPE type;
  void *pValue;
  CK_ULONG ulValueLen;
} Attr;
typedef struct {
  CK_MECHANISM_TYPE mechanism;
  void *pParameter;
  CK_ULONG ulParameterLen;
} Mech;
typedef struct {
  CK_BYTE *pIv;
  CK_ULONG ulIvLen;
  CK_ULONG ulIvBits;
  CK_BYTE *pAAD;
  CK_ULONG ulAADLen;
  CK_ULONG ulTagBits;
} GcmParams;
typedef struct {
  unsigned char major, minor;
} Version;
typedef struct {
  unsigned char *pInterfaceName;
  void *pFunctionList;
  CK_ULONG flags;
} Interface;

/* The first entries of CK_FUNCTION_LIST are identical in v2.40 and v3.0. */
typedef struct {
  Version version;
  CK_RV (*C_Initialize)(void *);
  CK_RV (*C_Finalize)(void *);
  void *C_GetInfo, *C_GetFunctionList, *C_GetSlotList, *C_GetSlotInfo, *C_GetTokenInfo,
      *C_GetMechanismList, *C_GetMechanismInfo, *C_InitToken, *C_InitPIN, *C_SetPIN;
  CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void *, void *, CK_SESSION_HANDLE *);
  CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
  void *C_CloseAllSessions, *C_GetSessionInfo, *C_GetOperationState, *C_SetOperationState;
  CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE *, CK_ULONG);
  void *C_Logout, *C_CreateObject, *C_CopyObject;
  CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
  void *C_GetObjectSize, *C_GetAttributeValue, *C_SetAttributeValue, *C_FindObjectsInit,
      *C_FindObjects, *C_FindObjectsFinal;
  CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, Mech *, CK_OBJECT_HANDLE);
  CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
  void *C_EncryptUpdate, *C_EncryptFinal;
  CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, Mech *, CK_OBJECT_HANDLE);
  CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
  void *C_DecryptUpdate, *C_DecryptFinal, *C_DigestInit, *C_Digest, *C_DigestUpdate,
      *C_DigestKey, *C_DigestFinal, *C_SignInit, *C_Sign, *C_SignUpdate, *C_SignFinal,
      *C_SignRecoverInit, *C_SignRecover, *C_VerifyInit, *C_Verify, *C_VerifyUpdate,
      *C_VerifyFinal, *C_VerifyRecoverInit, *C_VerifyRecover, *C_DigestEncryptUpdate,
      *C_DecryptDigestUpdate, *C_SignEncryptUpdate, *C_DecryptVerifyUpdate;
  CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, Mech *, Attr *, CK_ULONG, CK_OBJECT_HANDLE *);
} FnList;

#define CKM_AES_KEY_GEN 0x1080UL
#define CKM_AES_GCM 0x1087UL
#define CKA_CLASS 0x0UL
#define CKA_TOKEN 0x1UL
#define CKA_KEY_TYPE 0x100UL
#define CKA_ENCRYPT 0x104UL
#define CKA_DECRYPT 0x105UL
#define CKA_VALUE_LEN 0x161UL
#define CKO_SECRET_KEY 4UL
#define CKK_AES 0x1fUL
#define CKR_OK 0UL
#define IV_LEN 12
#define TAG_BYTES 16

static const char *rv_name(CK_RV rv) {
  switch (rv) {
  case 0x00: return "CKR_OK";
  case 0x05: return "CKR_GENERAL_ERROR";
  case 0x06: return "CKR_FUNCTION_FAILED";
  case 0x07: return "CKR_ARGUMENTS_BAD";
  case 0x1b: return "CKR_ACTION_PROHIBITED";
  case 0x54: return "CKR_FUNCTION_NOT_SUPPORTED";
  case 0x60: return "CKR_KEY_HANDLE_INVALID";
  case 0x70: return "CKR_MECHANISM_INVALID";
  case 0x71: return "CKR_MECHANISM_PARAM_INVALID";
  case 0x90: return "CKR_OPERATION_ACTIVE";
  case 0x150: return "CKR_BUFFER_TOO_SMALL";
  default: return "(see PKCS#11 headers)";
  }
}

static void hex(const char *label, const CK_BYTE *b, size_t n) {
  printf("    %s: ", label);
  for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
  printf("\n");
}

static int all_zero(const CK_BYTE *b, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (b[i]) return 0;
  return 1;
}

static void random_bytes(CK_BYTE *b, size_t n) {
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f || fread(b, 1, n, f) != n) {
    fprintf(stderr, "cannot read /dev/urandom\n");
    exit(2);
  }
  fclose(f);
}

static FnList *F;
static CK_SESSION_HANDLE S;
static CK_OBJECT_HANDLE KEY;

/* mode: 0 zero IV buffer + length query (exact KMS FIPS sequence), 1 zero IV, single call,
 *       2 random caller IV + length query (KMS non-FIPS sequence), 3 NULL pIv / ulIvLen 0. */
static void scenario(const char *title, int mode) {
  static const CK_BYTE plain[32] = "0123456789abcdef0123456789abcdef";
  CK_BYTE iv[IV_LEN] = {0}, sent_iv[IV_LEN] = {0};
  CK_BYTE out[sizeof plain + TAG_BYTES];
  CK_ULONG outlen = sizeof out, qlen = 0;
  CK_RV rv;
  printf("\n[%s]\n", title);
  if (mode == 2) random_bytes(iv, IV_LEN);
  memcpy(sent_iv, iv, IV_LEN);
  GcmParams p = {mode == 3 ? NULL : iv, mode == 3 ? 0 : IV_LEN, mode == 3 ? 0 : IV_LEN * 8, NULL,
                 0, TAG_BYTES * 8};
  Mech m = {CKM_AES_GCM, &p, sizeof p};
  rv = F->C_EncryptInit(S, &m, KEY);
  printf("    C_EncryptInit            -> %#lx %s\n", rv, rv_name(rv));
  if (rv != CKR_OK) return;
  if (mode != 1 && mode != 3) {
    rv = F->C_Encrypt(S, (CK_BYTE *)plain, sizeof plain, NULL, &qlen);
    printf("    C_Encrypt (length query) -> %#lx %s (len %lu)\n", rv, rv_name(rv), qlen);
    if (rv != CKR_OK) return;
  }
  rv = F->C_Encrypt(S, (CK_BYTE *)plain, sizeof plain, out, &outlen);
  printf("    C_Encrypt                -> %#lx %s (len %lu)\n", rv, rv_name(rv), outlen);
  if (rv != CKR_OK) return;
  if (mode != 3) {
    hex("IV sent    ", sent_iv, IV_LEN);
    hex("IV after   ", iv, IV_LEN);
  }
  if (mode == 0 || mode == 1) {
    if (all_zero(iv, IV_LEN))
      printf("    RESULT: call accepted but the HSM did NOT write a generated IV (IV still zero): "
             "the KMS FIPS build refuses this\n");
    else
      printf("    RESULT: the HSM generated and returned an IV: the KMS FIPS build can use this\n");
  } else if (mode == 2) {
    printf("    RESULT: a caller-chosen IV is accepted (the KMS non-FIPS build can use this)\n");
  } else {
    printf("    RESULT: accepted with a NULL IV, but the IV is not returned in pIv: not usable by "
           "the KMS\n");
    return;
  }
  /* Round trip with the IV that was used, to prove the ciphertext is decryptable. */
  CK_BYTE back[sizeof plain + TAG_BYTES];
  CK_ULONG backlen = sizeof back;
  GcmParams dp = {iv, IV_LEN, IV_LEN * 8, NULL, 0, TAG_BYTES * 8};
  Mech dm = {CKM_AES_GCM, &dp, sizeof dp};
  rv = F->C_DecryptInit(S, &dm, KEY);
  if (rv == CKR_OK) rv = F->C_Decrypt(S, out, outlen, back, &backlen);
  printf("    decrypt round trip       -> %#lx %s%s\n", rv, rv_name(rv),
         rv == CKR_OK && backlen == sizeof plain && !memcmp(back, plain, sizeof plain)
             ? " (plaintext matches)"
             : "");
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: PKCS11_PIN=... %s <library.so> <slot-id> [user|so]\n", argv[0]);
    return 2;
  }
  const char *pin = getenv("PKCS11_PIN");
  void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!lib) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    return 2;
  }
  printf("library: %s\n", argv[1]);

  static const char *msg_syms[] = {"C_MessageEncryptInit", "C_EncryptMessage",
                                   "C_MessageEncryptFinal", "C_MessageDecryptInit",
                                   "C_DecryptMessage", "C_MessageDecryptFinal"};
  printf("exported PKCS#11 v3.0 message symbols (the KMS treats the message API as available "
         "when they are present, even as stubs):\n");
  for (size_t i = 0; i < sizeof msg_syms / sizeof *msg_syms; i++)
    printf("    %-24s %s\n", msg_syms[i], dlsym(lib, msg_syms[i]) ? "exported" : "absent");
  CK_RV (*get_iface)(void *, void *, Interface **, CK_ULONG) = dlsym(lib, "C_GetInterface");
  if (!get_iface) {
    printf("    C_GetInterface           absent (no v3.0 interface table)\n");
  } else {
    Interface *ifc = NULL;
    CK_RV r = get_iface(NULL, NULL, &ifc, 0);
    if (r == CKR_OK && ifc && ifc->pFunctionList)
      printf("    C_GetInterface           default interface version %d.%d\n",
             ((Version *)ifc->pFunctionList)->major, ((Version *)ifc->pFunctionList)->minor);
    else
      printf("    C_GetInterface           -> %#lx %s\n", r, rv_name(r));
  }

  CK_RV (*get_list)(FnList **) = dlsym(lib, "C_GetFunctionList");
  if (!get_list || get_list(&F) != CKR_OK || !F) {
    fprintf(stderr, "C_GetFunctionList failed\n");
    return 2;
  }
  CK_RV rv = F->C_Initialize(NULL);
  if (rv != CKR_OK && rv != 0x191) {
    fprintf(stderr, "C_Initialize -> %#lx %s\n", rv, rv_name(rv));
    return 2;
  }
  rv = F->C_OpenSession(strtoul(argv[2], NULL, 0), 0x6 /* SERIAL|RW */, NULL, NULL, &S);
  if (rv != CKR_OK) {
    fprintf(stderr, "C_OpenSession -> %#lx %s\n", rv, rv_name(rv));
    return 2;
  }
  if (pin) {
    int so = argc > 3 && !strcmp(argv[3], "so");
    rv = F->C_Login(S, so ? 0 : 1, (CK_BYTE *)pin, strlen(pin));
    if (rv != CKR_OK && rv != 0x100) {
      fprintf(stderr, "C_Login -> %#lx %s\n", rv, rv_name(rv));
      return 2;
    }
  }

  CK_BBOOL yes = 1, no = 0;
  CK_ULONG cls = CKO_SECRET_KEY, ktype = CKK_AES, klen = 32;
  Attr tmpl[] = {{CKA_CLASS, &cls, sizeof cls},    {CKA_KEY_TYPE, &ktype, sizeof ktype},
                 {CKA_VALUE_LEN, &klen, sizeof klen}, {CKA_TOKEN, &no, 1},
                 {CKA_ENCRYPT, &yes, 1},           {CKA_DECRYPT, &yes, 1}};
  Mech gen = {CKM_AES_KEY_GEN, NULL, 0};
  rv = F->C_GenerateKey(S, &gen, tmpl, sizeof tmpl / sizeof *tmpl, &KEY);
  printf("\nC_GenerateKey (temporary AES-256 session key) -> %#lx %s\n", rv, rv_name(rv));
  if (rv != CKR_OK) return 2;

  scenario("A. KMS FIPS build: zero IV buffer, length query, then encrypt", 0);
  scenario("B. zero IV buffer, single C_Encrypt call (no length query)", 1);
  scenario("C. KMS non-FIPS build: random IV chosen by the caller", 2);
  scenario("D. NULL pIv / ulIvLen 0 (is this the HSM's convention for 'generate the IV'?)", 3);

  F->C_DestroyObject(S, KEY);
  F->C_CloseSession(S);
  F->C_Finalize(NULL);
  return 0;
}
