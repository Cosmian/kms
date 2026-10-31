/* PKCS#11 shim emulating a FIPS-mode HSM that never accepts a caller-chosen AES-GCM IV.
 *
 * Everything is forwarded to the real module named by SOFTHSM2_PKCS11_LIB; only
 * C_EncryptInit for CKM_AES_GCM is intercepted:
 *   - a NULL or non-12-byte IV buffer, or any non-zero caller IV, is refused with
 *     CKR_MECHANISM_PARAM_INVALID (FIPS 140-3 IG C.H: the module generates the IV);
 *   - an all-zero 12-byte buffer is accepted, a fresh IV is generated here and written back
 *     into it, like a FIPS-mode HSM.
 * Decryption is untouched: it legitimately receives the stored IV.
 *
 * With -DACCEPT_CALLER_IV the caller's own IV is used as-is, modelling a non-FIPS module;
 * the zero-buffer/HSM-generation rule then does not apply.
 *
 * Build without flags for PKCS#11 v2.40 behaviour. Build with -DV3_MESSAGE to also export a
 * PKCS#11 v3.0 interface whose message-encryption family always fails (a v3 library whose
 * message AES-GCM is unsupported). The message-decryption family stays absent, so KMS
 * decryption uses the classic path.
 */
#include <dlfcn.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../../crate/hsm/base_hsm/tests/fixtures/pkcs11_fixture.h"

#define CKM_AES_GCM 0x1087UL
#define CKR_FUNCTION_NOT_SUPPORTED 0x54UL
#define CKR_MECHANISM_INVALID 0x70UL
#define CKR_MECHANISM_PARAM_INVALID 0x71UL
#define GCM_IV_LEN 12UL

typedef struct CkAesGcmParams {
  CK_BYTE *pIv;
  CK_ULONG ulIvLen;
  CK_ULONG ulIvBits;
  CK_BYTE *pAAD;
  CK_ULONG ulAADLen;
  CK_ULONG ulTagBits;
} CkAesGcmParams;

/* Optional trace of the intercepted calls, so a test can prove which PKCS#11 path ran. */
static void mark(const char *what) {
  const char *path = getenv("FIPS_IV_SHIM_MARKER");
  FILE *file;
  if (path == 0) {
    return;
  }
  file = fopen(path, "a");
  if (file != 0) {
    fprintf(file, "%s\n", what);
    fclose(file);
  }
}

static CkFunctionList30 g_mine;
static int g_loaded;
static CK_RV (*g_real_encrypt_init)(CK_SESSION_HANDLE, CkMechanism *, CK_OBJECT_HANDLE);

static CK_RV shim_encrypt_init(CK_SESSION_HANDLE, CkMechanism *, CK_OBJECT_HANDLE);

static int load_real(void) {
  const char *path;
  void *lib;
  CK_RV (*get_list)(CkFunctionList30 **);
  CkFunctionList30 *list = 0;
  if (g_loaded) {
    return 0;
  }
  path = getenv("SOFTHSM2_PKCS11_LIB");
  if (path == 0) {
    path = "/usr/lib/softhsm/libsofthsm2.so";
  }
  lib = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (lib == 0) {
    fprintf(stderr, "fips-iv-shim: dlopen(%s): %s\n", path, dlerror());
    return -1;
  }
  *(void **)(&get_list) = dlsym(lib, "C_GetFunctionList");
  if (get_list == 0 || get_list(&list) != CKR_OK || list == 0) {
    fprintf(stderr, "fips-iv-shim: real C_GetFunctionList failed\n");
    return -1;
  }
  /* The real module exports the v2.40 prefix; copy only the fields it has. */
  memcpy(&g_mine, list, offsetof(CkFunctionList30, C_GetInterfaceList));
  g_mine.version.major = 2;
  g_mine.version.minor = 40;
  g_real_encrypt_init =
      (CK_RV (*)(CK_SESSION_HANDLE, CkMechanism *, CK_OBJECT_HANDLE))g_mine.C_EncryptInit;
  g_mine.C_EncryptInit = (CkGenericFn)shim_encrypt_init;
  g_loaded = 1;
  return 0;
}

#ifndef ACCEPT_CALLER_IV
static int fill_random(CK_BYTE *dst, size_t len) {
  int fd = open("/dev/urandom", O_RDONLY);
  ssize_t got;
  if (fd < 0) {
    return -1;
  }
  got = read(fd, dst, len);
  close(fd);
  return got == (ssize_t)len ? 0 : -1;
}
#endif

static CK_RV shim_encrypt_init(CK_SESSION_HANDLE session, CkMechanism *mechanism,
                               CK_OBJECT_HANDLE key) {
  if (load_real() != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  mark("classic-encrypt-init");
#ifdef ACCEPT_CALLER_IV
  return g_real_encrypt_init(session, mechanism, key);
#else
  if (mechanism != 0 && mechanism->mechanism == CKM_AES_GCM) {
    CkAesGcmParams *params = (CkAesGcmParams *)mechanism->pParameter;
    CK_ULONG i;
    if (params == 0 || params->pIv == 0 || params->ulIvLen != GCM_IV_LEN) {
      return CKR_MECHANISM_PARAM_INVALID;
    }
    for (i = 0; i < GCM_IV_LEN; i++) {
      if (params->pIv[i] != 0) {
        return CKR_MECHANISM_PARAM_INVALID;
      }
    }
    if (fill_random(params->pIv, GCM_IV_LEN) != 0) {
      return CKR_ARGUMENTS_BAD;
    }
  }
#endif
  return g_real_encrypt_init(session, mechanism, key);
}

#ifdef V3_MESSAGE
static CK_RV message_encrypt_init(CK_SESSION_HANDLE session, CkMechanism *mechanism,
                                  CK_OBJECT_HANDLE key) {
  (void)session;
  (void)mechanism;
  (void)key;
  mark("message-encrypt-init");
  return CKR_MECHANISM_INVALID;
}

static CK_RV unsupported(void) { return CKR_FUNCTION_NOT_SUPPORTED; }

static CkInterface g_interface;

CK_EXPORT CK_RV C_GetInterfaceList(CkInterface *pInterfaceList, CK_ULONG_PTR pulCount) {
  if (pulCount == 0) {
    return CKR_ARGUMENTS_BAD;
  }
  if (pInterfaceList == 0) {
    *pulCount = 1;
    return CKR_OK;
  }
  pInterfaceList[0] = g_interface;
  *pulCount = 1;
  return CKR_OK;
}

CK_EXPORT CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CkVersion *pVersion,
                               CkInterface **ppInterface, CK_ULONG flags) {
  (void)pInterfaceName;
  (void)pVersion;
  (void)flags;
  if (ppInterface == 0) {
    return CKR_ARGUMENTS_BAD;
  }
  *ppInterface = &g_interface;
  return CKR_OK;
}

__attribute__((constructor)) static void shim_constructor(void) {
  if (load_real() != 0) {
    return;
  }
  g_mine.version.major = 3;
  g_mine.version.minor = 0;
  g_mine.C_MessageEncryptInit = (CkGenericFn)message_encrypt_init;
  g_mine.C_EncryptMessage = (CkGenericFn)unsupported;
  g_mine.C_EncryptMessageBegin = (CkGenericFn)unsupported;
  g_mine.C_EncryptMessageNext = (CkGenericFn)unsupported;
  g_mine.C_MessageEncryptFinal = (CkGenericFn)unsupported;
  g_interface.pInterfaceName = (CK_UTF8CHAR_PTR)"PKCS 11";
  g_interface.pFunctionList = &g_mine;
  g_interface.flags = 0;
}
#endif

CK_EXPORT CK_RV C_GetFunctionList(CkFunctionList30 **pp) {
  if (pp == 0) {
    return CKR_ARGUMENTS_BAD;
  }
  if (load_real() != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  *pp = &g_mine;
  return CKR_OK;
}
