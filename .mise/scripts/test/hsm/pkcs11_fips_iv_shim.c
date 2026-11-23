/* PKCS#11 shim emulating a FIPS-mode HSM that never accepts a caller-chosen AES-GCM IV.
 *
 * Everything is forwarded to the real module named by SHIM_BACKEND_LIB (default
 * SOFTHSM2_PKCS11_LIB: SoftHSM2, or the Idemia simulator); only C_EncryptInit for
 * CKM_AES_GCM is intercepted:
 *   - a NULL or non-12-byte IV buffer, or any non-zero caller IV, is refused with
 *     CKR_MECHANISM_PARAM_INVALID (FIPS 140-3 IG C.H: the module generates the IV);
 *   - an all-zero 12-byte buffer is accepted, a fresh IV is generated here and written back
 *     into it, like a FIPS-mode HSM.
 * Decryption is untouched: it legitimately receives the stored IV.
 *
 * With -DACCEPT_CALLER_IV the caller's own IV is used as-is, modelling a non-FIPS module;
 * the zero-buffer/HSM-generation rule then does not apply.
 *
 * With -DMESSAGE_INIT_NOT_SUPPORTED (and -DV3_MESSAGE) C_MessageEncryptInit returns
 * CKR_FUNCTION_NOT_SUPPORTED instead of CKR_MECHANISM_INVALID.
 *
 * Build without flags for PKCS#11 v2.40 behaviour. Build with -DV3_MESSAGE to also export a
 * PKCS#11 v3.0 interface whose message-encryption family always fails (a v3 library whose
 * message AES-GCM is unsupported). The message-decryption family stays absent, so KMS
 * decryption uses the classic path.
 *
 * If FIPS_IV_SHIM_MARKER names a file, every intercepted call is appended to it. For
 * AES-GCM the IV provenance is recorded too, so a test can prove which IV reached the module:
 *   gcm-iv-zero       the caller handed an all-zero 12-byte buffer (the module must fill it)
 *   gcm-iv-nonzero    the caller handed a non-zero IV
 *   gcm-iv-invalid    the caller handed a NULL or non-12-byte IV buffer
 *   gcm-iv-generated  the shim generated an IV and wrote it back
 *
 * Linux/macOS: cc -shared -fPIC.  Windows: cl /LD (links bcrypt.lib) or gcc -shared.
 */
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#endif
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../crate/hsm/base_hsm/tests/fixtures/pkcs11_fixture.h"

#define CKM_AES_GCM 0x1087UL
#define CKR_FUNCTION_NOT_SUPPORTED 0x54UL
#define CKR_MECHANISM_INVALID 0x70UL
#define CKR_MECHANISM_PARAM_INVALID 0x71UL
#define GCM_IV_LEN 12UL

/* Cryptoki structures are 1-byte packed on Windows (see pkcs11_fixture.h). */
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

/* Optional trace of the intercepted calls, so a test can prove which PKCS#11 path ran.
 * The KMS calls the shim from several threads: each line is appended with one atomic write
 * (O_APPEND on POSIX, FILE_APPEND_DATA + a shared open on Windows) so no line is lost or
 * interleaved; a stdio fopen/fclose per call loses lines to sharing violations on Windows. */
static void mark(const char *what) {
  const char *path = getenv("FIPS_IV_SHIM_MARKER");
  char line[96];
  int len;
  if (path == 0) {
    return;
  }
  len = snprintf(line, sizeof line, "%s\n", what);
  if (len <= 0 || (size_t)len >= sizeof line) {
    return;
  }
#ifdef _WIN32
  {
    DWORD written = 0;
    HANDLE file = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
      (void)WriteFile(file, line, (DWORD)len, &written, NULL);
      CloseHandle(file);
    }
  }
#else
  {
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd >= 0) {
      ssize_t ignored = write(fd, line, (size_t)len);
      (void)ignored;
      close(fd);
    }
  }
#endif
}

static CkFunctionList30 g_mine;
static int g_loaded;
static CK_RV (*g_real_encrypt_init)(CK_SESSION_HANDLE, CkMechanism *, CK_OBJECT_HANDLE);

static CK_RV shim_encrypt_init(CK_SESSION_HANDLE, CkMechanism *, CK_OBJECT_HANDLE);

#ifdef _WIN32
/* A host running the OpenSSL FIPS provider (fips.dll, activated through OPENSSL_CONF) and an
 * OpenSSL-based backend such as SoftHSM2 load the SAME fips.dll into one process; its module
 * state is global, so the backend then fails (SoftHSM2 answers CKR_PIN_INCORRECT at login).
 * The mingw-built backend reads its environment from msvcrt.dll, a copy of the process
 * environment taken at startup and independent of the host's (UCRT) one. With
 * SHIM_BACKEND_ISOLATE_OPENSSL set, OPENSSL_CONF is therefore blanked in msvcrt.dll only: the
 * backend uses its default OpenSSL provider while the host keeps its FIPS configuration. */
static void isolate_backend_openssl_env(void) {
  HMODULE crt;
  int (*put_env)(const char *);
  if (getenv("SHIM_BACKEND_ISOLATE_OPENSSL") == 0) {
    return;
  }
  crt = LoadLibraryA("msvcrt.dll");
  if (crt == 0) {
    return;
  }
  *(void **)(&put_env) = (void *)GetProcAddress(crt, "_putenv");
  if (put_env != 0) {
    put_env("OPENSSL_CONF=");
  }
}
#endif

static int load_real(void) {
  const char *path;
  CK_RV (*get_list)(CkFunctionList30 **);
  CkFunctionList30 *list = 0;
  if (g_loaded) {
    return 0;
  }
  path = getenv("SHIM_BACKEND_LIB");
  if (path == 0 || path[0] == '\0') {
    path = getenv("SOFTHSM2_PKCS11_LIB");
  }
#ifdef _WIN32
  isolate_backend_openssl_env();
  {
    HMODULE lib;
    if (path == 0 || path[0] == '\0') {
      path = "C:\\SoftHSMv2\\lib\\softhsm\\libsofthsm2.dll";
    }
    lib = LoadLibraryA(path);
    if (lib == 0) {
      fprintf(stderr, "fips-iv-shim: LoadLibrary(%s) failed: error %lu\n", path,
              (unsigned long)GetLastError());
      return -1;
    }
    *(void **)(&get_list) = (void *)GetProcAddress(lib, "C_GetFunctionList");
  }
#else
  {
    void *lib;
    if (path == 0 || path[0] == '\0') {
      path = "/usr/lib/softhsm/libsofthsm2.so";
    }
    lib = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (lib == 0) {
      fprintf(stderr, "fips-iv-shim: dlopen(%s): %s\n", path, dlerror());
      return -1;
    }
    *(void **)(&get_list) = dlsym(lib, "C_GetFunctionList");
  }
#endif
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
#ifdef _WIN32
  return BCryptGenRandom(NULL, dst, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#else
  int fd = open("/dev/urandom", O_RDONLY);
  ssize_t got;
  if (fd < 0) {
    return -1;
  }
  got = read(fd, dst, len);
  close(fd);
  return got == (ssize_t)len ? 0 : -1;
#endif
}
#endif

static CK_RV shim_encrypt_init(CK_SESSION_HANDLE session, CkMechanism *mechanism,
                               CK_OBJECT_HANDLE key) {
  if (load_real() != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  mark("classic-encrypt-init");
  if (mechanism != 0 && mechanism->mechanism == CKM_AES_GCM) {
    CkAesGcmParams *params = (CkAesGcmParams *)mechanism->pParameter;
    CK_ULONG i;
    int all_zero = 1;
    if (params == 0 || params->pIv == 0 || params->ulIvLen != GCM_IV_LEN) {
      mark("gcm-iv-invalid");
#ifndef ACCEPT_CALLER_IV
      return CKR_MECHANISM_PARAM_INVALID;
#endif
    } else {
      for (i = 0; i < GCM_IV_LEN; i++) {
        if (params->pIv[i] != 0) {
          all_zero = 0;
        }
      }
      mark(all_zero ? "gcm-iv-zero" : "gcm-iv-nonzero");
#ifndef ACCEPT_CALLER_IV
      if (!all_zero) {
        return CKR_MECHANISM_PARAM_INVALID;
      }
      if (fill_random(params->pIv, GCM_IV_LEN) != 0) {
        return CKR_ARGUMENTS_BAD;
      }
      mark("gcm-iv-generated");
#endif
    }
  }
  return g_real_encrypt_init(session, mechanism, key);
}

#ifdef V3_MESSAGE
static CK_RV message_encrypt_init(CK_SESSION_HANDLE session, CkMechanism *mechanism,
                                  CK_OBJECT_HANDLE key) {
  (void)session;
  (void)mechanism;
  (void)key;
  mark("message-encrypt-init");
#ifdef MESSAGE_INIT_NOT_SUPPORTED
  return CKR_FUNCTION_NOT_SUPPORTED; /* a v3 table whose message entries are all stubs */
#else
  return CKR_MECHANISM_INVALID;
#endif
}

static CK_RV unsupported(void) { return CKR_FUNCTION_NOT_SUPPORTED; }

#ifdef MESSAGE_INIT_NOT_SUPPORTED
static CK_RV message_decrypt_init(CK_SESSION_HANDLE session, CkMechanism *mechanism,
                                  CK_OBJECT_HANDLE key) {
  (void)session;
  (void)mechanism;
  (void)key;
  mark("message-decrypt-init");
  return CKR_FUNCTION_NOT_SUPPORTED;
}
#endif

static CkInterface g_interface;
static int g_v3_ready;

/* Builds the v3.0 table on top of the loaded real module (idempotent). */
static int shim_init_v3(void) {
  if (g_v3_ready) {
    return 0;
  }
  if (load_real() != 0) {
    return -1;
  }
  g_mine.version.major = 3;
  g_mine.version.minor = 0;
  g_mine.C_MessageEncryptInit = (CkGenericFn)message_encrypt_init;
  g_mine.C_EncryptMessage = (CkGenericFn)unsupported;
  g_mine.C_EncryptMessageBegin = (CkGenericFn)unsupported;
  g_mine.C_EncryptMessageNext = (CkGenericFn)unsupported;
  g_mine.C_MessageEncryptFinal = (CkGenericFn)unsupported;
#ifdef MESSAGE_INIT_NOT_SUPPORTED
  /* the decrypt family is stubbed too, so the KMS sees a complete v3 message surface */
  g_mine.C_MessageDecryptInit = (CkGenericFn)message_decrypt_init;
  g_mine.C_DecryptMessage = (CkGenericFn)unsupported;
  g_mine.C_DecryptMessageBegin = (CkGenericFn)unsupported;
  g_mine.C_DecryptMessageNext = (CkGenericFn)unsupported;
  g_mine.C_MessageDecryptFinal = (CkGenericFn)unsupported;
#endif
  g_interface.pInterfaceName = (CK_UTF8CHAR_PTR)"PKCS 11";
  g_interface.pFunctionList = &g_mine;
  g_interface.flags = 0;
  g_v3_ready = 1;
  return 0;
}

#ifndef _WIN32
/* Loading another library from DllMain is forbidden under the Windows loader lock, so the
 * Windows build initialises lazily from the exported entry points instead. */
__attribute__((constructor)) static void shim_constructor(void) { (void)shim_init_v3(); }
#endif

CK_EXPORT CK_RV C_GetInterfaceList(CkInterface *pInterfaceList, CK_ULONG_PTR pulCount) {
  if (pulCount == 0 || shim_init_v3() != 0) {
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
  if (ppInterface == 0 || shim_init_v3() != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  *ppInterface = &g_interface;
  return CKR_OK;
}
#endif

CK_EXPORT CK_RV C_GetFunctionList(CkFunctionList30 **pp) {
  if (pp == 0) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef V3_MESSAGE
  if (shim_init_v3() != 0) {
    return CKR_ARGUMENTS_BAD;
  }
#else
  if (load_real() != 0) {
    return CKR_ARGUMENTS_BAD;
  }
#endif
  *pp = &g_mine;
  return CKR_OK;
}
