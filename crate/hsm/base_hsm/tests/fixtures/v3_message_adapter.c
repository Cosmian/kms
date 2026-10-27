/* Test-only PKCS#11 v3.0 adapter that adds the message-based signature functions
 * (`C_MessageSignInit`/`C_SignMessage`/`C_MessageSignFinal` and the verify family) on top of
 * any classic PKCS#11 library (SoftHSM2 in `mise run test:hsm-softhsm2`).
 *
 * No reachable token implements the v3.0 message signature API, so this adapter provides one
 * backed by real crypto: `C_SignMessage` runs the target's `C_SignInit` + `C_Sign` with the
 * mechanism and key stored at message init, and `C_VerifyMessage` likewise with
 * `C_VerifyInit` + `C_Verify`. The message context is held per session in the adapter.
 *
 * The adapter exports only `C_GetFunctionList`/`C_GetInterface` (like `minimal_pkcs11.c`) plus
 * the `v3_adapter_*` test controls. Unix only.
 */

#include "pkcs11_fixture.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>

#define CKR_HOST_MEMORY 2UL
#define CKR_GENERAL_ERROR 5UL
#define CKR_FUNCTION_NOT_SUPPORTED 84UL
#define CKR_MECHANISM_INVALID 112UL
#define CKR_MECHANISM_PARAM_INVALID 113UL
#define CKR_OPERATION_ACTIVE 144UL
#define CKR_OPERATION_NOT_INITIALIZED 145UL
#define CKR_BUFFER_TOO_SMALL 336UL

#define MAX_SESSIONS 1024
#define MAX_PARAM 64
#define MAX_REJECTED 16
#define SIGNATURE_BUFFER 1024

typedef CK_RV (*FnInit)(CK_SESSION_HANDLE, CkMechanism *, CK_OBJECT_HANDLE);
typedef CK_RV (*FnSign)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
typedef CK_RV (*FnVerify)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG);
typedef CK_RV (*FnCloseSession)(CK_SESSION_HANDLE);

/* Counter indices, shared with the Rust test. */
enum {
  CNT_SIGN_INIT_MSG, CNT_SIGN_MSG, CNT_SIGN_FINAL_MSG,
  CNT_VERIFY_INIT_MSG, CNT_VERIFY_MSG, CNT_VERIFY_FINAL_MSG,
  CNT_SIGN_INIT, CNT_VERIFY_INIT, CNT_LEN
};
static CK_ULONG g_counts[CNT_LEN];
#define COUNT(i) __atomic_fetch_add(&g_counts[i], 1, __ATOMIC_RELAXED)

/* One message context (mechanism + parameter bytes + key) of one family. */
typedef struct {
  int active;
  CkMechanism mech;
  unsigned char param[MAX_PARAM];
  CK_OBJECT_HANDLE key;
} MsgCtx;

typedef struct {
  int used;
  CK_SESSION_HANDLE h;
  MsgCtx sign;
  MsgCtx verify;
} SessState;

static SessState g_sess[MAX_SESSIONS];
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static CkFunctionList30 *g_target;
static CkFunctionList30 g_list;
static int g_list_built;
static CK_ULONG g_rejected[MAX_REJECTED];
static CK_ULONG g_rejected_len;

/* Callers hold g_mu. */
static SessState *find_session(CK_SESSION_HANDLE h) {
  int i;
  for (i = 0; i < MAX_SESSIONS; i++) {
    if (g_sess[i].used && g_sess[i].h == h) { return &g_sess[i]; }
  }
  return 0;
}

static SessState *find_or_create_session(CK_SESSION_HANDLE h) {
  int i;
  SessState *s = find_session(h);
  if (s != 0) { return s; }
  for (i = 0; i < MAX_SESSIONS; i++) {
    if (!g_sess[i].used) {
      memset(&g_sess[i], 0, sizeof(g_sess[i]));
      g_sess[i].used = 1;
      g_sess[i].h = h;
      return &g_sess[i];
    }
  }
  return 0;
}

static int is_rejected(CK_MECHANISM_TYPE m) {
  CK_ULONG i;
  for (i = 0; i < g_rejected_len; i++) {
    if (g_rejected[i] == m) { return 1; }
  }
  return 0;
}

static CK_RV message_init(int is_sign, CK_SESSION_HANDLE h, CkMechanism *m, CK_OBJECT_HANDLE key) {
  SessState *s;
  MsgCtx *ctx;
  COUNT(is_sign ? CNT_SIGN_INIT_MSG : CNT_VERIFY_INIT_MSG);
  if (m == 0) { return CKR_ARGUMENTS_BAD; }
  pthread_mutex_lock(&g_mu);
  if (is_rejected(m->mechanism)) {
    pthread_mutex_unlock(&g_mu);
    return CKR_MECHANISM_INVALID;
  }
  if (m->ulParameterLen > MAX_PARAM) {
    pthread_mutex_unlock(&g_mu);
    return CKR_MECHANISM_PARAM_INVALID;
  }
  s = find_or_create_session(h);
  if (s == 0) {
    pthread_mutex_unlock(&g_mu);
    return CKR_HOST_MEMORY;
  }
  ctx = is_sign ? &s->sign : &s->verify;
  if (ctx->active) {
    pthread_mutex_unlock(&g_mu);
    return CKR_OPERATION_ACTIVE;
  }
  ctx->mech = *m;
  if (m->ulParameterLen > 0 && m->pParameter != 0) {
    memcpy(ctx->param, m->pParameter, m->ulParameterLen);
  }
  ctx->key = key;
  ctx->active = 1;
  pthread_mutex_unlock(&g_mu);
  return CKR_OK;
}

static CK_RV adapter_message_sign_init(CK_SESSION_HANDLE h, CkMechanism *m, CK_OBJECT_HANDLE k) {
  return message_init(1, h, m, k);
}
static CK_RV adapter_message_verify_init(CK_SESSION_HANDLE h, CkMechanism *m, CK_OBJECT_HANDLE k) {
  return message_init(0, h, m, k);
}

/* Copies the session's context out under the lock, with `pParameter` pointing at a local copy of
 * the parameter bytes. Returns CKR_OPERATION_NOT_INITIALIZED when no context is open. */
static CK_RV snapshot(int is_sign, CK_SESSION_HANDLE h, CkMechanism *mech,
                      unsigned char param[MAX_PARAM], CK_OBJECT_HANDLE *key) {
  SessState *s;
  MsgCtx *ctx;
  pthread_mutex_lock(&g_mu);
  s = find_session(h);
  ctx = s == 0 ? 0 : (is_sign ? &s->sign : &s->verify);
  if (ctx == 0 || !ctx->active) {
    pthread_mutex_unlock(&g_mu);
    return CKR_OPERATION_NOT_INITIALIZED;
  }
  memcpy(param, ctx->param, MAX_PARAM);
  *mech = ctx->mech;
  mech->pParameter = mech->ulParameterLen > 0 ? param : 0;
  *key = ctx->key;
  pthread_mutex_unlock(&g_mu);
  return CKR_OK;
}

static CK_RV adapter_sign_message(CK_SESSION_HANDLE h, CK_VOID_PTR pParameter,
                                  CK_ULONG ulParameterLen, CK_BYTE *pData, CK_ULONG ulDataLen,
                                  CK_BYTE *pSignature, CK_ULONG_PTR pulSignatureLen) {
  CkMechanism mech;
  unsigned char param[MAX_PARAM];
  CK_OBJECT_HANDLE key;
  CK_BYTE buf[SIGNATURE_BUFFER];
  CK_ULONG buf_len = SIGNATURE_BUFFER;
  CK_RV rv;
  (void)ulParameterLen;
  COUNT(CNT_SIGN_MSG);
  if (pParameter != 0 || pulSignatureLen == 0) { return CKR_ARGUMENTS_BAD; }
  rv = snapshot(1, h, &mech, param, &key);
  if (rv != CKR_OK) { return rv; }
  rv = ((FnInit)g_target->C_SignInit)(h, &mech, key);
  if (rv != CKR_OK) { return rv; }
  rv = ((FnSign)g_target->C_Sign)(h, pData, ulDataLen, buf, &buf_len);
  if (rv != CKR_OK) { return rv; }
  if (pSignature == 0) { *pulSignatureLen = buf_len; return CKR_OK; }
  if (*pulSignatureLen < buf_len) { *pulSignatureLen = buf_len; return CKR_BUFFER_TOO_SMALL; }
  memcpy(pSignature, buf, buf_len);
  *pulSignatureLen = buf_len;
  return CKR_OK;
}

static CK_RV adapter_verify_message(CK_SESSION_HANDLE h, CK_VOID_PTR pParameter,
                                    CK_ULONG ulParameterLen, CK_BYTE *pData, CK_ULONG ulDataLen,
                                    CK_BYTE *pSignature, CK_ULONG ulSignatureLen) {
  CkMechanism mech;
  unsigned char param[MAX_PARAM];
  CK_OBJECT_HANDLE key;
  CK_RV rv;
  (void)ulParameterLen;
  COUNT(CNT_VERIFY_MSG);
  if (pParameter != 0) { return CKR_ARGUMENTS_BAD; }
  rv = snapshot(0, h, &mech, param, &key);
  if (rv != CKR_OK) { return rv; }
  rv = ((FnInit)g_target->C_VerifyInit)(h, &mech, key);
  if (rv != CKR_OK) { return rv; }
  return ((FnVerify)g_target->C_Verify)(h, pData, ulDataLen, pSignature, ulSignatureLen);
}

static CK_RV message_final(int is_sign, CK_SESSION_HANDLE h) {
  SessState *s;
  MsgCtx *ctx;
  COUNT(is_sign ? CNT_SIGN_FINAL_MSG : CNT_VERIFY_FINAL_MSG);
  pthread_mutex_lock(&g_mu);
  s = find_session(h);
  ctx = s == 0 ? 0 : (is_sign ? &s->sign : &s->verify);
  if (ctx == 0 || !ctx->active) {
    pthread_mutex_unlock(&g_mu);
    return CKR_OPERATION_NOT_INITIALIZED;
  }
  ctx->active = 0;
  pthread_mutex_unlock(&g_mu);
  return CKR_OK;
}
static CK_RV adapter_message_sign_final(CK_SESSION_HANDLE h) { return message_final(1, h); }
static CK_RV adapter_message_verify_final(CK_SESSION_HANDLE h) { return message_final(0, h); }

static CK_RV adapter_not_supported(void) { return CKR_FUNCTION_NOT_SUPPORTED; }

/* Classic entry points: count, then forward to the target. */
static CK_RV adapter_sign_init(CK_SESSION_HANDLE h, CkMechanism *m, CK_OBJECT_HANDLE k) {
  COUNT(CNT_SIGN_INIT);
  return ((FnInit)g_target->C_SignInit)(h, m, k);
}
static CK_RV adapter_verify_init(CK_SESSION_HANDLE h, CkMechanism *m, CK_OBJECT_HANDLE k) {
  COUNT(CNT_VERIFY_INIT);
  return ((FnInit)g_target->C_VerifyInit)(h, m, k);
}

/* Closing a session drops its message contexts, like a real token would. */
static CK_RV adapter_close_session(CK_SESSION_HANDLE h) {
  SessState *s;
  pthread_mutex_lock(&g_mu);
  s = find_session(h);
  if (s != 0) { s->used = 0; }
  pthread_mutex_unlock(&g_mu);
  return ((FnCloseSession)g_target->C_CloseSession)(h);
}

static CkInterface g_interface;
static CK_RV get_interface_list(CkInterface *pInterfaceList, CK_ULONG_PTR pulCount) {
  if (pulCount == 0) { return CKR_ARGUMENTS_BAD; }
  if (pInterfaceList != 0) { pInterfaceList[0] = g_interface; }
  *pulCount = 1;
  return CKR_OK;
}

CK_EXPORT CK_RV C_GetFunctionList(CkFunctionList30 **ppFunctionList);
CK_EXPORT CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CkVersion *pVersion,
                               CkInterface **ppInterface, CK_ULONG flags);

/* Builds the v3.0 list from the target's v2.40 list (version header + the 68 classic
 * function pointers, i.e. everything before `C_GetInterfaceList`). */
static CK_RV build_list(void) {
  pthread_mutex_lock(&g_mu);
  if (g_target == 0) {
    pthread_mutex_unlock(&g_mu);
    return CKR_GENERAL_ERROR;
  }
  if (!g_list_built) {
    memset(&g_list, 0, sizeof(g_list));
    memcpy(&g_list, g_target, offsetof(CkFunctionList30, C_GetInterfaceList));
    g_list.version.major = 3;
    g_list.version.minor = 0;
    g_list.C_GetFunctionList = (CkGenericFn)C_GetFunctionList;
    g_list.C_GetInterfaceList = (CkGenericFn)get_interface_list;
    g_list.C_GetInterface = (CkGenericFn)C_GetInterface;
    g_list.C_SignInit = (CkGenericFn)adapter_sign_init;
    g_list.C_VerifyInit = (CkGenericFn)adapter_verify_init;
    g_list.C_CloseSession = (CkGenericFn)adapter_close_session;
    g_list.C_MessageSignInit = (CkGenericFn)adapter_message_sign_init;
    g_list.C_SignMessage = (CkGenericFn)adapter_sign_message;
    g_list.C_SignMessageBegin = (CkGenericFn)adapter_not_supported;
    g_list.C_SignMessageNext = (CkGenericFn)adapter_not_supported;
    g_list.C_MessageSignFinal = (CkGenericFn)adapter_message_sign_final;
    g_list.C_MessageVerifyInit = (CkGenericFn)adapter_message_verify_init;
    g_list.C_VerifyMessage = (CkGenericFn)adapter_verify_message;
    g_list.C_VerifyMessageBegin = (CkGenericFn)adapter_not_supported;
    g_list.C_VerifyMessageNext = (CkGenericFn)adapter_not_supported;
    g_list.C_MessageVerifyFinal = (CkGenericFn)adapter_message_verify_final;
    g_interface.pInterfaceName = (CK_UTF8CHAR_PTR)"PKCS 11";
    g_interface.pFunctionList = &g_list;
    g_interface.flags = 0;
    g_list_built = 1;
  }
  pthread_mutex_unlock(&g_mu);
  return CKR_OK;
}

CK_EXPORT CK_RV C_GetFunctionList(CkFunctionList30 **ppFunctionList) {
  CK_RV rv;
  if (ppFunctionList == 0) { return CKR_ARGUMENTS_BAD; }
  rv = build_list();
  if (rv != CKR_OK) { return rv; }
  *ppFunctionList = &g_list;
  return CKR_OK;
}

CK_EXPORT CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CkVersion *pVersion,
                               CkInterface **ppInterface, CK_ULONG flags) {
  CK_RV rv;
  (void)pInterfaceName;
  (void)pVersion;
  (void)flags;
  if (ppInterface == 0) { return CKR_ARGUMENTS_BAD; }
  rv = build_list();
  if (rv != CKR_OK) { return rv; }
  *ppInterface = &g_interface;
  return CKR_OK;
}

/* Test controls. */

CK_EXPORT CK_RV v3_adapter_set_target(const char *path) {
  void *handle;
  void *sym;
  CkFunctionList30 *list = 0;
  CK_RV rv;
  if (path == 0) { return CKR_GENERAL_ERROR; }
  handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (handle == 0) { return CKR_GENERAL_ERROR; }
  sym = dlsym(handle, "C_GetFunctionList");
  if (sym == 0) { return CKR_GENERAL_ERROR; }
  rv = ((CK_RV (*)(CkFunctionList30 **))sym)(&list);
  if (rv != CKR_OK || list == 0) { return CKR_GENERAL_ERROR; }
  pthread_mutex_lock(&g_mu);
  g_target = list;
  g_list_built = 0;
  pthread_mutex_unlock(&g_mu);
  return CKR_OK;
}

CK_EXPORT void v3_adapter_set_rejected(const CK_ULONG *mechs, CK_ULONG n) {
  CK_ULONG i;
  pthread_mutex_lock(&g_mu);
  g_rejected_len = n > MAX_REJECTED ? MAX_REJECTED : n;
  for (i = 0; i < g_rejected_len; i++) { g_rejected[i] = mechs[i]; }
  pthread_mutex_unlock(&g_mu);
}

CK_EXPORT void v3_adapter_counts(CK_ULONG out[8]) {
  CK_ULONG i;
  for (i = 0; i < CNT_LEN; i++) { out[i] = __atomic_load_n(&g_counts[i], __ATOMIC_RELAXED); }
}
