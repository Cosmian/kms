#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>

// Minimal prototypes to avoid linking against libcrypto
typedef void OSSL_LIB_CTX;
typedef struct ossl_provider_st OSSL_PROVIDER;

typedef OSSL_PROVIDER *(*OSSL_PROVIDER_load_f)(OSSL_LIB_CTX *libctx, const char *name);
typedef int (*EVP_set_default_properties_f)(OSSL_LIB_CTX *libctx, const char *propq);

static void __attribute__((constructor)) fips_bootstrap_ctor(void) {
  // Resolve symbols from the main program (statically linked libcrypto)
  OSSL_PROVIDER_load_f p_OSSL_PROVIDER_load =
      (OSSL_PROVIDER_load_f)dlsym(RTLD_DEFAULT, "OSSL_PROVIDER_load");
  EVP_set_default_properties_f p_EVP_set_default_properties =
      (EVP_set_default_properties_f)dlsym(RTLD_DEFAULT, "EVP_set_default_properties");

  if (!p_OSSL_PROVIDER_load || !p_EVP_set_default_properties) {
    // OpenSSL not in this process; nothing to do
    return;
  }

  // Ensure providers are available early. Do not force default properties here
  // so non-FIPS algorithms (e.g., Ed25519/Ed448) can be used in tests that
  // expect them while still having the FIPS provider available.
  p_OSSL_PROVIDER_load(NULL, "base");
  p_OSSL_PROVIDER_load(NULL, "fips");
}
