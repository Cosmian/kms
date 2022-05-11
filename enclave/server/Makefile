ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
SGX_SIGNER_KEY ?= /opt/cosmian-internal/cosmian-signer-key.pem

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
# can also use "all" for having something like `strace`
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: kms.manifest
ifeq ($(SGX),1)
all: kms.manifest.sgx kms.sig kms.token
endif

kms.manifest: kms.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint="./scripts"  \
		$< >$@

kms.manifest.sgx: kms.manifest
	gramine-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest kms.manifest \
		--output $@

kms.sig: kms.manifest.sgx

kms.token: kms.sig
	gramine-sgx-get-token --output $@ --sig $^

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig OUTPUT scripts/testdir/*

.PHONY: distclean
distclean: clean
