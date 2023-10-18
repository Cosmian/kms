ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
SGX_SIGNER_KEY ?= /opt/cosmian-internal/cosmian-signer-key.pem
SGX_SIGNER_PUBLIC_KEY = cosmian-signer-key.pub
KMS_USE_BOOTSTRAP_SERVER = "${KMS_USE_BOOTSTRAP_SERVER}"
KMS_USE_CERTBOT = "${KMS_USE_CERTBOT}"
KMS_CERTBOT_HOSTNAME = "${KMS_CERTBOT_HOSTNAME}"
KMS_CERTBOT_EMAIL = "${KMS_CERTBOT_EMAIL}"
KMS_CERTBOT_USE_TEE_KEY = "${KMS_CERTBOT_USE_TEE_KEY}"


ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
# can also use "all" for having something like `strace`
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: kms.manifest
ifeq ($(SGX),1)
all: kms.manifest.sgx kms.sig
endif

kms.manifest: kms.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint_abs="$(PWD)/scripts"  \
		-Dentrypoint="/scripts"  \
		-Dsgx_signer_public_key=$(SGX_SIGNER_PUBLIC_KEY) \
		-Dkms_use_bootstrap_server=$(KMS_USE_BOOTSTRAP_SERVER) \
        -Dkms_use_cerbot=$(KMS_USE_CERTBOT) \
        -Dkms_cerbot_hostname=$(KMS_CERTBOT_HOSTNAME) \
        -Dkms_cerbot_email=$(KMS_CERTBOT_EMAIL) \
        -Dkms_cerbot_use_tee_key=$(KMS_CERTBOT_USE_TEE_KEY) \
		-Dkms_domain="$(KMS_DOMAIN)" \
		$< >$@

kms.manifest.sgx: kms.manifest
	gramine-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest kms.manifest \
		--output $@
	openssl rsa -in $(SGX_SIGNER_KEY) -pubout -out public_data/$(SGX_SIGNER_PUBLIC_KEY)

kms.sig: kms.manifest.sgx

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.sig OUTPUT scripts/testdir/*

.PHONY: distclean
distclean: clean
