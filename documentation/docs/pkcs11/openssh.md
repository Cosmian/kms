# OpenSSH PKCS#11 provider for Cosmian KMS

The Cosmian KMS can be used as a PKCS#11 provider for OpenSSH, allowing you to use keys stored in the
KMS for SSH authentication.
This guide explains how to set up the Cosmian KMS PKCS#11 provider for OpenSSH, including
installation, configuration, and usage.

## Install the Cosmian KMS PKCS#11 provider

If you installed the CLI using a a Debian or RPM package, the Cosmian KMS PKCS#11 provider is available
as a shared library in the `/usr/local/lib/libcosmian_pkcs11.so` directory.

export COSMIAN_PKCS11_LOGGING_LEVEL=debug
ssh -I /Users/bgrieder/projects/cli/target/debug/libcosmian_pkcs11.dylib demo-kms.cosmian.dev