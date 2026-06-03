## Features

- Log OpenSSL CPU hardware-acceleration feature flags (AES-NI, PCLMULQDQ, AVX, AVX2, SHA, VAES, RDRAND, etc.) at server startup for compliance and audit purposes. Decoded for x86_64, AArch64, and PowerPC; raw string logged for other architectures.

## Refactor

- Add `OpenSSL_version_num()` liveness check and `// SAFETY:` justification to `cpu_features_info()` unsafe block ([#963](https://github.com/Cosmian/kms/pull/963))
- Replace raw `openssl_sys::OpenSSL_version_num()` calls in `init_openssl_providers*` with safe `openssl::version::number()` wrapper, eliminating unnecessary unsafe blocks
- Extract `OPENSSL_3_0_VERSION_NUMBER` named constant to replace hardcoded `0x3000_0000` magic number
