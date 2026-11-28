## Bug Fixes

- Fix the FIPS `bench:pkcs11 --delegated` encrypt run (nightly `test:hsm - fips`): the RSAES-PKCS1-v1_5 `encrypt/rsa-pkcs` and `decrypt/rsa-pkcs` modes, which the HSM session refuses in FIPS builds, are now selected in non-FIPS builds only instead of aborting the run with `RsaPkcsV15 is unavailable in FIPS mode`
