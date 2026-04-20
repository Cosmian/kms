## CI

- Make Crypt2Pay CI setup resilient to `prepare_crypt2pay.sh` self-test failures (`unsupported key type 'aes'`) by continuing when `/usr/lib/libpkcs11c2p.so` and `/etc/c2p/c2p.xml` are present.
