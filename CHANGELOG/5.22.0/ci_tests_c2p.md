## CI

- Make Crypt2Pay CI setup resilient to `prepare_crypt2pay.sh` self-test failures (`unsupported key type 'aes'`) by continuing when `/usr/lib/libpkcs11c2p.so` and `/etc/c2p/c2p.xml` are present.
- Strip `route-nopull` from OpenVPN config to accept server-pushed routes for proper VPN routing to the Crypt2Pay HSM.
- Add TCP connectivity check (30 retries) against the C2P HSM host/port before running tests to fail fast when the service is unreachable.
- Fix Crypt2Pay `prepare_crypt2pay.sh`: install CA into `ssl/authorities` (matching the `<Authorities>` config) instead of `ssl/`.
- Fix Crypt2Pay HSM port: the SSL service now runs on port 3001 (port 3002 is firewalled).
- Add bridge CA workaround in `prepare_crypt2pay.sh`: the C2P package ships a CA cert re-issued with a new subject DN (`O=Eviden, OU=Trustway, CN=CA-C2P`) but the HSM server cert still references the old issuer DN (`CN=CA-C2P`). A bridge CA with the old DN and matching public key is generated and installed under the server cert's dgst hash so the C2P SSL lookup succeeds.
- Clean up stale tun0 interface before starting OpenVPN to avoid route conflicts.
- Fix VPN log file permissions for non-root readability.

## Bug Fixes

- Fix `cargo fmt` issue in `session_impl.rs` (`debug!` macro line length).
- Remove unused `cosmian_logger` dev-dependency from `crypt2pay_pkcs11_loader` crate.
