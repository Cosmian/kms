## Security

### PKI / TLS
- Reject revoked mTLS client certificates: new `clients_crl_dir` option (`--clients-crl-dir`, `KMS_CLIENTS_CRL_DIR`) points to an OpenSSL hashed directory of CRLs checked on the HTTPS and KMIP socket servers, fail-closed (a missing or expired CRL of the issuing CA rejects its clients) ([#1493](https://github.com/Cosmian/kms/issues/1493), COSMIAN-2026-079). Setup action: to enforce revocation, set `clients_crl_dir` (requires `clients_ca_cert_file`), run `openssl rehash` and publish renewed CRLs under the next suffix (`.r1`, `.r2`, ...).
- A failing database lookup no longer looks like "nothing found": `Locate`, CRL generation and OCSP return the error, and OCSP answers an unsigned `tryLater` response instead of `unknown` ([#1493](https://github.com/Cosmian/kms/issues/1493), COSMIAN-2026-080).
- CRL downloads are capped while streaming (including chunked responses), only parseable CRLs are cached (256 entries, 64 MiB) and at most 8 run at once ([#1493](https://github.com/Cosmian/kms/issues/1493), COSMIAN-2026-081).
- CRL Distribution Point host names are resolved by the KMS and rejected when any address is internal, then pinned; the blocked IPv4 ranges now include `0.0.0.0/8`, `100.64.0.0/10`, `192.0.0.0/24`, the documentation, benchmarking, multicast and reserved ranges, and IPv6 multicast, documentation and NAT64-embedded addresses ([#1493](https://github.com/Cosmian/kms/issues/1493), COSMIAN-2026-082). Setup action: a CRL Distribution Point on a private, CGNAT (`100.64.0.0/10`) or other blocked address is no longer fetched (`Validate` reports the chain invalid, `Import` warns and keeps `Active`); publish the CRL on a public address or serve it from the KMS (`kms_public_url`). The same blocklist now applies to the Google CSE `original_kacls_url`.
- A CRL that cannot be fetched, parsed or verified no longer marks an imported certificate `Compromised`; only a certificate listed in a verified CRL does ([#1493](https://github.com/Cosmian/kms/issues/1493), COSMIAN-2026-083).

## Bug Fixes

### Hardening
- SCEP: `scep_allow_renewal_without_challenge` now defaults to `false`: `GetCACaps` no longer advertises `Renewal` and a `RenewalReq` is refused (`badRequest`) unless enabled ([#1493](https://github.com/Cosmian/kms/issues/1493)). Setup action: operators whose devices renew with a still-valid certificate and no challenge must set `scep_allow_renewal_without_challenge = true` (TOML key or `--scep-allow-renewal-without-challenge true`); otherwise devices re-enroll with `PKCSReq` and the challenge. Configuration files that set the key explicitly are unchanged.

## Documentation

- Document `clients_crl_dir`, the CRL download safeguards and the SCEP renewal default (`authentication.md`, `pki-revocation.md`, `pki-enrollment-scep.md`, log reference)
