## Bug Fixes

- **certificates**: fix `certificatePolicies` extension failing with "no config database" when a CPS qualifier (`CPS:url` or `CPS.N:url`) is provided in the `--certificate-extensions` CNF file. Replaced the OpenSSL conf-based `X509Extension::new_nid` path with a native Rust DER builder that requires no OpenSSL config database, and which also correctly handles the numbered-qualifier syntax (`CPS.1:`, `CPS.2:`, …) used by PKI tools such as Opentrust.

## Testing

- **certificates**: add `test_old_new_nid_fails_for_cps_syntax` (negative test pinning the old broken path) and `test_certificate_policies_with_cps_qualifier` (positive test for the native DER encoder).
- **scripts**: add `.github/scripts/test/test_certificate_policies.sh` (bash regression script) and `.github/scripts/test/igcnv4_root_ca.cnf` (customer-provided CNF fixture that triggers the bug).
