## Features

### Integrations / Databases

- Added official support and integration test coverage for **SAP ASE (Adaptive Server Enterprise)** Transparent Data Encryption (TDE) via `cosmian_pkcs11` (`libcosmian_pkcs11.so`). SAP ASE delegates master key creation, activation, and data-encryption-key wrapping to the Eviden KMS over KMIP HTTPS.
- Added official support and integration test coverage for **IBM Db2 LUW** Transparent Data Encryption (TDE) via the native IBM GSKit KMIP client (KMIP 1.1) connecting directly to the Eviden KMS binary KMIP socket over mutual TLS (mTLS).

## Documentation

- Added dedicated integration guides and architecture walkthroughs for SAP ASE in `documentation/docs/integrations/databases/sap_ase_tde.md` and IBM Db2 LUW in `documentation/docs/integrations/databases/ibm_db2_luw_tde.md`.
- Added end-to-end Mermaid sequence diagrams illustrating the connection workflows, including explicit representation of `cosmian_pkcs11` in the path for SAP ASE and Oracle TDE, as well as the KMS backing database operations.
- Updated `README.md` database integration table with SAP ASE and IBM Db2 LUW entries and corresponding documentation links.

## Testing

- Added automated Docker-based integration tests:
  - `.mise/scripts/test/test_ase_tde.sh` (`mise run test:ase`): exercises SAP ASE container setup, `libcosmian_pkcs11.so` provider loading, external keystore key generation, and encrypted table operations.
  - `.mise/scripts/test/test_db2_tde.sh` (`mise run test:db2`): exercises IBM Db2 container setup, GSKit PKCS#12 keystore preparation, KMIP client configuration (`ekeystore.cfg`), and encrypted database creation against the Eviden KMS KMIP socket.
- Added test vectors and CI workflow integration in `.github/workflows/test_all.yml`.
