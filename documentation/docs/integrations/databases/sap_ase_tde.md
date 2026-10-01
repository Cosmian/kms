# SAP ASE TDE with Eviden KMS

This guide describes the integration between Eviden KMS and **SAP Sybase Adaptive Server Enterprise (ASE)** for Transparent Data Encryption (TDE).

SAP ASE uses the Eviden PKCS#11 provider (`libcosmian_pkcs11.so`) as an external keystore to generate and store HSM-backed encryption keys.

The integration tests run in non-FIPS mode because the PKCS#11 provider test path currently builds with the `non-fips` feature.

## Architecture

SAP ASE does not connect to KMIP directly. It loads the `cosmian_pkcs11` provider library (`libcosmian_pkcs11.so`), which translates PKCS#11 operations into KMIP-over-HTTPS requests sent to Eviden KMS. The KMS persists key metadata and ciphertext in its configured database backend.

```mermaid
sequenceDiagram
    autonumber
    participant ASE as SAP ASE
    participant PKCS11 as cosmian_pkcs11 (libcosmian_pkcs11.so)
    participant KMS as Eviden KMS Server
    participant DB as KMS Database Backend (PostgreSQL / MySQL / SQLite / Redis)

    Note over ASE,PKCS11: Credential Configuration
    ASE->>PKCS11: sp_encryption 'hsm_credential', 'lib=libcosmian_pkcs11.so; pin=...; slot=1'
    PKCS11->>PKCS11: Load ckms.toml & client certificate
    PKCS11-->>ASE: Credentials stored

    Note over ASE,DB: Key Creation & Persistence
    ASE->>PKCS11: CREATE ENCRYPTION KEY on external keystore
    PKCS11->>KMS: POST /kmip (KMIP Create Request with client cert)
    KMS->>DB: Register and activate AES key
    DB-->>KMS: Key identifier and state stored
    KMS-->>PKCS11: KMIP Create Response (Key UID)
    PKCS11-->>ASE: HSM-backed key available (SQL success)
```

## Prerequisites

- Docker and Docker Compose.
- A local checkout of the Eviden KMS repository.
- Test certificates under `test_data/certificates/client_server/` (or production mTLS certificates).
- Access to the SAP ASE Developer Edition installer. The default download URL is used by the test script, but can be overridden with `ASE_INSTALLER_URL`.

| Product | Tested path | Test entry point |
| --- | --- | --- |
| SAP ASE 16 | PKCS#11 provider (`libcosmian_pkcs11.so`) to KMS HTTPS endpoint | `.mise/scripts/test/test_ase_tde.sh` |

## Configuration

The test builds the `cosmian-ase-kmip` Docker image for `linux/amd64`, builds `libcosmian_pkcs11.so`, and copies the provider into the running ASE container.

The provider reads a `ckms.toml` configuration file:

```toml
[http_config]
server_url = "https://host.docker.internal:<KMS_HTTP_PORT>"
accept_invalid_certs = true
tls_client_pkcs12_path = "/opt/sap/ASE-16_1/ssl/client.p12"
tls_client_pkcs12_password = "password"
```

Configure the ASE external keystore and provider credential with `isql`:

```sql
sp_configure 'external keystore', 0, 'HSM'
go
sp_configure 'enable encrypted columns', 1
go
sp_encryption 'system_encr_passwd', 'MasterPass1!'
go
sp_encryption 'hsm_credential', 'lib=libcosmian_pkcs11.so; pin=0000; slot=1'
go
create encryption key hsm_key on external keystore with keylength 256 init_vector random
go
```

The `lib`, `pin`, and `slot` parameters are passed to the PKCS#11 provider. KMIP endpoint, TLS, and KMS credentials remain in `ckms.toml` and are not configured as ASE KMIP parameters.

## Integration Testing

Run the integration test with:

```bash
mise run test:ase --variant non-fips
```

The test verifies:

1. mTLS rejection without a valid client certificate.
2. Direct KMS REST encrypt/decrypt round-trip.
3. Provider loading inside the SAP ASE container.
4. Creation of an HSM-backed AES key via SQL `create encryption key`.
5. Visibility and validation of the newly created key in KMS via `ckms locate`.

## Troubleshooting

- **Provider loading failure:** If ASE cannot load `libcosmian_pkcs11.so`, inspect container logs and ensure the library is built for `linux/amd64` and has no unsatisfied dynamic dependencies.
- **TLS negotiation error:** If ASE fails during TLS negotiation with KMS, verify the CA certificate, server certificate hostname, client certificate/PKCS#12 bundle, and KMS client-CA trust configuration.

The complete reproducible procedure is in `.mise/scripts/test/test_ase_tde.sh`.
