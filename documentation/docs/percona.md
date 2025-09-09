# Using pg_tde with Cosmian KMS and PostgreSQL 17 (Percona)

This guide demonstrates how to configure PostgreSQL 17 with Percona's `pg_tde` extension to use Cosmian KMS for transparent data encryption (TDE).

<!-- TOC -->
- [Using pg\_tde with Cosmian KMS and PostgreSQL 17 (Percona)](#using-pg_tde-with-cosmian-kms-and-postgresql-17-percona)
    - [Prerequisites](#prerequisites)
    - [Configuration Steps](#configuration-steps)
        - [1. Configure PostgreSQL](#1-configure-postgresql)
        - [2. Enable TDE Extension](#2-enable-tde-extension)
        - [3. Configure the KMS Key Provider](#3-configure-the-kms-key-provider)
        - [4. Set the Default Encryption Key](#4-set-the-default-encryption-key)
        - [5. Ensure event triggers are set (usually created on extension install)](#5-ensure-event-triggers-are-set-usually-created-on-extension-install)
        - [6. Enable Wal Encrypt and TDE Enforce Encryption (not mandatory but strongly recommended)](#6-enable-wal-encrypt-and-tde-enforce-encryption-not-mandatory-but-strongly-recommended)
        - [7. Create encrypted tables](#7-create-encrypted-tables)
        - [8. Verify if a table is encrypted](#8-verify-if-a-table-is-encrypted)
        - [9. Insert and query data transparently](#9-insert-and-query-data-transparently)
        - [10. Check current encryption settings](#10-check-current-encryption-settings)
    - [Troubleshooting \& Notes](#troubleshooting--notes)
<!-- TOC -->

## Prerequisites

Before starting, ensure you have:

- PostgreSQL 17 (Percona Server for PostgreSQL 17.5.2 or later)
- `pg_tde` extension installed
- Access to a running Cosmian KMS server
- Appropriate SSL certificates for KMIP communication

## Configuration Steps

### 1. Configure PostgreSQL

Edit your `postgresql.conf` file to activate tde extension:

```conf
shared_preload_libraries = 'pg_tde,percona_pg_telemetry'
```

**Important:** Changes to `shared_preload_libraries` require a PostgreSQL restart to take effect.

```bash
sudo systemctl restart postgresql@17-main.service
```

### 2. Enable TDE Extension

Create the `pg_tde` extension in your target database(s):

```sql
CREATE EXTENSION pg_tde;
```

### 3. Configure the KMS Key Provider

Connect to your PostgreSQL database and add the Cosmian KMS as a key provider using the KMIP protocol:

```sql
SELECT pg_tde_add_global_key_provider_kmip(
  'kms_provider',                -- Provider name (can be customized)
  'kms-host.example.com',        -- Your KMS server hostname
  5696,                          -- KMIP port (default is 5696)
  '/path/to/client_cert.pem',    -- Client certificate file path
  '/path/to/client_key.pem',     -- Client private key file path
  '/path/to/ca_cert.pem'         -- Certificate Authority file path
);
```

**Note:** Replace the placeholder values with your actual KMS server details and certificate paths.

### 4. Set the Default Encryption Key

Configure the default encryption key using the KMS provider:

```sql
SELECT pg_tde_create_key_using_global_key_provider('key_01', 'kms_provider');

SELECT pg_tde_set_server_key_using_global_key_provider('key_01', 'kms_provider');

SELECT pg_tde_set_default_key_using_global_key_provider('key_01', 'kms_provider');
```

The first parameter (`key_01`) is the key identifier, and the second parameter (`kms_provider`) must match the provider name from step 3.

---

### 5. Ensure event triggers are set (usually created on extension install)

```sql
CREATE EVENT TRIGGER pg_tde_ddl_start ON ddl_command_start
  EXECUTE FUNCTION pg_tde_ddl_command_start_capture();

CREATE EVENT TRIGGER pg_tde_ddl_end ON ddl_command_end
  EXECUTE FUNCTION pg_tde_ddl_command_end_capture();
```

> If the trigger already exists, this error can be safely ignored.

---

### 6. Enable Wal Encrypt and TDE Enforce Encryption (not mandatory but strongly recommended)

Edit your `postgresql.conf` again and add:

```conf
pg_tde.wal_encrypt = on
pg_tde.enforce_encryption = on
```

**Important:** Changes to `pg_tde.wal_encrypt` or `pg_tde.enforce_encryption` require a PostgreSQL restart to take effect.

```bash
sudo systemctl restart postgresql@17-main.service
```

### 7. Create encrypted tables

```sql
CREATE TABLE sensitive_data (
  id serial PRIMARY KEY,
  secret_text text
) USING tde_heap;
```

> The `USING tde_heap` clause ensures the table is encrypted using pg_tde.

---

### 8. Verify if a table is encrypted

```sql
SELECT pg_tde_is_encrypted('public.sensitive_data'::regclass);
-- Expected output: t (true)
```

---

### 9. Insert and query data transparently

Encryption is transparent; use standard SQL commands:

```sql
INSERT INTO sensitive_data (secret_text) VALUES ('Top secret info');
SELECT * FROM sensitive_data;
```

Data is stored encrypted on disk but returned in plaintext when queried.

---

### 10. Check current encryption settings

```sql
SHOW pg_tde.wal_encrypt;
SHOW pg_tde.enforce_encryption;
SHOW pg_tde.inherit_global_providers;
```

---

## Troubleshooting & Notes

- `shared_preload_libraries` must include at least `'pg_tde'`.
- To change `pg_tde`,  `pg_tde.wal_encrypt` or `pg_tde.enforce_encryption`, a percona server restart is mandatory.

- Ensure SSL certificates are properly secured with appropriate file permissions
- Store certificate files in a secure location accessible only to the PostgreSQL service
- Regularly rotate encryption keys as per your security policy
- Monitor KMS connectivity and have appropriate failover procedures

Common issues and solutions:

| Function                                                          | Description                                 |
|-------------------------------------------------------------------|---------------------------------------------|
| `pg_tde_add_global_key_provider_kmip(...)`                        | Add KMIP key provider                       |
| `pg_tde_set_default_key_using_global_key_provider(key, provider)` | Set default encryption key using a provider |
| `pg_tde_is_encrypted(regclass)`                                   | Check if table is encrypted                 |
| `pg_tde_default_key_info()`                                       | Show info about default encryption key      |

For more detailed information, refer to the [official pg_tde documentation](https://github.com/percona/postgres/tree/TDE_REL_17_STABLE/contrib/pg_tde).
