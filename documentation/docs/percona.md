# Documentation – Using `pg_tde` with Cosmian KMS and PostgreSQL 17 (Percona)

---

## 1. Prerequisites

- PostgreSQL 17 (Percona Server for PostgreSQL 17.5.2)
- `pg_tde` extension installed
- Cosmian KMS server accessible


---

## 2. PostgreSQL Configuration

### Edit `postgresql.conf` to include:

```conf
shared_preload_libraries = 'pg_tde,percona_pg_telemetry'
pg_tde.wal_encrypt = on
pg_tde.enforce_encryption = on
```

> **Note:** Changing `pg_tde.wal_encrypt` or `pg_tde.enforce_encryption` requires a PostgreSQL restart.

### Restart PostgreSQL service:

```bash
sudo systemctl restart postgresql@17-main.service
```

---

## 3. Add KMS Key Provider in PostgreSQL

Example :

```sql
SELECT pg_tde_add_global_key_provider_kmip(
  'kms_provider',           -- provider_name
  'kms-host.example.com',   -- KMIP host
  5696,                     -- KMIP port
  '/path/to/client_cert.pem', -- Client certificate
  '/path/to/client_key.pem',  -- Client private key
  '/path/to/ca_cert.pem'      -- CA certificate
);
```

### Set the default encryption key

```sql
SELECT pg_tde_set_default_key_using_global_key_provider('key_01', 'kms_provider');
```

---

## 4. Enable the extension in your database(s)

```sql
CREATE EXTENSION pg_tde;
```

---

## 5. Ensure event triggers are set (usually created on extension install)

```sql
CREATE EVENT TRIGGER pg_tde_ddl_start ON ddl_command_start
  EXECUTE FUNCTION pg_tde_ddl_command_start_capture();

CREATE EVENT TRIGGER pg_tde_ddl_end ON ddl_command_end
  EXECUTE FUNCTION pg_tde_ddl_command_end_capture();
```

> If trigger already exists, this error can be safely ignored.

---

## 6. Create encrypted tables

```sql
CREATE TABLE sensitive_data (
  id serial PRIMARY KEY,
  secret_text text
) USING tde_heap;
```

> The `USING tde_heap` clause ensures the table is encrypted using pg_tde.

---

## 7. Verify if a table is encrypted

```sql
SELECT pg_tde_is_encrypted('public.sensitive_data'::regclass);
-- Expected output: t (true)
```

---

## 8. Insert and query data transparently

Encryption is transparent; use standard SQL commands:

```sql
INSERT INTO sensitive_data (secret_text) VALUES ('Top secret info');
SELECT * FROM sensitive_data;
```

Data is stored encrypted on disk but returned in plaintext when queried.

---

## 9. Check current encryption settings

```sql
SHOW pg_tde.wal_encrypt;
SHOW pg_tde.enforce_encryption;
SHOW pg_tde.inherit_global_providers;
```

---

## 10. Troubleshooting & Notes

- `shared_preload_libraries` must include at least `'pg_tde'`.
- To change `pg_tde.wal_encrypt` or `pg_tde.enforce_encryption`, a server restart is mandatory.


---

## Appendix – Key `pg_tde` Functions

| Function                                                          | Description                                 |
|-------------------------------------------------------------------|---------------------------------------------|
| `pg_tde_add_global_key_provider_kmip(...)`                        | Add KMIP key provider                       |
| `pg_tde_set_default_key_using_global_key_provider(key, provider)` | Set default encryption key using a provider |
| `pg_tde_is_encrypted(regclass)`                                   | Check if table is encrypted                 |
| `pg_tde_default_key_info()`                                       | Show info about default encryption key      |

---
