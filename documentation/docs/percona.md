# Using pg_tde with Cosmian KMS and PostgreSQL 17 (Percona)

This guide demonstrates how to configure PostgreSQL 17 with Percona's `pg_tde` extension to use Cosmian KMS for transparent data encryption (TDE).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Before You Start: Understanding pg_tde Architecture](#before-you-start-understanding-pgtde-architecture)
- [Configuration Steps](#configuration-steps)
- [Encryption Scope and What Gets Encrypted](#encryption-scope-and-what-gets-encrypted)
- [Key Management: DEK, Internal Keys and Principal Keys](#key-management-dek-internal-keys-and-principal-keys)
- [Verification and Testing](#verification-and-testing)
- [Troubleshooting & Solutions](#troubleshooting--solutions)
- [Operational Considerations](#operational-considerations)

---

## Prerequisites

Before starting, ensure you have:

- PostgreSQL 17 (Percona Server for PostgreSQL 17.x or later)[1]
- `pg_tde` extension installed
- Access to a running Cosmian KMS server
- Appropriate SSL certificates for KMIP communication (TLS 1.2+)[2]

---

## Before You Start: Understanding pg_tde Architecture

### Global Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│            Application / SQL Queries                        │
│           (SELECT, INSERT, UPDATE, DELETE)                  │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
                  (Data in plaintext in memory)
                             │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│      PostgreSQL + pg_tde Extension + Percona Patches        │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ SMGR (Storage Manager) - Interception Layer          │   │
│  └────────────────────────┬─────────────────────────────┘   │
│                           │                                 │
│       ┌───────────────────┴───────────────────────┐         │
│       │                                           │         │
│       ▼                                           ▼         │
│    TDE Tables                                Non-TDE Tables │
│ (USING tde_heap)                            (standard heap) │ 
│                                                             │
│             ┌─────────────┬──────────────┐                  │
│             │             │              │                  │
│             ▼             ▼              ▼                  │
│         Encryption        No         Encryption (optional,  │
│          of pages      encryption    WAL only if enabled)   │
│         (CBC-128)                    (CTR-128) WAL          │
└──────────────┬─────────────┬──────────────┬─────────────────┘
               │             │              │
               ▼             ▼              ▼
           Disk (encrypted data)
           WAL Files (encrypted if pg_tde.wal_encrypt = on)
```

### KMIP Communication Flow

```
┌──────────────────────────────────────┐
│   PostgreSQL + pg_tde                │
│   (KMIP Client)                      │
└────────────┬─────────────────────────┘
             │
             │ KMIP over TLS 1.2/1.3
             │ Port 5696 (binary)
             │ Required certificates:
             │  - client_cert.pem
             │  - client_key.pem
             │  - ca_cert.pem
             │
             ▼
┌──────────────────────────────────────┐
│   Cosmian KMS 5.6+                   │
│   (KMIP Server)                      │
│                                      │
│  Supported operations:               │
│  ✓ Create (create keys)              │
│  ✓ Get (retrieve keys)               │
│  ✓ Destroy (delete keys)             │
│  ✓ Register (register objects)       │
│  ✓ Locate (find objects)             │
│  ✓ Activate (activate)               │
│  ✓ Revoke (revoke)                   │
│                                      │
│  Protocol: KMIP 1.x and 2.x[2]       │
│  Profile: Baseline Server            │
└──────────────────────────────────────┘
```

---

## Configuration Steps

### 1. Configure PostgreSQL

Edit your `postgresql.conf` file to activate the TDE extension:[1]

```conf
shared_preload_libraries = 'pg_tde,percona_pg_telemetry'
```

**Important:** Changes to `shared_preload_libraries` require a PostgreSQL restart to take effect.[1]

```bash
sudo systemctl restart postgresql@17-main.service
```

### 2. Enable TDE Extension

Create the `pg_tde` extension in your target database(s):[1]

```sql
CREATE EXTENSION pg_tde;
```

This will automatically create event triggers needed for pg_tde operation.

### 3. Configure the KMS Key Provider

Connect to your PostgreSQL database and add the Cosmian KMS as a key provider using the KMIP protocol:[1]

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

**Note:** Replace the placeholder values with your actual KMS server details and certificate paths.[1]

**Certificate Requirements:**[2]
- All certificates must be in PEM format
- Client certificates must be X.509 compliant
- TLS 1.2 or higher is required for KMIP communication
- Certificate files must be readable by the PostgreSQL system user

### 4. Set the Default Encryption Key

Configure the default encryption key using the KMS provider:[1]

```sql
SELECT pg_tde_create_key_using_global_key_provider('key_01', 'kms_provider');

SELECT pg_tde_set_server_key_using_global_key_provider('key_01', 'kms_provider');

SELECT pg_tde_set_default_key_using_global_key_provider('key_01', 'kms_provider');
```

The first parameter (`key_01`) is the key identifier, and the second parameter (`kms_provider`) must match the provider name from step 3.[1]

**What happens in this step:**
- `pg_tde_create_key_using_global_key_provider()` creates a Principal Key managed by Cosmian KMS
- `pg_tde_set_server_key_using_global_key_provider()` sets the server-level default key
- `pg_tde_set_default_key_using_global_key_provider()` sets the database-level default key

### 5. Ensure Event Triggers Are Set

Event triggers are usually created automatically when the extension is installed. To verify or recreate them:[1]

```sql
CREATE EVENT TRIGGER pg_tde_ddl_start ON ddl_command_start
  EXECUTE FUNCTION pg_tde_ddl_command_start_capture();

CREATE EVENT TRIGGER pg_tde_ddl_end ON ddl_command_end
  EXECUTE FUNCTION pg_tde_ddl_command_end_capture();
```

If the trigger already exists, this error can be safely ignored.[1]

These triggers ensure that DDL operations (table creation, modification) properly handle encryption metadata.

### 6. Enable WAL Encrypt and TDE Enforce Encryption

Edit your `postgresql.conf` again and add:[1]

```conf
pg_tde.wal_encrypt = on
pg_tde.enforce_encryption = on
```

**Important:** Changes to `pg_tde.wal_encrypt` or `pg_tde.enforce_encryption` require a PostgreSQL restart to take effect.[1]

```bash
sudo systemctl restart postgresql@17-main.service
```

**About these parameters:**[1]
- `pg_tde.wal_encrypt = on` encrypts Write-Ahead Log files (production-ready as of Percona PostgreSQL 17.5.3)
- `pg_tde.enforce_encryption = on` prevents creation of unencrypted tables when a default key is set (strongly recommended)

### 7. Create Encrypted Tables

```sql
CREATE TABLE sensitive_data (
  id serial PRIMARY KEY,
  secret_text text
) USING tde_heap;
```

The `USING tde_heap` clause ensures the table is encrypted using pg_tde.[1]

**Important:** Only tables created with `USING tde_heap` are encrypted. Existing non-TDE tables remain unencrypted unless migrated.

### 8. Verify if a Table is Encrypted

```sql
SELECT pg_tde_is_encrypted('public.sensitive_data'::regclass);
-- Expected output: t (true)
```

### 9. Insert and Query Data Transparently

Encryption is transparent; use standard SQL commands:[1]

```sql
INSERT INTO sensitive_data (secret_text) VALUES ('Top secret info');

SELECT * FROM sensitive_data;
```

Data is stored encrypted on disk but returned in plaintext when queried.[1]

### 10. Check Current Encryption Settings

```sql
SHOW pg_tde.wal_encrypt;
SHOW pg_tde.enforce_encryption;
SHOW pg_tde.inherit_global_providers;
```

---

## Encryption Scope and What Gets Encrypted

### ✅ WHAT IS ENCRYPTED

#### Application Data

| Component | Status | Details |
|-----------|--------|---------|
| Tables `USING tde_heap` | ✓ Encrypted | Complete row data, all columns[3] |
| Index on TDE tables | ✓ Encrypted | B-trees, Hash, GiST, GIN, BRIN, etc.[3] |
| TOAST tables | ✓ Encrypted | Compressed/out-of-page data (e.g. long TEXT)[3] |
| Sequences (TDE tables) | ✓ Encrypted | Related to encrypted tables[3] |
| Temporary tables (TDE) | ✓ Encrypted | Temporary tables for TDE data operations[3] |

#### Logs and Transactions

| Component | With `pg_tde.wal_encrypt = on` | Details |
|-----------|--------------------------------|---------|
| WAL (Write-Ahead Log) | ✓ Encrypted | Transaction logs (GA status since v17.5.3)[4] |
| WAL before images | ✓ Encrypted | Row states before modification[4] |
| WAL after images | ✓ Encrypted | Row states after modification[4] |

#### Backup and Recovery

| Tool | Status | Notes |
|------|--------|-------|
| `pg_tde_basebackup` | ✓ Supported | With `--wal-method=stream` or `--wal-method=none`[1] |
| `pgBackRest` | ✓ Supported | Compatible with encrypted WAL[4] |
| WAL restore | ✓ Supported | Via `pg_tde_restore_encrypt` wrapper[1] |

### ❌ WHAT IS NOT ENCRYPTED

#### System Metadata and Catalogs

| Component | Reason | Consequence |
|-----------|--------|------------|
| PostgreSQL system catalogs | Architectural | Table/column names, types remain plaintext |
| TDE table metadata | Architectural | Schema, table name, column name, data types |
| Statistics (`pg_stat_*`) | Not supported | System statistics information |
| Configuration files | Not encrypted | `postgresql.conf`, `pg_hba.conf` |

#### Tables and Files

| Component | Reason | Solution |
|-----------|--------|----------|
| Standard `heap` tables | By design | Only `tde_heap` tables are encrypted |
| Non-TDE tables | Selective | Create with `USING tde_heap` for encryption |
| Temporary files (>work_mem) | Limitation | Overflow data unencrypted on disk[5] |
| System log files | Not supported | PostgreSQL logs in plaintext on disk |

---

## Key Management: DEK, Internal Keys and Principal Keys

### Two-Level Key Architecture

pg_tde uses a **two-level key hierarchy** for data encryption:[3]

```
┌────────────────────────────────────────────────────────┐
│         PRINCIPAL KEY (Master Key)                     │
│                                                        │
│  - Stored externally in Cosmian KMS (KMIP)             │
│  - ONE per database                                    │
│  - Encrypts Internal Keys (AES-128-GCM)[3]             │
│  - Accessible only via TLS KMIP connection[2]          │
│                                                        │
│  Creation:                                             │
│  pg_tde_create_key_using_global_key_provider()         │
└────────────────────┬───────────────────────────────────┘
                     │
                     │ Encrypts (AES-128-GCM)
                     │ via KMIP wrap function
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│  INTERNAL KEYS (Data Encryption Keys / DEK)            │
│                                                        │
│  - Stored locally: $PGDATA/pg_tde/[3]                  │
│  - Encrypted by Principal Key[3]                       │
│  - ONE unique key per relation (OID)[3]                │
│  - Data encryption algorithms:[3]                      │
│    * Tables: AES-128-CBC                               │
│    * WAL: AES-128-CTR                                  │
│    * Keys: AES-128-GCM (principal wrap)                │
└────────────────────┬───────────────────────────────────┘
                     │
                     │ Encrypt (AES-128-CBC/CTR)
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│  ENCRYPTED DATA (User Data)                            │
│                                                        │
│  - Table pages stored encrypted on disk[3]             │
│  - Index pages stored encrypted[3]                     │
│  - WAL data encrypted (if pg_tde.wal_encrypt = on)[3]  │
└────────────────────────────────────────────────────────┘
```

### Internal Keys (DEK) Details

#### Generation and Storage

| Aspect | Detail |
|--------|--------|
| **Generation** | Automatic when `CREATE TABLE ... USING tde_heap`[3] |
| **Identifier** | Unique OID (Object Identifier) per relation[3] |
| **Location** | `$PGDATA/pg_tde/<database_oid>/`[3] |
| **File** | `<relation_oid>.key` (binary, encrypted)[3] |
| **Visibility** | Not readable directly without Principal Key[3] |
| **Rotation** | Via `VACUUM FULL`, `ALTER TABLE SET ACCESS METHOD`, or `CREATE TABLE AS SELECT`[3] |

#### Disk Structure Example

```
$PGDATA/pg_tde/
├── global/                          # Global section
│   ├── provider_config              # Global provider configuration
│   └── server_key.key               # WAL server key (if enabled)
│
└── 16384/                           # Database OID (example)
    ├── provider_config              # Database provider configuration
    ├── 16385.key                    # Internal key for table OID=16385
    ├── 16386.key                    # Internal key for index OID=16386
    ├── 16387.key                    # Internal key for index OID=16387
    ├── 16388.key                    # Internal key for TOAST OID=16388
    └── 16389.key                    # Internal key for sequence OID=16389
```

#### Security Considerations

| Aspect | Detail | Recommendation |
|--------|--------|-----------------|
| **File Permissions** | Inherited from `$PGDATA` (pg:pg 700)[3] | ✓ Good, ensure root cannot read |
| **Backup Protection** | DEK files copied with backup (remain encrypted)[3] | ✓ Safe for off-site storage |
| **RAM Cache** | Principal Key and DEKs decrypted in RAM[3] | ⚠️ Protect with: lock_memory, disable core dumps |
| **Swap Memory** | Keys can be paged to swap[3] | ⚠️ Use encrypted swap (dm-crypt, zswap) |

#### Recommended Protections

```bash
# 1. Disable core dumps
echo "kernel.core_pattern = /dev/null" >> /etc/sysctl.conf
sysctl -p

# 2. Encrypt swap (optional but recommended)
# Use dm-crypt or zswap

# 3. Lock PostgreSQL memory (optional but recommended)
ulimit -l unlimited
# or in postgresql.conf:
# lock_memory = true

# 4. Secure KMS certificates
sudo chmod 400 /path/to/client_cert.pem
sudo chmod 400 /path/to/client_key.pem
sudo chown postgres:postgres /path/to/*.pem
```

### Key Monitoring

#### Verify Current Keys

```sql
-- Check server default Principal Key
SELECT pg_tde_server_key_info();
-- Result: (key_name, provider_name)

-- Check current database Principal Key
SELECT pg_tde_key_info();

-- Check default Principal Key (if used)
SELECT pg_tde_default_key_info();

-- List all configured providers
SELECT * FROM pg_tde_list_all_global_key_providers();
SELECT * FROM pg_tde_list_all_database_key_providers();
```

#### Verify KMS Connectivity

```sql
-- Test Principal Key availability
SELECT pg_tde_verify_key();
SELECT pg_tde_verify_server_key();
SELECT pg_tde_verify_default_key();

-- If these fail: Check PostgreSQL logs for KMIP errors
-- tail -f $PGDATA/log/postgresql.log | grep -i kmip
```

---

## Verification and Testing

### Initial Setup Verification

```sql
-- 1. Verify extension is loaded
SELECT * FROM pg_extension WHERE extname = 'pg_tde';

-- 2. Verify configuration parameters
SHOW shared_preload_libraries;
SHOW pg_tde.wal_encrypt;
SHOW pg_tde.enforce_encryption;

-- 3. Verify KMS provider is configured
SELECT * FROM pg_tde_list_all_global_key_providers();

-- 4. Verify keys are set
SELECT pg_tde_server_key_info();
SELECT pg_tde_default_key_info();

-- 5. Verify KMS connectivity
SELECT pg_tde_verify_key();
SELECT pg_tde_verify_server_key();

-- 6. Create test table
CREATE TABLE test_encrypted (
  id serial PRIMARY KEY,
  data text
) USING tde_heap;

-- 7. Verify it's encrypted
SELECT pg_tde_is_encrypted('public.test_encrypted'::regclass);
-- Expected output: t (true)

-- 8. Test data insertion and retrieval
INSERT INTO test_encrypted (data) VALUES ('Test data');
SELECT * FROM test_encrypted;
-- Data should be returned in plaintext
```

### WAL Encryption Verification

```sql
-- Check if WAL encryption is enabled
SHOW pg_tde.wal_encrypt;

-- Verify encryption is active
SELECT pg_tde_is_wal_encrypted();

-- Check WAL files (encrypted WAL segments have standard naming)
SELECT name FROM pg_ls_waldir() 
ORDER BY name DESC LIMIT 5;
```

---

## Troubleshooting & Solutions

### Common Issues and Diagnostic Flow

#### 1. PostgreSQL Fails to Start

```
ERROR: could not load shared library "pg_tde"
or
ERROR: could not connect to KMIP server
```

**Diagnostic steps:**

```bash
# 1. Check if extension is compiled correctly
ls -la $PGINSTALL/lib/pg_tde.so

# 2. Check PostgreSQL logs
tail -f $PGDATA/log/postgresql.log

# 3. Verify KMS is reachable
telnet <kms-host> 5696

# 4. Check certificate paths
ls -la /path/to/*.pem
file /path/to/client_cert.pem
```

**SQL Verification:**

```sql
SELECT pg_tde_verify_key();
SELECT pg_tde_verify_server_key();
SELECT * FROM pg_tde_list_all_global_key_providers();
```

**Solutions:**
- Verify `shared_preload_libraries` contains `pg_tde`
- Restart PostgreSQL after configuration changes
- Ensure Cosmian KMS is running: `telnet <kms-host> 5696`
- Check firewall/network between PostgreSQL and KMS

#### 2. TLS Certificate Verification Failed

```
ERROR: SSL/TLS certificate verification failed
DETAIL: certificate verify failed / self signed certificate
```

**Diagnostic:**

```bash
# Verify certificate details
openssl x509 -in /path/to/ca_cert.pem -text -noout

# Check certificate expiration
openssl x509 -in /path/to/client_cert.pem -noout -dates

# Verify certificate chain
openssl verify -CAfile /path/to/ca_cert.pem /path/to/client_cert.pem

# Test KMIP connection manually (if PyKMIP available)
python3 -m kmip.demos.client -b /path/to/client_cert.pem \
  -k /path/to/client_key.pem \
  -ca /path/to/ca_cert.pem \
  --server <kms-host> --port 5696
```

**Solutions:**
- Verify certificate files exist and are readable: `ls -la /path/to/*.pem`
- Check certificate expiration dates
- Verify CA certificate chain is complete
- Ensure certificate paths in `pg_tde_add_global_key_provider_kmip()` are correct

#### 3. Key Not Found or Access Denied

```
ERROR: Failed to retrieve principal key 'key_01' from KMS provider 'kms_provider'
DETAIL: Key not found / Access denied
```

**Diagnostic:**

```sql
-- Verify KMS connectivity
SELECT pg_tde_verify_key();
SELECT pg_tde_verify_server_key();

-- Check configured keys
SELECT pg_tde_key_info();
SELECT pg_tde_server_key_info();

-- Check provider configuration
SELECT * FROM pg_tde_list_all_global_key_providers();
```

**Solutions:**
- Verify the key exists on Cosmian KMS
- Verify the key name matches exactly (case-sensitive)
- Check KMS user/role has permissions to access the key
- Verify database OID if using database-level keys: `SELECT datoid FROM pg_database WHERE datname = current_database();`
- Check `$PGDATA/pg_tde/` directory permissions

#### 4. Performance Degradation After Enabling TDE

```
Problem: Slower queries, high CPU usage
```

**Diagnostic:**

```sql
-- Check cache hit ratio
SELECT sum(heap_blks_read) / (sum(heap_blks_read) + 
        sum(heap_blks_hit)) AS cache_hit_ratio
FROM pg_stat_user_tables;

-- Check query plans
EXPLAIN ANALYZE SELECT * FROM sensitive_data LIMIT 1000;
```

**Solutions:**
- Increase `shared_buffers` to reduce disk I/O
- Check CPU supports AES-NI (hardware acceleration):
  ```bash
  grep -o 'aes' /proc/cpuinfo | head -1
  ```
- Monitor I/O performance with `iostat -x 1`
- Note: Percona reports ~10% overhead in most cases[4]

### Certificate Management Best Practices

```bash
# 1. Organize certificate files
mkdir -p /etc/postgresql/kmip-certs
sudo cp /path/to/*.pem /etc/postgresql/kmip-certs/
sudo chmod 400 /etc/postgresql/kmip-certs/*.pem
sudo chown postgres:postgres /etc/postgresql/kmip-certs/

# 2. Set correct paths in pg_tde configuration
SELECT pg_tde_add_global_key_provider_kmip(
  'kms_provider',
  'kms-host.example.com',
  5696,
  '/etc/postgresql/kmip-certs/client_cert.pem',
  '/etc/postgresql/kmip-certs/client_key.pem',
  '/etc/postgresql/kmip-certs/ca_cert.pem'
);

# 3. Monitor certificate expiration
openssl x509 -in /etc/postgresql/kmip-certs/client_cert.pem -noout -dates | \
  grep notAfter

# 4. Plan certificate rotation before expiration
# Test with new certificates before cutover
```
---

## Operational Considerations

### Migration from Non-TDE to TDE Tables

```
┌────────────────────────────────────────────────┐
│  Migration from non-TDE to TDE table           │
└────────────────────┬───────────────────────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
        ▼                         ▼
    Method 1:                  Method 2:
  CREATE TABLE AS             ALTER TABLE
        │                         │
        ▼                         ▼
  CREATE TABLE t_new       ALTER TABLE t_old
  USING tde_heap           SET ACCESS METHOD
  AS SELECT * FROM         tde_heap;
  t_old;
        │                         │
        ▼                         ▼
  DROP TABLE t_old;   (Recreates index, constraints,
  ALTER TABLE t_new   foreign keys)
  RENAME TO t_old;
        │                         │
        └────────────┬────────────┘
                     │
                     ▼
            ✓ TDE table created
              (exclusive lock)
```

**Impact:**
- Exclusive lock on table during migration
- Complete data rewrite
- Time proportional to table size
- Disk usage x2 during operation

**Recommendation:** Perform during maintenance window on production systems.

### Key Rotation

#### Principal Key Rotation

```sql
-- 1. Create new key on Cosmian KMS
SELECT pg_tde_create_key_using_global_key_provider(
  'key_02', 'kms_provider'
);

-- 2. Switch to new key
-- (Re-encrypts all internal keys)
SELECT pg_tde_set_default_key_using_global_key_provider(
  'key_02', 'kms_provider'
);

-- 3. Verify rotation is complete
SELECT pg_tde_default_key_info();

-- 4. Old key can be archived/destroyed after verification
-- (Cosmian KMS: key revoke/destroy operations)
```

**Notes:**
- Internal keys are re-encrypted (non-blocking operation)
- Old key retained for recovery purposes
- Does not re-encrypt user data (only wraps internal keys)
- Minimal performance impact

#### Internal Key Rotation (Existing Tables)

No direct in-place internal key rotation. Use one of these workarounds:

```sql
-- Method 1: VACUUM FULL (simpler but locks table)
VACUUM FULL sensitive_data;
-- Note: Table remains in memory during operation

-- Method 2: CREATE TABLE AS (more controlled)
CREATE TABLE sensitive_data_new USING tde_heap AS 
  SELECT * FROM sensitive_data;

-- Recreate indexes
CREATE INDEX idx_sensitive_data_id ON sensitive_data_new(id);

-- Swap tables
DROP TABLE sensitive_data;
ALTER TABLE sensitive_data_new RENAME TO sensitive_data;

-- Verify new encryption
SELECT pg_tde_is_encrypted('public.sensitive_data'::regclass);
```

**Performance Comparison:**
| Method | Lock Duration | Disk I/O | Downtime |
|--------|--------------|----------|----------|
| VACUUM FULL | Full table | Low | Minimal |
| CREATE TABLE AS | Full table | High (copy all) | Moderate |

### Backup and Recovery

#### Physical Backup with Encrypted WAL

```bash
# Full backup with streaming WAL
pg_tde_basebackup -D /path/to/backup \
  --wal-method=stream \
  -R \
  -v

# Or with archived WAL (requires WAL archiving configured)
pg_tde_basebackup -D /path/to/backup \
  --wal-method=none \
  -R

# WAL archiving setup (in postgresql.conf)
archive_mode = on
archive_command = 'pg_tde_archive_decrypt %f %p | pgbackrest archive-push %p'

# WAL restore setup (in recovery.conf or postgresql.conf)
restore_command = 'pgbackrest archive-get %f %p'
```

#### Recovery Point Objective (RPO)

```
┌──────────────────────────────────────────────────────┐
│  Recommended backup strategy                         │
├──────────────────────────────────────────────────────┤
│                                                      │
│ Baseline + Continuous WAL Archiving:                 │
│                                                      │
│  pg_tde_basebackup (baseline)                        │
│      │                                               │
│  ────┼──────────────────────────────────             │
│      │  WAL segments (archived)                      │
│      │  (archive_command)                            │
│      │                                               │
│      └──► Allows PITR up to last WAL segment         │
│                                                      │
│  RPO = 1 WAL segment (16 MB by default)              │
│  RTO = Time to replay WAL                            │
│                                                      │
└──────────────────────────────────────────────────────┘
```

### Failover and Standby Setup

#### Standby Configuration with Patroni

```yaml
# patroni.yml for pg_tde with Cosmian KMS
postgresql:
  # Use pg_tde_rewind, NOT standard pg_rewind if WAL encrypted
  pg_rewind: pg_tde_rewind
  
  parameters:
    shared_preload_libraries: pg_tde
    pg_tde.wal_encrypt: on
    pg_tde.enforce_encryption: on
    
    # Archive settings
    archive_mode: on
    archive_command: "pg_tde_archive_decrypt %f %p | pgbackrest archive-push %p"
    restore_command: "pgbackrest archive-get %f %p"
```

#### Failover Considerations

| Aspect | Impact | Solution |
|--------|--------|----------|
| **KMS Availability** | Critical | Primary and standby must both access KMS |
| **Certificates** | Critical | Distribute certificates to all replicas |
| **Principal Key** | Critical | Key must be accessible during recovery |
| **Encrypted WAL** | High | Use `pg_tde_rewind` not standard `pg_rewind`[5] |

**Important:** If using encrypted WAL, `pg_rewind` is incompatible. Use `pg_tde_rewind` instead.[5]

### Cosmian KMS Compatibility

**Supported features with pg_tde:**[2]
- KMIP 1.x and 2.x protocols
- Baseline Server profile (fully compliant)
- AES-128-CBC, AES-128-CTR, AES-128-GCM algorithms
- Key creation, retrieval, destruction, rotation
- TLS 1.2+ for secure communication

**Backup and Replication Tools Compatibility:**

| Tool | With WAL Encryption | Notes |
|------|-------------------|-------|
| pg_tde_basebackup | ✓ Supported[1] | Recommended tool |
| pgBackRest | ✓ Supported[4] | Production-ready |
| Patroni | ✓ Supported[4] | Use pg_tde_rewind |
| pg_rewind | ✗ Incompatible[5] | Use pg_tde_rewind instead |
| pg_createsubscriber | ✗ Incompatible[5] | Create subscriber manually |
| pg_receivewal | ✗ Incompatible[5] | Use pgBackRest or Patroni |
| Barman | ✗ Incompatible[5] | Use pgBackRest instead |

---

### Ongoing Maintenance

1. **Monitor KMS connectivity:**
   ```sql
   SELECT pg_tde_verify_key();
   ```

2. **Plan key rotation:**
   - Principal keys: Via Cosmian KMS management
   - Internal keys: Via table recreation (VACUUM FULL or ALTER TABLE SET ACCESS METHOD)

3. **Backup strategy:**
   - Use `pg_tde_basebackup` or `pgBackRest`
   - Archive encrypted WAL files
   - Test recovery procedures regularly

4. **Certificate rotation:**
   - Plan before expiration
   - Test with new certificates before cutover

### References

- [Percona pg_tde Documentation](https://percona.github.io/pg_tde/main/)[1]
- [Cosmian KMS KMIP Support](https://docs.cosmian.com/key_management_system/kmip/)[2]
- [Percona pg_tde Architecture](https://docs.percona.com/pg-tde/architecture/architecture.html)[3]
- [Percona WAL Encryption Blog (2025-09-01)](https://percona.community/blog/2025/09/01/pg_tde-can-now-encrypt-your-wal-on-prod/)[4]
- [Percona pg_tde Limitations](https://docs.percona.com/pg-tde/index/tde-limitations.html#currently-unsupported-wal-tools)[5]

---

## Official Documentation Links

- [Percona pg_tde Official Docs](https://docs.percona.com/pg-tde/)
- [Cosmian KMS Percona Integration](https://docs.cosmian.com/key_management_system/percona/)
- [Percona Server for PostgreSQL 17](https://www.percona.com/software/postgresql/percona-server-for-postgresql)

