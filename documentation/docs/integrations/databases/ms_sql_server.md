Cosmian KMS integrates with Microsoft SQL Server External key management using a Windows DLL implementing the [SQL Server Extensible Key Management (EKM)](https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/extensible-key-management-ekm?view=sql-server-ver17).

The Windows DLL is a SQL Server EKM provider that forwards key operations to the Cosmian KMS over mutual TLS.  This allows SQL Server features like column-level encryption and Transparent Data Encryption (TDE) to use keys managed by the Cosmian KMS, without exposing key material to the SQL Server host.

The Windows DLL is available in a separate project on [GitHub](https://github.com/Cosmian/ekm_sql_server); pre-built signed DLLs are available for [download](https://package.cosmian.com).

# Deployment Guide

This document explains how to install and configure the Cosmian EKM SQL Server provider, starting from a signed DLL. Follow the steps in order.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Windows Server 2016+ or Windows 10/11 | x64 |
| SQL Server 2016+ (any edition) with EKM support | Standard or Enterprise; Express does not support EKM |
| Cosmian KMS 5.x | Must run on the same machine (or be network-reachable) |
| Signed `cosmian_ekm_sql_server.dll` | See the [KMS repository](https://github.com/Cosmian/kms) for build instructions |
| PowerShell 5.1 (elevated) | For the setup scripts |
| `sqlcmd` on the system `PATH` | Part of SQL Server Tools or installable standalone |

---

## 1. Install SQL Server

Install SQL Server with default settings.  The instance name used throughout
this guide is the **default instance** (`MSSQLSERVER`).  For a named instance,
substitute `MSSQL$<InstanceName>` wherever a service name is needed.

Ensure the **SQL Server Database Engine** service account is noted
(default: `NT SERVICE\MSSQLSERVER`).

---

## 2. Start the Cosmian KMS

The KMS must be running and accessible before SQL Server loads the EKM provider.

```powershell
# Example — adjust paths and config file as needed
cosmian_kms_server.exe --config kms_server.toml
```

The KMS must be configured with:

- TLS certificate trusted by this machine (or `accept_invalid_certs = true` in
  `config.toml` during development)
- At least one client certificate entry matching the SQL Server credential identity

Verify the KMS is reachable:

```powershell
Test-NetConnection -ComputerName localhost -Port 9998
```

---

## 3. Prepare the machine (one-time)

```powershell
# Creates directories and grants ACLs to the SQL Server service account
scripts\Initialize-EkmEnvironment.ps1

# Creates the Authenticode code-signing certificate (if not already present)
scripts\New-EkmCertificate.ps1
```

These are one-time operations per machine.

---

## 4. Install the provider configuration

Create `C:\ProgramData\Cosmian\EKM\config.toml` (see
[config.toml.example](config.toml.example) for the full schema):

```toml
max_age_seconds = 1800
stale_collector_period_seconds = 120

[kms]
server_url = "https://localhost:9998"
accept_invalid_certs = false          # set true only for local dev

[[kms.certificates]]
username = "admin"
client_cert = 'C:\ProgramData\Cosmian\EKM\admin.cert.pem'
client_key  = 'C:\ProgramData\Cosmian\EKM\admin.key.pem'
```

Copy the mTLS client certificate and key files to the paths referenced above, and
copy the KMS CA certificate so TLS verification succeeds.

---

## 5. Deploy the DLL

```powershell
# Must be run as Administrator
scripts\Deploy-EkmDll.ps1
```

This script:

1. Verifies the DLL's Authenticode signature.
2. Stops the `MSSQLSERVER` service.
3. Copies the DLL to `C:\Program Files\Cosmian\EKM\cosmian_ekm_sql_server.dll`.
4. Starts the `MSSQLSERVER` service.
5. Registers (or re-registers) `CosmianEKM` as a cryptographic provider.

To deploy to a named instance or skip the service restart:

```powershell
scripts\Deploy-EkmDll.ps1 -SqlServiceName "MSSQL`$MyInstance"
scripts\Deploy-EkmDll.ps1 -SkipServiceRestart   # register only
```

---

## 6. Enable EKM in SQL Server

Connect to SQL Server (e.g. via SSMS or sqlcmd) and run:

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

EXEC sp_configure 'EKM provider enabled', 1;
RECONFIGURE;
```

---

## 7. Register the provider

If `Deploy-EkmDll.ps1` was run with `-SkipRegistration`, register manually:

```sql
CREATE CRYPTOGRAPHIC PROVIDER CosmianEKM
FROM FILE = 'C:\Program Files\Cosmian\EKM\cosmian_ekm_sql_server.dll';
```

Verify:

```sql
SELECT name, is_enabled FROM sys.cryptographic_providers WHERE name = 'CosmianEKM';
```

---

## 8. Create a credential and map it to a login

Each SQL Server login that uses EKM keys must have a credential that maps to a
KMS identity (the `username` in `config.toml`).

```sql
-- Create the credential
CREATE CREDENTIAL Cosmian_EKM_Cred
WITH IDENTITY = 'admin',      -- must match [[kms.certificates]] username
     SECRET   = 'unused'
FOR CRYPTOGRAPHIC PROVIDER CosmianEKM;

-- Map to a Windows login (adjust the login name)
ALTER LOGIN [HOSTNAME\YourLogin] ADD CREDENTIAL Cosmian_EKM_Cred;
```

---

## 9. Create keys

```sql
USE master;

-- Asymmetric key (RSA 2048)
CREATE ASYMMETRIC KEY MyRsaKey
FROM PROVIDER CosmianEKM
WITH ALGORITHM = RSA_2048,
     PROVIDER_KEY_NAME = 'my-rsa-key',
     CREATION_DISPOSITION = CREATE_NEW;

-- Symmetric key (AES 256)
CREATE SYMMETRIC KEY MyAesKey
FROM PROVIDER CosmianEKM
WITH ALGORITHM = AES_256,
     PROVIDER_KEY_NAME = 'my-aes-key',
     CREATION_DISPOSITION = CREATE_NEW;
```

---

## 10. Column-level encryption (quick check)

```sql
USE master;

-- Symmetric key protected by the EKM asymmetric key
CREATE SYMMETRIC KEY ColKey
WITH ALGORITHM = AES_256
ENCRYPTION BY ASYMMETRIC KEY MyRsaKey;

-- Encrypt
OPEN SYMMETRIC KEY ColKey DECRYPTION BY ASYMMETRIC KEY MyRsaKey;
SELECT ENCRYPTBYKEY(KEY_GUID('ColKey'), N'Hello EKM!');
CLOSE SYMMETRIC KEY ColKey;
```

---

## 11. Transparent Data Encryption (TDE)

```sql
-- Create a login backed by the EKM asymmetric key
CREATE LOGIN Cosmian_TDE_Login FROM ASYMMETRIC KEY MyRsaKey;

-- Credential for unattended access
CREATE CREDENTIAL Cosmian_TDE_Cred
WITH IDENTITY = 'admin', SECRET = 'unused'
FOR CRYPTOGRAPHIC PROVIDER CosmianEKM;
ALTER LOGIN Cosmian_TDE_Login ADD CREDENTIAL Cosmian_TDE_Cred;

-- Enable TDE on a database
USE MyDatabase;
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER ASYMMETRIC KEY MyRsaKey;

ALTER DATABASE MyDatabase SET ENCRYPTION ON;
```

Monitor encryption progress:

```sql
SELECT db.name, dek.encryption_state, dek.percent_complete
FROM sys.dm_database_encryption_keys dek
JOIN sys.databases db ON dek.database_id = db.database_id;
```

State 3 means fully encrypted.

---

## 12. Run integration tests

```powershell
# All-in-one: build + sign + deploy + copy test config
scripts\Prepare-Integration-Tests.ps1

# Then run the tests
cargo test --test integration -- --test-threads=1
```

---

## Troubleshooting

### Provider not loading

Check the EKM log file:

```text
C:\ProgramData\Cosmian\EKM\logs\cosmian_ekm.log.<date>
```

### "Cannot open database / invalid object name"

The SQL Server service account needs `Modify` rights on
`C:\ProgramData\Cosmian\EKM\`.  Re-run `Initialize-EkmEnvironment.ps1`.

### KMS connection errors

- Verify `config.toml` has the correct `server_url`.
- Confirm the client certificate CN or SAN matches the SQL credential identity.
- Check the KMS server is running: `Test-NetConnection localhost -Port 9998`.

### Key operations fail after redeployment

If the DLL is replaced, SQL Server must be restarted to reload it.  Run
`Deploy-EkmDll.ps1` (which handles the restart automatically).
