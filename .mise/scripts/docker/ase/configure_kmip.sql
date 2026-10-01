-- configure_kmip.sql
-- Configure SAP ASE KMIP TDE (requires ASE 16.0 SP03+ Enterprise/Express).
-- Executed inside the container after ASE is ready.
-- Fails gracefully: errors caught by the test script.

-- Enable PCI compliance features (prerequisite for encryption at rest)
sp_configure 'enable pci', 1
go

-- Enable SSL (required for KMIP mTLS)
sp_configure 'ssl server identity', 'KMIP_CLIENT'
go

-- Point ASE at the KMS KMIP socket endpoint
-- KMIP_SERVER_ADDR injected by test script via sed or isql -v
sp_configure 'kmip server address', 0, '$(KMIP_ADDR)'
go

-- Client cert label in the SSL keystore (set up via ssl_key)
sp_configure 'kmip ssl cert', 0, '$(SYBSSL)/client.p12'
go
sp_configure 'kmip ssl password', 0, 'password'
go
sp_configure 'kmip ssl ca', 0, '$(SYBSSL)/kms_ca.crt'
go

-- Create an encryption key backed by the KMIP KMS
-- The key name will appear in the KMS as a Locate result
CREATE ENCRYPTION KEY TESTKEY FOR DATABASE
    INIT WITH KEYTYPE SYMMETRIC ALGORITHM AES KEYLEN 256
    EXTERNAL KEY MANAGER 1
go

-- Create a test database with TDE
CREATE DATABASE KMIPDB ON DEFAULT = 10 LOG ON DEFAULT = 5
    FOR LOAD
go
ALTER DATABASE KMIPDB SET ENCRYPTION ON KEY TESTKEY
go
