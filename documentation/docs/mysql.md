# MySQL Enterprise 8.4 + Cosmian KMS Integration

## Executive Summary

This document provides a comprehensive guide for integrating MySQL Enterprise with Cosmian Key Management System (KMS) using the `keyring_okv` plugin for Transparent Data Encryption (TDE). This lab demonstrates secure key management and data encryption at rest in a controlled environment.

---

## Table of Contents

1. [Version Requirements](#version-requirements)
2. [Technical Specifications](#technical-specifications)
3. [Architecture Overview](#architecture-overview)
4. [Prerequisites](#prerequisites)
5. [Installation and Configuration](#installation-and-configuration)
6. [Capabilities and Features](#capabilities-and-features)
7. [Testing and Validation](#testing-and-validation)
8. [Advanced Resilience Testing](#advanced-resilience-testing)
9. [Troubleshooting](#troubleshooting)
10. [References](#references)

---

## Version Requirements

### Minimum Versions for TDE with keyring_okv

| Component | Minimum Version | Notes |
|-----------|-----------------|-------|
| **MySQL Enterprise** | 8.0+ | keyring_okv plugin available in Enterprise Edition |
| **Cosmian KMS** | 5.14+ | Full KMIP 1.1 compatibility |
| **KMIP Protocol** | 1.1 | Standard protocol version supported by keyring_okv |
| **OpenSSL** | 3.0+ | For TLS 1.3 and mTLS certificate support |

**Note:** This lab uses **MySQL 8.4.7** and **Cosmian KMS 5.14+** which are the stable, production-ready versions recommended for new deployments.

---

## Technical Specifications

### System Requirements

| Component | Version | Specification |
|-----------|---------|---------------|
| **MySQL Enterprise Server** | 8.4.7-commercial | Generic Linux x86_64 binary (glibc 2.28) |
| **Cosmian KMS** | 5.14+ | KMIP 1.1 server with socket support |
| **Operating System** | Ubuntu 24.04 LTS (Noble) | Debian 10+, RHEL 8+, or any modern Linux (x86_64) |
| **OpenSSL** | 3.6.0 (+ 3.1.2 FIPS provider) | For TLS/mTLS communication |
| **Network** | Dedicated subnet | Low-latency, isolated lab network |

### Network Architecture

```text
┌──────────────────────────────────────────────────────────┐
│                  Isolated Lab Network                    │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────────────┐      ┌──────────────────────┐   │
│  │   Cosmian KMS       │      │  MySQL Enterprise    │   │
│  │  (v5.14+)           │      │  (v8.4.7)            │   │
│  │                     │◄────►│                      │   │
│  │ HTTP:  9998 (HTTPS) │      │ Port 3306 (MySQL)    │   │
│  │ KMIP:  5696 (TLS)   │      │ KMIP via TLS         │   │
│  │ DB:    SQLite       │      │ keyring_okv plugin   │   │
│  └─────────────────────┘      └──────────────────────┘   │
│         Protocol: KMIP 1.1 over TLS 1.3                  │
└──────────────────────────────────────────────────────────┘
```

### Key Management Flow

```text
MySQL InnoDB
     │
     ├─ Generates encryption key (TEK)
     │
     └─► keyring_okv plugin (MySQL 8.0+)
            │
            ├─ Connects to Cosmian KMS via KMIP (TLS)
            │
            └─► Cosmian KMS (v5.14+, Port 5696)
                   │
                   ├─ Stores/retrieves master key
                   │
                   └─► SQLite Database (persistent)
```

---

## Architecture Overview

### Component Roles

**Cosmian KMS (v5.14+):**

- Acts as external Key Management System
- Manages encryption keys for MySQL
- Provides KMIP 1.1 protocol support
- Stores keys in persistent SQLite database
- Enforces mutual TLS (mTLS) authentication with client certificates
- Independent of MySQL lifecycle

**MySQL Enterprise (v8.0.13+, ideally 8.4+):**

- Runs `keyring_okv` plugin as KMIP client
- Generates and manages Transparent Data Encryption (TDE) keys
- Encrypts table data at rest using master key from KMS
- Communicates with KMS via secure KMIP protocol
- Does NOT store master keys locally (security by design)
- Maintains in-memory cache during uptime for performance

### Security Model

- **Authentication:** Mutual TLS (mTLS) with X.509 certificates
- **Encryption:** AES-256 for data, TLS 1.3 for transport
- **Key Storage:** Centralized in Cosmian KMS (never persisted on MySQL filesystem)
- **Key Access:** Only via authenticated KMIP protocol over TLS
- **Cache Invalidation:** Automatic on KMS unavailability

---

## Prerequisites

### Hardware Requirements

- **Cosmian KMS Server:** 1 vCPU, 2 GB RAM, 10 GB storage
- **MySQL Enterprise Server:** 2 vCPU, 4 GB RAM, 20 GB storage
- **Network:** Low-latency connection (<10 ms ping recommended)

### Software Requirements

On **Cosmian KMS Host (v5.14+):**

- Ubuntu 20.04+, | RHEL 8+ | or equivalent
- Ope | x86_64 architecturenSSL 3.0+
- Rust toolchain (if building from source)

On **MySQL Enterprise Host (v8.0.13+, v8.4.7+ recommended):**

- Ubuntu 24.04 LTS
- libaio1t64 (or libaio compatibility layer)
- libncurses-dev or libncurses6
- xz-utils
- OpenSSL 3.0+

### Certificates and Keys (PKI)

For mutual TLS authentication:

- CA certificate (`ca.crt`)
- CA private key (`ca.key`) - for signing
- Server certificate with key (`kms.p12` or separate files)
- Client certificate for MySQL (`mysql-client.crt`)
- Client private key for MySQL (`mysql-client.key`)

---

## Installation and Configuration

### Step 1: Prepare Cosmian KMS (v5.14+)

#### 1.1 Deploy Cosmian KMS Server

Choose your Linux distribution and refer to [installation guide](./installation/installation_getting_started.md)

Verify the installed version and configuration file location:

```bash
cosmian_kms --version
cat /etc/cosmian/kms.toml
```

#### 1.2 Configure KMS TOML File

Edit `kms.toml`:

```toml
default_username = "admin"
force_default_username = true

[logging]
otlp = ""  # Disabled for lab
enable_metering = false
rust_log = "info,cosmian_kms=debug"
## rolling_log_dir = "path_to_logging_directory"
## rolling_log_dir = "path_to_logging_directory"

[tls]
tls_p12_file = "scripts/certifs/kms.p12"
tls_p12_password = "YOURTLSPASSWORD"
clients_ca_cert_file = "scripts/certifs/ca.crt"

[socket_server]
socket_server_start = true
socket_server_port = 5696
socket_server_hostname = "0.0.0.0"

[http]
port = 9998
hostname = "0.0.0.0"

[ui_config]
ui_index_html_folder = "/usr/local/cosmian/ui/dist"
kms_public_url = "https://localhost:9998"

[db]
database-type="mysql"
database-url="mysql://kms_user:kms_password@mysql-server:3306/kms"
```

**Key Configuration Notes:**

- `clients_ca_cert_file` is **required** for mTLS validation
- `socket_server_port` 5696 is standard KMIP port
- Ensure database path is on persistent storage

#### 1.3 Start Cosmian KMS (v5.14+)

```bash
export COSMIAN_KMS_CONF=/path/to/kms.toml
RUST_LOG=INFO ./cosmian_kms > /tmp/kms.log 2>&1 &

# Verify listening ports
ss -lntp | grep cosmian_kms

# Expected output:
# LISTEN ... :5696 ... cosmian_kms (KMIP socket)
# LISTEN ... :9998 ... cosmian_kms (HTTP API)
```

---

### Step 2: Prepare MySQL Enterprise Host (v8.0.13+, v8.4.7+ recommended)

#### 2.1 Install Prerequisites

```bash
# On MySQL host
sudo apt update
sudo apt install -y libaio1t64 libncurses-dev xz-utils openssl

# Create libaio compatibility symlink for Ubuntu 24.04
sudo ln -s /usr/lib/x86_64-linux-gnu/libaio.so.1t64 \
           /usr/lib/x86_64-linux-gnu/libaio.so.1
```

#### 2.2 Extract MySQL Enterprise Binary (v8.0.13+)

```bash
cd /usr/local
# For MySQL 8.4.7:
sudo tar xvf /tmp/mysql-commercial-8.4.7-linux-glibc2.28-x86_64.tar.xz
# Or for MySQL 8.0.x (8.0.13+):
# sudo tar xvf /tmp/mysql-commercial-8.0.xx-linux-glibc2.28-x86_64.tar.xz

sudo ln -sf mysql-commercial-8.4.7-linux-glibc2.28-x86_64 mysql
sudo chown -R mysql:mysql /usr/local/mysql*
```

#### 2.3 Create MySQL System User and Directories

```bash
sudo groupadd mysql 2>/dev/null || true
sudo useradd -r -g mysql -s /bin/false mysql 2>/dev/null || true

sudo mkdir -p /var/lib/mysql-data /var/log/mysql /var/run/mysqld
sudo chown -R mysql:mysql /var/lib/mysql-data /var/log/mysql /var/run/mysqld
```

#### 2.4 Initialize MySQL Data Directory

```bash
cd /usr/local/mysql
sudo -u mysql ./bin/mysqld \
  --initialize \
  --user=mysql \
  --datadir=/var/lib/mysql-data \
  --log-error=/var/log/mysql/mysqld.log

# Capture temporary root password
grep "temporary password" /var/log/mysql/mysqld.log
# Save this password for next step
```

---

### Step 3: Configure KMIP Client Certificates

#### 3.1 Generate MySQL Client Certificate

```bash
# On a machine with CA key access
cd /path/to/pki

# Generate MySQL client private key
openssl genrsa -out mysql-client.key 4096

# Create Certificate Signing Request
openssl req -new \
  -key mysql-client.key \
  -out mysql-client.csr \
  -subj "/CN=mysql-kmip-client/O=Lab/C=FR"

# Sign with CA
openssl x509 -req \
  -in mysql-client.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out mysql-client.crt \
  -days 365 \
  -sha256

# Resulting files:
# - mysql-client.crt (client certificate)
# - mysql-client.key (client private key)
# - ca.crt (CA certificate - already existing)
```

#### 3.2 Copy Certificates to MySQL Host

```bash
# From PKI machine to MySQL host
scp mysql-client.crt mysql-client.key ca.crt \
    user@mysql-host:/tmp/

# On MySQL host
sudo mkdir -p /usr/local/mysql/mysql-keyring-okv/ssl
sudo cp /tmp/mysql-client.crt /usr/local/mysql/mysql-keyring-okv/ssl/cert.pem
sudo cp /tmp/mysql-client.key /usr/local/mysql/mysql-keyring-okv/ssl/key.pem
sudo cp /tmp/ca.crt /usr/local/mysql/mysql-keyring-okv/ssl/CA.pem

# Set proper permissions
sudo chown -R mysql:mysql /usr/local/mysql/mysql-keyring-okv/ssl
sudo chmod 600 /usr/local/mysql/mysql-keyring-okv/ssl/key.pem
sudo chmod 644 /usr/local/mysql/mysql-keyring-okv/ssl/cert.pem
sudo chmod 644 /usr/local/mysql/mysql-keyring-okv/ssl/CA.pem
```

---

### Step 4: Configure keyring_okv Plugin (MySQL 8.0+)

#### 4.1 Create okvclient.ora Configuration File

```bash
# On MySQL host
sudo tee /usr/local/mysql/mysql-keyring-okv/okvclient.ora > /dev/null <<'EOF'
SERVER=<kms-host>:5696
SSL_DIR=/usr/local/mysql/mysql-keyring-okv/ssl
SSL_CERT=cert.pem
SSL_KEY=key.pem
SSL_CA=CA.pem
EOF

sudo chown mysql:mysql /usr/local/mysql/mysql-keyring-okv/okvclient.ora
sudo chmod 600 /usr/local/mysql/mysql-keyring-okv/okvclient.ora
```

**Configuration Notes:**

- Replace `<kms-host>` with actual KMS hostname/IP
- Port 5696 is standard KMIP port
- SSL_DIR must point to directory containing cert, key, and CA

#### 4.2 Create MySQL Configuration File (v8.0+)

```bash
# Create /etc/my.cnf
sudo tee /etc/my.cnf > /dev/null <<'EOF'
[mysqld]
user=mysql
basedir=/usr/local/mysql
datadir=/var/lib/mysql-data
socket=/var/run/mysqld/mysqld.sock
log-error=/var/log/mysql/mysqld.log
pid-file=/var/run/mysqld/mysqld.pid
port=3306

# KMIP Keyring Plugin (MUST load early, before InnoDB)
# Available in MySQL 8.0 Enterprise Edition
early-plugin-load=keyring_okv.so
keyring_okv_conf_dir=/usr/local/mysql/mysql-keyring-okv

# Optional: Enable TDE by default for new tables (MySQL 8.0.16+)
default_table_encryption=ON
EOF
```

**Critical Configuration Points:**

- `early-plugin-load` must be set **before** InnoDB initialization
- `keyring_okv_conf_dir` must point to directory with `okvclient.ora`
- Plugin must be loaded before any encrypted tables are accessed
- Requires MySQL 8.0 Enterprise Edition
- `default_table_encryption` requires MySQL 8.0.16+

#### 4.3 Set MySQL Root Password

```bash
# Start MySQL
sudo -u mysql /usr/local/mysql/bin/mysqld \
  --datadir=/var/lib/mysql-data \
  --log-error=/var/log/mysql/mysqld.log \
  --socket=/var/run/mysqld/mysqld.sock &

sleep 5

# Connect with temporary password (from step 2.4)
/usr/local/mysql/bin/mysql -u root -p \
  --socket=/var/run/mysqld/mysqld.sock
# Enter temporary password when prompted

# Inside MySQL:
ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewSecurePassword123!';
FLUSH PRIVILEGES;
EXIT;

# Stop MySQL
sudo systemctl stop mysqld
sleep 3
```

---

### Step 5: Start MySQL with KMS Integration

```bash
# Clean up any residual lock files
sudo rm -f /var/lib/mysql-data/*.lock
sudo rm -f /var/run/mysqld/mysqld.lock

# Start MySQL with configuration file
sudo -u mysql /usr/local/mysql/bin/mysqld \
  --defaults-file=/etc/my.cnf &

sleep 5

# Verify running
ps aux | grep mysqld | grep -v grep
```

---

## Capabilities and Features

### Transparent Data Encryption (TDE)

#### Master Key Rotation

```sql
-- Rotate the master encryption key (generates new key in KMS)
ALTER INSTANCE ROTATE INNODB MASTER KEY;
```

**Note:** Rotation takes ~0.5 seconds; existing data remains accessible

#### Create Encrypted Tables

```sql
CREATE TABLE sensitive_data (
  id INT PRIMARY KEY,
  credit_card VARCHAR(20),
  ssn VARCHAR(11)
) ENCRYPTION='Y';
```

#### Encrypt Existing Tables

```sql
-- Enable encryption on an unencrypted table
ALTER TABLE existing_table ENCRYPTION='Y';
```

#### Per-Tablespace Encryption (MySQL 8.0.13+)

```sql
-- Create a general tablespace with encryption (MySQL 8.0.13+)
-- All tables created in this tablespace will be encrypted
CREATE TABLESPACE ts_encrypted ADD DATAFILE 'ts_encrypted.ibd' ENCRYPTION='Y';

-- Create a table in the encrypted tablespace
CREATE TABLE secure_table (id INT PRIMARY KEY) TABLESPACE=ts_encrypted;
-- secure_table is automatically encrypted (inherits from tablespace)

-- OR encrypt an existing tablespace (MySQL 8.0.13+)
-- This affects all tables within the tablespace
ALTER TABLESPACE ts_existing ENCRYPTION='Y';

### Key Management Verification

```sql
-- Check keyring plugin status
SELECT PLUGIN_NAME, PLUGIN_STATUS
FROM INFORMATION_SCHEMA.PLUGINS
WHERE PLUGIN_NAME = 'keyring_okv';

-- Verify encryption on table
SELECT * FROM INFORMATION_SCHEMA.INNODB_TABLESPACES
WHERE NAME = 'database/table_name';

-- Verify table definition
SHOW CREATE TABLE table_name\G
```

### Data At Rest Verification

```bash
# Verify data is encrypted in file (no plaintext strings)
strings /var/lib/mysql-data/database/table_name.ibd | \
  grep -i "sensitive_keyword" || \
  echo "✓ No plaintext data found (encryption OK)"
```

### Key Storage Architecture

- **Master Key:** Stored only in Cosmian KMS database
- **Tablespace Keys (TEK):** Encrypted with master key, stored in InnoDB
- **Cache:** Kept in MySQL memory during runtime for performance
- **Persistence:** Survives MySQL restart (key retrieved from KMS)
- **Security Boundary:** Cache invalidated if KMS unreachable at startup

### Limitations

- **Single Master Key:** One master encryption key per MySQL instance
- **Network Dependency:** KMS unavailability blocks new MySQL starts
- **Cache Behavior:** Data accessible from cache until MySQL restart
- **No Local Fallback:** Encrypted data inaccessible without KMS access at startup
- **Version Requirements:** Requires MySQL Enterprise 8.0+ with keyring_okv support

---

## Testing and Validation

### Test 1: Verify Plugin is Active

```bash
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock <<'EOF'
SELECT PLUGIN_NAME, PLUGIN_STATUS
FROM INFORMATION_SCHEMA.PLUGINS
WHERE PLUGIN_NAME = 'keyring_okv';
EOF
```

**Expected Output:**

```text
| keyring_okv | ACTIVE |
```

**Pass Criteria:** Plugin status is `ACTIVE`

---

### Test 2: Create Encrypted Table and Verify Encryption

```bash
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock <<'EOF'
-- Create encrypted table
CREATE TABLE mysql.test_tde (
  id INT PRIMARY KEY,
  secret VARCHAR(255)
) ENCRYPTION='Y';

-- Insert test data
INSERT INTO mysql.test_tde (id, secret) VALUES
  (1, 'Sensitive-Data-001'),
  (2, 'Sensitive-Data-002');

-- Retrieve data
SELECT * FROM mysql.test_tde;

-- Verify encryption setting
SELECT * FROM INFORMATION_SCHEMA.INNODB_TABLESPACES
WHERE NAME = 'mysql/test_tde';
EOF
```

**Expected Output:**

```text
| ENCRYPTION: Y |
| STATE: normal |
```

**Pass Criteria:**

- Table created successfully
- Data inserted and retrieved
- ENCRYPTION field shows 'Y'

---

### Test 3: Verify Data Encryption at Rest

```bash
# Verify no plaintext in datafile
strings /var/lib/mysql-data/mysql/test_tde.ibd | \
  grep -i "Sensitive-Data" || \
  echo "✓ No plaintext detected (encryption confirmed)"
```

**Pass Criteria:** No plaintext keywords found in binary file

---

### Test 4: Convert Unencrypted Table to Encrypted

```bash
# Create a non-encrypted table with data
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock <<'EOF'
CREATE TABLE mysql.test_unencrypted (
  id INT PRIMARY KEY,
  secret VARCHAR(255)
) ENCRYPTION='N';

-- Insert test data
INSERT INTO mysql.test_unencrypted (id, secret) VALUES
  (1, 'Plaintext-Data-001'),
  (2, 'Plaintext-Data-002'),
  (3, 'Plaintext-Data-003');

-- Verify plaintext is visible in file (for reference)
SELECT * FROM mysql.test_unencrypted;
EOF

# Verify plaintext exists before encryption
strings /var/lib/mysql-data/mysql/test_unencrypted.ibd | \
  grep -i "Plaintext-Data" && echo "✓ Plaintext found (expected)"

# Now convert to encrypted
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock <<'EOF'
-- Convert table to encrypted (uses ALGORITHM=COPY internally)
ALTER TABLE mysql.test_unencrypted ENCRYPTION='Y';

-- Verify encryption is now active
SELECT * FROM INFORMATION_SCHEMA.INNODB_TABLESPACES
WHERE NAME = 'mysql/test_unencrypted';

-- Verify data is still accessible
SELECT * FROM mysql.test_unencrypted;
EOF

# Verify plaintext is now gone
strings /var/lib/mysql-data/mysql/test_unencrypted.ibd | \
  grep -i "Plaintext-Data" || \
  echo "✓ No plaintext found (encryption successful)"

# Restart MySQL to verify persistence
sudo systemctl stop mysqld
sleep 3

sudo -u mysql /usr/local/mysql/bin/mysqld \
  --defaults-file=/etc/my.cnf &

sleep 5

# Verify data survives restart
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock \
  -e "SELECT * FROM mysql.test_unencrypted;"
```

**Pass Criteria:**

- Table encryption conversion succeeds
- Data remains accessible before and after conversion
- Plaintext data encrypted at rest
- Data persists after MySQL restart

---

### Test 5: Master Key Rotation

```bash
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock <<'EOF'
-- Rotate the master key
ALTER INSTANCE ROTATE INNODB MASTER KEY;

-- Verify table still accessible after rotation
SELECT COUNT(*) FROM mysql.test_tde;

-- Confirm data integrity
SELECT * FROM mysql.test_tde;
EOF
```

**Expected Output:**

```text
Query OK, 0 rows affected (0.58 sec)
```

**Pass Criteria:**

- Key rotation succeeds
- Data remains accessible and intact

---

### Test 6: Data Persistence After MySQL Restart

```bash
# Insert marker data
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock <<'EOF'
INSERT INTO mysql.test_tde (id, secret) VALUES (999, 'Persistence-Check');
SELECT COUNT(*) as row_count FROM mysql.test_tde;
EOF

# Restart MySQL
sudo systemctl stop mysqld
sleep 3

sudo -u mysql /usr/local/mysql/bin/mysqld \
  --defaults-file=/etc/my.cnf &

sleep 5

# Verify data survived
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock <<'EOF'
SELECT * FROM mysql.test_tde WHERE id = 999;
SELECT COUNT(*) as rows_after_restart FROM mysql.test_tde;
EOF
```

**Expected Output:**

```text
| id  | secret             |
|-----|--------------------|
| 999 | Persistence-Check  |

rows_after_restart: (same as before restart)
```

**Pass Criteria:**

- Data persists after MySQL restart
- Master key successfully retrieved from KMS
- Row count unchanged

---

### Test 7: TLS Communication Verification

```bash
# Test direct TLS connection to KMS KMIP endpoint
timeout 5 openssl s_client -connect <kms-host>:5696 \
  -cert /usr/local/mysql/mysql-keyring-okv/ssl/cert.pem \
  -key /usr/local/mysql/mysql-keyring-okv/ssl/key.pem \
  -CAfile /usr/local/mysql/mysql-keyring-okv/ssl/CA.pem \
  < /dev/null 2>&1 | grep "Verify return code"
```

**Expected Output:**

```text
Verify return code: 0 (ok)
```

**Pass Criteria:** TLS handshake succeeds with valid certificates

---

## Advanced Resilience Testing

### Resilience Test 1: KMS Unavailability with MySQL Running

**Scenario:** Brief KMS outage while MySQL is operational

```bash
# Step 1: Verify data accessible (KMS running)
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock \
  -e "SELECT COUNT(*) FROM mysql.test_tde;"

# Step 2: Stop KMS
systemctl stop cosmian_kms

# Step 3: Verify data still accessible (from cache)
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock \
  -e "SELECT COUNT(*) FROM mysql.test_tde;"
# ✓ Data accessible (master key in MySQL memory cache)

# Step 4: Restart KMS
systemctl start cosmian_kms

# Step 5: Verify access continues
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock \
  -e "SELECT * FROM mysql.test_tde LIMIT 1;"
```

**Results:**

```text
✓ Data accessible while KMS down (cache hit)
✓ Data accessible after KMS restart
✓ No service interruption during brief outage
```

---

### Resilience Test 2: KMS Unavailability with MySQL Restart

**Scenario:** KMS down when MySQL starts (critical test)

```bash
# Step 1: Verify KMS is stopped
ps aux | grep cosmian_kms | grep -v grep
# (should return nothing)

# Step 2: Restart MySQL (KMS OFFLINE)
sudo systemctl stop mysqld
sleep 3

sudo -u mysql /usr/local/mysql/bin/mysqld \
  --defaults-file=/etc/my.cnf &

sleep 5

# Step 3: Try to access encrypted data
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock \
  -e "SELECT * FROM mysql.test_tde;" 2>&1
```

**Expected Error:**

```text
ERROR 3185 (HY000): Can't find master key from keyring,
please check in the server log if a keyring is loaded and initialized successfully.
```

**Result:**

```text
✓ Security working correctly
✓ Encrypted data inaccessible without KMS
✓ MySQL started but cannot decrypt
```

---

### Resilience Test 3: Recovery After KMS Outage + Restart

**Scenario:** Full recovery workflow after KMS was offline

```bash
# Step 1: KMS is still down, MySQL started with error above

# Step 2: Start KMS (v5.14+)
systemctl start cosmian_kms

# Step 3: MySQL still cannot access (cache was invalidated)
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock \
  -e "SELECT * FROM mysql.test_tde;" 2>&1
# Still ERROR 3185

# Step 4: Restart MySQL to reconnect to KMS
sudo systemctl stop mysqld
sleep 3

sudo -u mysql /usr/local/mysql/bin/mysqld \
  --defaults-file=/etc/my.cnf &

sleep 5

# Step 5: Data now accessible
/usr/local/mysql/bin/mysql -u root -pYourPassword \
  --socket=/var/run/mysqld/mysqld.sock \
  -e "SELECT * FROM mysql.test_tde;"
```

**Results:**

```text
✓ KMS restart does NOT automatically recover cached state
✓ MySQL restart required to re-establish KMS connection
✓ Data fully recoverable with proper startup order
```

**Lessons Learned:**

1. Keep KMS and MySQL in sync (start/stop in order)
2. Monitor KMS availability separately
3. Set up automated alerts for KMS downtime

---

## TDE Benchmark Report (1,000,000 rows)

### Execution Times

| Operation | Encrypted Table (TDE) | Non-Encrypted Table | TDE Overhead |
|-----------|----------------------|--------------------|--------------|
| Bulk INSERT | 12.11 s | 11.05 s | **+9%** |
| Full scan SELECT (cold cache) | 2.06 s | 1.41 s | **+47%** |
| Full scan SELECT (warm cache) | 2.26 s | 1.46 s | **+55%** |
| Lookup SELECT (PK, warm) | 0.018 s | 0.015 s | **≈ 0%** |

## Performance by Workload Type

| Workload Type | TDE Impact | Comments |
|---------------|-----------|----------|
| OLTP (INSERT / PK lookup) | 🟢 Low | Overhead negligible in production |
| Sequential scan | 🟠 Moderate | Crypto cost visible, especially with warm cache |
| Analytical (aggregations) | 🔴 Higher | CPU-bound, plan for extra CPU resources |

---

## Troubleshooting

### Issue: "Can't find master key from keyring"

**Symptom:**

```text
ERROR 3185 (HY000): Can't find master key from keyring,
please check in the server log if a keyring is loaded and initialized successfully.
```

**Root Causes:**

1. Cosmian KMS (v5.14+) is not running or unreachable
2. Network connectivity issue between MySQL and KMS
3. Certificate authentication failed
4. Plugin failed to initialize

**Solutions:**

1. **Verify Cosmian KMS (v5.14+) is running:**

   ```bash
   ps aux | grep cosmian_kms | grep -v grep
   ss -lntp | grep 5696
   ```

2. **Check network connectivity:**

   ```bash
   nc -zv <kms-host> 5696
   ping <kms-host>
   ```

3. **Verify certificate validity:**

   ```bash
   openssl x509 -in /usr/local/mysql/mysql-keyring-okv/ssl/cert.pem -text -noout
   # Check NotBefore and NotAfter dates
   ```

4. **Check MySQL error log:**

   ```bash
   tail -n 100 /var/log/mysql/mysqld.log | grep -i "keyring\|error\|tls"
   ```

5. **Verify okvclient.ora configuration:**

   ```bash
   cat /usr/local/mysql/mysql-keyring-okv/okvclient.ora
   ```

6. **Verify MySQL Enterprise version has keyring_okv support:**

   ```bash
   /usr/local/mysql/bin/mysql --version
   # Must be MySQL 8.0 Enterprise Edition or higher
   ```

---

### Issue: "Encryption information can't be decrypted"

**Symptom:**

```text
ERROR 12226: Encryption information in datafile: ./mysql/test_tde.ibd
can't be decrypted
```

**Causes:**

- Table was created with a key that's no longer accessible
- Datafile corruption
- KMS unavailable during startup

**Solutions:**

1. **If test/development data:**

   ```bash
   # Remove problematic datafile
   sudo mv /var/lib/mysql-data/mysql/test_tde.ibd \
           /var/lib/mysql-data/mysql/test_tde.ibd.backup

   # Restart MySQL
   sudo systemctl stop mysqld
   sleep 3
   sudo -u mysql /usr/local/mysql/bin/mysqld \
     --defaults-file=/etc/my.cnf &

   # Drop table and recreate
   /usr/local/mysql/bin/mysql -u root -pYourPassword \
     --socket=/var/run/mysqld/mysqld.sock \
     -e "DROP TABLE mysql.test_tde;"
   ```

2. **If production data, investigate:**
   - Check KMS (v5.14+) availability during startup
   - Verify master key is accessible
   - Check certificate validity
   - Review MySQL error logs

---

### Issue: Certificate Expiry

**Symptom:**

```text
SSL: CERTIFICATE_VERIFY_FAILED
```

**Solution:**

```bash
# Check certificate expiry
openssl x509 -in /usr/local/mysql/mysql-keyring-okv/ssl/cert.pem \
  -noout -dates

# Generate new certificate before expiry
openssl genrsa -out mysql-client.key.new 4096
openssl req -new \
  -key mysql-client.key.new \
  -out mysql-client.csr.new \
  -subj "/CN=mysql-kmip-client/O=Lab/C=FR"

openssl x509 -req \
  -in mysql-client.csr.new \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out mysql-client.crt.new \
  -days 365 \
  -sha256

# Replace certificates (during maintenance window)
sudo cp mysql-client.crt.new \
     /usr/local/mysql/mysql-keyring-okv/ssl/cert.pem

sudo cp mysql-client.key.new \
     /usr/local/mysql/mysql-keyring-okv/ssl/key.pem

sudo chown mysql:mysql /usr/local/mysql/mysql-keyring-okv/ssl/cert.pem
sudo chown mysql:mysql /usr/local/mysql/mysql-keyring-okv/ssl/key.pem
sudo chmod 600 /usr/local/mysql/mysql-keyring-okv/ssl/key.pem

# Restart MySQL to use new certificates
sudo systemctl stop mysqld
sleep 3
sudo -u mysql /usr/local/mysql/bin/mysqld \
  --defaults-file=/etc/my.cnf &
```

---

## References

### Official Documentation

- [MySQL Enterprise Edition](https://www.mysql.com/products/enterprise/)
- [MySQL keyring_okv KMIP Plugin](https://dev.mysql.com/doc/refman/8.4/en/keyring-okv-plugin.html)
- [MySQL Transparent Data Encryption](https://dev.mysql.com/doc/refman/8.4/en/innodb-tablespace-encryption.html)
- [MySQL 8.0 Release Notes](https://dev.mysql.com/doc/relnotes/mysql/8.0/en/)
- [Cosmian KMS Documentation](https://docs.cosmian.com/key_management_system/)
- [KMIP Specification](http://docs.oasis-open.org/kmip/spec/)

### Key Files and Paths

| Component | Path |
|-----------|------|
| MySQL Binary | `/usr/local/mysql/bin/mysqld` |
| MySQL Config | `/etc/my.cnf` |
| Data Directory | `/var/lib/mysql-data/` |
| Error Log | `/var/log/mysql/mysqld.log` |
| Socket File | `/var/run/mysqld/mysqld.sock` |
| KMIP Config | `/usr/local/mysql/mysql-keyring-okv/okvclient.ora` |
| SSL Certificates | `/usr/local/mysql/mysql-keyring-okv/ssl/` |
| Cosmian Config | `/path/to/kms.toml` |
| Cosmian DB | `/path/to/cosmian-kms/sqlite-data/kms.db` |

### Default Credentials (Lab Only)

| User | Password | Scope |
|------|----------|-------|
| root (MySQL) | Set during installation | Local MySQL |
| admin (Cosmian) | Configured in kms.toml | KMS REST API |

**SECURITY NOTE:** Change all default credentials before production use.

---

## Contact and Support

For issues related to:

- **MySQL Enterprise:** [Oracle MySQL Support](https://www.mysql.com/products/enterprise/)
- **Cosmian KMS:** [Cosmian GitHub Issues](https://github.com/Cosmian/kms/issues)
