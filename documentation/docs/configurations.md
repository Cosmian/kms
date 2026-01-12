# Configuration Examples

This page provides a comprehensive collection of TOML configuration file examples for the Cosmian KMS server. Each configuration has been validated and tested to ensure it works correctly with the KMS server.

All configuration examples can be used by:

1. Saving the content to a file (e.g., `kms.toml`)
2. Starting the server with: `cosmian_kms_server -c kms.toml` or using the environment variable `COSMIAN_KMS_CONF=kms.toml`

For complete documentation on all available configuration options, see the [Configuration file](server_configuration_file.md) reference.

## Quick Start Configurations

### [basic-http](#basic-http) {#basic-http}

Basic HTTP server configuration with default settings.

```toml
# Basic HTTP configuration
[http]
port = 9998
hostname = "0.0.0.0"
```

**Use case:** Development, testing, or internal networks where TLS is not required.

---

## Authentication Configurations

### [jwt-auth](#jwt-auth) {#jwt-auth}

JWT authentication using Google as the identity provider.

```toml
# JWT authentication configuration using idp_auth format
[idp_auth]
# issuer,jwks[,aud1[,aud2...]] (jwks & audiences optional; any-of when multiple)
jwt_auth_provider = ["https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,cosmian_kms,another_client_id"]
```

**Use case:** Authenticate users with Google Identity tokens, suitable for organizations using Google Workspace.

---

### [api-token-auth](#api-token-auth) {#api-token-auth}

API token authentication using a symmetric key.

```toml
# API token authentication configuration
[http]
api_token_id = "test-symmetric-key-id"
```

**Use case:** Service-to-service authentication or when using a pre-shared symmetric key for authentication.

---

### [tls-client-cert](#tls-client-cert) {#tls-client-cert}

TLS client certificate authentication with mutual TLS.

```toml
# TLS Client Certificate Authentication
[tls]
# For FIPS mode (default build):
tls_cert_file = "certificates/server.crt"
tls_key_file = "certificates/server.key"
clients_ca_cert_file = "certificates/ca.crt"

# For non-FIPS mode:
# tls_p12_file = "certificates/server.p12"
# tls_p12_password = "password"
# clients_ca_cert_file = "certificates/ca.crt"
```

**Use case:** High-security environments requiring mutual TLS authentication with client certificates.

---

### [multifactor-tls-jwt](#multifactor-tls-jwt) {#multifactor-tls-jwt}

Multi-factor authentication combining TLS client certificates and JWT tokens.

```toml
# Multi-factor TLS + JWT authentication (idp_auth format)
[tls]
# For FIPS mode (default build):
# tls_cert_file = "certificates/server.crt"
# tls_key_file = "certificates/server.key"
# clients_ca_cert_file = "certificates/ca.crt"

# For non-FIPS mode:
tls_p12_file = "certificates/server.p12"
tls_p12_password = "password"
clients_ca_cert_file = "certificates/ca.crt"

[idp_auth]
# Empty audience example: no audiences after JWKS URL (audience check skipped)
jwt_auth_provider = ["https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,"]
```

**Use case:** Maximum security environments requiring both certificate and token-based authentication.

---

### [multifactor-jwt-api](#multifactor-jwt-api) {#multifactor-jwt-api}

Multi-factor authentication combining JWT tokens and API token authentication.

```toml
# Multi-factor JWT + API token authentication (idp_auth format)
[idp_auth]
# Multiple audiences example (any-of)
jwt_auth_provider = ["https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,frontend,cli"]

[http]
api_token_id = "test-symmetric-key-id"
```

**Use case:** Flexible authentication allowing both user JWT tokens and service API tokens.

---

## Database Configurations

### [mysql-database](#mysql-database) {#mysql-database}

MySQL database configuration for production deployments.

```toml
# MySQL database configuration
[db]
database_type = "mysql"
database_url = "mysql://kms_user:kms_password@mysql-server:3306/kms"
```

**Use case:** Production deployments requiring a robust, scalable database backend.

---

### [mysql-with-cert](#mysql-with-cert) {#mysql-with-cert}

MySQL database with client certificate authentication.

```toml
# MySQL database configuration with client certificate
[db]
database_type = "mysql"
database_url = "mysql://mysql_server:3306/kms"
# Note: Configure client certificate via command-line option:
# --mysql-user-cert-file cert.p12
```

**Use case:** MySQL deployments requiring certificate-based database authentication.

---

### [postgresql-database](#postgresql-database) {#postgresql-database}

PostgreSQL database configuration for production deployments.

```toml
# PostgreSQL database configuration
[db]
database_type = "postgresql"
database_url = "postgres://kms_user:kms_password@postgres-server:5432/kms"
```

**Use case:** Production deployments requiring strong reliability, advanced SQL features, and horizontal scaling options.

---

### [sqlite-database](#sqlite-database) {#sqlite-database}

Lightweight embedded SQLite configuration (default when no DB settings are provided).

```toml
# SQLite database configuration (default path)
[db]
database_type = "sqlite"
sqlite_path = "./sqlite-data"  # Defaults to ./sqlite-data
# clear_database = false         # Set to true to wipe the DB on each start (DANGEROUS)
```

**Use case:** Local development, testing, or small single-instance deployments where simplicity outweighs concurrency needs.

---

### [redis-findex-database](#redis-findex-database) {#redis-findex-database}

Redis with Findex encrypted data and searchable indexes (non-FIPS build only).

```toml
# Redis Findex database configuration (non-FIPS feature)
[db]
database_type = "redis-findex"
database_url = "redis://redis-server:6379"
redis_master_password = "change_me_master_password"   # Master password derives encryption key
redis_findex_label = "v1"                             # Rotation label (change to re-encrypt indexes)
```

**Use case:** Environments requiring encrypted server-side indexes and low-latency lookups with application-level protection.

---

## Google Workspace CSE Configuration

### [google-cse](#google-cse) {#google-cse}

Complete Google Workspace Client-Side Encryption setup.

```toml
# Google CSE configuration
kms_public_url = "http://localhost:9998"

# JWT authentication with Google
[idp_auth]
jwt_auth_provider = ["https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,"]

# Google CSE configuration
[google_cse_config]
google_cse_enable = true
```

**Use case:** Enabling Google Workspace Client-Side Encryption for Gmail and Drive.

---

## Logging and Monitoring Configurations

### [otlp-logging](#otlp-logging) {#otlp-logging}

OpenTelemetry (OTLP) logging configuration with Jaeger integration.

```toml
# OTLP logging configuration
[logging]
otlp = "http://localhost:4317"
quiet = true
```

**Use case:** Centralized logging and distributed tracing with OpenTelemetry-compatible systems.

---

### [file-logging](#file-logging) {#file-logging}

Rolling file logging configuration.

```toml
# Rolling file logging
[logging]
rolling_log_dir = "/var/log/cosmian"
rolling_log_name = "kms"
rust_log = "info,cosmian_kms_server=debug"
```

**Use case:** Production deployments requiring persistent log files with rotation.

---

### [syslog-logging](#syslog-logging) {#syslog-logging}

System logging configuration for Linux systems.

```toml
# Syslog logging
[logging]
log_to_syslog = true
quiet = true
rust_log = "warn,cosmian_kms_server=info"
```

**Use case:** Integration with system logging infrastructure on Linux servers.

---

## Production Configurations

### [production-https](#production-https) {#production-https}

Complete production configuration with HTTPS, authentication, and MySQL.

```toml
# Production HTTPS configuration
kms_public_url = "https://kms.example.com"

[http]
port = 443
hostname = "0.0.0.0"

[tls]
# For FIPS mode (default build):
# tls_cert_file = "/etc/ssl/kms/server.crt"
# tls_key_file = "/etc/ssl/kms/server.key"

# For non-FIPS mode:
tls_p12_file = "/etc/ssl/kms/server.p12"
tls_p12_password = "secure_password"

[idp_auth]
jwt_auth_provider = ["https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,kms.example.com"]

[db]
database_type = "mysql"
database_url = "mysql://kms_user:secure_password@mysql.internal:3306/kms"

[logging]
rolling_log_dir = "/var/log/cosmian"
rust_log = "warn,cosmian_kms_server=info"
```

**Use case:** Full production deployment with security, scalability, and monitoring.

---

### [ui-load-balanced](#ui-load-balanced) {#ui-load-balanced}

Production configuration exposing the Web UI behind a load balancer, with deterministic session cookies across KMS instances.

```toml
# Public URL exposed by the load balancer
kms_public_url = "https://kms-ui.example.com"

[http]
port = 9998
hostname = "0.0.0.0"

# UI configuration: static assets served from this folder
[ui_config]
ui_index_html_folder = "./ui/dist"

# Session salt used to derive the UI session cookie encryption key.
# This value MUST be identical across all KMS instances behind the
# same load balancer so any instance can decrypt the UI session cookie.
ui_session_salt = "change-me-and-keep-secret"

[logging]
rust_log = "info,cosmian_kms_server=info"
```

**Use case:** Web UI deployments behind a load balancer where UI session cookies must remain valid across all KMS instances.

---

### [ha-cluster](#ha-cluster) {#ha-cluster}

High-availability cluster configuration.

```toml
# High-availability cluster configuration
kms_public_url = "https://kms-cluster.example.com"

[http]
port = 9998
hostname = "0.0.0.0"

[tls]
# For FIPS mode (default build):
# tls_cert_file = "/etc/ssl/kms/server.crt"
# tls_key_file = "/etc/ssl/kms/server.key"

# For non-FIPS mode:
tls_p12_file = "/etc/ssl/kms/server.p12"
tls_p12_password = "cluster_password"

[db]
database_type = "postgresql"
database_url = "postgres://kms_user:password@postgres-cluster:5432/kms"

[logging]
otlp = "http://jaeger-collector:4317"
rust_log = "info,cosmian_kms_server=info"
```

**Use case:** High-availability deployments with load balancing and shared database.

---

## Specialized Configurations

### [redis-findex](#redis-findex) {#redis-findex}

Redis with Findex configuration for encrypted storage.

```toml
# Redis with Findex configuration
[db]
database_type = "redis-findex"
database_url = "redis://redis-server:6379"
redis_master_password = "secure_master_password"
redis_findex_label = "production_label"

[logging]
rust_log = "info,cosmian_kms_server=info,cosmian_findex_client=debug"
```

**Use case:** Zero-trust environments with application-level encryption of database contents.

---

### [hsm-integration](#hsm-integration) {#hsm-integration}

Hardware Security Module (HSM) integration.

```toml
# HSM integration configuration
[hsm]
pkcs11_library = "/usr/lib/libpkcs11.so"
slot_number = 1
pin = "hsm_user_pin"

[logging]
rust_log = "info,cosmian_kms_server=info"
```

**Use case:** Hardware-backed key protection using PKCS#11 compatible HSMs.

---

### [key-wrapping](#key-wrapping) {#key-wrapping}

Automatic key wrapping with a Key Encryption Key (KEK) and selective automatic unwrapping.

```toml
# Key wrapping configuration
# Force all newly created and imported keys to be wrapped by the specified KEK
key_encryption_key = "hsm-kek-id"

# Automatically unwrap specific object types when retrieved
default_unwrap_type = ["SymmetricKey", "SecretData"]

[logging]
rust_log = "info,cosmian_kms_server=info"
```

**Use case:** Ensure all keys in the KMS database are wrapped by an HSM key for enhanced security.
The server transparently unwraps keys when needed, caching them in memory without storing clear-text keys in the database.
Commonly used with HSM integration to protect all KMS keys with a master KEK stored in the HSM. The cache expires after a configurable duration (default 15 minutes).

---

### [development-debug](#development-debug) {#development-debug}

Development configuration with detailed debugging.

```toml
# Development debugging configuration
[http]
port = 9998
hostname = "127.0.0.1"

[logging]
rust_log = "debug,cosmian_kms_server=trace,actix_web=debug"
```

**Use case:** Development and troubleshooting with maximum logging detail.

---

## Testing Configurations

### [integration-test](#integration-test) {#integration-test}

Configuration for integration testing environments.

```toml
# Integration testing configuration
[http]
port = 19998
hostname = "127.0.0.1"

[db]
database_type = "sqlite"
sqlite_path = "./test-sqlite-data"
cleanup_on_startup = true

[logging]
quiet = true
rust_log = "error"
```

**Use case:** Automated testing environments with isolated database and minimal logging.

---

## Related Documentation

- [Configuration file reference](server_configuration_file.md) - Complete parameter documentation
- [Command line arguments](server_cli.md) - CLI options reference
- [Authentication](authentication.md) - Detailed authentication setup
- [Database configuration](database.md) - Database backend options
- [TLS configuration](tls.md) - TLS and certificate setup
- [Logging](logging.md) - Logging and monitoring options
