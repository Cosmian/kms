# Cosmian KMS Server

The **KMS Server** is the main component of the Cosmian Key Management System, providing secure key management, cryptographic operations, and KMIP protocol support.

## Overview

The KMS server is a high-performance, FIPS 140-3 compliant server application that provides comprehensive key management services. It supports multiple database backends, HSM integration, and offers both REST API and KMIP protocol interfaces.

## Features

### Core Functionality

- **Key Management**: Generate, store, and manage cryptographic keys
- **Certificate Management**: Handle X.509 certificates and PKI operations
- **Cryptographic Operations**: Encryption, decryption, signing, and verification
- **KMIP Protocol**: Full KMIP 1.0-2.1 compliance
- **REST API**: Modern HTTP API for easy integration
- **Web UI**: Browser-based management interface

### Security Features

- **FIPS 140-3 Compliance**: Certified cryptographic modules
- **Multi-Factor Authentication**: Support for various authentication methods
- **Access Control**: Fine-grained permissions and role-based access
- **Audit Logging**: Comprehensive logging of all operations
- **HSM Integration**: Hardware Security Module support

### Compilation Features

The KMS server provides several features which can be enabled at compilation time:

| Feature    | Description                                                                                                         | Development | Production |
| ---------- | ------------------------------------------------------------------------------------------------------------------- | ----------- | ---------- |
| `non-fips` | Enable non-FIPS cryptographic algorithms and features                                                              | ✅          |            |
| `insecure` | Disable authentication and use HTTP (development only)                                                             | ✅          |            |
| `timeout`  | Binary stops after 3 months from compilation date                                                                  |             |            |

**Legend**: ✅ = Recommended for this environment

### Development Mode

For development, you can use `--features insecure` to disable authentication and HTTPS:

```bash
cargo build --features insecure
cargo run --features insecure --
```

This configuration:

- Disables authentication requirements
- Uses HTTP instead of HTTPS
- Suitable for local development only

### Non-FIPS Mode

Enable additional cryptographic algorithms:

```bash
cargo build --features non-fips
cargo run --features non-fips
```

### Timeout Feature

Create a time-limited binary (stops after 3 months):

```bash
cargo build --features timeout
```

## Configuration

The server configuration can be provided through multiple methods (in order of precedence):

- Environment variables
- A dotenv `.env` file at the location where you start the binary
- Command line arguments

The list of parameters, which depends on the compiled features, can be obtained by doing:

```sh
cosmian_kms_server -h
```

A server for development can be quickly run as follow (with sqlite):

```sh
cargo run
```

## Configure the authentication

The KMS server relies on an OAuth2 authentication provided by Auth0 to authenticate the user.

Example of how to run for test authentication:

```sh
KMS_JWT_AUTH_PROVIDER="https://demo-kms.eu.auth0.com" cargo run
```

This authentication enables the KMS to deal with several users with the same database.
If there is no `KMS_JWT_AUTH_PROVIDER` provided, the KMS disables the authentication. Only one user is allowed.
If so, `admin` will be the user id.

## In-depth understanding

### Database

The database is made up of two tables: `objects` et `read_access`.

#### `objects` table

This table is designed to contain the kmip objects. A row is described as:

- `id` which is the index of the kmip object. This value is known by a user and used to retrieve any stored objects
- `object` is the object itself
- `state` could be `PreActive`, `Active`, `Deactivated`, `Compromised`, `Destroyed` or `Destroyed_Compromised`
- `owner` is the external id (email) of the user the object belongs to

#### `read_access` table

Object's owner can allow any other user to perform actions on a given object.

This table describes those actions a specific user is allowed to perform onto the object:

- `id` which is the internal id of the kmip object
- `userid` which is the external id of the user: its email address
- `permissions` is a serialized JSON list containing one or more of the following flags: `Create`, `Get`, `Encrypt`, `Decrypt`, `Import`, `Revoke`, `Locate`, `Rekey`, `Destroy` defining the operation kinds the user is granted

The `userid` field will be used to check authorization by matching the email address contained in the authorization JWT.
