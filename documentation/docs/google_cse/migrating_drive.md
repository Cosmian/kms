# Migrating existing Google Drive encrypted content to a new key service

This guide explains how to migrate encrypted content in Google Drive to a new key management service (KMS), specifically using Cosmian KMS.

For a complete overview of Google's migration flow and all available options, refer to
[Google’s official technical documentation](https://support.google.com/a/answer/12850453#migrate).

## Cosmian KMS migration support and configuration

Cosmian KMS supports the Google Client-Side Encryption (CSE) migration process by implementing the required endpoints, including:

- `POST <KMS_PUBLIC_URL>/google_cse/rewrap`

- `POST <KMS_PUBLIC_URL>/google_cse/privilegedunwrap`

These endpoints allow Cosmian KMS to serve as either the source or target key service during a migration.

## JWT Authentication for Migration

Google’s migration flow requires both key services (KACLS) to authenticate with each other via signed JWTs. To support this:

Cosmian KMS generates a dedicated RSA key pair at startup (if not already present in the database).

- The private key is stored under the ID: `google_cse_rsa`
- The public key is stored under the ID: `google_cse_rsa_pk`

## Key Persistence Across Restarts & Multiple Instances

To ensure consistent JWT signatures and seamless privileged unwrap operations across multiple instances or restarts, you can
manually provide a persistent RSA private key using the --google-cse-migration-key CLI option.

This key must be in PEM-encoded PKCS#8 format.

## Public Key Exposure

To allow other KACLS to verify JWT signatures, Cosmian KMS exposes its public RSA key at:

- `GET <KMS_PUBLIC_URL>/google_cse/certs`

This endpoint serves a JWKS (JSON Web Key Set) containing the public signing key.
