# Migrating existing Google Drive encrypted content to a new key service

This guide explains how to migrate encrypted content in Google Drive to a new key management service (KMS), specifically using Eviden KMS.

For a complete overview of Google's migration flow and all available options, refer to
[Google's official technical documentation](https://support.google.com/a/answer/12850453#migrate).

## Eviden KMS migration support and configuration

Eviden KMS supports the Google Client-Side Encryption (CSE) migration process by implementing the required endpoints, including:

- `POST <KMS_PUBLIC_URL>/google_cse/rewrap`

- `POST <KMS_PUBLIC_URL>/google_cse/privilegedunwrap`

These endpoints allow Eviden KMS to serve as either the source or target key service during a migration.

## JWT Authentication for Migration

Google's migration flow requires both key services (KACLS) to authenticate with each other via signed JWTs. To support this:

Eviden KMS generates a dedicated RSA key pair at startup (if not already present in the database).

- The private key is stored under the ID: `google_cse_rsa`
- The public key is stored under the ID: `google_cse_rsa_pk`

Note: the JWT tokens MUST have their audience set to `kacls-migration`.

## Accepting migrations from another KACLS

The KACLS that currently holds the data (the original KACLS) accepts a migration on `privilegedunwrap` only from the
KACLS URLs listed in `google_cse_incoming_url_whitelist` (`--google-cse-incoming-url-whitelist`). Its token is verified
against the keys published by the whitelisted KACLS at `<url>/certs`, and it is accepted only when:

- its audience contains `kacls-migration`;
- its `kacls_url` claim is the URL of this KACLS (`<KMS_PUBLIC_URL>/google_cse`); the claim is mandatory;
- its `resource_name` claim equals the `resource_name` of the request.

A whitelisted KACLS token is a migration token only: it is never accepted by the other CSE endpoints nor by the KMIP API.

## Privileged endpoints and `google_cse_privileged_users`

`privilegedwrap`, `privilegedunwrap` and `privilegedprivatekeydecrypt` skip the document access control. Besides the
migration tokens above (`privilegedunwrap` only, since they carry no user identity), they accept the identity-provider
tokens of the users listed in `google_cse_privileged_users` (`--google-cse-privileged-users`,
`KMS_GOOGLE_CSE_PRIVILEGED_USERS`), matched case-insensitively on the `google_email` or, when absent, the `email` claim.
The option is empty by default: no user can then call these endpoints and a migration uses a whitelisted KACLS token.

## Key Persistence Across Restarts & Multiple Instances

To ensure consistent JWT signatures and seamless privileged unwrap operations across multiple instances or restarts, you can
manually provide a persistent RSA private key using the --google-cse-migration-key CLI option.

This key must be in PEM-encoded PKCS#8 format.

## Public Key Exposure

To allow other KACLS to verify JWT signatures, Eviden KMS exposes its public RSA key at:

- `GET <KMS_PUBLIC_URL>/google_cse/certs`

This endpoint serves a JWKS (JSON Web Key Set) containing the public signing key.
