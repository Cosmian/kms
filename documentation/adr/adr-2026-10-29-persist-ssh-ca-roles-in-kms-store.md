---
title: "ADR-2026-10-29: Persist SSH CA and roles in the KMS object store"
status: "Accepted"
date: "2026-10-29"
authors: "KMS maintainers, operators, and security reviewers"
tags: ["architecture", "decision", "ssh", "key-management"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-10-29: Persist SSH CA and roles in the KMS object store

## Status

Accepted

## Context

Issue #864 adds authenticated management endpoints for an SSH certificate authority and its signing roles. The selected CA is an existing KMS-managed private key, which may be software-backed or resident in an HSM. The CA selection and role policy must survive server restarts and be consistent across KMS instances sharing a database. The private key must remain governed by the existing KMS key permissions and must never be exported for SSH signing.

The KMS already provides a database-backed object store with ownership, authorization, and atomic updates. Adding dedicated tables would require schema and migration work across every database backend.

The SSH certificate issuer also needs a well-defined CA algorithm set. The issue does not prescribe one, so the implementation should follow the KMS's existing algorithm and feature-gate policy.

## Decision

Persist the configured CA UID, its validated public-key binding, and SSH role policies as reserved records in the existing KMS object store. The records use the internal owner `cosmian-ssh-api-internal`, carry the `_ssh_api` tag, and can only be changed by an active Crypto Officer. Their UIDs are not a public namespace: KMIP clients choose the UIDs of the objects they create, so a predictable UID could be occupied beforehand. Each UID is the first 16 bytes of an HMAC-SHA256, under a domain-separated server-internal key, of the record name (`ca`, `role:<name>`). That key is generated once from `KmsRng` and stored in the database `parameters` table, which no KMIP operation can read or write, so every instance sharing the database derives the same UIDs. SSH signing resolves and binds to the configured key generation, then uses the existing KMS signing path; HSM-backed keys are signed through the crypto oracle. The CA private key is never loaded into the SSH API or returned by it.

The password-generation endpoint remains stateless: it returns a fresh 32-character alphanumeric value generated through `KmsRng`, and neither stores nor logs that value.

Support RSA-SHA2 and NIST ECDSA CA keys in both build variants; allow Ed25519 CA keys only in non-FIPS builds. Unsupported key types and HSM mechanisms fail explicitly.

## Consequences

### Positive

- **POS-001**: CA and role configuration survives restarts and is shared by server instances using the same database.
- **POS-002**: Existing object-store authorization and atomic persistence mechanisms are reused instead of adding backend-specific tables.
- **POS-003**: The selected key generation and public-key binding can be checked before every signing request, preventing silent use of a rotated key.
- **POS-004**: HSM keys remain non-exportable and are signed through the existing crypto-oracle boundary.
- **POS-005**: A KMIP client cannot pre-create, overwrite or deny the SSH records, because it cannot compute their UIDs. The same server key derives the KV store's metadata UIDs (`routes/kv/metadata.rs`).

### Negative

- **NEG-001**: A versioned serialization format must be protected from ordinary KMIP and REST object operations; the records rely on the secret UID derivation, the reserved owner and the `_ssh_api` tag, and every read re-checks owner, state, object type and tag.
- **NEG-002**: Database restore and failover procedures also restore the active SSH CA and role configuration, and must restore the `parameters` table with it: without the server UID key, the existing records can no longer be located.
- **NEG-003**: Operators must explicitly configure a key and role policy before certificates can be issued.

## Alternatives Considered

### Server configuration file

- **ALT-001 Description**: Store the CA UID and role policies in the server TOML configuration.
- **ALT-002 Rejection Reason**: The issue specifies runtime management endpoints; file-based updates would require restart/deployment coordination and could diverge between instances.

### Dedicated database tables

- **ALT-003 Description**: Add SSH-specific configuration and role tables to every supported database backend.
- **ALT-004 Rejection Reason**: This duplicates the existing durable, authorized object-store capability and increases migration and backend-maintenance burden without a requirement for relational querying.

### Exportable or externally managed CA key

- **ALT-005 Description**: Generate an SSH CA private key in the route or accept private-key bytes from an administrator.
- **ALT-006 Rejection Reason**: This violates the requirement to use an existing KMS-managed key, breaks HSM non-exportability, and bypasses existing key authorization and signing controls.

### Predictable reserved UID namespace

- **ALT-007 Description**: Store the records at fixed or publicly derivable UIDs (for example a hash of the record name) under a reserved prefix.
- **ALT-008 Rejection Reason**: KMIP clients may choose the UID of the objects they create, so any client that can compute the UID can occupy it first and block the SSH configuration. The test `preclaimed_public_record_uid_does_not_block_configuration` covers a client that pre-claims the former unkeyed UID.

## Implementation Notes

- **IMP-001**: Derive each record UID with `record_uid` (HMAC-SHA256 under `KMS::internal_uid_key`, domain `cosmian-kms-ssh-record-v2:`); the key is created on first use and stored in the `parameters` table as `kv_metadata_uid_key`. Validate owner, state, object type, tag and serialized content before using a record.
- **IMP-002**: Require an active Crypto Officer with the `Sign` permission, who also owns (or may grant) the key, to configure the CA. Configuring it delegates the key's `Sign` right to the internal authority `SSH_RECORD_OWNER` and checks that the authority resolves the same public key. Role users are never granted `Sign` on the CA key: `authorize_role` (`routes/ssh/mod.rs`) lets a role's `allowed_users`, or an active Crypto Officer, request a certificate, and the certificate is signed as the internal authority. A missing and a denied role answer identically. Role checks (`allowed_principals`, `max_ttl`) are a role user's only path to a certificate; anyone granted raw `Sign` on the key bypasses them.
- **IMP-003**: Validate that the CA public key still matches the configured key generation before issuing a certificate. The public-key endpoint returns the public key captured during configuration; fail closed during signing if the key changes, the HSM is unavailable, or the mechanism is unsupported.
- **IMP-004**: Test persistence across KMS re-instantiation, software and HSM signing, authorization denials, malformed OpenSSH keys, principal/lifetime policy, and successful verification of every issued certificate.
- **IMP-005**: Exercise RSA-SHA2 and NIST ECDSA in both variants, and Ed25519 only in non-FIPS; document the supported set and test unsupported mechanisms fail closed.

## References

- **REF-001**: Issue #864, "Short-lived SSH certificates and externally rotated KV secrets."
- **REF-002**: Issue #863, versioned KV secret storage and access controls.
- **REF-003**: `crate/server/src/core/certificate/oracle_signing.rs`
- **REF-004**: `crate/server/src/core/kms/permissions.rs`
- **REF-005**: `crate/server/src/routes/kv/metadata.rs`
- **REF-006**: `crate/server/src/routes/ssh/storage.rs`
- **REF-007**: `crate/server/src/core/kms/mod.rs` (`KMS::internal_uid_key`)
- **REF-008**: `documentation/docs/configuration/secret_backends.md#internal-record-identifiers`
- **REF-009**: `crate/server/src/routes/ssh/mod.rs` (`configure_ca`, `authorize_role`, `sign`)
