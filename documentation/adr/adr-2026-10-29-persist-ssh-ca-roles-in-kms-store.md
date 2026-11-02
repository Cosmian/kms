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

Persist the configured CA UID, its validated public-key binding, and SSH role policies as reserved records in the existing KMS object store. The records use the internal owner `cosmian-ssh-api-internal` and can only be changed by an active Crypto Officer. SSH signing resolves and binds to the configured key generation, then uses the existing KMS signing path; HSM-backed keys are signed through the crypto oracle. The CA private key is never loaded into the SSH API or returned by it.

The password-generation endpoint remains stateless: it returns a fresh 32-character alphanumeric value generated through `KmsRng`, and neither stores nor logs that value.

Support RSA-SHA2 and NIST ECDSA CA keys in both build variants; allow Ed25519 CA keys only in non-FIPS builds. Unsupported key types and HSM mechanisms fail explicitly.

## Consequences

### Positive

- **POS-001**: CA and role configuration survives restarts and is shared by server instances using the same database.
- **POS-002**: Existing object-store authorization and atomic persistence mechanisms are reused instead of adding backend-specific tables.
- **POS-003**: The selected key generation and public-key binding can be checked before every signing request, preventing silent use of a rotated key.
- **POS-004**: HSM keys remain non-exportable and are signed through the existing crypto-oracle boundary.

### Negative

- **NEG-001**: Reserved object identifiers and a versioned serialization format must be protected from ordinary KMIP and REST object operations.
- **NEG-002**: Database restore and failover procedures also restore the active SSH CA and role configuration.
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

## Implementation Notes

- **IMP-001**: Reserve a collision-resistant UID namespace for SSH configuration and role records; validate serialized records before use.
- **IMP-002**: Require an active Crypto Officer for CA and role updates. Certificate requests must also pass the existing `Sign` authorization for the exact configured CA key.
- **IMP-003**: Validate that the CA public key still matches the configured key generation before issuing a certificate. The public-key endpoint returns the public key captured during configuration; fail closed during signing if the key changes, the HSM is unavailable, or the mechanism is unsupported.
- **IMP-004**: Test persistence across KMS re-instantiation, software and HSM signing, authorization denials, malformed OpenSSH keys, principal/lifetime policy, and successful verification of every issued certificate.
- **IMP-005**: Exercise RSA-SHA2 and NIST ECDSA in both variants, and Ed25519 only in non-FIPS; document the supported set and test unsupported mechanisms fail closed.

## References

- **REF-001**: Issue #864, "Short-lived SSH certificates and externally rotated KV secrets."
- **REF-002**: Issue #863, versioned KV secret storage and access controls.
- **REF-003**: `crate/server/src/core/certificate/oracle_signing.rs`
- **REF-004**: `crate/server/src/core/kms/permissions.rs`
- **REF-005**: `crate/server/src/routes/kv/metadata.rs`
