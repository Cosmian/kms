---
title: "ADR-2026-06-24: Introduce two-role RBAC (CryptoOfficer and Operator), replacing privileged_users"
status: "Accepted"
date: "2026-06-24"
authors: "security architects, KMS contributors"
tags: ["architecture", "decision", "security", "rbac", "fips"]
supersedes: ""
superseded_by: "2026-07-24-multi-domain-split-key-ceremony (planned)"
---

## Status

Accepted

## Context

Before this change the Cosmian KMS had no formal named roles.
Access control was implemented through a single flat list called `privileged_users`,
configured via `--privileged-users` (CLI) or `privileged_users =` in `kms.toml`.

Users in `privileged_users`:

- could create and import objects (the `Create` / `Import` lifecycle operations)
- could grant the `Create` access right to other users

All other authenticated users could only invoke operations on objects they had been
explicitly granted access to; there was no named "Operator" concept, no ownership
bypass, no Auditor or Administrator role of any kind.

Three problems drove this decision:

1. **Standards compliance gap.** ISO/IEC 19790:2012 §7.4 (incorporated verbatim by
   FIPS 140-3) mandates exactly two roles in a cryptographic module: **Crypto Officer**
   and **User** (here called Operator). The `privileged_users` list is an un-named
   capability bundle with no normative basis in the FIPS module boundary, creating
   ambiguity in compliance audits.

2. **Permission granularity.** `privileged_users` conflated two distinct concerns in a
   single undifferentiated list: key-lifecycle capability (Create, Import) and
   access-delegation capability (granting the Create right to others). It provided no
   way to separate crypto-use operations (Encrypt, Decrypt, Sign…) from key-management
   operations, and conferred no ownership-bypass for cross-object administration.

3. **No split-key ceremony path.** There was no mechanism to enforce dual control /
   split knowledge (NIST SP 800-57 Part 2 Rev 1 §4.6) for key-lifecycle operations.
   Any user listed in `privileged_users` gained full capability immediately, with no
   option for a m-of-n quorum activation ceremony at the module boundary.

## Decision

Replace `privileged_users` with two formal FIPS-aligned roles. The new server-level
`RolesConfig` struct contains a single `CryptoOfficerConfig` entry. Users not listed
in any role default to `Operator` (fail-secure per NIST SP 800-57 Part 2 Rev 1 §4.8).

### Role matrix

| Role | Allowed operations | Ownership bypass | Key material access |
|---|---|---|---|
| `Operator` | Encrypt, Decrypt, Sign, SignatureVerify, MAC, Hash, Locate, GetAttributes, Query | ✗ | ✗ |
| `CryptoOfficer` | Create, CreateKeyPair, Import, Certify, Rekey, RekeyKeyPair, Activate, Revoke, Destroy, Get, Export, SetAttribute, ModifyAttribute, AddAttribute, DeleteAttribute, GrantAccess, RevokeAccess, Locate, GetAttributes | ✓ | ✓ |

### Split-key ceremony activation (optional)

`CryptoOfficerConfig.require_ceremony = true` defers activation of the ownership bypass
until a KMIP `JoinSplitKey` operation with at least `threshold` shares tagged
`x-cosmian-crypto-officer-ceremony` completes. This implements NIST SP 800-57 Part 2
Rev 1 §4.6 (dual control / split knowledge) directly within the module boundary without
requiring external tooling.

Ceremony activation records are AES-256-GCM encrypted with keys derived from
`KMS_CEREMONY_SECRET`, preventing forgery via direct database writes.

### Audit and advanced RBAC

For deployments requiring finer-grained audit roles (`Auditor`, `DomainAdmin`,
`SuperAdmin`, `User`) or cross-domain isolation, the OPA integration path
(`--opa-server-url`) is the recommended mechanism. The `test_data/opa/kms.rego`
reference policy fully implements those roles with documented normative references.

## Consequences

### Positive

- **POS-001**: Exact alignment with ISO/IEC 19790:2012 §7.4 / FIPS 140-3 two-role
  module model — simplifies compliance audit evidence.
- **POS-002**: Configuration is normatively grounded: the new `[roles]` section maps
  directly to the two FIPS module roles. The former `privileged_users` flat list is
  replaced by `crypto_officer_users` with explicit, documented permission semantics.
- **POS-003**: `RolesConfig` is trivially correct — a single `CryptoOfficerConfig`
  with no cross-role consistency checks to maintain.
- **POS-004**: Test vectors now cover both role paths explicitly (`crypto_officer_role_*`
  and `operator_role_*`) giving clear behavioral contracts for each role.
- **POS-005**: Ceremony activation is a first-class CryptoOfficer feature built
  directly into `CryptoOfficerConfig` — operators see one cohesive ceremony flow.

### Negative

- **NEG-001**: Deployments using `privileged_users` must migrate: the config key must
  be renamed to `crypto_officer_users` (under the new `[roles]` section) and the
  `--privileged-users` CLI flag replaced with `--crypto-officer-users`. Servers with
  old configs will emit a parse error on startup.
- **NEG-002**: There is no built-in Auditor role. Deployments requiring compliance
  reporting or read-only audit access must use the OPA integration path
  (`--opa-server-url`) with the reference policy in `test_data/opa/kms.rego`.
- **NEG-003**: The OPA path requires an external sidecar; teams without OPA must rely
  on database-level or application-level audit logs for auditor-style access control.

## Alternatives Considered

### Keep privileged_users unchanged

- **ALT-001 Description**: Retain `privileged_users` as the sole access-control
  mechanism, possibly adding documentation mapping it to the Crypto Officer concept.
- **ALT-002 Rejection Reason**: The flag name carries no normative meaning, making
  compliance audit evidence weaker. It also cannot express the Operator/CryptoOfficer
  operation split, and provides no hook for a split-key ceremony. Any FIPS 140-3
  validation requires two named roles at the module boundary.

### Rename privileged_users without introducing named roles

- **ALT-003 Description**: Rename the config key to `crypto_officer_users` but keep
  the same undifferentiated permission bundle without a formal Operator role or
  ceremony mechanism.
- **ALT-004 Rejection Reason**: Loses the explicit operation-level separation between
  key-management (CryptoOfficer) and key-use (Operator), and loses the split-knowledge
  activation path required by NIST SP 800-57 Part 2 Rev 1 §4.6 for environments that
  mandate dual control on key lifecycle operations.

### Delegate all role management to OPA

- **ALT-005 Description**: Remove all built-in role enforcement; make OPA the sole
  arbiter of every operation.
- **ALT-006 Rejection Reason**: Forces every deployment — including simple single-user
  or air-gapped scenarios — to run an OPA sidecar. The two mandatory FIPS roles must be
  enforceable at the module boundary without external dependencies.

## Implementation Notes

- **IMP-001**: `crate/access/src/access.rs` — new `Role` enum with two variants:
  `Operator` and `CryptoOfficer`. New `CryptoOfficerConfig` and `RolesConfig` structs
  replace the former flat `privileged_users` field in `ServerParams`.
- **IMP-002**: `crate/server/src/config/command_line/roles_config.rs` — new CLI flags:
  `--crypto-officer-users`, `--crypto-officer-require-ceremony`,
  `--crypto-officer-total-parts`, `--ceremony-secret` (env `KMS_CEREMONY_SECRET`).
  The former `--privileged-users` flag is removed.
- **IMP-003**: `kms.toml` gains a new `[roles]` section accepting `crypto_officer_users`
  and related ceremony fields. The top-level `privileged_users` key is removed; servers
  with configs containing `privileged_users` will emit a parse error on startup.
  *Note: the planned multi-domain evolution (ADP-16, see Future Evolution below) will
  remove the `[roles]` TOML section entirely; `KMS_CEREMONY_SECRET` will be the only
  ceremony-related configuration.*
- **IMP-004**: Migration path: in every `kms.toml`, move `privileged_users = [...]` into
  a `[roles]` section and rename the key to `crypto_officer_users`.
- **IMP-005**: New FIPS test vectors in `test_data/vectors/access_control/` cover the
  role model: `crypto_officer_role_allowed_ops`, `operator_role_blocked_lifecycle`,
  and related privilege-escalation vectors. These are registered in
  `crate/test_kms_server/src/vector_runner.rs`.
- **IMP-006**: Security property — during `JoinSplitKey` the server holds the
  reconstructed ceremony secret momentarily in process RAM. The reconstructed key is
  stored as a managed object; the activation record carries its SHA-256 fingerprint.
  The planned multi-domain evolution (ADP-20) will zeroize the secret after
  verification, so it is **never stored**.

## Future Evolution

A second ADR (`documentation/docs/adr/2026-07-24-multi-domain-split-key-ceremony.md`,
in review as of 2026-07-24) extends this decision into a full multi-domain
architecture. Key changes that directly affect the artefacts introduced here:

| ADP | Impact on this ADR |
|-----|-------------------|
| **ADP-16** | `[roles]` TOML section removed; CO candidates assigned per-domain in a DB table. Only `KMS_CEREMONY_SECRET` env var survives. IMP-003/IMP-004 migration instructions become a transitional step only. |
| **ADP-20** | Reconstructed ceremony secret hash-verified then zeroized in RAM — never stored. Improves on the current model where the reconstructed key becomes a managed object. |
| **ADP-25** | Server generates the 256-bit ceremony secret internally (random); the operator-supplied `ceremony_secret` TOML field is removed. |
| **ADP-3/15** | CO candidates assigned per-domain; ceremony activates all CO candidates for that domain simultaneously (vs current per-user activation). |

Until that ADR is merged, the `[roles]` TOML section and the `--crypto-officer-users`
CLI flag described in IMP-002/IMP-003 remain the authoritative configuration surface.

## References

- **REF-001**: ISO/IEC 19790:2012 §7.4 — Crypto module role definitions (incorporated
  by FIPS 140-3)
- **REF-002**: NIST SP 800-57 Part 2 Rev 1 §4.6 — Dual control / split knowledge;
  §4.8 — Access control and need-to-know
- **REF-003**: PKCS#11 v3.0 — `CKU_SO` (Security Officer) and `CKU_USER`
- **REF-004**: ANSI/INCITS 359-2004 §4.2 — Hierarchical and Constrained RBAC models
- **REF-005**: `crate/access/src/access.rs` — `Role` enum and `RoleConfig` struct
- **REF-006**: `crate/server/src/config/command_line/roles_config.rs` — CLI flags
- **REF-007**: `test_data/opa/kms.rego` — Reference OPA policy with full 5-role model
  (`SuperAdmin`, `DomainAdmin`, `CryptoOfficer`, `Auditor`, `User`) for advanced deployments
- **REF-008**: `documentation/docs/configuration/key_ceremony.md` — ceremony walkthrough
