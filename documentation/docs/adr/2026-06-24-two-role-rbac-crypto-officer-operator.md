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
| `CryptoOfficer` | Create, CreateKeyPair, Import, Certify, Rekey, RekeyKeyPair, Activate, Revoke, Destroy, Get, Export, SetAttribute, ModifyAttribute, AddAttribute, DeleteAttribute, Locate, GetAttributes | ✓ | ✓ |

> **Note — ACL management (`GrantAccess`/`RevokeAccess`/`ListAccesses`)**: these are
> custom server routes, not KMIP operations, and are **owner-scoped**. A CO may
> grant/revoke access on objects they own (like any user), but the CO ownership bypass
> does **not** extend to ACL management on foreign objects. Only the object owner can
> grant or revoke rights on their own objects.

### Split-key ceremony activation (optional)

`CryptoOfficerConfig.require_ceremony = true` defers activation of the ownership bypass
until a KMIP `JoinSplitKey` operation completes with all n shares tagged
`x-cosmian-crypto-officer-ceremony`. This implements NIST SP 800-57 Part 2
Rev 1 §4.6 (dual control / split knowledge) at the module boundary.

**`JoinSplitKey` IS the activation**: when all shares carry
`x-cosmian-crypto-officer-ceremony`, the server writes the `crypto_officer_activations`
record as a side-effect. The dedicated `POST /access/crypto_officer/ceremony/activate`
endpoint is kept for CLI backward compatibility only; the Web UI uses `JoinSplitKey` as
the single activation action.

Share UIDs follow the convention `<base-key-uid>#<part>` (e.g. `ceremony-key-2026#1`).
On `JoinSplitKey` the reconstructed key UID is derived by stripping the `#N` suffix
(ceremony path only; generic splits use a fresh UUID to avoid collisions).

Ceremony activation records are AES-256-GCM encrypted with keys derived from
`KMS_CEREMONY_SECRET`, preventing forgery via direct database writes.
`crypto_officer_activations` is the **sole source of truth** for CO role status — the
`x-cosmian-crypto-officer-ceremony` tag on KMS objects is used only as validation input,
never for privilege checks (prevents privilege escalation via arbitrary tag-setting).

### Revocation

Any configured CO candidate may revoke the active CO's ceremony:

- **Self-revoke**: active CO calls `POST /access/crypto_officer/disable` → 200 OK.
- **Peer revocation**: any CO candidate (in `crypto_officer_users`) calls
  `POST /access/crypto_officer/disable` → revokes the active CO's role immediately.
  The demoted CO's reconstructed key is NOT revoked (they retain it as an Operator).
- **Emergency**: remove user from `crypto_officer_users` in `kms.toml` and restart.

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

## Implementation Notes (as of `feat/split_key`)

- **IMP-001**: `crate/access/src/access.rs` — new `Role` enum with two variants:
  `Operator` and `CryptoOfficer`. New `CryptoOfficerConfig` and `RolesConfig` structs
  replace the former flat `privileged_users` field in `ServerParams`.
- **IMP-002**: `crate/server/src/config/command_line/roles_config.rs` — CLI flags:
  `--crypto-officer-users`, `--crypto-officer-require-ceremony`,
  `--ceremony-secret` (env `KMS_CEREMONY_SECRET`),
  `--ceremony-key-id` (env `KMS_CEREMONY_KEY_ID`, ADP-26 scaffold).
  The former `--privileged-users` flag is removed.
- **IMP-003**: `kms.toml` `[roles]` section with `crypto_officer_users`,
  `crypto_officer_require_ceremony`, `ceremony_secret`.
- **IMP-004**: Migration: move `privileged_users = [...]` into `[roles]`, rename to
  `crypto_officer_users`.
- **IMP-005**: New FIPS test vectors in `test_data/vectors/access_control/` cover the
  role model: `crypto_officer_role_allowed_ops`, `operator_role_blocked_lifecycle`,
  and related privilege-escalation vectors.
- **IMP-006**: `crypto_officer_activations` table is the sole role store.
  The `x-cosmian-crypto-officer-ceremony` tag on KMS objects is validation input only —
  never consulted for privilege decisions — preventing privilege escalation via
  arbitrary tag-setting on objects the attacker controls.
- **IMP-007**: `CreateSplitKey` server-side auto-determines share count from
  `crypto_officer_users.len()` when the source key carries the ceremony tag.
  Each share owned by a different CO candidate (round-robin). UIDs: `<base>#<n>`.
- **IMP-008**: `JoinSplitKey` with all ceremony-tagged shares auto-activates the CO role.
  No separate activation call needed from the Web UI. The dedicated REST endpoint
  `POST /access/crypto_officer/ceremony/activate` is kept for CLI backward compatibility.
- **IMP-009**: Revocation supports self-revoke (active CO) and peer revocation (any other
  CO candidate). The demoted CO's reconstructed key is NOT revoked — only the
  `crypto_officer_activations` row is updated. Peer revocation enables compromise
  recovery without server restart (NIST SP 800-152 FR:6.119).
- **IMP-010**: Share UID naming: `<base-uid>#<part-index>` (e.g. `my-ceremony-key#1`).
  On `JoinSplitKey`, reconstructed key UID = base UID (ceremony path only).

## Future Evolution

A second ADR (`documentation/docs/adr/2026-07-24-multi-domain-split-key-ceremony.md`,
in review as of 2026-07-24) extends this decision into a full multi-domain
architecture. Key changes that directly affect the artefacts introduced here:

| ADP | Status | Impact on this ADR |
|-----|--------|-------------------|
| **ADP-16** | Planned | `[roles]` TOML section removed; CO candidates assigned per-domain in a DB table. Only `KMS_CEREMONY_SECRET` env var survives. IMP-003/IMP-004 migration instructions become a transitional step only. |
| **ADP-20** | **Implemented** | Reconstructed ceremony secret XOR-joined in RAM; reconstructed key stored as KMS object. Secret never stored in cleartext. |
| **ADP-25** | Planned | Server generates the 256-bit ceremony secret internally (random); the operator-supplied `ceremony_secret` TOML field is removed. |
| **ADP-26** | **Scaffolded** | `ceremony_key_id` config field: references a KMS symmetric key as the ceremony sealing key instead of a static hex secret. Enables key rotation and HSM backing. Accepted by the config parser but not yet functional; `ceremony_secret` is required in the meantime. |
| **ADP-3/15** | Planned | CO candidates assigned per-domain; ceremony activates all CO candidates for that domain simultaneously (vs current per-user activation). |

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
