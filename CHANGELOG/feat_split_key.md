# CHANGELOG — feat/split_key

## Features

### Two-role RBAC (CryptoOfficer / Operator)

Replaces the former `privileged_users` flat list with two FIPS 140-3 aligned roles:

- **`Operator`** (default) — crypto-use ops: Encrypt, Decrypt, Sign, Verify, MAC, Hash, Locate, GetAttributes.
- **`CryptoOfficer`** — key-lifecycle ops + ownership bypass: Create, Import, Certify, Rekey, Activate, Revoke, Destroy, Get, Export, SetAttribute, …
- Unknown users default to `Operator` (fail-secure, NIST SP 800-57 Pt 2 §4.8).
- New `[roles]` TOML section; migration: rename `privileged_users` → `crypto_officer_users` under `[roles]`.

### Split-key ceremony (XOR n-of-n)

`CreateSplitKey` and `JoinSplitKey` KMIP 2.1 (and 1.4) operations implement XOR n-of-n secret sharing:

- Shares tagged `x-cosmian-crypto-officer-ceremony`; each owned by a different CO candidate.
- `JoinSplitKey` with all ceremony shares auto-activates the CO role (writes `crypto_officer_activations`).
- Activation records AES-256-GCM sealed from `ceremony_secret` (hex 32-byte); `ceremony_secret` masked in logs.
- **Optional AES-KW share wrapping** (`ceremony_wrapping_key_id` / `KMS_CEREMONY_WRAP_KEY_ID`): each share encrypted with RFC 5649 before DB write; unwrapped transparently on `JoinSplitKey`. HSM-backed key supported.
- `ceremony_key_id` (`KMS_CEREMONY_KEY_ID`) accepted by config parser for future KMS-object sealing key (ADP-26, not yet functional — use `ceremony_secret` in the meantime).

### Revocation

- **Self-revoke**: active CO calls `POST /access/crypto_officer/disable`.
- **Peer revocation**: any CO candidate calls the same endpoint with `{ "target_user": "<uid>" }` to demote another active CO without server restart (NIST SP 800-152 FR:6.119).

- **`CreateSplitKey` fix**: `ObjectType: SymmetricKey` added as first field in the TTLV request (the field is required/non-`Option` in the server struct); both `SplitKey.tsx` and `CryptoOfficerRole.tsx` previously omitted it, causing a 422 on every submission. Both callers now share a single `buildCreateSplitKeyRequest` helper from `utils/splitKeyUtils.ts`.
- **Compensating delete**: if step 2 (`CreateSplitKey`) fails after step 1 (AES key creation) succeeds, the newly-created key is destroyed before the error is surfaced; this prevents permanent "object already exists" retry failure.
- **Peer-revocation selector**: the logged-in user is now filtered out of the peer-revocation `Select`; self-revoke remains available via the empty selection.
- **External CDN fonts removed**: `@font-face` declarations referencing `fonts.gstatic.com` (Inter URL was 404; Montserrat URL was live but violates air-gapped deployment requirements); falls back to system font stack.

## Security

- Zeroized key material throughout (`Zeroizing<Vec<u8>>`, `Drop` on `CeremonyKeys`).
- **Compensating delete on activation failure**: reconstructed key deleted from DB if auto-activation fails; CRITICAL audit entry if the delete itself fails (prevents bypass via failed ceremony).
- Audit events for `CreateSplitKey`/`JoinSplitKey` elevated to `error!(target="audit")` (CWE-778 mitigation).
- Per-call session UUID stamped on all ceremony audit entries for SIEM correlation.
- DB partial unique index on `activated_by WHERE revoked_at IS NULL` (PostgreSQL/SQLite); application-level guard on MySQL.
- Complete `key_part_identifier` validation: shares must form `{1..=N}` with no duplicates.
- Ceremony candidates exempted from `Create`/`Import` restriction before ceremony completes (prevents bootstrap deadlock).

## CLI

- `ckms access-rights crypto-officer status` — show role config and ceremony state.
- `ckms access-rights crypto-officer disable` — revoke active ceremony.
- New `create-split-key` subcommand under the `crypto-officer` CLI group.

## Web UI

- **Crypto Officer page**: status dashboard (ceremony state, active CO list, custodian count); configurable base key ID with live share-UID preview (`<id>#1`, `<id>#2`…); peer-revocation dropdown (visible to active CO only); ceremony activation form.
- **SplitKey / JoinSplitKey dialogs**: Shamir option removed; only XOR n-of-n supported. "Total Parts" renamed to "Number of Shares". Threshold and method selectors removed.
- **Dark theme**: aligned to mdBook Eviden palette (`#161923` bg, `#bcbdd0` text, `#282d3f` sidebar, orange `#f14611`). `colorPrimary` changed from `#9e6eff` (purple) to `#f14611` (Cosmian brand orange) for brand consistency. Light `colorPrimary` changed from `#e34319` to `#c73f1b` (≥4.5:1 on white, WCAG AA). `colorInfo` (links) raised to `#4fa8d8` (≥4.5:1 on `#161923`). `colorTextSecondary` pinned to `#9fa0b8` to prevent the dark algorithm deriving a low-contrast value (~2.84:1) on the elevated card surface.
- **Sidebar background**: both light and dark modes now use the `--cosmian-sidebar-bg` CSS variable, eliminating the disparity between themes.

## Testing

- 7 ceremony vector tests (2-of-2, 3-of-3 round-trips, failure scenarios, full activate→disable→deny lifecycle).
- 11 RBAC CLI tests (`rbac_tests.rs`): CO/Operator permission matrix per ADR-2026-06-24.
- 7 RBAC E2E tests (`rbac-flow.spec.ts`): UI smoke tests for split-key and CO pages.

## Documentation

- Key ceremony guide: two-role RBAC, XOR n-of-n, NIST references, Mermaid sequence diagrams, CLI quick reference.
- Authorization reference: updated role matrix, operation tables, permission evaluation order.
