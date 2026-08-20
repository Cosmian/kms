# CHANGELOG — feat/split_key

## Features — Key Ceremony (XOR n-of-n split knowledge)

- **Split-key ceremony for Crypto Officer role** (NIST SP 800-57 Part 2 Rev 1 §4.6 split knowledge):
  `CreateSplitKey` and `JoinSplitKey` KMIP 2.1 operations implement XOR-based secret sharing.
  All $n$ shares are required to reconstruct; threshold always equals total parts (n-of-n scheme).
- **Config-driven ceremony**: `[roles]` section gains `crypto_officer_require_ceremony`, `ceremony_secret`
  (hex-encoded 32-byte AES-256 key for GCM sealing), `crypto_officer_users`. When enabled, ceremony
  candidates are inactive until all shares are joined via `JoinSplitKey`.
- **Automatic share tagging**: shares created by ceremony candidates carry `x-cosmian-crypto-officer-ceremony`
  vendor attribute tag for automatic ceremony detection.
- **Active record management**: `crypto_officer_activations` table persists ceremony records with
  sealed payload (AES-256-GCM via KDF-derived keys), activated\_by/participants/key\_hash tracking,
  revoke support with `revoked_at`/`revoked_by`.

## Security Improvements

- **Zeroization of key material**: `xor_split` / `xor_join` now use `Zeroizing<Vec<u8>>` throughout;
  heap memory wiped on drop. Shares consumed via `into_iter()` (no clone), leaving a single
  zeroized copy. Derived `CeremonyKeys.obfuscation_key` zeroed on drop via explicit `Drop` impl.
- **`ceremony_secret` never logged**: custom `Debug` impl for `RolesConfig` masks `ceremony_secret`
  as `"<redacted>"`; prevents secret exposure when `RUST_LOG=debug`.
- **Compensating delete on activation failure**: `JoinSplitKey` now deletes the reconstructed
  key from the DB when ceremony auto-activation fails, then returns the error.  Previously the failure
  was non-fatal and the key persisted without an activation record — any user holding a Grant on the
  resulting UID could access it, bypassing ceremony dual-control.  A second CRITICAL audit entry is
  emitted if the compensating delete itself fails, enabling SIEM alerting.
- **Optional AES-KW share wrapping at rest**: new config field `ceremony_wrapping_key_id`
  (CLI `--ceremony-wrapping-key-id` / env `KMS_CEREMONY_WRAP_KEY_ID`).  When set, `CreateSplitKey`
  wraps each share's bytes with the referenced AES key using RFC 5649 (NIST SP 800-38F) before writing
  to the DB.  `JoinSplitKey` detects the `x-cosmian-share-wrapping-key` vendor attribute and unwraps
  transparently.  When the KMS is HSM-backed, the wrapping key can be HSM-resident, providing
  hardware-boundary protection equivalent to purpose-built HSM split-key solutions.
- **Split-key audit logs elevated to ERROR**: `CreateSplitKey` share-stored and source-key
  destroyed events, and the `JoinSplitKey` reconstructed-key-stored event, now emit at
  `error!(target="audit")`.  This ensures they are captured by SIEM/audit sinks regardless of the
  runtime `RUST_LOG` filter (CWE-778 mitigation).
- **Corrected doc comment on `CryptoOfficerConfig::validate()`**: the method previously said
  "currently a no-op" but the n≥3 guard was already implemented.  Doc updated to reflect the actual
  enforced invariant.
- **Ceremony session ID stamped on audit logs**: a `Uuid::new_v4()` ceremony session ID is
  generated once per `CreateSplitKey` call and stamped on every audit log entry for that call.
  Similarly, `JoinSplitKey` generates a join session ID.  This enables SIEM correlation of all shares
  from a single ceremony split (NIST SP 800-57 Part 2 Rev 1 §4.6 audit requirements).
- **DB-level uniqueness on `activated_by`**: `crypto_officer_activations` gains an
  `activated_by VARCHAR(255)` column.  PostgreSQL/SQLite add a partial unique index
  `WHERE revoked_at IS NULL` (at most one active record per user at DB level).  MySQL enforces at
  application layer (no partial-index support).  Idempotent startup migrations handle upgrades of
  existing databases.
- **Strict permission enforcement on JoinSplitKey**: ceremony activation is attempted as an
  auto-activation side-effect of `JoinSplitKey`. Activation failure is now **fatal** — the reconstructed
  key is deleted on failure.
- **Fail-secure unenrolled users**: when roles are configured, unknown users default to Operator
  (minimum privilege) instead of unrestricted access (NIST SP 800-57 Part 2 Rev 1 §4.8).
- **Prevent duplicate active ceremony records**: `activate_crypto_officer_ceremony` revokes prior active
  records before insert; SELECT uses `ORDER BY activated_at DESC LIMIT 1` for deterministic retrieval.
- **Complete `key_part_identifier` validation**: join verifies identifiers are unique and form `{1..=N}`,
  preventing duplicate-share attacks that would produce garbage reconstructed keys.
- **Explicit `UniqueIdentifier` handling**: `unwrap_or_default()` replaced with match on
  `TextString` variant; non-text UIDs return clear `KmsError::InvalidRequest`.

## Features — Role Model (Two-Role RBAC)

- **Two-role model**: `Operator` (default, read/write crypto ops) and `CryptoOfficer`
  (lifecycle + ownership bypass). Replaces earlier three-role design.
- **CryptoOfficerConfig**: simplified from former multi-role structs; fields are
  `users`, `require_ceremony`, `ceremony_secret` — no longer includes `total_parts` (removed as dead code).
- **`UserId` type safety**: dedicated newtype wrapping `String` with `From<&str>`, `Deref<Target=str>`,
  `PartialEq` for `&str`/`String`, plus `try_new()` rejecting empty strings. Serde derives added.
- **`ObjectHandle<'a>` enum**: typed object ID classifier with `is_hsm()`, `hsm_parts()`, prefix matching
  replacing the removed `has_prefix()` utility; used consistently across dispatch/permissions/HSM paths.

## CLI (`ckms`)

- `ckms access-rights crypto-officer status` — print CO role configuration and ceremony state
  (`GET /access/crypto-officer/status`).
- `ckms access-rights crypto-officer disable` — revoke active CO ceremony (requires active CO).
- Docs updated in `documentation/docs/kms_clients/main_commands.md` (heading levels fixed, trailing
  whitespace removed).

## Web UI

- **Crypto Officer page** (`/ui/access-rights/crypto-officer`): status page showing role config,
  ceremony activation state, CO user list, and Disable button (visible only when active ceremony exists;
  requires active CO privileges). Menu label shortened from "Crypto Officer Role" to "Crypto Officer".
- **Crypto Officer page fully localized**: all labels, descriptions, badges, tooltips, and ceremony
  workflow steps are now translated via i18n, including Chinese (`zh-CN`). The menu entry
  "Crypto Officer" is also localized.
- **Split Key and Join Split Key pages localized and kept generic**: both dialogs
  (`/ui/sym/keys/split` and `/ui/sym/keys/join`) render their headings, descriptions, labels,
  placeholders, validation messages, and result text via i18n (English and Chinese). They no longer
  reference the key ceremony or Crypto Officer role — the share count is always user-editable. The
  corresponding "Split"/"Join" menu entries are also localized.
- **Search Objects locate buttons across action forms**: key/object/certificate identifier inputs in
  symmetric, RSA, EC, Covercrypt, MAC, PQC, FPE, certificate, attribute, object, and rotation-policy
  dialogs now use the reusable `KeyIdInput` component so users can search and select existing objects
  directly from the form, with object-type filtering where applicable.
- **SplitKey / JoinSplitKey dialogs**: removed unsupported "Polynomial Sharing GF(2^8)" (Shamir) option;
  now defaults to XOR method. **Threshold (k) input removed** and **method selector removed** —
  only XOR n-of-n is supported. Renamed "Total Parts" to "Number of Shares". Updated descriptions
  to clarify all shares are required.
- **JoinSplitKey dialog**: method selector removed (XOR is the only option). Description updated
  to clarify all shares are required for n-of-n reconstruction.
- **Dark theme aligned with the documentation site**: the Web UI dark theme now reuses the same
  mdBook "navy" palette as `docs.cosmian.com` (near-black `#161923` background, `#bcbdd0` text,
  `#282d3f` sidebar) instead of the previous gray surfaces. The light theme uses the darker brand
  orange `#c73f1b` for the primary accent. The sidebar menu and all surfaces now switch together
  with the light/dark toggle.
- **Contrast fixes (WCAG AA)**: resolved unreadable colour combinations in dark mode — dark text on
  the black background (`text-gray-800`, `text-blue-800`, `text-red-800`), light-gray helper text on
  white, near-invisible borders, and the low-contrast orange/teal accents — now meet AA contrast in
  both themes.

## Bug Fixes

- **Ceremony candidate exemption extended to Create/Import**: ceremony candidates (users in
  `crypto_officer_users` with `require_ceremony = true`) can now create and import keys before
  completing the ceremony. Previously only `CreateSplitKey`/`JoinSplitKey` were exempted, causing
  a chicken-and-egg problem where candidates could not create the master key to split.
  The exemption remains scoped to ceremony candidates only — full CO privileges (ownership bypass)
  still require ceremony completion.
- **Missing test data restored**: re-added deleted config files in `test_data/configs/server/client/`
  (`auth_plain*.toml`, `jwt.toml`) required by integration tests (`test_kms_all_authentications`,
  `test_vendor_id_in_vendor_attributes`).
- **Lychee exclude patterns added**: example OAuth URLs in config templates excluded from link checking.
  Non-routable IP `1.2.3.4` (used in forward proxy tests) excluded from link checking.

## Testing

- **7 ceremony vector tests**: `create_split_key_xor` round-trip (2-of-2, 3-of-3), `join_split_key_*`
  variants covering consistency checks, failure scenarios, and full lifecycle activate→disable→deny.
- **11 RBAC CLI tests** (`rbac_tests.rs`): verify the two-role model per ADR-2026-06-24:
  CO can create/export/destroy keys; CO **cannot** encrypt/decrypt (Operator-only); Operator can
  encrypt/decrypt with grant; Operator cannot create/export/destroy keys; CO ownership bypass;
  Operator needs explicit grant; grant/revoke access flow.
- **7 RBAC E2E tests** (`rbac-flow.spec.ts`): SplitKey/JoinSplitKey UI loading, access control
  page smoke tests, grant access flow via UI, Crypto Officer page accessibility.
- Server config TOMLs: `cert_auth_crypto_officer.toml`, `cert_auth_crypto_officer_ceremony.toml`,
  `cert_auth_operator_only.toml`, `rbac/*.{toml}` for role-separation tests.
- Pre-commit hook fixes applied: shellcheck SC2329/SC2086/SC2119, Go tab→space normalization,
  CRLF→LF line endings, Python quote style, trailing whitespace, trailing newlines.

## Documentation

- **Key ceremony guide** (`documentation/docs/configuration/authorization/key_ceremony.md`): explains
  two-role RBAC, XOR n-of-n split knowledge, NIST references (SP 800-57 Pt 2 §4.6–§4.8), Mermaid
  sequence diagrams for 4-phase ceremony flow, and CLI quick reference.
- **Authorization reference** (`documentation/docs/configuration/authorization.md`): updated role model,
  operation tables, permission evaluation order, and normative requirements table.
