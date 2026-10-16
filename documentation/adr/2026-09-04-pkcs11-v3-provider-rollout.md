---
title: "ADR-2026-09-04: PKCS#11 v3.0 provider-side rollout (interfaces discovery + CKM_AES_GCM)"
status: "Accepted"
date: "2026-09-04"
authors: "HSM integration contributors"
tags: ["architecture", "decision", "hsm", "pkcs11", "backward-compatibility"]
supersedes: ""
superseded_by: ""
---

## Status

Accepted

## Context

ADR [2026-09-03](2026-09-03-pkcs11-v3-scope-decision-ffi-foundation.md) scoped the PKCS#11
v3.0 "capability probe" foundation to the **consumer side** only
(`crate/hsm/base_hsm`), and explicitly left the **provider side**
(`crate/clients/pkcs11/module` + `crate/clients/pkcs11/provider` — the library the KMS ships
so external applications such as Veracrypt, LUKS, Cryhod, Oracle TDE, and OpenSSH can use
KMS-managed keys as a PKCS#11 token) out of scope, tracked as follow-up work.

Issue [#1156](https://github.com/Cosmian/kms/issues/1156) ("PKCS#11 v3.0 rollout: provider
interfaces, mechanisms, consumer side, tests") requested that follow-up: implement the
provider-side `C_GetInterfaceList`/`C_GetInterface` v3.0 discovery entry points, wire a
missing native mechanism (`CKM_AES_GCM`), and add corresponding tests — all **additive**, with
no breaking change to any existing v2.40 consumer.

During investigation, `CKM_EDDSA`/`CKM_ECDSA` were found to be **already fully wired** in both
`mechanism.rs` and the provider's `kms_object.rs` prior to this change — no work was required
for those two mechanisms; this ADR documents that finding so it is not re-investigated later.

## Decision

1. **Interfaces discovery (`C_GetInterfaceList`/`C_GetInterface`)**: implemented as new,
   additive exported symbols. `CK_INFO.cryptokiVersion` is bumped from 2.40 to 3.1
   (`CRYPTOKI_VERSION_MAJOR`/`MINOR` from `pkcs11-sys` 0.2.25). `C_GetFunctionList` (v2.40
   entry point) is **not removed or changed in signature/behavior** — every existing v2.x
   consumer keeps working unmodified.
2. **Backend-registration chicken-and-egg problem**: KMS client/config/backend setup
   previously happened only inside `C_GetFunctionList`'s body. Since a v3.0-aware caller may
   call only `C_GetInterfaceList`/`C_GetInterface` and skip `C_GetFunctionList` entirely, this
   initialization was extracted into a shared, idempotent `ensure_backend_registered()`
   function, called by all three entry points. Idempotency was verified:
   `register_backend`/`register_pin_mode`/`register_login_fn` simply overwrite prior
   registration, and `initialize_logging` is guarded by `std::sync::Once`.
3. **Location of the new v3.0 statics vs. entry-point functions**: `FUNC_LIST_3_0`,
   `PKCS11_INTERFACE_NAME`, `PKCS11_INTERFACE` live in the **module crate**
   (`crate/clients/pkcs11/module/src/pkcs11.rs`), mirroring the existing `FUNC_LIST` pattern
   (fields statically known at compile time except the three entry-point pointers, which are
   patched at runtime). The exported `C_GetInterfaceList`/`C_GetInterface` *functions*
   themselves live in the **provider crate** (`crate/clients/pkcs11/provider/src/lib.rs`,
   alongside `C_GetFunctionList`) because only provider-crate code can perform the
   backend-init side effect.
4. **Non-null v3.0 function list**: per the Cryptoki v3.0 specification, `CK_FUNCTION_LIST_3_0`
   must contain no null function pointers. ~22 v3.0-only functions that this library does not
   natively implement (`C_LoginUser`, `C_SessionCancel`, and the 20 message-based bulk
   encrypt/decrypt/sign/verify functions) are wired to stubs returning
   `CKR_FUNCTION_NOT_SUPPORTED` via the existing `cryptoki_fn_not_supported!` macro, rather
   than left null (a null pointer risks crashing a naive caller that does not null-check every
   field). Applications needing those operations use the equivalent, fully-implemented v2.x
   calls (`C_Encrypt`/`C_Decrypt`/`C_Sign`/`C_Verify`).
5. **`CKM_AES_GCM`**: implemented end-to-end (mechanism parsing/validation in
   `core/mechanism.rs`, AAD threading and `ciphertext || tag` framing in the provider's
   `kms_object.rs`). The KMS's AES-GCM backend always produces/verifies a 128-bit (16-byte)
   tag (`AES_128/192/256_GCM_MAC_LENGTH` in `crate/crypto/src/crypto/symmetric/symmetric_ciphers.rs`),
   so `ulTagBits` is validated to be exactly 128 at parse time and rejected otherwise
   (`CKR_MECHANISM_INVALID`). IV is bounded to 1–128 bytes and AAD to 0–1 MiB to reject
   pathological/malicious mechanism parameters before any KMIP call is made.
6. **`C_GetInterface` semantics**: null `pInterfaceName` matches the sole "PKCS 11" interface;
   a non-null name must match exactly (bounded 64-byte NUL-terminated scan — the spec's name is
   only 7 bytes, so 64 is generous but still bounded to avoid any out-of-bounds read on a
   malicious/unterminated buffer); null `pVersion` is accepted, a non-null version must have
   `major == 3`; `flags` must be exactly 0 (this library makes no special guarantees such as
   fork-safety); a null `ppInterface` output parameter is rejected with `CKR_ARGUMENTS_BAD`.

## Consequences

### Positive

- **POS-001**: v3.0-aware PKCS#11 consumers can now discover this library's interface via the
  standard `C_GetInterfaceList`/`C_GetInterface` mechanism, matching modern Cryptoki tooling
  expectations.
- **POS-002**: `CKM_AES_GCM` gives PKCS#11 consumers authenticated encryption with associated
  data (AEAD) directly through the KMS-backed token, without needing a separate MAC step.
- **POS-003**: Zero breaking changes — every existing consumer (Veracrypt, LUKS, Cryhod, Oracle
  TDE, OpenSSH) that only knows `C_GetFunctionList` and the pre-existing mechanism set is
  entirely unaffected.

### Negative

- **NEG-001**: ~22 v3.0-only functions are present but not natively implemented (stubs
  returning `CKR_FUNCTION_NOT_SUPPORTED`); a strictly-v3.0-only consumer that requires the
  message-based bulk crypto API or `C_LoginUser`/`C_SessionCancel` cannot use this library for
  those specific operations yet. This is an accepted, documented limitation, not a defect.
- **NEG-002**: two additional `static mut` items (`FUNC_LIST_3_0`, `PKCS11_INTERFACE`) increase
  the amount of `unsafe`-adjacent global mutable state in the module crate, following the exact
  same pattern already accepted for `FUNC_LIST`.

## Alternatives Considered

### Full v3.0 message-based crypto API implementation

- **ALT-001 Description**: implement all message-based bulk encrypt/decrypt/sign/verify
  functions natively instead of stubbing them.
- **ALT-002 Rejection Reason**: no consumer integration currently requires the message-based
  API (Veracrypt, LUKS, Cryhod, Oracle TDE, OpenSSH all use the v2.x one-shot
  `C_Encrypt`/`C_Decrypt`/`C_Sign`/`C_Verify` calls); implementing it would be substantial
  unreviewed surface area with no consumer benefit today. Deferred to future work if a
  consumer need arises.

### Vendoring/regenerating `pkcs11-sys` via `bindgen` for full v3.0 binding coverage

- **ALT-003 Description**: fork or regenerate `pkcs11-sys` to gain the full v3.0 C header
  surface instead of relying on the crate's existing v0.2.25 bindings (which already include
  `CK_INTERFACE`, `CK_FUNCTION_LIST_3_0`, and `CK_GCM_PARAMS`).
- **ALT-004 Rejection Reason**: unnecessary — `pkcs11-sys` 0.2.25 already exposes every type
  needed for this work; no vendoring/build-system burden was justified.

## Implementation Notes

- **IMP-001**: `cargo clippy --all-targets --features non-fips -- -D warnings` and the
  equivalent FIPS-mode invocation are both clean for `cosmian_pkcs11_module` and
  `cosmian_pkcs11`.
- **IMP-002**: test coverage — 7 new unit tests in `core/mechanism.rs` for `CKM_AES_GCM`
  parameter validation (valid IV/AAD, empty AAD, invalid tag bits, zero/oversized IV, oversized
  AAD, wrong parameter size), plus 2 new live-KMS integration tests in the provider crate's
  `tests.rs`: a full `CKM_AES_GCM` encrypt/decrypt round trip and a
  `C_GetInterfaceList`/`C_GetInterface` argument-validation/discovery test. All 36 module-crate
  tests and all 8 provider-crate tests pass with no regressions.
- **IMP-003**: success criterion — no existing PKCS#11 integration test or documented consumer
  workflow changes behavior; only new capabilities are exposed.

## References

- **REF-001**: ADR [2026-09-03](2026-09-03-pkcs11-v3-scope-decision-ffi-foundation.md) —
  consumer-side PKCS#11 v3.0 capability-probe foundation (issue #1153).
- **REF-002**: [PKCS#11 provider module](../integrations/pkcs11_provider.md) — user-facing
  reference documentation for this rollout.
- **REF-003**: OASIS Cryptoki v3.0 specification — interfaces discovery model
  (`C_GetInterfaceList`/`C_GetInterface`) and `CKM_AES_GCM` mechanism definition.
- **REF-004**: Relevant codebase files: `crate/clients/pkcs11/module/src/pkcs11.rs`,
  `crate/clients/pkcs11/module/src/core/mechanism.rs`,
  `crate/clients/pkcs11/provider/src/lib.rs`, `crate/clients/pkcs11/provider/src/kms_object.rs`.
