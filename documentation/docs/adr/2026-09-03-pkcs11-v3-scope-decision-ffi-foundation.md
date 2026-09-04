---
title: "ADR-2026-09-03: PKCS#11 v3.0 scope decision and FFI foundation"
status: "Accepted"
date: "2026-09-03"
authors: "HSM integration contributors"
tags: ["architecture", "decision", "hsm", "pkcs11", "backward-compatibility"]
supersedes: ""
superseded_by: ""
---

## Status

Accepted

## Context

Eviden KMS implements Cryptoki (PKCS#11) v2.40 on both sides of the protocol:

- the **provider side** (`crate/clients/pkcs11/module` + `crate/clients/pkcs11/provider`),
  exposing KMS-managed keys as a PKCS#11 token to external applications;
- the **consumer side** (`crate/hsm/base_hsm` + vendor loaders), talking to real HSMs
  (SoftHSM2, Utimaco, Proteccio, Crypt2Pay, SmartCard HSM).

Both sides depend on the external `pkcs11-sys` crate (v0.2.25), which only binds the
Cryptoki v2.40 header surface. It has no `CK_INTERFACE`, no
`C_GetInterfaceList`/`C_GetInterface`, no message-based crypto function pointers, and
none of the v3.0 mechanism constants (`CKM_EDDSA`, `CKM_HKDF_DERIVE`,
`CKM_SP800_108_*`, etc.). This is the bottleneck for every other PKCS#11 v3.0 item on
the HSM integration roadmap (see issue
[#1153](https://github.com/Cosmian/kms/issues/1153)).

PKCS#11 v3.0 (OASIS Cryptoki v3.0 §3.2) adds an "interfaces" discovery model:
`C_GetInterfaceList`/`C_GetInterface` supersede `C_GetFunctionList` — but the spec
explicitly retains `C_GetFunctionList` for backward compatibility; it is not removed.

Traced `crate/hsm/base_hsm/src/hsm_lib.rs`: it resolves every Cryptoki function by
stable C symbol name via `libloading`, never via `C_GetFunctionList` or
`C_GetInterfaceList`. `CK_INFO` is byte-identical between v2.40 and v3.0. Any future
v3.0 adoption on the consumer side **must** be additive/optional so that v2.x-only
HSMs (all vendor loaders currently supported) are never broken — this was stated as a
hard acceptance criterion for the whole "PKCS#11 v3.0" milestone.

## Decision

1. **FFI approach**: do **not** fork/vendor `pkcs11-sys` and regenerate the full v3.0
   binding surface via `bindgen` at this time. Instead, hand-write only the minimal
   additional FFI surface required for a **capability probe**:
   `CK_INTERFACE`, `CK_INTERFACE_PTR`, and the `C_GetInterfaceList` function-pointer
   type, defined locally in `crate/hsm/base_hsm/src/pkcs11_v3.rs`. This was one of the
   three options considered in #1153 ("hand-writing only the new pieces needed") and
   was chosen because:
   - it unblocks a first, safe, additive step immediately, with no new external
     dependency and no vendoring/build-system burden;
   - full native mechanism wiring (EdDSA/X25519/HKDF/message-based AEAD) is separately
     scoped follow-up work and does not need the v3.0 function-list layout yet;
   - it keeps the change minimal and independently reviewable, per this repository's
     "minimal, focused commits" rule.
2. **Scope of this decision**: consumer side only (`crate/hsm/base_hsm`). The provider
   side (`crate/clients/pkcs11/module` + `provider`) is unaffected by this change and
   remains a v2.40 token implementation; extending it to v3.0 is out of scope here and
   tracked separately.
3. **Conformance level**: interfaces discovery only (capability probe), not full
   native mechanism wiring. `HsmLib` gained:
   - `HsmLib::supports_pkcs11_v3_interfaces() -> bool` — `true` only if the loaded
     library exports `C_GetInterfaceList`.
   - `HsmLib::list_pkcs11_v3_interfaces() -> HResult<Option<Vec<InterfaceDescriptor>>>`
     — `Ok(None)` for v2.40-only libraries (the common case today, e.g. SoftHSM2),
     `Ok(Some(list))` (possibly empty) otherwise. `InterfaceDescriptor` intentionally
     does not expose the raw `pFunctionList` pointer: consuming it safely requires the
     full v3.0 function-list layout, deferred to follow-up work.
4. **Backward compatibility**: `HsmLib::instantiate` resolves `C_GetInterfaceList`
   best-effort (`library.get(...).ok()`), exactly like every other symbol resolution
   in this file is *not* changed — every existing `C_*` function is still resolved by
   stable per-symbol name, unconditionally. Loading a v2.40-only library where
   `C_GetInterfaceList` is absent cannot fail `instantiate`; the probe simply reports
   "not supported". No existing HSM vendor loader (SoftHSM2, Utimaco, Proteccio,
   Crypt2Pay, SmartCard HSM) is touched by this change.

## Consequences

- **Positive**: unblocks capability detection for future v3.0 adoption without a
  vendoring effort; zero risk to existing HSM integrations (purely additive); testable
  in isolation via a pure `parse_interfaces` function (no FFI needed for unit tests).
- **Negative**: does not yet provide the v3.0 mechanism constants or message-based
  crypto operations — a full `pkcs11-sys` fork/bindgen effort (or a switch to
  `cryptoki`/`cryptoki-sys` for the consumer side) remains necessary for those and is
  tracked as separate follow-up milestone items.
- **Follow-up**: once a concrete v3.0 HSM target is available for validation, extend
  `pkcs11_v3.rs` with the `CK_FUNCTION_LIST_3_0` layout and `C_GetInterface` binding to
  actually invoke v3.0-only mechanisms, still behind the same additive fallback
  pattern established here.
