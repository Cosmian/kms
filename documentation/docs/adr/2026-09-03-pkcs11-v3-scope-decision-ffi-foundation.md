---
title: "ADR-2026-09-03: PKCS#11 v3.0 scope decision and FFI foundation"
status: "Amended"
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

Both sides depend on the external `pkcs11-sys` crate (v0.2.25).
The original issue assumed this release only bound the Cryptoki v2.40 header surface.
Subsequent source and checksum verification established that v0.2.25 already includes
`CK_INTERFACE`, `C_GetInterfaceList`/`C_GetInterface`, the message-based function pointers,
and the v3.0 mechanism constants.
The dependency is therefore not the blocker; the KMS only needs to consume its existing
bindings (see issue [#1153](https://github.com/Cosmian/kms/issues/1153)).

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

1. **FFI approach**: do **not** fork/vendor `pkcs11-sys`.
   Use its existing `CK_INTERFACE`, `CK_INTERFACE_PTR`, and `CK_C_GetInterfaceList`
   definitions for the **capability probe**.
   This approach:
   - it unblocks a first, safe, additive step immediately, with no new external
     dependency and no vendoring/build-system burden;
   - leaves full native mechanism wiring (EdDSA/X25519/HKDF/message-based AEAD) to its
     separately scoped follow-up work;
   - it keeps the change minimal and independently reviewable, per this repository's
     "minimal, focused commits" rule.
2. **Scope of this decision**: the consumer side (`crate/hsm/base_hsm`) gains optional
   discovery, while the provider side retains `C_GetFunctionList` and additionally
   exposes the standard PKCS#11 v3.1 interface through `C_GetInterfaceList` and
   `C_GetInterface`.
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
- **Negative**: does not yet consume the message-based crypto operations or additional
  native mechanisms; those remain separately scoped follow-up milestone items.
- **Follow-up**: once a concrete v3.0 HSM target is available for validation, extend
  `pkcs11_v3.rs` with the `CK_FUNCTION_LIST_3_0` layout and `C_GetInterface` binding to
  actually invoke v3.0-only mechanisms, still behind the same additive fallback
  pattern established here.
