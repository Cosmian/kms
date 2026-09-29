---
name: 'KMIP Operations'
description: 'Keep KMIP request/response types, the dispatcher, and the handler implementation in sync when adding a KMIP operation'
applyTo: 'crate/kmip/src/**/*.rs, crate/server/src/core/operations/**/*.rs'
---

# KMIP operation sync

A new KMIP operation spans the protocol types, the dispatcher, and the handler.

## Checklist

- [ ] `crate/kmip/src/kmip_2_1/kmip_operations.rs` — request/response types defined; variant added to the `Operation` enum
- [ ] `crate/server/src/core/operations/dispatch.rs` — match arm added for the new operation
- [ ] `crate/server/src/core/operations/<operation>.rs` — handler implemented
- [ ] Handler registered in `crate/server/src/core/operations/mod.rs`
- [ ] Run `/kmip-compliance <OperationName>` to validate spec compliance

> Rule 4.3 of `/kms-sync-rules`. For KMIP type/serialization conventions, see `rust-kmip.instructions.md`.
