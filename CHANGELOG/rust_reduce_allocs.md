# Server allocation reduction across request and lifecycle paths

## Breaking Changes

### KMIP

- `cosmian_kmip`: `TTLV.tag` and `KmipEnumerationVariant.name` are now `Cow<'static, str>` instead of `String`. Serializers and the binary decoder borrow static tag names, and the JSON deserializer borrows known KMIP 2.1 tags. Replace `x.tag.as_str()` with `&*x.tag` or `x.tag.as_ref()`, and use `.into()` when building a `TTLV`.

## Security

- `Get`/`Export` of a key with `Fresh = true` could write the auto-unwrapped key back to the database when `default_unwrap_types` was set. The write-back now uses the stored object. See `SECURITY.md` (COSMIAN-2026-031).

## Refactor

- `ObjectWithMetadata::into_parts`; `Database::retrieve_objects` returns `Arc<ObjectWithMetadata>`; `retrieve_object_for_operation` returns `Arc<ObjectWithMetadata>` and clones only when it mutates.
- Borrow keys (`key_bytes_ref`) in symmetric decrypt, FPE, MAC, split/join key and derive key; move instead of clone in Activate, Revoke, Get/Export, key-pair creation and the attribute operations.
- SQLite: queries converted once, objects serialized before the writer closure. PostgreSQL: `Json<T>` reads/writes. MySQL: no intermediate `Value`.
- Audit: `AuditResult::as_canonical_str` returns `Cow`, the row hash is streamed (canonical bytes unchanged).
- Middlewares, JOSE headers, AWS XKS SigV4 body, Google CSE and the rotate-name cache avoid per-request copies.

### Performance

Measured once per tree on debug builds (single sample, counting allocator), base commit `20274da5b` vs this branch:

| Case | Allocations | Bytes |
|---|---|---|
| 4 KiB `Encrypt` decode+encode, binary TTLV | 76 → 32 | 28,391 → 27,838 |
| 4 KiB `Encrypt` decode+encode, JSON TTLV | 101 → 69 | 61,228 → 60,837 |
| `retrieve_object_for_operation`, cached key | 36 → 3 | 42,823 → 13,264 |
| SQLite `atomic(UpdateObject)` | 57 → 39 | 12,713 → 7,391 |

Other changes in this branch were not measured.
