## Bug Fixes

### KMIP
- The TTLV deserializer returns an error instead of panicking when a payload requests a `char`, a tuple struct or a tuple/struct enum variant; `deserialize_byte_buf` now behaves like `deserialize_bytes`

## Testing

- AKLC-M-3-14 now checks that `ModifyAttribute` of the `ActivationDate` of an Active key is refused (step 5)
- `test_set_attribute` is ignored with a reference to its tracking issue ([#1463](https://github.com/Cosmian/kms/issues/1463)) instead of "Too much verbosity"

## Refactor

- Remove stale `TODO`/`FIXME` comments and dead commented-out tests; the pending work is tracked in GitHub issues [#1451](https://github.com/Cosmian/kms/issues/1451) to [#1463](https://github.com/Cosmian/kms/issues/1463)
- Multi-part stream eviction uses `HashMap::extract_if`
