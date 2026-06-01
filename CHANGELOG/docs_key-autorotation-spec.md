## Bug Fixes

- Fix KMIP spec reference: `§4.7` → `§4.8` in `rekey/common.rs` ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix KMIP spec reference: `§6.1.8` → `§6.1.45` for `ReCertify` operation ([#968](https://github.com/Cosmian/kms/pull/968))
- Add ownership check in `rewrap_dependants` to skip keys not owned by the caller ([#968](https://github.com/Cosmian/kms/pull/968))
- Simplify `relink_keys_to_new_certificate` by passing `old_cert_uid` directly instead of extracting from attributes ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix `rewrap_dependants` losing `activation_date` metadata on Redis-findex: use attributes from `retrieve_object` instead of `find_wrapped_by` which fails on wrapped keys ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix KMIP 1.4 XML test cleanup: use Revoke + Destroy(remove:true) to fully purge stale objects from Redis-findex ([#968](https://github.com/Cosmian/kms/pull/968))

## Refactor

- Extract `find-wrapped-by` SQL into `query.sql` and `query_mysql.sql` using `rawsql::Loader` macros ([#968](https://github.com/Cosmian/kms/pull/968))
- Add `PublicKey` variant to SQLite `find_wrapped_by` inline query ([#968](https://github.com/Cosmian/kms/pull/968))
- Implement `find_wrapped_by` for Redis-findex backend ([#968](https://github.com/Cosmian/kms/pull/968))

## Testing

- Add 6 non-regression test vectors for key rotation scenarios:
  `rekey_wrapping_key`, `rekey_wrapped_key`, `rekey_wrapping_key_with_links`,
  `rekey_wrapping_key_double_chain`, `kek_rekey_wrapped`, `rekey_wrapped_deactivated` ([#968](https://github.com/Cosmian/kms/pull/968))

## Documentation

- Add key auto-rotation specification document covering all 6 rotation
  scenarios (plain symmetric, wrapping key, wrapped key, asymmetric pair,
  wrapped private key, server-wide KEK), rotation policy attributes,
  server-side scheduler, KMIP attribute tables, and implementation roadmap.
