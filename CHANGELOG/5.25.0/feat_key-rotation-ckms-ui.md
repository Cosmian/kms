# CHANGELOG — feat/key-rotation-ckms-ui

## Bug Fixes (E2E)

- Fix `rotation-policy.spec.ts`: AntD v5 `InputNumber` (rc-input-number 9.5) passes extra props including `data-testid` directly to the inner `<input>` element; remove the incorrect `input` child combinator from locators ([#968](https://github.com/Cosmian/kms/pull/968))

## Features

- Add `--rotation-name`, `--rotation-interval`, `--rotation-offset` flags to `ckms sym keys create`, `ckms ec keys create`, `ckms rsa keys create`, and `ckms pqc keys create` — rotation policy is applied via `SetAttribute` immediately after key creation
- Add shared `RotationPolicyArgs` clap struct (`crate/clients/clap/src/actions/shared/rotation_policy_args.rs`) reused across all four create actions
- Add **Rotation Policy** section (Rotation Name / Interval / Offset fields) to `SymKeysCreate`, `ECKeysCreate`, `RsaKeysCreate`, `PqcKeysCreate` UI pages — policy is applied via WASM `set_rotate_*` calls after key creation

- Add standalone **Rotation Policy** top-level menu item in the Web UI sidebar that regroups Set/Get Rotation Policy pages for all 4 key types (Symmetric, RSA, EC, PQC) under `/ui/rotation-policy/{sym,rsa,ec,pqc}/{set,get}`; remove the Set/Get Rotation Policy entries from each per-key-type Keys submenu ([#968](https://github.com/Cosmian/kms/pull/968))
- In FIPS mode, the PQC child is automatically hidden from the Rotation Policy menu ([#968](https://github.com/Cosmian/kms/pull/968))

## Testing

- Add Playwright E2E tests for key rotation policy (sym, RSA, EC, PQC): set-rotation-policy, get-rotation-policy, re-key — `ui/tests/e2e/rotation-policy.spec.ts`
- Add HSM KEK self-wrap regression test vector `test_data/vectors/hsm/kek_bootstrap_self_create/` with 6 TTLV-JSON steps covering AES-256 KEK bootstrap, DEK lifecycle and AES-GCM roundtrip
- Add `crate/test_kms_server/src/test_env.rs` for safe in-process environment variable overrides (avoids `unsafe set_var` in Rust 1.87+)
- Register `hsm_kek_uncreated` server type and `ONCE_VECTOR_HSM_KEK_UNCREATED` OnceCell in vector runner

## Bug Fixes

- Fix RSA and EC `ReKeyKeyPair` in FIPS mode: `generate_replacement` now carries the `cryptographic_usage_mask` from the old private/public key into `private_key_attributes`/`public_key_attributes` of the `CreateKeyPair` request so that the FIPS compliance check (`got None but expected among 0x...`) no longer fails ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix HSM self-wrap: server-wide KEK wrapping now skips keys whose UID starts with `hsm::` prefix, preventing infinite recursion when the KEK itself is created on the HSM — `crate/server/src/core/wrapping/wrap.rs`
- Fix OAuth2 login redirect server not stopping after the first callback, causing TCP TIME_WAIT port conflicts when the test suite is run multiple times in quick succession — `crate/clients/client/src/http_client/login.rs`
- Fix CLI documentation: `--name` → `--rotation-name` in all examples in `key_auto_rotation.md` ([#968](https://github.com/Cosmian/kms/pull/968))
- Move `SetRotationPolicyAction` and `GetRotationPolicyAction` to `shared/` module and wire into RSA, EC, and PQC key subcommands ([#968](https://github.com/Cosmian/kms/pull/968))
- Add shared `ReKeyKeyPairAction` in CLI and wire `ckms rsa/ec/pqc keys re-key` subcommands ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix **Search Objects** Date column: `activation_date`, `initial_date`, `original_creation_date`, `rotate_date` were serialized as seconds; now serialized as milliseconds so `formatUnixDate` receives the correct epoch value ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix **Search Objects** missing rotate_* attributes: add `rotate_name`, `rotate_interval`, `rotate_offset`, `rotate_generation`, `rotate_latest` match arms in `parse_selected_attributes_flatten` and include all date/rotate keys in the `ENRICH_ATTRIBUTE_KEYS` constant used by all `enrichUids` calls in `Locate.tsx` ([#968](https://github.com/Cosmian/kms/pull/968))
- Add WASM binding `rekey_keypair_ttlv_request` / `parse_rekey_keypair_ttlv_response` for asymmetric key rotation ([#968](https://github.com/Cosmian/kms/pull/968))
- Add Web UI pages for Re-Key, Set Rotation Policy, Get Rotation Policy under RSA, EC, and PQC key sections ([#968](https://github.com/Cosmian/kms/pull/968))
- Consolidate 8 per-key-type rotation policy components (Set×4 + Get×4 for sym/rsa/ec/pqc) into 2 generic reusable components `ui/src/actions/RotationPolicy/SetRotationPolicy.tsx` and `GetRotationPolicy.tsx` ([#968](https://github.com/Cosmian/kms/pull/968))
- Fix Web UI Certificate Issuance page Option 3 (Certificate ID to Re-certify) to call the dedicated KMIP `ReCertify` operation (new UID + replacement links) instead of `Certify` (in-place upsert); add `build_re_certify_request` in `client_utils`, `re_certify_ttlv_request`/`parse_re_certify_ttlv_response` WASM bindings ([#968](https://github.com/Cosmian/kms/pull/968))
- Add E2E CLI tests for rotation policy on symmetric, RSA, EC key types (`test_keyset_workflow`, `test_rekey_non_latest_rejected`, `test_rsa_set_and_get_rotation_policy`, `test_ec_set_and_get_rotation_policy`) ([#968](https://github.com/Cosmian/kms/pull/968))
- Add E2E CLI tests for `re-key` on RSA, EC, PQC key pairs (`test_rsa_rekey`, `test_ec_rekey`, `test_pqc_rekey`, `test_pqc_set_and_get_rotation_policy`) ([#968](https://github.com/Cosmian/kms/pull/968))

## Documentation

- Reorder implementation roadmap in `key_auto_rotation.md`: UI/CLI features become PR 2, notifications stay PR 3, auto-rotation scheduler becomes PR 4; close GitHub PR #973 (superseded), update PR #970 and #971 titles/descriptions
