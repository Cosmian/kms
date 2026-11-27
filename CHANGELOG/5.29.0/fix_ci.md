# Dependency bumps and CI fixes

## Build

- Merge Dependabot bumps: `rcgen` 0.14 (#1296), `k256` 0.14 (#1295), `num-bigint-dig` 0.9 (#1294), `etcetera` 0.11 (#1293),
  `redis` 1.x (#1292), on top of the grouped minor/patch bumps (#1289), `num-bigint` 0.5 (#1290) and `quick-xml` 0.42 (#1291).
- Adapt the TTLV XML parser to the `quick-xml` 0.42 `str`-based API.
- Adapt secp256k1 ECDSA signing/verification to `k256` 0.14 (`signature` 3); signatures are unchanged (RFC 6979, SHA-256, low-S).
- Enable the `uuid` `js` RNG feature for the WASM client (`uuid` ≥ 1.12 needs an explicit RNG source on `wasm32-unknown-unknown`).
- Allow the `BSL-1.0` license in `deny.toml` (`xxhash-rust`, required by `redis` 1.x); drop the now-unneeded
  `RUSTSEC-2026-0258` ignore (`h2` 0.3 left the tree).
- Record `cargo-vet` exemptions for all new and bumped crates.

## CI

- Dependabot: group minor/patch version updates and security updates into one PR per ecosystem.
- Keep the SAP ASE test image on `ubuntu:22.04` (`libaio1` is renamed `libaio1t64` from 24.04 on) and ignore its major
  Ubuntu bumps in Dependabot.
- Fix new Clippy findings (`large_futures`, `result_large_err`, deprecated `cc::Tool::env`).
