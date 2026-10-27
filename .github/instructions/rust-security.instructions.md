---
name: 'Rust Security Invariants'
description: 'Constant-time secret comparison, secret memory and log hygiene, no test-only auth branches, fail-closed authorization'
applyTo: 'crate/**/*.rs'
---

# Security invariants for generated Rust

Rules for **new or modified** code. Legacy violations exist: when you touch one, fix it in the same change.

## 1. Compare secrets in constant time

- MAC, signature tag, token, API key, password, challenge, nonce and any other secret/attacker-supplied byte string is compared with `subtle::ConstantTimeEq` (`a.ct_eq(b).into()`) or `openssl::memcmp::eq`. Never `==`, `!=`, `starts_with`, `contains` or `Vec`/`String` equality.
- Compare secrets of unknown length by hashing both sides first, as `secrets_equal` in `crate/server/src/routes/enrollment.rs` does.
- Reference fix: `MACVerify` in `crate/server/src/core/operations/mac.rs`.

## 2. Secret memory

- A field or local holding a password, PIN, token, secret, seed or key bytes is `Zeroizing<_>` (the workspace convention) or a wrapper with a redacting `Debug`.
- Never `#[derive(Debug)]` / implement `Display` on a type holding such a field unless the impl prints a placeholder.
- Config structs read from TOML/clap follow the same rule (existing plain-`String` secret fields in `est_config.rs`, `scep_config.rs`, `roles_config.rs`, `secret_backends/mod.rs` are legacy).

## 3. Logging

- Never log, at any level (including `trace!`): key material, plaintext, ciphertext, MAC/signature bytes, passwords, tokens, raw TTLV/KMIP/HTTP bodies.
- KMIP request/response `Display` impls base64-encode payload fields (`req_b64`/`opt_b64` in `crate/kmip/src/kmip_2_1/kmip_operations.rs`): never format a whole request/response (`{request}`, `{response}`, `{:?}`) into a log line. Log operation name, unique identifier, lengths, outcome.
- Use `cosmian_logger` macros. `dbg!`, `println!` and `eprintln!` are for `crate/clients/*` user output only, never libraries or the server.

## 4. No test-only behaviour in production paths

- Signature, expiry, authorization and TLS checks are never skipped by `#[cfg(test)]` or `cfg(any(test, feature = "insecure"))` inside a non-test item. Inject the behaviour through configuration or a trait.
- `insecure` is the only switch visible in a production binary; code enabling it logs an error at startup (see `start_kms_server.rs`).
- Legacy sites: `middlewares/auth_verifier/token.rs`, `jwt/jwt_config.rs`, `routes/ui_auth.rs`, `google_cse/jwt.rs`, `core/operations/validate.rs`.

## 5. Authorization fails closed

- A privileged service identity (e.g. the AWS XKS service user) is refused as a request principal and as a grant target by **one** central check, never by per-handler string comparisons. Add a negative test per reserved identity (PR #1107).
- Modifying or removing a security attribute (`Sensitive`, `Extractable`, ...) requires ownership or an explicit operation grant; a `Get`-only grant must not suffice. Test the `Get`-only case (PR #1198).
- A setting documented as required (client certificate, token, TLS) rejects when the credential is missing. Test the missing-credential case (PR #1278).
- Every new security check ships a negative test that fails if the check is removed.

> Reviewer pointers: `/security-review`, `/cryptography-review`, `/threat-model`. Rule text derived from the code and PR bodies cited above.
