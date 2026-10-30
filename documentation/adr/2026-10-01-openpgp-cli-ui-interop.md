---
title: "ADR-2026-10-01: OpenPGP Client Surfaces, Parity, and Interoperability Testing Architecture"
status: "Accepted"
date: "2026-10-01"
authors: "Architecture Team"
tags: ["architecture", "openpgp", "gnupg", "cli", "wasm", "web-ui", "interoperability"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-10-01: OpenPGP Client Surfaces, Parity, and Interoperability Testing Architecture

## Status

Accepted

## Context

Server-side OpenPGP (`ObjectType::PGPKey`) support was previously merged to branch `feat/kmip_pgp` implementing KMIP 2.1 `Create`, `Import`, `Export`, `Encrypt`, `Decrypt`, `Sign`, and `SignatureVerify` operations over OpenPGP keys. However, the client interfaces (`ckms` CLI and React Web UI) lacked OpenPGP subcommands and pages, leaving users without standard management or cryptographic workflows for OpenPGP objects.

Furthermore, the existing test coverage was limited to in-KMS RSA-3072 key creation round-tripped through `gpg --import`. It lacked:

- Cross-origin testing where keys generated externally in GnuPG are imported into the KMS for decryption and signing.
- Ed25519 profile testing against GnuPG.
- Negative tests and boundary pinning for server-side limitations (such as rejection of passphrase-protected keys, rejection of pre-hashed `DigestedData`, rejection of multi-part streaming, and wrapped-key handling).
- Testing with RFC 3156 PGP/MIME email messages.

A clear architectural decision was needed to deliver client parity across CLI, WASM, and Web UI surfaces while freezing server-side KMIP behavior and validating interoperability against real external GnuPG tooling.

## Decision

1. **Client Surface Gating**:
   - Introduce `ckms pgp` subcommand group under `crate/clients/clap/src/actions/pgp/` gated behind `#[cfg(feature = "non-fips")]`.
   - Add Web UI OpenPGP route tree (`/ui/pgp/*`), action components (`PgpKeysCreate`, `PgpEncrypt`, `PgpDecrypt`, `PgpSign`, `PgpVerify`), and navigation menu entries, dynamically excluded when running in FIPS mode alongside PQC, MAC, FPE, and Anonymize.
   - Extend WASM bridge in `cosmian_kms_client_wasm` with `create_pgp_key_ttlv_request`, `get_pgp_algorithms`, `encrypt_pgp_ttlv_request`, and `decrypt_pgp_ttlv_request`.

2. **Server-Side Behavior Frozen**:
   - Make zero modifications to server cryptographic operations or KMIP dispatch logic. Plumb only SPA deep-linking routing allowlists (`/pgp{_:.*}` in `start_kms_server.rs`).

3. **Battle-Testing Interoperability Suite**:
   - Implement an exhaustive 24-test integration matrix in `crate/test_kms_server/src/pgp_gnupg_tests.rs` covering:
     - Direction 1 (GnuPG &rarr; KMS): GnuPG-generated Ed25519 and RSA-3072 keys imported into KMS for decryption and signing, public-only imports, subkey signature verification, and ASCII-armored vs. binary input acceptance.
     - Direction 2 (KMS &rarr; GnuPG): KMS-generated Ed25519 and RSA keys (2048, 3072, 4096 bits) exported and used in GnuPG.
     - Direction 3 (Negative Boundaries): Pinning server rejections of inline signatures, cleartext signatures, digested data, streaming operations, and invalid key lengths.
     - Direction 4 (PGP/MIME RFC 3156): End-to-end encrypted and signed MIME email validation in the GnuPG &rarr; KMS direction.
   - Provide an end-to-end MISE test task `.mise/scripts/test/test_gnupg.sh` and CI matrix entry in `.github/workflows/test_all.yml` testing the binary CLI against live KMS and GnuPG instances.

4. **Handling Discovered Operational Constraints**:
   - GnuPG key generation requires generating encryption-capable subkeys (`ecdh/cv25519` or `RSA`) with non-AEAD preference lists (`AES256`, `SHA512`, `ZLIB`, etc.) to prevent GnuPG from emitting SEIPDv2 AEAD packets (packet type 20) unsupported by standard OpenPGP v4 decryptors.
   - PGPKey wrap-on-create (`wrapping_key_id`) is not supported by the underlying key-wrapping encoding logic and is pinned as an error, with the restriction explicitly documented.
   - HTTP 500 error sanitization preserves confidentiality by returning generic error messages across REST endpoints for low-level crypto parse errors.

## Consequences

### Positive

- **POS-001**: Full client feature parity for OpenPGP across `ckms` CLI, WASM bindings, and the Web UI in English, French, and Simplified Chinese.
- **POS-002**: High-confidence regression prevention and standards validation via 24 automated cross-tool tests with real GnuPG binaries in isolated environments.
- **POS-003**: Executable documentation and negative tests pinning all operational boundaries of the OpenPGP subsystem.

### Negative

- **NEG-001**: OpenPGP operations remain restricted to non-FIPS builds as RFC 4880 / RFC 9580 primitives are not FIPS 140-3 approved.
- **NEG-002**: KMS Encrypt and Sign emit binary OpenPGP packets only; callers requiring ASCII armor must armor payloads client-side or post-process them.

## Alternatives Considered

### Full Server-Side SEIPDv2 / Passphrase Support

- **ALT-001 Description**: Extend `pgp_ops.rs` and `cosmian_kms_crypto` to parse GnuPG AEAD type 20 packets, decrypt passphrase-protected secret keys inside the KMS, and support streaming signatures.
- **ALT-002 Rejection Reason**: Excluded by project scope and constraints. Server-side behavior was explicitly frozen; client surfaces and interop test harnesses were built to accurately pin and integrate with existing server behavior.

### S/MIME Protocol Support

- **ALT-003 Description**: Add S/MIME email encryption and signing endpoints.
- **ALT-004 Rejection Reason**: S/MIME uses X.509 certificates and PKCS#7 / CMS rather than OpenPGP key rings. PGP/MIME (RFC 3156) fulfills the OpenPGP email use-case without conflating distinct certificate infrastructures.

## Implementation Notes

- **IMP-001**: Export formats (`pgp-secret`, `pgp-public`) in `client_utils` must disable PEM encoding (`encode_to_pem = false`) because OpenPGP armor is already ASCII-wrapped.
- **IMP-002**: OpenPGP User ID vendor attributes use `VENDOR_ID_COSMIAN` (`"cosmian"`) matching exact-match vendor identification rules.
- **IMP-003**: Playwright E2E tests (`pgp-key-flow.spec.ts`) validate UI form rendering, creation, download, import round-trips, and lifecycle destruction.

## References

- **REF-001**: RFC 4880: OpenPGP Message Format
- **REF-002**: RFC 3156: MIME Security with OpenPGP
- **REF-003**: `crate/kmip/src/kmip_2_1/requests/create.rs`, `crate/clients/clap/src/actions/pgp/`, `crate/test_kms_server/src/pgp_gnupg_tests.rs`, `ui/src/actions/Pgp/`
