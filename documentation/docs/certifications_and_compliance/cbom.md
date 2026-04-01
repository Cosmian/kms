# Cryptography Bill of Materials (CBOM)

A **Cryptography Bill of Materials (CBOM)** is a formal inventory of all cryptographic assets used
in a software system — algorithms, key types, parameters, and the libraries that implement them.
It follows the [CycloneDX 1.6](https://cyclonedx.org/specification/overview/) standard and is
designed to support:

- **Crypto-agility audits**: identify which algorithms are in use and where, to plan migration when
  standards change (e.g. deprecation of RSA-2048 or SHA-1).
- **Post-quantum readiness**: track which operations still rely on classical algorithms vulnerable
  to quantum attacks.
- **Compliance reporting**: demonstrate that only approved algorithms are in use for FIPS or other
  regulatory frameworks.
- **Supply chain security**: record implementing libraries (e.g. OpenSSL, RustCrypto) with their
  versions alongside the algorithms they provide.

## CBOM artifact

The Cosmian KMS CBOM is generated from the actual source code and `Cargo.lock`, ensuring it
reflects the running codebase rather than a manual registry.

| File | Format | Description |
|------|--------|-------------|
| [`cbom/cbom.cdx.json`](../../../../cbom/cbom.cdx.json) | CycloneDX 1.6 JSON | Full cryptographic asset inventory |

The CBOM covers:

- All symmetric and asymmetric algorithms (AES-GCM, ChaCha20-Poly1305, RSA, ECDSA, EdDSA, …)
- Post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA, Covercrypt)
- Key derivation functions (PBKDF2, HKDF, Argon2)
- Hash functions (SHA-2, SHA-3)
- Key encapsulation and wrapping schemes
- The implementing Rust crates (RustCrypto, OpenSSL, Cosmian) with versions from `Cargo.lock`
- FIPS compliance status per algorithm

## Regenerating the CBOM

Re-run the generator after any algorithm or dependency change:

```bash
python3 .github/scripts/sbom/generate_cbom.py --output cbom/cbom.cdx.json
```

The script:

1. Runs `cargo metadata --features non-fips` to read implementing-library versions from `Cargo.lock`.
2. Scans Rust source files under `crate/` to confirm each algorithm is actively referenced.
3. Emits a CycloneDX 1.6 CBOM JSON document.

Only the algorithm catalogue inside the script requires manual maintenance when a new algorithm is
added or removed; library versions and source-scan results are refreshed automatically.

## Importing into SBOM platforms

The CBOM uses the same CycloneDX format as the [SBOM](../../../../sbom/README.md), so it can be
imported into any CycloneDX-compatible platform such as
[Dependency-Track](https://dependencytrack.org/):

```bash
curl -X POST "https://dtrack.example.com/api/v1/bom" \
  -H "X-Api-Key: ${API_KEY}" \
  -H "Content-Type: multipart/form-data" \
  -F "project=${PROJECT_UUID}" \
  -F "bom=@cbom/cbom.cdx.json"
```

## Standards & references

- [CycloneDX CBOM specification](https://cyclonedx.org/capabilities/cbom/)
- [NIST Post-Quantum Cryptography standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CISA Post-Quantum Cryptography initiative](https://www.cisa.gov/quantum)
