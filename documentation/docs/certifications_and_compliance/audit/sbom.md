# Software Bill of Materials (SBOM)

A **Software Bill of Materials (SBOM)** is a formal record of all components, libraries, and
dependencies used to build a software artifact — analogous to an ingredient list for software.
Cosmian KMS ships SBOMs for every release to support:

- **Supply chain security**: identify exactly which packages and versions are included in each build.
- **Vulnerability management**: cross-reference components against CVE databases to detect
  known vulnerabilities before they reach production.
- **License compliance**: audit open-source licenses across the full dependency tree.
- **Regulatory requirements**: satisfy NTIA, CISA, and EU CRA SBOM mandates for critical software.

## Artifacts

SBOMs are generated from **Nix build outputs**, providing a complete and reproducible view of
runtime dependencies. They are available for all build variants:

| Artifact | Variants | Location |
|----------|----------|----------|
| KMS server | `fips` / `non-fips` × `static` / `dynamic` | `sbom/server/<variant>/<link>/` |
| `ckms` CLI | `fips` / `non-fips` × `static` / `dynamic` | `sbom/ckms/<variant>/<link>/` |
| OpenSSL 3.1.2 (FIPS derivation) | — | `sbom/openssl_3_1_2/` |
| OpenSSL 3.6.0 (non-FIPS derivation) | — | `sbom/openssl_3_6_0/` |

Each output directory contains:

| File | Format | Purpose |
|------|--------|---------|
| `bom.cdx.json` | CycloneDX 1.5 JSON | Import into SBOM platforms (e.g., Dependency-Track) |
| `bom.spdx.json` | SPDX 2.3 JSON | License compliance and SPDX tooling |
| `sbom.csv` | CSV | Tabular component inventory |
| `vulns.csv` | CSV | Deduplicated vulnerability rows (CVE/OSV/Grype/Vulnix) |
| `graph.png` | PNG | Visual dependency graph |
| `meta.json` | JSON | Build metadata (variant, link, counts, timestamps) |

The default FIPS static server SBOM is at
[`sbom/server/fips/static/bom.cdx.json`](../../../sbom/server/fips/static/bom.cdx.json).

## Vulnerability scanning

Vulnerability data is produced by [vulnxscan](https://github.com/tiiuae/sbomnix), which aggregates
three sources:

- **Grype** — scans against NVD, GitHub Security Advisories, and other databases.
- **Vulnix** — scans against the NixOS security tracker with Nix-specific package context.
- **OSV** — queries the [OSV database](https://osv.dev) for additional coverage.

Duplicate CVE rows (e.g. `CVE-2026-0915`, `UBUNTU-CVE-2026-0915`, `DEBIAN-CVE-2026-0915`) are
collapsed to a single entry by `nix/scripts/dedup_cves.py` before the file is committed.

## Regenerating the SBOM

Re-run after any change to `Cargo.lock` or the package version:

```bash
# All combinations (server + ckms + OpenSSL derivations)
bash .github/scripts/nix.sh sbom

# Server only — one specific combination
bash .github/scripts/nix.sh sbom --target server --variant fips --link static

# OpenSSL 3.6.0 derivation only
bash .github/scripts/nix.sh sbom --target openssl_3_6_0
```

See [`sbom/README.md`](../../../sbom/README.md) for the full regeneration guide and usage
examples (Dependency-Track upload, `jq` queries, vulnerability review).

## Standards & references

- [CycloneDX specification](https://cyclonedx.org/specification/overview/)
- [SPDX specification](https://spdx.github.io/spdx-spec/) — ISO/IEC 5962:2021
- [NTIA SBOM guidance](https://www.ntia.gov/sbom)
- [CISA SBOM resources](https://www.cisa.gov/sbom)
- [sbomnix toolchain](https://github.com/tiiuae/sbomnix)
