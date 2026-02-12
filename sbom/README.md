# SBOM (Software Bill of Materials)

This directory contains Software Bill of Materials (SBOM) reports for Cosmian KMS builds generated from Nix outputs, using industry-standard tools and formats.

## 📋 Overview

An SBOM is a formal record containing the details and supply chain relationships of components used in building software. These SBOMs are generated from the Nix build outputs, providing a complete and reproducible view of dependencies.

Report locations:

- `sbom/openssl/` — SBOM + vulnerability scan for the OpenSSL derivation used by the builds
- `sbom/server/<variant>/<link>/` — SBOM + vulnerability scan for the server derivation
    - `<variant>`: `fips` | `non-fips`
    - `<link>`: `static` | `dynamic`

## 📁 Reports (and purpose)

The SBOM generator produces several "base" reports.

Important: folders are kept clean on purpose. Each SBOM output directory contains only **two CSV files**:

- `sbom.csv` — component inventory
- `vulns.csv` — vulnerability rows (CVE-like duplicates removed in-place)

| Report | Where | Purpose |
|------|------|---------|
| `bom.cdx.json` | `sbom/**/` | CycloneDX 1.5 SBOM for import into SBOM platforms (e.g., Dependency-Track) |
| `bom.spdx.json` | `sbom/**/` | SPDX 2.3 SBOM for compliance workflows and SPDX tooling |
| `sbom.csv` | `sbom/**/` | Tabular component inventory (package name/version/system metadata) |
| `vulns.csv` | `sbom/**/` | Vulnerability rows from `vulnxscan`, then deduplicated by CVE YEAR-ID (see below) |
| `graph.png` | `sbom/**/` | Visual dependency graph |
| `meta.json` | `sbom/**/` | Build metadata (target/variant/link, counts, timestamps) |

### CVE deduplication

During generation, `vulns.csv` is deduplicated in-place by an external script:

- `nix/scripts/dedup_cves.py`

It removes duplicate CVE-like rows based on the normalized **YEAR-ID** key, so e.g. `CVE-2026-0915`, `UBUNTU-CVE-2026-0915`, and `DEBIAN-CVE-2026-0915` collapse to a single row.

This script intentionally does **not** treat advisory IDs such as `RHSA-2026:0794` as CVEs.

## 🔧 Tools Used

### [sbomnix](https://github.com/tiiuae/sbomnix)

**Purpose:** Generate SBOM from Nix packages
**Description:** Core tool that analyzes Nix store paths and generates standards-compliant SBOM files (CycloneDX, SPDX). It reads Nix derivations to extract package metadata, licenses, and dependencies.

**Features:**

- Generates CycloneDX and SPDX SBOMs
- Extracts Nixpkgs metadata
- Supports CSV export for analysis
- Handles complex dependency graphs

### [vulnxscan](https://github.com/tiiuae/sbomnix)

**Purpose:** Multi-source vulnerability scanning
**Description:** Part of the sbomnix suite, combines multiple vulnerability scanners to provide comprehensive security analysis. Aggregates results from both Vulnix and Grype for enhanced coverage.

**Features:**

- Orchestrates multiple vulnerability scanners
- Deduplicates results across sources
- Provides unified vulnerability reports
- Filters false positives and patched vulnerabilities

Note: the current `vulns.csv` includes an `osv` column as well, since `vulnxscan` also queries OSV.

### [Vulnix](https://github.com/nix-community/vulnix)

**Purpose:** NixOS vulnerability scanner
**Description:** Scans Nix store paths for known security vulnerabilities by cross-referencing with the NVD (National Vulnerability Database). Specialized for Nix packages.

**Features:**

- Direct integration with NixOS security tracker
- Understands Nix package versioning
- CVE database matching
- Low false-positive rate for Nix packages

### [Grype](https://github.com/anchore/grype)

**Purpose:** Container and package vulnerability scanner
**Description:** Open-source vulnerability scanner by Anchore that matches packages against multiple vulnerability databases (NVD, GitHub Security Advisories, etc.).

**Features:**

- Multi-database vulnerability matching
- Regular database updates
- Supports multiple package ecosystems
- Detailed CVE reporting with CVSS scores

### [OSV](https://osv.dev/)

**Purpose:** Vulnerability database and API
**Description:** `vulnxscan` queries OSV to enrich vulnerability coverage across multiple ecosystems.

### [nixgraph](https://github.com/tiiuae/sbomnix)

**Purpose:** Nix dependency graph visualization
**Description:** Part of sbomnix, generates visual dependency graphs showing runtime dependencies between Nix packages.

**Features:**

- GraphViz-based visualization
- Runtime dependency analysis
- Customizable graph layouts
- Helps identify dependency chains

## 📊 Usage Examples

### Import to Dependency-Track

Pick the `bom.cdx.json` you want to import (for example, `sbom/server/fips/static/bom.cdx.json` or `sbom/openssl/bom.cdx.json`).

```bash
curl -X POST "https://dtrack.example.com/api/v1/bom" \
  -H "X-Api-Key: ${API_KEY}" \
  -H "Content-Type: multipart/form-data" \
  -F "project=${PROJECT_UUID}" \
  -F "bom=@bom.cdx.json"
```

### Validate SPDX Compliance

```bash
# Using spdx-tools
spdx-tools validate bom.spdx.json

# Using online validator
# Upload to https://tools.spdx.org/app/validate/
```

### Query with jq

```bash
# List all components with versions
jq '.components[] | {name, version}' bom.cdx.json

# Find specific package
jq '.packages[] | select(.name | contains("openssl"))' bom.spdx.json

# Count components by license
jq '[.components[].licenses[].license.id] | group_by(.) |
    map({license: .[0], count: length})' bom.cdx.json

# List high-severity vulnerabilities
jq -r '.[] | select(.severity | tonumber > 7) |
    [.vuln_id, .package, .severity] | @tsv' vulns.csv
```

### Review Vulnerabilities

```bash
# View all vulnerabilities
cat vulns.csv | column -t -s,

# Filter by severity
awk -F',' '$5 > 7.0' vulns.csv | column -t -s,

# Group by package
tail -n +2 vulns.csv | cut -d',' -f3 | sort | uniq -c | sort -rn
```

## 🔍 Vulnerability analysis notes

Note: `vulnxscan` aggregates multiple sources, so the raw scan may contain multiple rows for the same underlying CVE. The generator deduplicates CVE-like rows into a single `vulns.csv` to keep the output directory tidy.

The vulnerability scan combines results from multiple sources:

- **Grype**: Scans against NVD, GitHub Security Advisories, and other databases
- **Vulnix**: Scans against NixOS security tracker and NVD with Nix-specific context
- **OSV**: Queries the OSV database (<https://osv.dev>)
- **Combined Coverage**: Both scanners complement each other, with Vulnix excelling at Nix packages and Grype providing broader coverage

### Vulnerability Report Structure

```csv
vuln_id,url,package,version_local,severity,grype,osv,vulnix,sum,sortcol
CVE-2024-XXXX,https://...,package-name,1.2.3,7.5,1,0,1,2,2024A...
```

**Columns:**

- `vuln_id`: CVE identifier
- `url`: Link to NVD entry
- `package`: Affected package name
- `version_local`: Installed version
- `severity`: CVSS score (0-10)
- `grype`, `osv`, `vulnix`: Scanner detection flags (1=detected, 0=not detected)
- `sum`: Total number of scanners that detected the vulnerability
- `sortcol`: Sorting helper column

## 🔒 Security Notes

1. **OpenSSL**: For server `--link static`, OpenSSL is statically linked; for `--link dynamic`, it is a runtime dependency
2. **Nix Store**: All dependencies are from Nix store with cryptographically verified, pinned versions
3. **Reproducibility**: The SBOM reflects the exact build output, ensuring reproducibility
4. **Coverage**: SBOM includes runtime dependencies only (build-time dependencies excluded)
5. **Updates**: Vulnerability data is point-in-time; re-run scans regularly for updates

## 🔄 Regenerating the SBOM

```bash
# From repository root (generates OpenSSL + all server combinations)
bash .github/scripts/nix.sh sbom

# OpenSSL derivation only (writes under sbom/openssl)
bash .github/scripts/nix.sh sbom --target openssl

# All server combinations (writes under sbom/server/<variant>/<link>)
bash .github/scripts/nix.sh sbom --target server

# One specific server combination
bash .github/scripts/nix.sh sbom --target server --variant fips --link static

# Notes:
# - --variant/--link are only valid with: --target server (otherwise the command errors)
# - `vulns.csv` is deduplicated in-place (no extra CSV/TXT reports are generated)
# - Generation is run from an isolated temporary work directory to avoid accidental `sbom.*` files being written to the repository root

# Run the generator script directly (supports --target/--variant/--link/--output)
nix/scripts/generate_sbom.sh --target server --variant non-fips --link dynamic --output /custom/path
```

## 📚 Standards & Specifications

### CycloneDX 1.5

- **Specification**: <https://cyclonedx.org/specification/overview/>
- **Schema**: <https://cyclonedx.org/docs/1.5/json/>
- **Use Cases**: Supply chain security, dependency tracking, vulnerability management

### SPDX 2.3

- **Specification**: <https://spdx.github.io/spdx-spec/>
- **ISO Standard**: ISO/IEC 5962:2021
- **Use Cases**: License compliance, open source governance, legal review

## 🛠️ CI/CD Integration

### GitHub Actions

```yaml
- name: Generate SBOM
  run: bash .github/scripts/nix.sh sbom

- name: Upload SBOM to Dependency-Track
  uses: DependencyTrack/gh-upload-sbom@v1
  with:
    serverhostname: 'dtrack.example.com'
    apikey: ${{ secrets.DTRACK_API_KEY }}
    project: 'cosmian-kms'
    # Choose one SBOM artifact to upload (example: server fips/static)
    bomfilename: 'sbom/server/fips/static/bom.cdx.json'

- name: Archive SBOM artifacts
  uses: actions/upload-artifact@v3
  with:
    name: sbom-artifacts
    path: sbom/
```

## 📖 Additional Resources

- **OWASP CycloneDX**: <https://cyclonedx.org/>
- **SPDX**: <https://spdx.dev/>
- **NTIA SBOM Guide**: <https://www.ntia.gov/sbom>
- **CISA SBOM Resources**: <https://www.cisa.gov/sbom>
- **NixOS Security**: <https://nixos.org/manual/nixos/stable/#sec-security>

## 📝 Build Information

Check `meta.json` for:

- Build variant (fips/non-fips)
- Build timestamp
- Nix store path
- Component and vulnerability counts
- Generator tool version

---

**Generated by**: sbomnix, vulnxscan, vulnix, grype, nixgraph
**Maintained by**: Cosmian KMS Team
**License**: See individual component licenses in SBOM files
