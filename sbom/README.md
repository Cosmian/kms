# SBOM (Software Bill of Materials)

This directory contains a comprehensive Software Bill of Materials (SBOM) for the Cosmian KMS server, generated using industry-standard tools and formats.

## 📋 Overview

An SBOM is a formal record containing the details and supply chain relationships of components used in building software. This SBOM was generated from the Nix build output, providing a complete and reproducible view of all runtime dependencies.

## 📁 Generated Files

| File | Format | Standard | Description |
|------|--------|----------|-------------|
| `bom.cdx.json` | CycloneDX 1.5 | OWASP | Industry-standard SBOM format, compatible with Dependency-Track |
| `bom.spdx.json` | SPDX 2.3 | ISO/IEC 5962:2021 | ISO-standard SBOM format, widely used for compliance |
| `sbom.csv` | CSV | - | Simple tabular format for spreadsheet analysis |
| `vulns.csv` | CSV | - | Vulnerability scan results from multiple sources |
| `graph.png` | PNG | - | Visual dependency graph showing relationships |
| `meta.json` | JSON | - | Build metadata (variant, timestamp, component counts) |

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

## 🔍 Vulnerability Analysis

The vulnerability scan combines results from multiple sources:

- **Grype**: Scans against NVD, GitHub Security Advisories, and other databases
- **Vulnix**: Scans against NixOS security tracker and NVD with Nix-specific context
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

1. **OpenSSL**: Statically linked in the binary (not a runtime dependency)
2. **Nix Store**: All dependencies are from Nix store with cryptographically verified, pinned versions
3. **Reproducibility**: The SBOM reflects the exact build output, ensuring reproducibility
4. **Coverage**: SBOM includes runtime dependencies only (build-time dependencies excluded)
5. **Updates**: Vulnerability data is point-in-time; re-run scans regularly for updates

## 🔄 Regenerating the SBOM

```bash
# From repository root
bash .github/scripts/nix.sh sbom

# For non-FIPS variant
bash .github/scripts/nix.sh --variant non-fips sbom

# Custom output directory
nix/scripts/generate_sbom.sh --output /custom/path
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
    bomfilename: 'sbom/bom.cdx.json'

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
